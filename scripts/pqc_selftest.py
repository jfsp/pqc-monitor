#!/usr/bin/env python3
"""
PQC-Monitor: PQC key-exchange detection self-test.

Validates that the scanner correctly detects post-quantum (hybrid ML-KEM)
key-exchange groups against live reference hosts, using the REAL scanner code
path (scanner.tls_probe / scanner.cipher_enum) — not a reimplementation.

Run manually or from CI; NOT wired into app startup.

  python3 scripts/pqc_selftest.py                 # default reference hosts
  python3 scripts/pqc_selftest.py www.bportugal.pt example.com
  python3 scripts/pqc_selftest.py --sslscan       # cross-check vs sslscan
  python3 scripts/pqc_selftest.py --json          # machine-readable output

Exit code 0 = all expectations met, 1 = at least one mismatch/error.

Why an external cross-check (--sslscan) is useful
─────────────────────────────────────────────────
The in-process probe reports the group the server *negotiates with our
ClientHello*. sslscan links its own OpenSSL and enumerates every group the
server *offers*. Those can differ: a server may offer X25519MLKEM768 yet
negotiate classical X25519 if our stack doesn't advertise the hybrid. The
cross-check turns that silent gap into a visible diff.

Requirements for --sslscan: a recent sslscan linked against OpenSSL >= 3.5
(older builds don't know the hybrid groups and will report false negatives).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import ssl
import subprocess
import sys

# Make the repo importable when run from anywhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scanner.tls_probe import probe_tls, PQC_KEM_INDICATORS  # noqa: E402
from scanner.group_enum import enumerate_groups              # noqa: E402

# Reference hosts with expected PQC status. Keep this list small and stable;
# override on the command line for ad-hoc checks. `expect_pqc=None` means
# "don't assert, just report" — use for hosts whose config may change.
DEFAULT_HOSTS: list[tuple[str, int, bool | None]] = [
    ("www.bportugal.pt",            443, True),   # offers X25519MLKEM768
    ("pq.cloudflareresearch.com",   443, True),   # Cloudflare PQC reference
    ("example.com",                 443, False),  # classical-only baseline
]

_PQC_GROUP_RE = re.compile("|".join(re.escape(i) for i in PQC_KEM_INDICATORS), re.I)


def _is_pqc_group(name: str) -> bool:
    return bool(name) and bool(_PQC_GROUP_RE.search(name))


def _stack_can_offer_pqc() -> bool:
    """True if the local Python/OpenSSL can even negotiate a hybrid group.
    Needs SSLSocket.group() (Py>=3.13) and an OpenSSL new enough to offer the
    group by default (>=3.5). This is a heuristic, reported for context."""
    if not hasattr(ssl.SSLSocket, "group"):
        return False
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)", ssl.OPENSSL_VERSION)
    if not m:
        return False
    major, minor = int(m.group(1)), int(m.group(2))
    return (major, minor) >= (3, 5)


# ── In-process probe (the code under test) ────────────────────────────────────

def probe_host(host: str, port: int, timeout: int) -> dict:
    """Run the real scanner path and return a normalised result dict."""
    out: dict = {"host": host, "port": port, "ok": False, "error": ""}
    try:
        r = probe_tls(host, port, timeout=timeout)
        if not r.success:
            out["error"] = r.error or "handshake_failed"
            return out
        out.update(
            ok=True,
            tls_version=r.tls_version,
            cipher=r.cipher_suite,
            key_group=r.key_group,
            has_pqc_kem=r.has_pqc_kem,
            pqc_via_group=_is_pqc_group(r.key_group),
        )
        # OFFERED groups — the authoritative basis for PQC grading.
        # Independent of what our client happened to negotiate above.
        try:
            ge = enumerate_groups(host, port, timeout=float(timeout))
            out["offered_groups"] = ge.offered_groups
            out["offered_pqc"] = ge.pqc_groups
            out["has_pqc_offered"] = ge.has_pqc_kem
            out["hybrid_only"] = ge.hybrid_only
            if ge.error:
                out["group_enum_error"] = ge.error
        except Exception as e:
            out["offered_groups"] = []
            out["has_pqc_offered"] = None
            out["group_enum_error"] = str(e)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# ── Optional external oracle: sslscan ─────────────────────────────────────────

def sslscan_groups(host: str, port: int, timeout: int) -> dict:
    """Parse the KEM groups sslscan reports as *offered*. Returns
    {'available': bool, 'groups': [...], 'has_pqc': bool, 'error': str}."""
    exe = shutil.which("sslscan")
    if not exe:
        return {"available": False, "error": "sslscan not installed"}
    try:
        # --iana-names keeps naming aligned; not all builds support it, so we
        # fall back to a bare invocation on failure.
        cmd = [exe, "--no-colour", f"{host}:{port}"]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 20)
        text = proc.stdout + proc.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"available": True, "error": f"sslscan run failed: {e}"}

    groups: list[str] = []
    # Typical line (note: no colon in sslscan output):
    #   "KEMs offered                 X25519MLKEM768"
    m = re.search(r"^[ \t]*KEMs?\s+offered\b[ \t:]*(.+?)[ \t]*$", text,
                  re.I | re.M)
    if m:
        groups = [g for g in re.split(r"[\s,]+", m.group(1).strip()) if g]
    # Some builds annotate the group inline on TLS 1.3 suite lines instead.
    if not groups:
        groups = sorted(set(re.findall(r"\b\w*(?:MLKEM|Kyber)\w*\b", text, re.I)))
    return {
        "available": True,
        "groups": groups,
        "has_pqc": any(_is_pqc_group(g) for g in groups),
        "error": "",
        "version": _sslscan_version(exe),
    }


def _sslscan_version(exe: str) -> str:
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True,
                           timeout=10)
        return (p.stdout + p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr) else ""
    except Exception:
        return ""


# ── Reporting ─────────────────────────────────────────────────────────────────

def evaluate(res: dict, expect_pqc: bool | None, xcheck: dict | None) -> tuple[str, list[str]]:
    """Return (status, notes). status in {PASS, FAIL, WARN, ERROR}."""
    notes: list[str] = []
    if not res.get("ok"):
        return "ERROR", [res.get("error", "unknown error")]

    # Grade on OFFERED (server property); negotiated is reported for contrast.
    detected = bool(res.get("has_pqc_offered"))
    negotiated = bool(res.get("has_pqc_kem"))
    if detected and not negotiated:
        notes.append("server OFFERS PQC but our client negotiated classical "
                     "— expected on stacks that don't advertise the hybrid")

    # sslscan divergence: offered (sslscan) vs negotiated (us).
    if xcheck and xcheck.get("available") and not xcheck.get("error"):
        offered = xcheck.get("has_pqc")
        if offered and not detected:
            notes.append("sslscan sees PQC OFFERED but we negotiated classical "
                         "— server supports it; our ClientHello didn't select it")
        elif detected and not offered:
            notes.append("we detected PQC but sslscan did not "
                         "(check sslscan/OpenSSL version >= 3.5)")
        if xcheck.get("groups"):
            notes.append("sslscan groups: " + ", ".join(xcheck["groups"]))
    elif xcheck and xcheck.get("error"):
        notes.append("sslscan: " + xcheck["error"])

    if expect_pqc is None:
        return ("PASS" if detected else "WARN"), notes
    if detected == expect_pqc:
        return "PASS", notes
    return "FAIL", notes + [f"expected pqc={expect_pqc}, got {detected}"]


def main() -> int:
    ap = argparse.ArgumentParser(description="PQC detection self-test")
    ap.add_argument("hosts", nargs="*",
                    help="host[:port] to test (default: built-in reference set)")
    ap.add_argument("--sslscan", action="store_true",
                    help="cross-check against sslscan if installed")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if args.hosts:
        targets = []
        for h in args.hosts:
            host, _, port = h.partition(":")
            targets.append((host, int(port) if port else 443, None))
    else:
        targets = DEFAULT_HOSTS

    stack_ok = _stack_can_offer_pqc()
    results = []
    exit_code = 0

    for host, port, expect in targets:
        res = probe_host(host, port, args.timeout)
        xcheck = sslscan_groups(host, port, args.timeout) if args.sslscan else None
        status, notes = evaluate(res, expect, xcheck)
        if status in ("FAIL", "ERROR"):
            exit_code = 1
        results.append({"host": host, "port": port, "expect_pqc": expect,
                        "status": status, "result": res, "notes": notes,
                        "sslscan": xcheck})

    if args.json:
        print(json.dumps({"stack_can_offer_pqc": stack_ok, "results": results},
                         indent=2))
        return exit_code

    print(f"Local stack: {ssl.OPENSSL_VERSION} · "
          f"group() {'yes' if hasattr(ssl.SSLSocket, 'group') else 'NO'} · "
          f"can offer PQC: {'yes' if stack_ok else 'NO'}")
    if not stack_ok:
        print("  ⚠  This stack cannot negotiate hybrid groups — in-process "
              "detection will report classical. Use --sslscan as the oracle.")
    print("-" * 78)
    for r in results:
        res = r["result"]
        icon = {"PASS": "✓", "FAIL": "✗", "WARN": "~", "ERROR": "!"}[r["status"]]
        grp = res.get("key_group") or "—"
        offered = ", ".join(res.get("offered_pqc") or []) or "none"
        line = (f"{icon} {r['status']:5} {r['host']}:{r['port']:<5} "
                f"pqc_offered={res.get('has_pqc_offered', '?')} "
                f"[{offered}] negotiated={grp}")
        print(line)
        for n in r["notes"]:
            print(f"        · {n}")
    print("-" * 78)
    print("PASS" if exit_code == 0 else "FAILURES DETECTED")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
