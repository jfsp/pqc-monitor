#!/usr/bin/env python3
"""
PQC-Monitor: PQC key-exchange detection self-test.

Validates that the scanner correctly detects post-quantum (hybrid ML-KEM)
key-exchange groups against live reference hosts, using the REAL scanner code
path (scanner.tls_probe / scanner.cipher_enum) — not a reimplementation.

Run manually or from CI; NOT wired into app startup.

  python3 scripts/pqc_selftest.py                 # default reference hosts
  python3 scripts/pqc_selftest.py www.bportugal.pt example.com
  python3 scripts/pqc_selftest.py --testssl       # cross-check vs testssl.sh
  python3 scripts/pqc_selftest.py --json          # machine-readable output

Exit code 0 = all expectations met, 1 = at least one mismatch/error.

Why testssl.sh and NOT sslscan
──────────────────────────────
We grade on the groups a server OFFERS. Only testssl.sh reports that directly:

    KEMs offered                 MLKEM1024 X25519MLKEM768

sslscan (as of 2.1.5) reports only "Server Key Exchange Group(s)" — the group
it NEGOTIATED — so it cannot corroborate the offered set and will look like a
false negative if used as the oracle. It is the wrong instrument for this
measurement, regardless of its OpenSSL version.

  Install: https://github.com/testssl/testssl.sh  (e.g. /usr/local/bin/testssl.sh)

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
from scanner.group_enum import (enumerate_groups,             # noqa: E402
                                probe_negative_control)

# Reference hosts with expected PQC status. Keep this list small and stable;
# override on the command line for ad-hoc checks. `expect_pqc=None` means
# "don't assert, just report" — use for hosts whose config may change.
# NOTE: there is deliberately no "classical-only" host here. Any public host can
# end up behind a PQC-enabled CDN without notice (example.com resolves to a
# Cloudflare edge and duly offers Cloudflare's PQC groups), which makes a
# host-based negative control unreliable. False positives are caught instead by
# the GREASE control below, which is host-independent.
DEFAULT_HOSTS: list[tuple[str, int, bool | None]] = [
    ("www.google.com",   443, True),   # offers MLKEM1024 + X25519MLKEM768
    ("cloudflare.com",   443, True),   # offers X25519MLKEM768 (+ Kyber draft)
]

_PQC_GROUP_RE = re.compile("|".join(re.escape(i) for i in PQC_KEM_INDICATORS), re.I)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(t: str) -> str:
    return _ANSI_RE.sub("", t)


def _is_pqc_group(name: str) -> bool:
    return bool(name) and bool(_PQC_GROUP_RE.search(name))


def _can_report_negotiated_group() -> bool:
    """True if Python can REPORT the negotiated key-exchange group.

    This is NOT the same as "the stack can do PQC". SSLSocket.group() does not
    exist in CPython as of 3.13 (unmerged proposal gh-136306), so this is False
    on every current interpreter — even on OpenSSL 3.5, which negotiates
    X25519MLKEM768 quite happily. We simply cannot read which group was used.

    Grading does not depend on this: it uses OFFERED groups (group_enum), which
    are enumerated with a raw ClientHello and need no ssl-module support at all.
    """
    return hasattr(ssl.SSLSocket, "group")


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


# ── Optional external oracle: testssl.sh ──────────────────────────────────────

def testssl_groups(host: str, port: int, timeout: int = 300) -> dict:
    """Parse the KEM groups testssl.sh reports as *offered*.

    testssl prints (ANSI-coloured):
        KEMs offered                 MLKEM1024 X25519MLKEM768
    Returns {'available': bool, 'groups': [...], 'has_pqc': bool, 'error': str}.
    """
    # testssl.sh must be run from a full checkout (it needs its etc/ data files),
    # so a bare copy in /usr/local/bin does not work. Honour $PQC_TESTSSL.
    candidates = [
        os.environ.get("PQC_TESTSSL"),
        shutil.which("testssl.sh"), shutil.which("testssl"),
        "/opt/testssl/testssl.sh", "/usr/local/bin/testssl.sh",
    ]
    exe = next((c for c in candidates if c and os.path.exists(c)), None)
    if not exe:
        return {"available": False,
                "error": "testssl.sh not found (see github.com/testssl/testssl.sh)"}
    try:
        # --fs emits "KEMs offered". The rest are purely to stop testssl doing
        # work we don't need — the default scan hits EVERY A record of the host,
        # which is why google.com takes minutes.
        cmd = [
            exe,
            "--fs",                 # forward-secrecy section → "KEMs offered"
            "--ip", "one",          # only the first IP, not every A record
            "--nodns", "min",       # skip rDNS lookups
            "--warnings", "batch",  # never wait for a keypress
            "--color", "0",
            "--quiet",
            f"{host}:{port}",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        text = proc.stdout + proc.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"available": True, "error": f"testssl run failed: {e}"}

    text = _strip_ansi(text)   # belt-and-braces: --color 0 should suffice
    groups: list[str] = []
    m = re.search(r"^\s*KEMs?\s+offered\b[ \t:]*(.+?)\s*$", text, re.I | re.M)
    if m:
        groups = [g for g in re.split(r"[\s,]+", m.group(1).strip()) if g]
    if not groups:
        # Fallback: some versions annotate the group on TLS 1.3 suite lines.
        groups = sorted(set(re.findall(r"\b\w*(?:MLKEM|Kyber)\w*\b", text, re.I)))
    if not groups:
        return {"available": True, "groups": [], "has_pqc": False,
                "error": "no 'KEMs offered' line in testssl output"}
    return {
        "available": True,
        "groups": groups,
        "has_pqc": any(_is_pqc_group(g) for g in groups),
        "error": "",
    }


# ── Reporting ─────────────────────────────────────────────────────────────────

def evaluate(res: dict, expect_pqc: bool | None, xcheck: dict | None) -> tuple[str, list[str]]:
    """Return (status, notes). status in {PASS, FAIL, WARN, ERROR}.

    Grades on OFFERED groups. The negotiated group is reported for contrast but
    never decides the verdict — it depends on our client, not the server.
    """
    notes: list[str] = []
    if not res.get("ok"):
        return "ERROR", [res.get("error", "unknown error")]

    detected = bool(res.get("has_pqc_offered"))
    negotiated = bool(res.get("has_pqc_kem"))
    failed = False

    # Only meaningful if we can actually read the negotiated group; otherwise
    # has_pqc_kem is "unknown", not "false", and the comparison says nothing.
    if _can_report_negotiated_group() and detected and not negotiated:
        notes.append("server OFFERS PQC but our client negotiated classical "
                     "— check the local group preference order")

    # Cross-check against testssl, which also reports OFFERED KEMs: like-for-like.
    if xcheck and xcheck.get("available") and not xcheck.get("error"):
        theirs = {g.lower() for g in xcheck.get("groups", [])}
        ours = {g.lower() for g in (res.get("offered_pqc") or [])}
        if xcheck.get("groups"):
            notes.append("testssl KEMs offered: " + ", ".join(xcheck["groups"]))
        missed, extra = theirs - ours, ours - theirs
        if missed:
            notes.append("MISMATCH: testssl saw KEMs we missed: " + ", ".join(sorted(missed)))
            failed = True
        if extra:
            notes.append("MISMATCH: we report KEMs testssl did not: " + ", ".join(sorted(extra)))
            failed = True
        if not missed and not extra:
            notes.append("cross-check agrees with testssl")
    elif xcheck and xcheck.get("error"):
        notes.append("testssl: " + xcheck["error"])

    if expect_pqc is not None and detected != expect_pqc:
        notes.append(f"expected pqc_offered={expect_pqc}, got {detected}")
        failed = True

    if failed:
        return "FAIL", notes
    if expect_pqc is None:
        return ("PASS" if detected else "WARN"), notes
    return "PASS", notes


def main() -> int:
    ap = argparse.ArgumentParser(description="PQC detection self-test")
    ap.add_argument("hosts", nargs="*",
                    help="host[:port] to test (default: built-in reference set)")
    ap.add_argument("--testssl", action="store_true",
                    help="cross-check offered groups against testssl.sh")
    ap.add_argument("--timeout", type=int, default=10,
                    help="per-socket timeout for our own probes")
    ap.add_argument("--testssl-timeout", type=int, default=300,
                    help="wall-clock budget for each testssl run")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if args.hosts:
        targets = []
        for h in args.hosts:
            host, _, port = h.partition(":")
            targets.append((host, int(port) if port else 443, None))
    else:
        targets = DEFAULT_HOSTS

    can_report = _can_report_negotiated_group()
    results = []
    exit_code = 0

    # ── Soundness gate ────────────────────────────────────────────────────────
    # Probe reserved GREASE codepoints that NO server may ever select. If the
    # enumerator calls one "offered", it is producing false positives and every
    # other result in this run is untrustworthy.
    control_host = targets[0][0]
    control = probe_negative_control(control_host, targets[0][1], float(args.timeout))
    if not control["sound"]:
        exit_code = 1

    for host, port, expect in targets:
        res = probe_host(host, port, args.timeout)
        xcheck = testssl_groups(host, port, args.testssl_timeout) if args.testssl else None
        status, notes = evaluate(res, expect, xcheck)
        if status in ("FAIL", "ERROR"):
            exit_code = 1
        results.append({"host": host, "port": port, "expect_pqc": expect,
                        "status": status, "result": res, "notes": notes,
                        "testssl": xcheck})

    if args.json:
        print(json.dumps({"can_report_negotiated_group": can_report,
                          "negative_control": control,
                          "results": results}, indent=2))
        return exit_code

    print(f"Local stack: {ssl.OPENSSL_VERSION} · Python {sys.version.split()[0]}")
    if not can_report:
        print("  Note: SSLSocket.group() is unavailable (unmerged in CPython), so the "
              "negotiated\n        group cannot be read and shows as '—'. This is "
              "expected and harmless:\n        grading uses OFFERED groups, which need "
              "no ssl-module support.")
    if control["sound"]:
        print(f"Negative control ({control_host}): GREASE groups correctly rejected  ✓")
    else:
        print(f"Negative control ({control_host}): *** FALSE POSITIVES *** "
              f"{control['false_positives']} reported as offered.\n"
              f"  The enumerator is unsound — results below cannot be trusted.")
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
