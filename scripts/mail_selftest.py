#!/usr/bin/env python3
"""
PQC-Monitor: Mail self-test

Loads the exact mail configuration the web service uses (config.yaml + the
PQC_MAIL_PASSWORD environment variable) and attempts to send one message, so
relay credentials can be verified from the shell without going through the UI.

    python3 scripts/mail_selftest.py --to you@example.com
    python3 scripts/mail_selftest.py --to you@example.com --force   # ignore mail.enabled

It never prints the password — only its length and whether it contains spaces
(the usual Gmail app-password mistake). SMTP errors from the server are shown
verbatim (e.g. 535 BadCredentials) via the mailer's log output.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import logging
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)


def main() -> int:
    ap = argparse.ArgumentParser(description="Send a PQC-Monitor test email.")
    ap.add_argument("--to", required=True, help="Recipient address")
    ap.add_argument("--config", default=None, help="Path to config.yaml")
    ap.add_argument("--subject", default="PQC-Monitor mail self-test")
    ap.add_argument("--force", action="store_true",
                    help="Attempt the send even if mail.enabled is false")
    args = ap.parse_args()

    # Surface the mailer's INFO/WARNING lines (including the SMTP error).
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")

    from pqc_monitor import load_config
    from auth.mailer import Mailer

    cfg = load_config(args.config)
    mail = dict(cfg.get("mail", {}))

    pw = mail.get("relay_password", "") or ""
    print("Resolved mail configuration")
    print(f"  enabled        : {mail.get('enabled', False)}")
    print(f"  mode           : {mail.get('mode', 'local')}")
    print(f"  from_addr      : {mail.get('from_addr', '')}")
    if (mail.get("mode") or "local").lower() == "relay":
        print(f"  relay_host     : {mail.get('relay_host', '')}")
        print(f"  relay_port     : {mail.get('relay_port', '')}")
        print(f"  relay_security : {mail.get('relay_security', '')}")
        print(f"  relay_username : {mail.get('relay_username', '')}")
        print(f"  relay_password : set={bool(pw)} length={len(pw)} "
              f"contains_space={' ' in pw}")
        if " " in pw:
            print("  ! password contains spaces — Gmail app passwords must be "
                  "entered WITHOUT the display spaces (16 chars).")
        if not pw:
            print("  ! password is empty — check PQC_MAIL_PASSWORD is exported "
                  "to the service (see /proc/<pid>/environ).")
        src = "env PQC_MAIL_PASSWORD" if os.environ.get("PQC_MAIL_PASSWORD") \
              else "config mail.relay_password"
        print(f"  password source: {src}")
    else:
        print(f"  local_host     : {mail.get('local_host', '127.0.0.1')}")
        print(f"  local_port     : {mail.get('local_port', 25)}")

    if args.force:
        mail["enabled"] = True
    if not mail.get("enabled"):
        print("\nmail.enabled is false; nothing sent. Use --force to test anyway.")
        return 1

    print(f"\nSending test message to {args.to} ...")
    ok = Mailer(mail).send(
        args.to, args.subject,
        "This is a PQC-Monitor mail self-test. If you received it, the relay "
        "configuration is working.")
    print("RESULT:", "OK — message accepted by the server." if ok
          else "FAILED — see the error line above.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
