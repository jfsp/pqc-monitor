#!/usr/bin/env python3
"""
PQC-Monitor: score-only reassessment (scanner/reassess.py) through both
entry points: Orchestrator.reassess_run (POST /api/reassess, CLI reassess)
and scripts/reassess_all.py.

Regression cover for:
  * in-app reassess dropped group_enum → has_pqc False on every domain
  * in-app reassess dropped the chain / cipher-enum / CDN findings
  * reassessing a reassessment run (no raw scans) made every domain "na"
  * reassess_all mixed every historical probe (old expired certificate
    leaked into the newest row)

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)


def _scan(domain, port, ok, ts, version="TLSv1.3", expiry=200, key="ECDSA"):
    d = {"domain": domain, "port": port, "success": ok, "timestamp": ts}
    if ok:
        d.update({"tls_version": version, "cipher_suite": "TLS_AES_256_GCM_SHA384",
                  "certificate": {"key_type": key, "key_size_bits": 256,
                                  "signature_algorithm": "ecdsa-with-SHA256",
                                  "hash_algorithm": "SHA256",
                                  "days_to_expiry": expiry}})
    else:
        d["error"] = "timeout"
    return d


class ReassessFixture(unittest.TestCase):

    def setUp(self):
        from data.database import Database
        from scanner.cipher_enum import CipherEnumResult, CipherResult
        from scanner.group_enum import GroupEnumResult
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "r.db")
        self.db = db = Database(self.path)
        d = "p.example"
        # Old probed run: TLS 1.0, certificate expired since
        self.old = db.create_run([d])
        db.save_scan_result(self.old, _scan(d, 443, True, "2026-06-01T00:00:00+00:00",
                                            version="TLSv1", expiry=-30))
        db.save_assessment(self.old, {"domain": d, "score": 20, "level": "critical",
                                      "assessment_timestamp": "2026-06-01T00:00:01+00:00",
                                      "findings": [], "service_type": "web_primary"})
        # Newest probed run: TLS 1.3, PQC offered, 3DES accepted, one failed port
        self.new = db.create_run([d])
        db.save_scan_result(self.new, _scan(d, 443, True, "2026-09-01T00:00:00+00:00"))
        db.save_scan_result(self.new, _scan(d, 8443, False, "2026-09-01T00:00:00+00:00"))
        enum = CipherEnumResult(domain=d, port=443, timestamp="x", success=True,
                                supported_ciphers=[CipherResult(
                                    "DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                                    "TLSv1.2", 112, "RSA-3DES", "deprecated").__dict__],
                                has_3des=True, tls12_supported=True, tls13_supported=True)
        db.save_domain_extra(self.new, d, "cipher_enum", enum.to_dict())
        groups = GroupEnumResult(domain=d, port=443, timestamp="x", success=True,
                                 offered_groups=["X25519MLKEM768", "x25519"],
                                 has_pqc_kem=True, pqc_groups=["X25519MLKEM768"],
                                 hybrid_only=True, tls13_supported=True)
        db.save_domain_extra(self.new, d, "group_enum", groups.to_dict())
        db.save_assessment(self.new, {"domain": d, "score": 70, "level": "moderate",
                                      "assessment_timestamp": "2026-09-01T00:00:01+00:00",
                                      "has_pqc": True, "findings": [],
                                      "service_type": "web_primary"})
        # A domain never probed (assessment only) and a no-TLS domain
        db.save_assessment(self.new, {"domain": "ghost.example", "score": 0,
                                      "level": "na", "findings": []})
        db.save_scan_result(self.new, _scan("down.example", 443, False,
                                            "2026-09-01T00:00:00+00:00"))
        db.save_assessment(self.new, {"domain": "down.example", "score": 0,
                                      "level": "na", "findings": []})
        db.finish_run(self.old, "completed")
        db.finish_run(self.new, "completed")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def latest(self, domain):
        return {a["domain"]: a for a in self.db.get_latest_assessments()}[domain]

    def assert_current_state(self, a):
        msgs = " | ".join(f["message"] for f in a["findings_json"])
        self.assertEqual(a["has_pqc"], 1, msgs)
        self.assertIn("Server offers post-quantum key exchange: X25519MLKEM768", msgs)
        self.assertIn("3DES", msgs)                         # rebuilt cipher_enum finding
        self.assertNotIn("EXPIRED", msgs)                   # old run not mixed in
        self.assertNotIn("TLSv1 ", msgs + " ")
        self.assertEqual(a["services_assessed"], 1)
        self.assertEqual(a["service_type"], "web_primary")
        self.assertNotIn("8443", json.dumps(a.get("errors_json") or []))


class TestReassessRun(ReassessFixture):

    def _orch(self):
        from scanner.orchestrator import ScanOrchestrator
        return ScanOrchestrator({"db_path": self.path})

    def test_reassess_keeps_pqc_and_extra_findings(self):
        new_run = self._orch().reassess_run(self.new)
        self.assertEqual(self.db.get_run(new_run)["status"], "completed")
        self.assert_current_state(self.latest("p.example"))
        self.assertEqual(self.latest("down.example")["level"], "na")

    def test_reassess_of_a_reassessment_run(self):
        orch = self._orch()
        first = orch.reassess_run(self.new)
        second = orch.reassess_run(first)        # source falls back to probed run
        a = self.latest("p.example")
        self.assertEqual(a["run_id"], second)
        self.assert_current_state(a)

    def test_reassess_old_run_uses_old_data(self):
        self._orch().reassess_run(self.old)
        a = self.latest("p.example")
        msgs = " | ".join(f["message"] for f in a["findings_json"])
        self.assertIn("EXPIRED", msgs)
        self.assertEqual(a["has_pqc"], 0)

    def test_unknown_run(self):
        with self.assertRaises(ValueError):
            self._orch().reassess_run("nope")


class TestReassessAllScript(ReassessFixture):

    def test_score_only_uses_newest_probed_run(self):
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "reassess_all.py"),
             "--db", self.path, "--workers", "1"],
            capture_output=True, text=True, timeout=120, cwd=self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assert_current_state(self.latest("p.example"))
        self.assertEqual(self.latest("ghost.example")["level"], "na")


class TestSourceRun(ReassessFixture):

    def test_source_selection(self):
        from scanner.reassess import source_run
        self.assertEqual(source_run(self.db, "p.example"), self.new)
        self.assertEqual(source_run(self.db, "p.example", run_id=self.old), self.old)
        self.assertEqual(source_run(self.db, "p.example", run_id="zz",
                                    as_of="2026-07-01T00:00:00+00:00"), self.old)
        self.assertIsNone(source_run(self.db, "ghost.example"))


if __name__ == "__main__":
    unittest.main()
