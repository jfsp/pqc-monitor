#!/usr/bin/env python3
"""
PQC-Monitor: write-path integrity tests.

Guards save_assessment() against silently dropping columns (it lost
services_assessed / key_types twice: until ae26eef and again in 69a9259),
and checks scripts/backfill_services_assessed.py, including rows written by
score-only reassessment runs that have no raw scans of their own.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestSaveAssessmentColumns(unittest.TestCase):

    def setUp(self):
        from data.database import Database
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "i.db")
        self.db = Database(self.path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _row(self, domain):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            return dict(conn.execute("SELECT * FROM assessments WHERE domain=?",
                                     (domain,)).fetchone())
        finally:
            conn.close()

    def test_every_column_written_from_a_real_assessment(self):
        from scanner.crypto_assessor import CryptoAssessor
        assessor = CryptoAssessor()
        scan = {"domain": "a.example", "port": 443, "success": True,
                "timestamp": "2026-10-01T00:00:00+00:00", "tls_version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "certificate": {"key_type": "RSA", "key_size_bits": 2048,
                                "signature_algorithm": "sha256WithRSAEncryption",
                                "hash_algorithm": "SHA256", "days_to_expiry": 200}}
        a = assessor.assess_domain("a.example", [scan], service_type="web_primary")
        run = self.db.create_run(["a.example"])
        self.db.save_assessment(run, a.to_dict())
        row = self._row("a.example")
        missing = sorted(k for k, v in row.items() if v is None)
        self.assertEqual(missing, [], "columns not written by save_assessment")
        self.assertEqual(row["services_assessed"], 1)
        self.assertEqual(json.loads(row["key_types"]), ["RSA"])

    def test_na_assessment(self):
        run = self.db.create_run(["n.example"])
        self.db.save_assessment(run, {"domain": "n.example", "score": 0,
                                      "level": "na", "findings": []})
        row = self._row("n.example")
        self.assertEqual((row["services_assessed"], row["key_types"]), (0, "[]"))


class TestBackfill(unittest.TestCase):

    def setUp(self):
        from data.database import Database
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "b.db")
        db = Database(self.path)
        # network run with two successful services and one failure
        self.run = db.create_run(["w.example"])
        for port, ok, kt in ((443, True, "ECDSA"), (25, True, "RSA"), (8443, False, "")):
            db.save_scan_result(self.run, {
                "domain": "w.example", "port": port, "success": ok,
                "timestamp": "2026-09-01T00:00:00+00:00",
                "certificate": {"key_type": kt} if kt else None})
        # Later score-only reassessment: its own run, no raw scans
        self.rerun = db.create_run(["w.example"], notes="reassess")
        conn = sqlite3.connect(self.path)
        # Rows as written by the broken INSERT (defaults)
        conn.execute("INSERT INTO assessments (run_id, domain, assessed_at, score, level) "
                     "VALUES (?, 'w.example', '2026-09-01T00:00:01+00:00', 70, 'moderate')",
                     (self.run,))
        conn.execute("INSERT INTO assessments (run_id, domain, assessed_at, score, level) "
                     "VALUES (?, 'w.example', '2026-10-01T00:00:00+00:00', 71, 'moderate')",
                     (self.rerun,))
        # A reassessment older than any probe cannot be reconstructed
        conn.execute("INSERT INTO assessments (run_id, domain, assessed_at, score, level) "
                     "VALUES ('ghost', 'w.example', '2026-01-01T00:00:00+00:00', 50, 'weak')")
        conn.commit()
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _rows(self):
        conn = sqlite3.connect(self.path)
        try:
            return {r[0]: (r[1], r[2]) for r in conn.execute(
                "SELECT run_id, services_assessed, key_types FROM assessments")}
        finally:
            conn.close()

    def _run(self, *extra):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
        import backfill_services_assessed as bf
        return bf.main(["--db", self.path, *extra])

    def test_same_run_and_reassess_fallback(self):
        self.assertEqual(self._run(), 0)
        rows = self._rows()
        self.assertEqual(rows[self.run], (2, json.dumps(["ECDSA", "RSA"])))
        self.assertEqual(rows[self.rerun], (2, json.dumps(["ECDSA", "RSA"])))
        self.assertEqual(rows["ghost"][0], 0)          # predates every probe

    def test_same_run_only(self):
        self.assertEqual(self._run("--same-run-only"), 0)
        rows = self._rows()
        self.assertEqual(rows[self.run][0], 2)
        self.assertEqual(rows[self.rerun][0], 0)

    def test_dry_run_writes_nothing(self):
        self.assertEqual(self._run("--dry-run"), 0)
        self.assertEqual(self._rows()[self.run][0], 0)


if __name__ == "__main__":
    unittest.main()
