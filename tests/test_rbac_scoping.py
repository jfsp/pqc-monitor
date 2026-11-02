#!/usr/bin/env python3
"""
PQC-Monitor: RBAC scoping of the endpoints that used to return data for
every domain to every user: /api/export, /api/runs, /api/schedules,
/api/ct/stats, /api/ct/timeline, /api/roadmap/stats.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestRbacScoping(unittest.TestCase):

    def setUp(self):
        from data.database import Database
        from auth.store import AuthStore
        from auth.models import ROLE_ANALYST
        from scheduler.scan_scheduler import ScanScheduler
        import auth.auth_routes as _ar
        _ar._login_attempts.clear()
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "s.db")
        db = self.db = Database(self.path)
        self.org_a = db.create_organisation("Bank A")
        org_b = db.create_organisation("Bank B")
        db.set_org_domains(self.org_a, ["a1.example", "a2.example"])
        db.set_org_domains(org_b, ["b1.example"])

        def assess(run, dom, ts, score=60, level="moderate"):
            db.save_assessment(run, {"domain": dom, "assessment_timestamp": ts,
                                     "score": score, "level": level,
                                     "findings": [{"severity": "high", "category": "x",
                                                   "message": f"issue on {dom}"}]})
        self.run1 = db.create_run(["a1.example", "b1.example"])
        assess(self.run1, "a1.example", "2026-09-01T00:00:00+00:00")
        assess(self.run1, "b1.example", "2026-09-01T00:00:00+00:00", 20, "critical")
        self.run2 = db.create_run(["b1.example"])
        assess(self.run2, "b1.example", "2026-09-10T00:00:00+00:00", 25, "critical")

        # CT: b1 monitored twice (latest query must win), a1 once
        for dom, n, pqc, when in (("b1.example", 10, 1, "2026-08-01T00:00:00"),
                                  ("b1.example", 12, 2, "2026-09-01T00:00:00"),
                                  ("a1.example", 5, 0, "2026-09-02T00:00:00")):
            db.save_ct_summary({"domain": dom, "queried_at": when,
                                "total_certs_found": n, "pqc_certs_found": pqc,
                                "hybrid_certs_found": 0, "certificates": []})
        for dom, p1 in (("a1.example", 2), ("b1.example", 5)):
            db.save_roadmap(self.run1, {"domain": dom, "phase1_items": p1,
                                        "total_effort_days_min": 1,
                                        "total_effort_days_max": 2})
        sched = ScanScheduler(None, db)
        sched.add_schedule("only b", db.save_domain_list("lb", ["b1.example"]), 30)
        sched.add_schedule("a and b", db.save_domain_list("lab", ["A1.example", "b1.example"]), 30)
        with db._connect() as conn:          # estate-wide job without a list
            conn.execute("INSERT INTO scheduled_scans (name, interval_days, config_json) "
                         "VALUES ('SSL Labs sweep', 7, '{\"kind\": \"ssllabs_sweep\"}')")

        store = AuthStore(self.path)
        ana = store.create_user("ana", "ana@e.com", "password1234", ROLE_ANALYST)
        store.set_user_orgs(ana.id, [self.org_a])
        store.set_must_change_password(ana.id, False)
        from app_factory import create_app
        app = create_app({"db_path": self.path, "https_enabled": False,
                          "secret_key": "test-secret-32-chars-exactly!!!"})
        app.config["TESTING"] = True
        self.c = app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def login(self, u, p):
        self.c.post("/login", data={"username": u, "password": p}, follow_redirects=True)

    # ── /api/export ──────────────────────────────────────────────────────
    def test_export_scoped_for_analyst(self):
        self.login("ana", "password1234")
        csv = self.c.get("/app/api/export?format=csv").data.decode()
        self.assertIn("a1.example", csv)
        self.assertNotIn("b1.example", csv)
        js = json.loads(self.c.get("/app/api/export?format=json").data)
        self.assertEqual([a["domain"] for a in js["assessments"]], ["a1.example"])
        self.assertEqual(js["summary"]["total_domains"], 1)
        txt = self.c.get("/app/api/export?format=text").data.decode()
        self.assertNotIn("b1.example", txt)
        self.assertNotIn("TREND (last scans)", txt)
        # a specific run is filtered the same way
        js = json.loads(self.c.get(f"/app/api/export?format=json&run_id={self.run1}").data)
        self.assertEqual([a["domain"] for a in js["assessments"]], ["a1.example"])

    def test_export_admin_sees_all(self):
        self.login("admin", "changeme123")
        csv = self.c.get("/app/api/export?format=csv").data.decode()
        self.assertIn("a1.example", csv)
        self.assertIn("b1.example", csv)

    # ── /api/runs ────────────────────────────────────────────────────────
    def test_runs(self):
        self.login("admin", "changeme123")
        runs = self.c.get("/app/api/runs").get_json()
        self.assertEqual({r["run_id"]: r["domain_count"] for r in runs},
                         {self.run1: 2, self.run2: 1})
        self.assertTrue(all("domain_list" not in r for r in runs))
        self.c.get("/logout")
        self.login("ana", "password1234")
        runs = self.c.get("/app/api/runs").get_json()
        self.assertEqual([(r["run_id"], r["domain_count"]) for r in runs], [(self.run1, 1)])

    # ── /api/schedules ───────────────────────────────────────────────────
    def test_schedules(self):
        self.login("admin", "changeme123")
        self.assertEqual(len(self.c.get("/app/api/schedules").get_json()), 3)
        self.c.get("/logout")
        self.login("ana", "password1234")
        rows = self.c.get("/app/api/schedules").get_json()
        self.assertEqual(sorted(r["name"] for r in rows), ["SSL Labs sweep", "a and b"])
        self.assertTrue(all(set(r) == {"id", "name", "interval_days", "next_run",
                                       "last_run", "enabled"} for r in rows))

    # ── CT / roadmap stats ───────────────────────────────────────────────
    def test_ct_stats_latest_query_and_scope(self):
        self.login("admin", "changeme123")
        st = self.c.get("/app/api/ct/stats").get_json()
        self.assertEqual((st["domains_monitored"], st["total_certs"], st["total_pqc"]),
                         (2, 17, 2))              # b1's latest query, not 10+12
        self.c.get("/logout")
        self.login("ana", "password1234")
        st = self.c.get("/app/api/ct/stats").get_json()
        self.assertEqual((st["domains_monitored"], st["total_certs"], st["total_pqc"]),
                         (1, 5, 0))
        tl = self.c.get("/app/api/ct/timeline").get_json()
        self.assertEqual([(m["month"], m["all_total"]) for m in tl], [("2026-09", 5)])

    def test_roadmap_stats_scope(self):
        self.login("ana", "password1234")
        st = self.c.get("/app/api/roadmap/stats").get_json()
        self.assertEqual((st["domains"], st["total_p1_items"], st["domains_need_p1"]),
                         (1, 2, 1))
        self.c.get("/logout")
        self.login("admin", "changeme123")
        self.assertEqual(self.c.get("/app/api/roadmap/stats").get_json()["domains"], 2)

    def test_dashboard_export_url_has_app_prefix(self):
        self.login("admin", "changeme123")
        body = self.c.get("/app/").data.decode()
        self.assertIn("location.pathname.startsWith('/app') ? '/app' : ''", body)
        self.assertIn("run.domain_count != null", body)


if __name__ == "__main__":
    unittest.main()
