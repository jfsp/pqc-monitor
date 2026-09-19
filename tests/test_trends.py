"""
Tests for time-bucketed trends (data/trends.py) and the scoped
/app/api/trends + /app/api/trends/scopes endpoints.

All tests are fully offline.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data.trends import (
    compute_trends, choose_granularity, floor_ts, next_ts, bucket_count,
    default_stale_days, parse_ts, aggregate,
)

UTC = timezone.utc
NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


def _row(domain, ts, score=50, level="moderate", pqc=0):
    return {"domain": domain, "assessed_at": ts, "score": score,
            "level": level, "has_pqc": pqc}


# ══════════════════════════════════════════════════════════════════
# Calendar helpers
# ══════════════════════════════════════════════════════════════════

class TestCalendar(unittest.TestCase):

    def test_floor_week_is_monday(self):
        d = datetime(2026, 9, 19, 15, tzinfo=UTC)          # Saturday
        self.assertEqual(floor_ts(d, "week"), datetime(2026, 9, 14, tzinfo=UTC))

    def test_floor_quarter(self):
        d = datetime(2026, 8, 30, tzinfo=UTC)
        self.assertEqual(floor_ts(d, "quarter"), datetime(2026, 7, 1, tzinfo=UTC))

    def test_next_month_rolls_year(self):
        self.assertEqual(next_ts(datetime(2026, 12, 1, tzinfo=UTC), "month"),
                         datetime(2027, 1, 1, tzinfo=UTC))

    def test_next_quarter_rolls_year(self):
        self.assertEqual(next_ts(datetime(2026, 10, 1, tzinfo=UTC), "quarter"),
                         datetime(2027, 1, 1, tzinfo=UTC))

    def test_parse_naive_and_z(self):
        self.assertEqual(parse_ts("2026-06-25T10:00:00"),
                         datetime(2026, 6, 25, 10, tzinfo=UTC))
        self.assertEqual(parse_ts("2026-06-25T10:00:00Z"),
                         datetime(2026, 6, 25, 10, tzinfo=UTC))
        self.assertIsNone(parse_ts("garbage"))
        self.assertIsNone(parse_ts(None))

    def test_bucket_count(self):
        s = datetime(2026, 6, 25, tzinfo=UTC)
        self.assertEqual(bucket_count(s, NOW, "month"), 4)   # Jun..Sep


# ══════════════════════════════════════════════════════════════════
# Parameter resolution
# ══════════════════════════════════════════════════════════════════

class TestGranularityChoice(unittest.TestCase):

    def test_monthly_schedule_long_span_is_monthly(self):
        g, _ = choose_granularity(NOW - timedelta(days=400), NOW, 30)
        self.assertEqual(g, "month")

    def test_monthly_schedule_short_span_goes_finer(self):
        # 86 days of history, monthly cadence -> only 4 months -> weekly
        g, reason = choose_granularity(datetime(2026, 6, 25, tzinfo=UTC), NOW, 30)
        self.assertEqual(g, "week")
        self.assertIn("finer", reason)

    def test_daily_schedule(self):
        g, _ = choose_granularity(NOW - timedelta(days=30), NOW, 1)
        self.assertEqual(g, "day")

    def test_daily_schedule_long_span_goes_coarser(self):
        g, reason = choose_granularity(NOW - timedelta(days=730), NOW, 1)
        self.assertIn(g, ("week", "month"))
        self.assertIn("coarser", reason)

    def test_weekly_schedule(self):
        g, _ = choose_granularity(NOW - timedelta(days=180), NOW, 7)
        self.assertEqual(g, "week")

    def test_no_schedule_defaults_monthly(self):
        g, reason = choose_granularity(NOW - timedelta(days=365), NOW, None)
        self.assertEqual(g, "month")
        self.assertIn("default", reason)

    def test_stale_days(self):
        self.assertEqual(default_stale_days(30), 90)
        self.assertEqual(default_stale_days(1), 7)        # floor
        self.assertEqual(default_stale_days(365), 400)    # cap
        self.assertEqual(default_stale_days(None), 90)


# ══════════════════════════════════════════════════════════════════
# Aggregation
# ══════════════════════════════════════════════════════════════════

class TestAggregate(unittest.TestCase):

    def test_na_excluded_from_score_and_pqc_denominator(self):
        m = aggregate([
            _row("a", "", 80, "ready", 1),
            _row("b", "", 40, "weak", 0),
            _row("c", "", 0, "na", 0),
        ])
        self.assertEqual(m["monitored"], 3)
        self.assertEqual(m["scored"], 2)
        self.assertEqual(m["na"], 1)
        self.assertEqual(m["avg_score"], 60.0)
        self.assertEqual(m["pqc_pct"], 50.0)

    def test_empty(self):
        m = aggregate([])
        self.assertIsNone(m["avg_score"])
        self.assertIsNone(m["pqc_pct"])


class TestSnapshot(unittest.TestCase):

    def test_partial_rescan_does_not_skew_average(self):
        """The production bug: a one-domain rescan became a data point."""
        rows = [_row(f"d{i}.com", "2026-07-01T10:00:00Z", 80, "ready") for i in range(10)]
        rows.append(_row("d0.com", "2026-07-10T10:00:00Z", 0, "critical"))
        res = compute_trends(rows, granularity="week", now=NOW)
        b = [x for x in res["buckets"] if x["start"].startswith("2026-07-06")][0]
        self.assertEqual(b["monitored"], 10)
        self.assertEqual(b["avg_score"], 72.0)          # (9*80 + 0) / 10
        self.assertEqual(b["assessed"], 1)

    def test_carry_forward_fills_quiet_buckets(self):
        rows = [_row("a.com", "2026-07-01T00:00:00Z", 60),
                _row("a.com", "2026-09-01T00:00:00Z", 70)]
        res = compute_trends(rows, granularity="week", now=NOW)
        scores = [b["avg_score"] for b in res["buckets"]]
        self.assertNotIn(None, scores)
        self.assertEqual(scores[0], 60.0)
        self.assertEqual(scores[-1], 70.0)

    def test_monitored_grows_with_portfolio(self):
        rows = [_row("a.com", "2026-07-02T00:00:00Z"),
                _row("b.com", "2026-08-03T00:00:00Z"),
                _row("c.com", "2026-09-02T00:00:00Z")]
        res = compute_trends(rows, granularity="month", now=NOW)
        self.assertEqual([b["monitored"] for b in res["buckets"]], [1, 2, 3])
        self.assertEqual([b["new_domains"] for b in res["buckets"]], [1, 1, 1])

    def test_stale_domains_drop_out(self):
        rows = [_row("old.com", "2026-01-05T00:00:00Z"),
                _row("new.com", "2026-09-01T00:00:00Z")]
        res = compute_trends(rows, granularity="month", stale_days=90, now=NOW)
        last = res["buckets"][-1]
        self.assertEqual(last["monitored"], 1)
        self.assertEqual(last["stale"], 1)

    def test_last_bucket_partial_and_as_of_now(self):
        rows = [_row("a.com", "2026-09-01T00:00:00Z")]
        res = compute_trends(rows, granularity="month", now=NOW)
        last = res["buckets"][-1]
        self.assertTrue(last["partial"])
        self.assertEqual(parse_ts(last["t"]), NOW)

    def test_future_rows_ignored(self):
        rows = [_row("a.com", "2026-09-01T00:00:00Z"),
                _row("b.com", "2027-01-01T00:00:00Z")]
        res = compute_trends(rows, granularity="month", now=NOW)
        self.assertEqual(res["meta"]["total_domains"], 1)

    def test_range_clips_start_but_keeps_history(self):
        rows = [_row("a.com", "2026-01-10T00:00:00Z", 30),
                _row("b.com", "2026-09-10T00:00:00Z", 90)]
        res = compute_trends(rows, granularity="month", range_key="90d",
                             stale_days=400, now=NOW)
        first = res["buckets"][0]
        self.assertTrue(first["start"].startswith("2026-06"))
        self.assertEqual(first["monitored"], 1)         # a.com carried in
        self.assertEqual(res["buckets"][-1]["avg_score"], 60.0)

    def test_empty(self):
        res = compute_trends([], now=NOW)
        self.assertEqual(res["buckets"], [])
        self.assertIsNotNone(res["meta"]["granularity"])

    def test_manual_day_over_long_span_is_capped(self):
        rows = [_row("a.com", "2020-01-01T00:00:00Z")]
        res = compute_trends(rows, granularity="day", stale_days=400, now=NOW)
        self.assertNotEqual(res["meta"]["granularity"], "day")
        self.assertLessEqual(len(res["buckets"]), 1000)

    def test_performance_large_portfolio(self):
        rows = []
        base = datetime(2025, 9, 19, tzinfo=UTC)
        for m in range(12):
            ts = (base + timedelta(days=30 * m)).isoformat()
            rows += [_row(f"d{i}.example", ts, i % 100, "moderate") for i in range(3000)]
        t0 = time.time()
        res = compute_trends(rows, granularity="week", now=NOW)
        self.assertLess(time.time() - t0, 5.0)
        self.assertEqual(res["buckets"][-1]["monitored"], 3000)


class TestActivity(unittest.TestCase):

    def test_only_in_bucket_assessments(self):
        rows = [_row(f"d{i}.com", "2026-07-01T10:00:00Z", 80, "ready") for i in range(10)]
        rows.append(_row("d0.com", "2026-07-10T10:00:00Z", 20, "critical"))
        res = compute_trends(rows, granularity="week", mode="activity", now=NOW)
        by = {b["start"][:10]: b for b in res["buckets"]}
        self.assertEqual(by["2026-06-29"]["monitored"], 10)
        self.assertEqual(by["2026-07-06"]["monitored"], 1)
        self.assertEqual(by["2026-07-06"]["avg_score"], 20.0)
        self.assertIsNone(by["2026-07-13"]["avg_score"])   # no scans that week

    def test_latest_per_domain_in_bucket(self):
        rows = [_row("a.com", "2026-07-01T00:00:00Z", 10, "critical"),
                _row("a.com", "2026-07-02T00:00:00Z", 90, "ready")]
        res = compute_trends(rows, granularity="month", mode="activity", now=NOW)
        self.assertEqual(res["buckets"][0]["avg_score"], 90.0)
        self.assertEqual(res["buckets"][0]["monitored"], 1)


# ══════════════════════════════════════════════════════════════════
# API — scoping
# ══════════════════════════════════════════════════════════════════

class TestTrendsAPI(unittest.TestCase):

    def setUp(self):
        from data.database import Database
        from auth.store import AuthStore
        from auth.models import ROLE_ANALYST
        import auth.auth_routes as _ar
        _ar._login_attempts.clear()

        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "t.db")
        self.db = Database(self.db_path)
        store = AuthStore(self.db_path)

        self.org_a = self.db.create_organisation("Bank A")
        self.org_b = self.db.create_organisation("Bank B")
        self.db.set_org_domains(self.org_a, ["a1.com", "a2.com"])
        self.db.set_org_domains(self.org_b, ["b1.com"])
        self.comm = self.db.create_community("Banks")
        self.db.set_community_orgs(self.comm, [self.org_a, self.org_b])

        for dom, ts, score in [("a1.com", "2026-07-01T00:00:00+00:00", 40),
                               ("a2.com", "2026-07-01T00:00:00+00:00", 60),
                               ("b1.com", "2026-07-01T00:00:00+00:00", 90),
                               ("x.com",  "2026-08-01T00:00:00+00:00", 10)]:
            run = self.db.create_run([dom])
            self.db.save_assessment(run, {
                "domain": dom, "assessment_timestamp": ts, "score": score,
                "level": "moderate", "findings": [], "has_pqc": False,
            })
            self.db.finish_run(run, "completed")

        u = store.create_user("ana", "ana@e.com", "password1234", ROLE_ANALYST)
        store.set_user_orgs(u.id, [self.org_a])
        store.set_must_change_password(u.id, False)

        from app_factory import create_app
        self.app = create_app({"db_path": self.db_path,
                               "secret_key": "test-secret-32-chars-exactly!!!",
                               "https_enabled": False})
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def _login(self, user, pw):
        self.client.post("/login", data={"username": user, "password": pw},
                         follow_redirects=True)

    def test_requires_auth(self):
        self.assertEqual(self.client.get("/app/api/trends").status_code, 401)

    def test_admin_sees_all(self):
        self._login("admin", "changeme123")
        d = self.client.get("/app/api/trends?granularity=month").get_json()
        self.assertEqual(d["meta"]["total_domains"], 4)
        self.assertEqual(d["buckets"][-1]["monitored"], 4)

    def test_admin_org_and_community_scope(self):
        self._login("admin", "changeme123")
        d = self.client.get(f"/app/api/trends?scope=org:{self.org_b}").get_json()
        self.assertEqual(d["meta"]["total_domains"], 1)
        d = self.client.get(f"/app/api/trends?scope=community:{self.comm}").get_json()
        self.assertEqual(d["meta"]["total_domains"], 3)
        self.assertIn("Banks", d["meta"]["scope_label"])

    def test_analyst_scoped_to_own_domains(self):
        self._login("ana", "password1234")
        d = self.client.get("/app/api/trends").get_json()
        self.assertEqual(d["meta"]["total_domains"], 2)
        self.assertEqual(d["buckets"][-1]["avg_score"], 50.0)

    def test_analyst_cannot_scope_foreign_org_or_community(self):
        self._login("ana", "password1234")
        r = self.client.get(f"/app/api/trends?scope=org:{self.org_b}")
        self.assertEqual(r.status_code, 403)
        r = self.client.get(f"/app/api/trends?scope=community:{self.comm}")
        self.assertEqual(r.status_code, 403)

    def test_bad_scope(self):
        self._login("admin", "changeme123")
        self.assertEqual(self.client.get("/app/api/trends?scope=org:x").status_code, 400)
        self.assertEqual(self.client.get("/app/api/trends?scope=foo").status_code, 400)

    def test_scopes_listing(self):
        self._login("admin", "changeme123")
        vals = [s["value"] for s in self.client.get("/app/api/trends/scopes").get_json()]
        self.assertIn("all", vals)
        self.assertIn(f"community:{self.comm}", vals)
        self.assertIn(f"org:{self.org_b}", vals)
        self.client.get("/logout")
        self._login("ana", "password1234")
        vals = [s["value"] for s in self.client.get("/app/api/trends/scopes").get_json()]
        self.assertIn(f"org:{self.org_a}", vals)
        self.assertNotIn(f"org:{self.org_b}", vals)
        self.assertNotIn(f"community:{self.comm}", vals)

    def test_schedule_interval_drives_granularity(self):
        from scheduler.scan_scheduler import ScanScheduler
        self._login("admin", "changeme123")
        dl = self.db.save_domain_list("all", ["a1.com", "a2.com", "b1.com", "x.com"])
        ScanScheduler(None, self.db).add_schedule("daily", dl, interval_days=1)
        d = self.client.get("/app/api/trends?range=30d").get_json()
        self.assertEqual(d["meta"]["min_interval_days"], 1)
        self.assertEqual(d["meta"]["granularity"], "day")

    def test_cache_hit_and_invalidation(self):
        import app_routes
        app_routes._TRENDS_CACHE.clear()
        self._login("admin", "changeme123")
        d1 = self.client.get("/app/api/trends?granularity=month").get_json()
        d2 = self.client.get("/app/api/trends?granularity=month").get_json()
        self.assertFalse(d1["meta"]["cached"])
        self.assertTrue(d2["meta"]["cached"])
        self.assertEqual(d1["buckets"], d2["buckets"])
        # Different scope must not reuse the "all" entry
        d3 = self.client.get(f"/app/api/trends?granularity=month&scope=org:{self.org_b}").get_json()
        self.assertFalse(d3["meta"]["cached"])
        self.assertEqual(d3["meta"]["total_domains"], 1)
        # A new assessment changes the data version -> miss
        run = self.db.create_run(["new.com"])
        self.db.save_assessment(run, {"domain": "new.com",
            "assessment_timestamp": "2026-09-01T00:00:00+00:00", "score": 50,
            "level": "moderate", "findings": [], "has_pqc": False})
        d4 = self.client.get("/app/api/trends?granularity=month").get_json()
        self.assertFalse(d4["meta"]["cached"])
        self.assertEqual(d4["meta"]["total_domains"], 5)

    def test_cache_does_not_leak_scope_label(self):
        import app_routes
        app_routes._TRENDS_CACHE.clear()
        self._login("admin", "changeme123")
        self.client.get("/app/api/trends")
        d = self.client.get("/app/api/trends").get_json()
        self.assertEqual(d["meta"]["scope_label"], "All domains")

    def test_domains_endpoint_scoped(self):
        self._login("admin", "changeme123")
        self.assertEqual(self.client.get("/app/api/trends/domains").get_json(),
                         ["a1.com", "a2.com", "b1.com", "x.com"])
        self.assertEqual(self.client.get(
            f"/app/api/trends/domains?scope=org:{self.org_b}").get_json(), ["b1.com"])
        self.client.get("/logout")
        self._login("ana", "password1234")
        self.assertEqual(self.client.get("/app/api/trends/domains").get_json(),
                         ["a1.com", "a2.com"])
        r = self.client.get(f"/app/api/trends/domains?scope=org:{self.org_b}")
        self.assertEqual(r.status_code, 403)


class TestTrendRows(unittest.TestCase):

    def setUp(self):
        from data.database import Database
        self.tmpdir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.tmpdir, "r.db"))
        for dom in ("a.com", "B.com", "c.com"):
            run = self.db.create_run([dom])
            self.db.save_assessment(run, {"domain": dom,
                "assessment_timestamp": "2026-07-01T00:00:00+00:00", "score": 1,
                "level": "weak", "findings": [], "has_pqc": False})

    def test_small_scope_sql_path_case_insensitive(self):
        got = {r["domain"] for r in self.db.get_trend_rows(["A.com", "b.com"])}
        self.assertEqual(got, {"a.com", "B.com"})

    def test_large_scope_python_path(self):
        scope = ["a.com", "c.com"] + [f"x{i}.com" for i in range(2000)]
        got = {r["domain"] for r in self.db.get_trend_rows(scope)}
        self.assertEqual(got, {"a.com", "c.com"})

    def test_empty_scope(self):
        self.assertEqual(self.db.get_trend_rows([]), [])

    def test_version_changes_on_insert(self):
        v1 = self.db.get_assessments_version()
        run = self.db.create_run(["d.com"])
        self.db.save_assessment(run, {"domain": "d.com",
            "assessment_timestamp": "2026-07-02T00:00:00+00:00", "score": 1,
            "level": "weak", "findings": [], "has_pqc": False})
        self.assertNotEqual(v1, self.db.get_assessments_version())

    def _plan(self, sql):
        with self.db._connect() as c:
            return " ".join(r[-1] for r in c.execute("EXPLAIN QUERY PLAN " + sql))

    def test_version_query_never_scans_table(self):
        """Regression: MAX(assessed_at) forced a full table scan (504s in prod)."""
        plan = self._plan("SELECT COUNT(*), MAX(id) FROM assessments")
        self.assertNotRegex(plan, r"SCAN assessments(?! USING)")
        import inspect
        from data.database import Database
        self.assertNotIn("MAX(assessed_at)",
                         inspect.getsource(Database.get_assessments_version).split('"""')[-1])

    def test_trend_rows_use_covering_index_when_present(self):
        import subprocess
        script = os.path.join(os.path.dirname(__file__), "..", "scripts", "add_trend_index.py")
        out = subprocess.run([sys.executable, script, "--db", self.db.db_path],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("COVERING INDEX idx_assessments_trend", out.stdout)
        cols = "SELECT domain, assessed_at, score, level, has_pqc FROM assessments"
        self.assertIn("COVERING INDEX idx_assessments_trend", self._plan(cols))
        self.assertIn("COVERING INDEX idx_assessments_trend",
                      self._plan(cols + " WHERE lower(domain) IN ('a.com')"))
        # idempotent, and results unchanged
        again = subprocess.run([sys.executable, script, "--db", self.db.db_path],
                               capture_output=True, text=True)
        self.assertIn("already exists", again.stdout)
        got = {r["domain"] for r in self.db.get_trend_rows(["A.com", "b.com"])}
        self.assertEqual(got, {"a.com", "B.com"})


if __name__ == "__main__":
    unittest.main()
