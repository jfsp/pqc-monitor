#!/usr/bin/env python3
"""
Tests for the 2026-09 scheduling overhaul:

- DB-anchored ScanScheduler (next_run is the source of truth, restart-safe,
  labelled runs, stale next_run repair, serialised scans, auto-list reconcile)
- auto schedules (main / no-TLS rescan / SSL Labs sweep), idempotent
- DNS presence classification of no-TLS domains
- throttled SSL Labs sweep (cache hits, polling, 429 back-off, auth abort,
  freshness skip, target selection)
- IP-address SANs no longer break JSON persistence

SPDX-License-Identifier: GPL-3.0-or-later
"""

import datetime as _dt
import ipaddress
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone

from data.database import Database
from scheduler import schedule_audit as sa
from scheduler.scan_scheduler import ScanScheduler, SCHEDULED_NOTES_PREFIX
from scanner import dns_status as ds
from scanner.ssllabs_sweep import SSLLabsSweep


def _iso(dt):
    return dt.isoformat()


def _now():
    return datetime.now(timezone.utc)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.tmp, "t.db"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers ---------------------------------------------------------
    def add_domain(self, domain, level="moderate", https=True, when=None):
        run_id = self.db.create_run([domain])
        ts = _iso(when or _now())
        if https:
            self.db.save_scan_result(run_id, {
                "domain": domain, "port": 443, "success": True,
                "tls_version": "TLSv1.3", "timestamp": ts})
        self.db.save_assessment(run_id, {
            "domain": domain, "level": level,
            "score": 0 if level == "na" else 50,
            "assessment_timestamp": ts})
        self.db.finish_run(run_id)
        return run_id

    def insert_schedule(self, name="s", list_id=None, interval=30,
                        next_run=None, last_run=None, config=None, enabled=1):
        with self.db._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scheduled_scans (name, domain_list_id, interval_days, "
                "next_run, last_run, enabled, config_json) VALUES (?,?,?,?,?,?,?)",
                (name, list_id, interval, next_run, last_run, enabled,
                 json.dumps(config or {})))
            return cur.lastrowid

    def schedule(self, sid):
        with self.db._connect() as conn:
            return dict(conn.execute("SELECT * FROM scheduled_scans WHERE id=?",
                                     (sid,)).fetchone())


class FakeOrchestrator:
    def __init__(self, db, delay=0.0):
        self.db = db
        self.calls = []
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def scan_domains(self, domains, sector="", region="", country_code="",
                     country="", use_shodan=False, notes=""):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            run_id = self.db.create_run(domains, notes=notes)
            self.calls.append({"domains": list(domains), "notes": notes,
                               "run_id": run_id})
            time.sleep(self.delay)
            self.db.finish_run(run_id)
            return run_id
        finally:
            with self._lock:
                self.active -= 1


# ─── Scheduler ────────────────────────────────────────────────────────────

class TestSchedulerAnchoring(_Base):
    def test_due_uses_next_run_not_process_start(self):
        lid = self.db.save_domain_list("l", ["a.example"])
        past = self.insert_schedule("past", lid, next_run=_iso(_now() - timedelta(hours=1)))
        future = self.insert_schedule("future", lid, next_run=_iso(_now() + timedelta(days=3)))
        sched = ScanScheduler(FakeOrchestrator(self.db), self.db)
        due = [r["id"] for r in sched.due_schedules()]
        self.assertIn(past, due)
        self.assertNotIn(future, due)

    def test_null_next_run_starts_cadence_without_firing(self):
        lid = self.db.save_domain_list("l", ["a.example"])
        sid = self.insert_schedule("n", lid, interval=30, next_run=None)
        sched = ScanScheduler(FakeOrchestrator(self.db), self.db)
        self.assertEqual(sched.due_schedules(), [])
        nxt = datetime.fromisoformat(self.schedule(sid)["next_run"])
        self.assertGreater(nxt, _now() + timedelta(days=29))

    def test_repair_stale_next_run(self):
        # Production state 2026-09-19: next 08-28, ran 09-04, never advanced.
        sid = self.insert_schedule(
            "legacy", None, interval=30,
            next_run="2026-08-28T21:39:56+00:00",
            last_run="2026-09-04T08:26:04+00:00")
        sched = ScanScheduler(FakeOrchestrator(self.db), self.db)
        self.assertEqual(sched.repair_stale_next_run(), 1)
        self.assertTrue(self.schedule(sid)["next_run"].startswith("2026-10-04T08:26"))
        self.assertEqual(sched.repair_stale_next_run(), 0)   # idempotent

    def test_run_labels_notes_and_advances_next_run(self):
        lid = self.db.save_domain_list("l", ["a.example", "b.example"])
        sid = self.insert_schedule("Weekly thing", lid, interval=7,
                                   next_run=_iso(_now() - timedelta(minutes=5)))
        orch = FakeOrchestrator(self.db)
        sched = ScanScheduler(orch, self.db)
        before = _now()
        self.assertEqual(sched.tick(), [sid])
        sched.wait_idle(10)
        self.assertEqual(len(orch.calls), 1)
        self.assertEqual(orch.calls[0]["notes"], f"{SCHEDULED_NOTES_PREFIX}#{sid} Weekly thing")
        row = self.schedule(sid)
        self.assertIsNotNone(row["last_run"])
        nxt = datetime.fromisoformat(row["next_run"])
        self.assertGreaterEqual(nxt, before + timedelta(days=7) - timedelta(seconds=5))
        self.assertEqual(sched.tick(), [])        # not due any more

    def test_not_started_twice_while_running(self):
        lid = self.db.save_domain_list("l", ["a.example"])
        sid = self.insert_schedule("slow", lid, next_run=_iso(_now() - timedelta(minutes=1)))
        orch = FakeOrchestrator(self.db, delay=0.5)
        sched = ScanScheduler(orch, self.db)
        self.assertEqual(sched.tick(), [sid])
        self.assertEqual(sched.tick(), [])
        sched.wait_idle(10)
        self.assertEqual(len(orch.calls), 1)

    def test_scans_are_serialised(self):
        lid = self.db.save_domain_list("l", ["a.example"])
        past = _iso(_now() - timedelta(minutes=1))
        self.insert_schedule("one", lid, next_run=past)
        self.insert_schedule("two", lid, next_run=past)
        orch = FakeOrchestrator(self.db, delay=0.3)
        sched = ScanScheduler(orch, self.db)
        self.assertEqual(len(sched.tick()), 2)
        sched.wait_idle(10)
        self.assertEqual(len(orch.calls), 2)
        self.assertEqual(orch.max_active, 1)

    def test_new_schedule_picked_up_without_restart(self):
        orch = FakeOrchestrator(self.db)
        sched = ScanScheduler(orch, self.db)
        self.assertEqual(sched.tick(), [])
        lid = self.db.save_domain_list("l", ["x.example"])
        sid = self.insert_schedule("added later", lid,
                                   next_run=_iso(_now() - timedelta(seconds=1)))
        self.assertEqual(sched.tick(), [sid])
        sched.wait_idle(10)

    def test_shutdown_leaves_next_run_for_retry(self):
        lid = self.db.save_domain_list("l", ["a.example"])
        past = _iso(_now() - timedelta(minutes=1))
        sid = self.insert_schedule("killed", lid, next_run=past)
        orch = FakeOrchestrator(self.db, delay=0.3)
        sched = ScanScheduler(orch, self.db)
        sched.tick()
        sched._stop.set()
        sched.wait_idle(10)
        self.assertEqual(self.schedule(sid)["next_run"], past)

    def test_mark_interrupted_runs(self):
        rid = self.db.create_run(["a"], notes="scheduled:#1 x")
        manual = self.db.create_run(["b"], notes="")
        self.assertEqual(self.db.mark_interrupted_runs(SCHEDULED_NOTES_PREFIX), 1)
        runs = {r["run_id"]: r["status"] for r in self.db.list_runs(10)}
        self.assertEqual(runs[rid], "interrupted")
        self.assertEqual(runs[manual], "running")

    def test_disabled_schedule_ignored(self):
        lid = self.db.save_domain_list("l", ["a.example"])
        self.insert_schedule("off", lid, enabled=0,
                             next_run=_iso(_now() - timedelta(days=1)))
        self.assertEqual(ScanScheduler(FakeOrchestrator(self.db), self.db).tick(), [])


class TestAutoReconcile(_Base):
    def test_main_auto_list_includes_domains_added_after_creation(self):
        self.add_domain("old.example")
        self.add_domain("gone.example", level="na")
        sa.ensure_auto_schedules(self.db, ssllabs=False)
        self.add_domain("new.example")            # appears after the list was built
        row = sa._find_schedule_by_name(self.db, sa.AUTO_SCHEDULE_NAME)
        self._make_due(row["id"])
        orch = FakeOrchestrator(self.db)
        sched = ScanScheduler(orch, self.db)
        # only run the main schedule in this test
        self._disable_others(row["id"])
        sched.tick(); sched.wait_idle(10)
        scanned = set(orch.calls[0]["domains"])
        self.assertEqual(scanned, {"old.example", "new.example"})

    def test_na_rescan_only_resolvable_and_records_unresolvable(self):
        self.add_domain("svc.example")
        for d in ("resolves.example", "nx.example", "noaddr.example", "err.example"):
            self.add_domain(d, level="na", https=False)
        sa.ensure_auto_schedules(self.db, ssllabs=False)
        row = sa._find_schedule_by_name(self.db, sa.AUTO_NA_SCHEDULE_NAME)
        self._make_due(row["id"])
        self._disable_others(row["id"])

        fake = {"resolves.example": (ds.RESOLVABLE, ["192.0.2.1"]),
                "nx.example": (ds.NXDOMAIN, []),
                "noaddr.example": (ds.NO_ADDRESS, []),
                "err.example": (ds.DNS_ERROR, [])}
        orig = ds.classify
        ds.classify = lambda d, timeout=5.0, resolver_factory=None: fake[d]
        try:
            # refresh_dns_status binds classify as a default arg; patch the
            # function used by the scheduler path instead
            orig_refresh = ds.refresh_dns_status
            ds.refresh_dns_status = lambda db, domains, **kw: orig_refresh(
                db, domains, classify_fn=lambda d, timeout=5.0: fake[d])
            orch = FakeOrchestrator(self.db)
            sched = ScanScheduler(orch, self.db)
            sched.tick(); sched.wait_idle(10)
        finally:
            ds.classify = orig
            ds.refresh_dns_status = orig_refresh
        self.assertEqual(orch.calls[0]["domains"], ["resolves.example"])
        unres = ds.unresolvable_domains(self.db)
        self.assertEqual(set(unres), {"nx.example", "noaddr.example"})

    def _make_due(self, sid):
        with self.db._connect() as conn:
            conn.execute("UPDATE scheduled_scans SET next_run=? WHERE id=?",
                         (_iso(_now() - timedelta(minutes=1)), sid))

    def _disable_others(self, sid):
        with self.db._connect() as conn:
            conn.execute("UPDATE scheduled_scans SET enabled=0 WHERE id<>?", (sid,))


class TestEnsureAutoSchedules(_Base):
    def test_creates_three_and_is_idempotent(self):
        self.add_domain("a.example")
        self.add_domain("b.example", level="na", https=False)
        out = sa.ensure_auto_schedules(self.db)
        self.assertEqual(out["main"]["schedule_action"], "create")
        self.assertEqual(out["na"]["schedule_action"], "create")
        self.assertEqual(out["ssllabs"]["schedule_action"], "create")
        rows = {r["name"]: r for r in sa._read_scheduled_scans(self.db)}
        self.assertEqual(len(rows), 3)
        self.assertEqual(sa.schedule_kind(rows[sa.AUTO_SSLLABS_SCHEDULE_NAME]),
                         sa.KIND_SSLLABS)
        self.assertEqual(sa.auto_kind(rows[sa.AUTO_SCHEDULE_NAME]), sa.AUTO_SERVICEABLE)
        self.assertEqual(sa.auto_kind(rows[sa.AUTO_NA_SCHEDULE_NAME]), sa.AUTO_NA)
        # SSL Labs sweep starts soon; no-TLS rescan in ~1 day
        sweep_next = datetime.fromisoformat(rows[sa.AUTO_SSLLABS_SCHEDULE_NAME]["next_run"])
        self.assertLess(sweep_next, _now() + timedelta(hours=1))

        out2 = sa.ensure_auto_schedules(self.db)
        self.assertEqual(out2["main"]["schedule_action"], "unchanged")
        self.assertEqual(out2["na"]["schedule_action"], "unchanged")
        self.assertEqual(out2["ssllabs"]["schedule_action"], "unchanged")
        self.assertEqual(len(sa._read_scheduled_scans(self.db)), 3)

    def test_dry_run_writes_nothing(self):
        self.add_domain("a.example")
        sa.ensure_auto_schedules(self.db, dry_run=True)
        self.assertEqual(sa._read_scheduled_scans(self.db), [])
        self.assertEqual(self.db.get_domain_lists(), [])

    def test_legacy_main_row_recognised_and_tagged(self):
        self.add_domain("a.example")
        sa.create_monthly_all_domains(self.db)       # old-style row, no "auto" key
        row = sa._find_schedule_by_name(self.db, sa.AUTO_SCHEDULE_NAME)
        self.assertEqual(sa.auto_kind(row), sa.AUTO_SERVICEABLE)   # by name
        sa.ensure_auto_schedules(self.db, ssllabs=False)
        row = sa._find_schedule_by_name(self.db, sa.AUTO_SCHEDULE_NAME)
        self.assertEqual(sa.row_config(row).get("auto"), sa.AUTO_SERVICEABLE)

    def test_audit_ignores_list_for_sweep(self):
        self.add_domain("a.example")
        sa.ensure_auto_schedules(self.db)
        rep = sa.audit_schedules(self.db)
        sweep = [s for s in rep["schedules"] if s["kind"] == sa.KIND_SSLLABS][0]
        self.assertEqual(sweep["problems"], [])


# ─── DNS status ───────────────────────────────────────────────────────────

class _FakeResolver:
    def __init__(self, table):
        self.table = table
        self.lifetime = None

    def resolve(self, name, rtype):
        import dns.resolver
        import dns.exception
        v = self.table.get((name, rtype))
        if v == "NX":
            raise dns.resolver.NXDOMAIN()
        if v == "NOANS" or v is None:
            raise dns.resolver.NoAnswer()
        if v == "TIMEOUT":
            raise dns.exception.Timeout()
        return v


class TestDnsStatus(_Base):
    def _cls(self, table, name):
        return ds.classify(name, resolver_factory=lambda: _FakeResolver(table))

    def test_classification(self):
        t = {("a.ex", "A"): ["192.0.2.1"],
             ("six.ex", "A"): "NOANS", ("six.ex", "AAAA"): ["2001:db8::1"],
             ("nx.ex", "A"): "NX",
             ("txt.ex", "A"): "NOANS", ("txt.ex", "AAAA"): "NOANS",
             ("slow.ex", "A"): "TIMEOUT", ("slow.ex", "AAAA"): "TIMEOUT"}
        self.assertEqual(self._cls(t, "a.ex"), (ds.RESOLVABLE, ["192.0.2.1"]))
        self.assertEqual(self._cls(t, "six.ex")[0], ds.RESOLVABLE)
        self.assertEqual(self._cls(t, "nx.ex")[0], ds.NXDOMAIN)
        self.assertEqual(self._cls(t, "txt.ex")[0], ds.NO_ADDRESS)
        self.assertEqual(self._cls(t, "slow.ex")[0], ds.DNS_ERROR)

    def test_since_preserved_across_rechecks(self):
        self.add_domain("gone.example", level="na", https=False)
        f = lambda d, timeout=5.0: (ds.NXDOMAIN, [])
        ds.refresh_dns_status(self.db, ["gone.example"], classify_fn=f)
        first = self.db.latest_extra_bulk(ds.DATA_TYPE)["gone.example"]["since"]
        time.sleep(0.01)
        ds.refresh_dns_status(self.db, ["gone.example"], classify_fn=f)
        blob = self.db.latest_extra_bulk(ds.DATA_TYPE)["gone.example"]
        self.assertEqual(blob["since"], first)
        self.assertNotEqual(blob["checked_at"], first)
        # comes back → status and since change
        ds.refresh_dns_status(self.db, ["gone.example"],
                              classify_fn=lambda d, timeout=5.0: (ds.RESOLVABLE, ["192.0.2.9"]))
        blob = self.db.latest_extra_bulk(ds.DATA_TYPE)["gone.example"]
        self.assertEqual(blob["status"], ds.RESOLVABLE)
        self.assertEqual(blob["previous_status"], ds.NXDOMAIN)
        self.assertNotEqual(blob["since"], first)


# ─── SSL Labs sweep ───────────────────────────────────────────────────────

class FakeSSLLabs:
    """Scriptable stand-in for SSLLabsClient."""
    available = True

    def __init__(self, script=None, info=None):
        self.script = {k: list(v) for k, v in (script or {}).items()}
        self.calls = []
        self._info = info or {"maxAssessments": 25, "currentAssessments": 0,
                              "newAssessmentCoolOff": 0}
        self._lock = threading.Lock()

    def info(self):
        return self._info

    def analyze(self, params):
        host = params["host"]
        with self._lock:
            self.calls.append(dict(params))
            seq = self.script.get(host)
            if not seq:
                return 200, _report(host, "READY")
            return seq.pop(0) if len(seq) > 1 else seq[0]


def _report(host, status, grade="A", msg=""):
    body = {"host": host, "status": status, "statusMessage": msg,
            "testTime": 1758240000000, "endpoints": []}
    if status == "READY":
        body["endpoints"] = [{"ipAddress": "192.0.2.1", "grade": grade,
                              "statusMessage": "Ready"}]
    return body


class TestSSLLabsSweep(_Base):
    def _sweep(self, client, **kw):
        kw.setdefault("poll_seconds", 0.01)
        return SSLLabsSweep(self.db, client, **kw)

    def test_targets_https_serviceable_and_not_fresh(self):
        self.add_domain("web.example")
        self.add_domain("mailonly.example", https=False)
        self.add_domain("notls.example", level="na", https=False)
        fresh_run = self.add_domain("fresh.example")
        self.db.save_domain_extra(fresh_run, "fresh.example", "ssllabs", {"grade": "A"})
        sw = self._sweep(FakeSSLLabs())
        self.assertEqual(sw.targets(), ["web.example"])
        self.assertEqual(sw.stats["skipped_fresh"], 1)

    def test_cached_ready_and_polled_ready_are_stored(self):
        self.add_domain("cached.example")
        self.add_domain("new.example")
        client = FakeSSLLabs({
            "new.example": [(200, _report("new.example", "IN_PROGRESS")),
                            (200, _report("new.example", "IN_PROGRESS")),
                            (200, _report("new.example", "READY", grade="B"))],
        })
        res = self._sweep(client).run()
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["ready"], 2)
        self.assertEqual(res["cached"], 1)
        saved = self.db.latest_extra_bulk("ssllabs")
        self.assertEqual(saved["cached.example"]["grade"], "A")
        self.assertEqual(saved["new.example"]["grade"], "B")
        # the first call for each host uses fromCache (never startNew)
        first = [c for c in client.calls if c["host"] == "new.example"][0]
        self.assertEqual(first.get("fromCache"), "on")
        self.assertNotIn("startNew", first)

    def test_error_is_stored_and_not_retried(self):
        self.add_domain("bad.example")
        client = FakeSSLLabs({"bad.example": [
            (200, _report("bad.example", "ERROR", msg="Unable to connect to the server"))]})
        res = self._sweep(client).run()
        self.assertEqual(res["error"], 1)
        blob = self.db.latest_extra_bulk("ssllabs")["bad.example"]
        self.assertEqual(blob["status"], "ERROR")
        self.assertIn("Unable to connect", blob["status_message"])
        # next sweep: fresh record → skipped
        self.assertEqual(self._sweep(client).targets(), [])

    def test_429_backs_off_requeues_and_lowers_concurrency(self):
        self.add_domain("a.example")
        client = FakeSSLLabs({"a.example": [(429, None),
                                            (200, _report("a.example", "READY"))]})
        sw = self._sweep(client, concurrency=3)
        import scanner.ssllabs_sweep as mod
        old = mod.PAUSE_429_MIN
        mod.PAUSE_429_MIN = 0
        sw._pause_429 = 0
        try:
            res = sw.run()
        finally:
            mod.PAUSE_429_MIN = old
        self.assertEqual(res["rate_limited"], 1)
        self.assertEqual(res["ready"], 1)
        self.assertEqual(res["remaining"], 0)

    def test_auth_failure_aborts(self):
        for d in ("a.example", "b.example", "c.example"):
            self.add_domain(d)
        client = FakeSSLLabs({d: [(441, None)] for d in ("a.example", "b.example", "c.example")})
        res = self._sweep(client, concurrency=1).run()
        self.assertEqual(res["status"], "aborted")
        self.assertEqual(len(client.calls), 1)

    def test_concurrency_respects_info_limit(self):
        client = FakeSSLLabs(info={"maxAssessments": 3, "currentAssessments": 1,
                                   "newAssessmentCoolOff": 1000})
        sw = self._sweep(client, concurrency=10)
        self.assertEqual(sw._initial_concurrency(), 1)     # 3 - 1 - 1 headroom
        self.assertAlmostEqual(sw._cooloff, 1.2)

    def test_timeout_counts_and_does_not_store(self):
        self.add_domain("slow.example")
        client = FakeSSLLabs({"slow.example": [(200, _report("slow.example", "IN_PROGRESS"))]})
        res = self._sweep(client, assessment_timeout=0.05).run()
        self.assertEqual(res["timeout"], 1)
        self.assertNotIn("slow.example", self.db.latest_extra_bulk("ssllabs"))

    def test_unavailable_client(self):
        class Off:
            available = False
        self.assertEqual(SSLLabsSweep(self.db, Off()).run()["status"], "unavailable")

    def test_scheduler_runs_sweep_kind(self):
        self.add_domain("a.example")
        sid = self.insert_schedule("sweep", None, interval=7,
                                   next_run=_iso(_now() - timedelta(minutes=1)),
                                   config={"kind": "ssllabs_sweep"})
        orch = FakeOrchestrator(self.db)
        orch.ssllabs = FakeSSLLabs()
        sched = ScanScheduler(orch, self.db, {"ssllabs_email": ""})
        sched.tick(); sched.wait_idle(10)
        self.assertEqual(orch.calls, [])                     # not a scan
        self.assertIn("a.example", self.db.latest_extra_bulk("ssllabs"))
        self.assertIsNotNone(self.schedule(sid)["last_run"])


# ─── IP SAN serialisation ────────────────────────────────────────────────

def _cert_with_ip_san():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ip-san.example")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("ip-san.example"),
                x509.IPAddress(ipaddress.ip_address("192.0.2.10")),
                x509.IPAddress(ipaddress.ip_address("2001:db8::10"))]), False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


class TestIpSanSerialisation(_Base):
    def test_tls_probe_sans_are_strings(self):
        from scanner.tls_probe import _parse_certificate
        info = _parse_certificate(_cert_with_ip_san())
        self.assertIn("192.0.2.10", info.san_domains)
        self.assertIn("2001:db8::10", info.san_domains)
        json.dumps(info.san_domains)

    def test_chain_node_sans_are_strings(self):
        from scanner.chain_validator import _parse_cert_node
        node = _parse_cert_node(_cert_with_ip_san(), 0)
        self.assertIn("192.0.2.10", node.san_domains)
        json.dumps(node.to_dict())

    def test_save_scan_result_tolerates_ip_objects(self):
        rid = self.db.create_run(["x.example"])
        self.db.save_scan_result(rid, {
            "domain": "x.example", "port": 443, "success": True,
            "certificate": {"sans": [ipaddress.ip_address("192.0.2.1")]}})
        self.assertEqual(len(self.db.get_domain_scans("x.example")), 1)


if __name__ == "__main__":
    unittest.main()
