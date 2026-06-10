#!/usr/bin/env python3
"""
PQC-Monitor: Unit Tests — RBAC Auth Layer
Tests for AuthStore, permissions, session handling, domain scoping,
audit logging, and all protected API endpoints.
All tests are fully offline.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auth.models import (
    User, ROLE_ADMIN, ROLE_ANALYST,
    has_permission, PERMISSIONS,
)
from auth.store import AuthStore


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_store(tmpdir=None) -> tuple[AuthStore, str]:
    if tmpdir is None:
        tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "auth_test.db")
    # AuthStore._ensure_default_admin needs domain_lists table to exist
    # so we init the full DB first
    from data.database import Database
    Database(db_path)   # creates all tables including domain_lists
    store = AuthStore(db_path)
    return store, db_path


def _make_app(db_path: str):
    from app_factory import create_app
    app = create_app({
        "db_path": db_path,
        "secret_key": "test-secret-key-for-testing-only-32chars",
        "https_enabled": False,   # allow HTTP in tests (default, but explicit)
    })
    app.config["TESTING"] = True
    return app


# ═══════════════════════════════════════════════════════════════════
# Permission model tests
# ═══════════════════════════════════════════════════════════════════

class TestPermissions(unittest.TestCase):

    def test_admin_has_user_manage(self):
        self.assertTrue(has_permission(ROLE_ADMIN, "user.manage"))

    def test_admin_has_scan_run(self):
        self.assertTrue(has_permission(ROLE_ADMIN, "scan.run"))

    def test_admin_has_admin_panel(self):
        self.assertTrue(has_permission(ROLE_ADMIN, "admin.panel"))

    def test_analyst_cannot_manage_users(self):
        self.assertFalse(has_permission(ROLE_ANALYST, "user.manage"))

    def test_analyst_cannot_run_scans(self):
        self.assertFalse(has_permission(ROLE_ANALYST, "scan.run"))

    def test_analyst_can_export_reports(self):
        self.assertTrue(has_permission(ROLE_ANALYST, "report.export"))

    def test_unknown_role_has_no_permissions(self):
        self.assertFalse(has_permission("superuser", "user.manage"))
        self.assertFalse(has_permission("", "anything"))

    def test_unknown_permission_returns_false(self):
        self.assertFalse(has_permission(ROLE_ADMIN, "does.not.exist"))

    def test_admin_has_more_permissions_than_analyst(self):
        admin_perms   = PERMISSIONS[ROLE_ADMIN]
        analyst_perms = PERMISSIONS[ROLE_ANALYST]
        self.assertGreater(len(admin_perms), len(analyst_perms))

    def test_user_can_method(self):
        u = User(id=1, username="u", email="u@e.com",
                 role=ROLE_ADMIN, password_hash="x")
        self.assertTrue(u.can("user.manage"))
        a = User(id=2, username="a", email="a@e.com",
                 role=ROLE_ANALYST, password_hash="x")
        self.assertFalse(a.can("user.manage"))

    def test_is_admin_property(self):
        admin   = User(id=1, username="a", email="a@e.com",
                       role=ROLE_ADMIN, password_hash="x")
        analyst = User(id=2, username="b", email="b@e.com",
                       role=ROLE_ANALYST, password_hash="x")
        self.assertTrue(admin.is_admin)
        self.assertFalse(analyst.is_admin)


# ═══════════════════════════════════════════════════════════════════
# AuthStore — user CRUD
# ═══════════════════════════════════════════════════════════════════

class TestAuthStore(unittest.TestCase):

    def setUp(self):
        self.store, self.db_path = _make_store()

    def test_default_admin_created(self):
        users = self.store.list_users()
        admins = [u for u in users if u.role == ROLE_ADMIN]
        self.assertEqual(len(admins), 1)
        self.assertEqual(admins[0].username, "admin")

    def test_create_analyst(self):
        u = self.store.create_user(
            "alice", "alice@example.com", "supersecret123", ROLE_ANALYST
        )
        self.assertEqual(u.username, "alice")
        self.assertEqual(u.role, ROLE_ANALYST)
        self.assertTrue(u.is_active)

    def test_password_not_stored_plaintext(self):
        u = self.store.create_user(
            "bob", "bob@example.com", "mypassword123", ROLE_ANALYST
        )
        self.assertNotIn("mypassword123", u.password_hash)
        # werkzeug produces pbkdf2: or scrypt: prefix — neither is plaintext
        self.assertIn(":", u.password_hash)

    def test_short_password_rejected(self):
        with self.assertRaises(ValueError):
            self.store.create_user("x", "x@x.com", "short", ROLE_ANALYST)

    def test_invalid_role_rejected(self):
        with self.assertRaises(ValueError):
            self.store.create_user("y", "y@y.com", "validpassword", "superuser")

    def test_duplicate_username_raises(self):
        self.store.create_user("dup", "dup1@e.com", "password1234", ROLE_ANALYST)
        with self.assertRaises(Exception):
            self.store.create_user("dup", "dup2@e.com", "password1234", ROLE_ANALYST)

    def test_get_user_by_id(self):
        u = self.store.create_user("carol", "carol@e.com", "password1234", ROLE_ANALYST)
        fetched = self.store.get_user_by_id(u.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.username, "carol")

    def test_get_user_by_username_case_insensitive(self):
        self.store.create_user("Dave", "dave@e.com", "password1234", ROLE_ANALYST)
        u = self.store.get_user_by_username("dave")
        self.assertIsNotNone(u)
        u2 = self.store.get_user_by_username("DAVE")
        self.assertIsNotNone(u2)

    def test_get_nonexistent_user_returns_none(self):
        self.assertIsNone(self.store.get_user_by_id(99999))
        self.assertIsNone(self.store.get_user_by_username("nobody"))

    def test_update_user_role(self):
        u = self.store.create_user("eve", "eve@e.com", "password1234", ROLE_ANALYST)
        updated = self.store.update_user(u.id, role=ROLE_ADMIN)
        self.assertEqual(updated.role, ROLE_ADMIN)

    def test_update_user_deactivate(self):
        u = self.store.create_user("frank", "frank@e.com", "password1234", ROLE_ANALYST)
        updated = self.store.update_user(u.id, is_active=False)
        self.assertFalse(updated.is_active)

    def test_delete_user(self):
        u = self.store.create_user("grace", "grace@e.com", "password1234", ROLE_ANALYST)
        self.store.delete_user(u.id)
        self.assertIsNone(self.store.get_user_by_id(u.id))

    def test_set_password(self):
        u = self.store.create_user("heidi", "heidi@e.com", "oldpassword1", ROLE_ANALYST)
        self.store.set_password(u.id, "newpassword99")
        result = self.store.authenticate("heidi", "newpassword99")
        self.assertIsNotNone(result)
        result_old = self.store.authenticate("heidi", "oldpassword1")
        self.assertIsNone(result_old)

    def test_list_users_returns_all(self):
        for i in range(3):
            self.store.create_user(f"user{i}", f"u{i}@e.com", "passw0rd123", ROLE_ANALYST)
        users = self.store.list_users()
        # 1 default admin + 3 new
        self.assertEqual(len(users), 4)


# ═══════════════════════════════════════════════════════════════════
# AuthStore — authentication & lockout
# ═══════════════════════════════════════════════════════════════════

class TestAuthentication(unittest.TestCase):

    def setUp(self):
        self.store, _ = _make_store()
        self.store.create_user("ivan", "ivan@e.com", "correcthorse1", ROLE_ANALYST)

    def test_correct_credentials_return_user(self):
        u = self.store.authenticate("ivan", "correcthorse1")
        self.assertIsNotNone(u)
        self.assertEqual(u.username, "ivan")

    def test_wrong_password_returns_none(self):
        u = self.store.authenticate("ivan", "wrongpassword")
        self.assertIsNone(u)

    def test_unknown_username_returns_none(self):
        u = self.store.authenticate("nobody", "anything")
        self.assertIsNone(u)

    def test_inactive_user_cannot_login(self):
        u = self.store.create_user("judy", "judy@e.com", "password1234", ROLE_ANALYST)
        self.store.update_user(u.id, is_active=False)
        result = self.store.authenticate("judy", "password1234")
        self.assertIsNone(result)

    def test_successful_login_records_last_login(self):
        u = self.store.authenticate("ivan", "correcthorse1")
        self.assertIsNotNone(u.last_login)
        self.assertTrue(len(u.last_login) > 0)

    def test_failed_logins_increment(self):
        for _ in range(3):
            self.store.authenticate("ivan", "wrong")
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT failed_logins FROM users WHERE username='ivan'"
            ).fetchone()
        self.assertEqual(row["failed_logins"], 3)

    def test_failed_logins_reset_on_success(self):
        self.store.authenticate("ivan", "wrong")
        self.store.authenticate("ivan", "correcthorse1")
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT failed_logins FROM users WHERE username='ivan'"
            ).fetchone()
        self.assertEqual(row["failed_logins"], 0)

    def test_account_locked_after_max_failures(self):
        for _ in range(self.store.MAX_FAILED_ATTEMPTS):
            self.store.authenticate("ivan", "wrong")
        # Even correct password now returns None
        result = self.store.authenticate("ivan", "correcthorse1")
        self.assertIsNone(result)


# ═══════════════════════════════════════════════════════════════════
# Domain-list assignment
# ═══════════════════════════════════════════════════════════════════

class TestDomainListAssignment(unittest.TestCase):

    def setUp(self):
        self.store, self.db_path = _make_store()
        from data.database import Database
        self.db = Database(self.db_path)
        # Create two domain lists
        self.list_a = self.db.save_domain_list(
            "Finance Spain", ["bancosantander.es", "bbva.es"], "finance Spain"
        )
        self.list_b = self.db.save_domain_list(
            "Healthcare EU", ["ema.europa.eu", "isciii.es"], "healthcare EU"
        )
        self.analyst = self.store.create_user(
            "ken", "ken@e.com", "password1234", ROLE_ANALYST
        )

    def test_assign_domain_list(self):
        self.store.assign_domain_list(self.analyst.id, self.list_a)
        u = self.store.get_user_by_id(self.analyst.id)
        self.assertIn(self.list_a, u.domain_list_ids)

    def test_revoke_domain_list(self):
        self.store.assign_domain_list(self.analyst.id, self.list_a)
        self.store.revoke_domain_list(self.analyst.id, self.list_a)
        u = self.store.get_user_by_id(self.analyst.id)
        self.assertNotIn(self.list_a, u.domain_list_ids)

    def test_set_domain_lists_replaces_all(self):
        self.store.assign_domain_list(self.analyst.id, self.list_a)
        self.store.set_domain_lists(self.analyst.id, [self.list_b])
        u = self.store.get_user_by_id(self.analyst.id)
        self.assertNotIn(self.list_a, u.domain_list_ids)
        self.assertIn(self.list_b, u.domain_list_ids)

    def test_get_user_domains_returns_flat_list(self):
        self.store.assign_domain_list(self.analyst.id, self.list_a)
        self.store.assign_domain_list(self.analyst.id, self.list_b)
        domains = self.store.get_user_domains(self.analyst.id)
        self.assertIn("bancosantander.es", domains)
        self.assertIn("ema.europa.eu", domains)

    def test_user_with_no_lists_sees_no_domains(self):
        domains = self.store.get_user_domains(self.analyst.id)
        self.assertEqual(domains, [])

    def test_no_duplicate_domains(self):
        # Same domain in two lists should appear only once
        list_c = self.db.save_domain_list("Overlap", ["bancosantander.es"], "")
        self.store.assign_domain_list(self.analyst.id, self.list_a)
        self.store.assign_domain_list(self.analyst.id, list_c)
        domains = self.store.get_user_domains(self.analyst.id)
        self.assertEqual(domains.count("bancosantander.es"), 1)

    def test_assign_duplicate_is_idempotent(self):
        self.store.assign_domain_list(self.analyst.id, self.list_a)
        self.store.assign_domain_list(self.analyst.id, self.list_a)  # second call
        u = self.store.get_user_by_id(self.analyst.id)
        self.assertEqual(u.domain_list_ids.count(self.list_a), 1)


# ═══════════════════════════════════════════════════════════════════
# Audit log
# ═══════════════════════════════════════════════════════════════════

class TestAuditLog(unittest.TestCase):

    def setUp(self):
        self.store, _ = _make_store()

    def test_log_event_stored(self):
        self.store.log(1, "alice", "login", ip_address="1.2.3.4")
        events = self.store.get_audit_log(limit=10)
        self.assertTrue(any(e.action == "login" for e in events))

    def test_log_fields_populated(self):
        self.store.log(1, "alice", "login", resource="",
                        ip_address="10.0.0.1", detail="test")
        events = self.store.get_audit_log()
        e = next(x for x in events if x.username == "alice")
        self.assertEqual(e.ip_address, "10.0.0.1")
        self.assertEqual(e.detail, "test")

    def test_anonymous_log_no_user_id(self):
        self.store.log(None, "anonymous", "login_failed", ip_address="5.5.5.5")
        events = self.store.get_audit_log()
        anon = next(x for x in events if x.username == "anonymous")
        self.assertIsNone(anon.user_id)

    def test_filter_by_user_id(self):
        self.store.log(1, "alice", "login")
        self.store.log(2, "bob", "login")
        events = self.store.get_audit_log(user_id=1)
        self.assertTrue(all(e.user_id == 1 for e in events))

    def test_limit_respected(self):
        for i in range(20):
            self.store.log(1, "tester", f"action_{i}")
        events = self.store.get_audit_log(limit=5)
        self.assertLessEqual(len(events), 5)

    def test_ordered_newest_first(self):
        for i in range(3):
            self.store.log(1, "tester", f"action_{i}")
        events = self.store.get_audit_log()
        if len(events) >= 2:
            self.assertGreaterEqual(events[0].timestamp, events[1].timestamp)


# ═══════════════════════════════════════════════════════════════════
# Flask integration — endpoint protection
# ═══════════════════════════════════════════════════════════════════

class TestEndpointProtection(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        store, self.db_path = _make_store(self.tmpdir)
        self.store = store
        # Create test users
        self.analyst = store.create_user(
            "lara", "lara@e.com", "password1234", ROLE_ANALYST
        )
        self.app = _make_app(self.db_path)
        self.client = self.app.test_client()
        # Clear rate-limiter state between tests
        import auth.auth_routes as _ar
        _ar._login_attempts.clear()

    def _login(self, username, password):
        return self.client.post("/login", data={
            "username": username, "password": password
        }, follow_redirects=True)

    def test_root_redirects_to_login(self):
        r = self.client.get("/", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_api_without_auth_returns_401(self):
        r = self.client.get("/app/api/summary")
        self.assertEqual(r.status_code, 401)

    def test_admin_panel_without_auth_returns_401(self):
        r = self.client.get("/admin/api/users")
        self.assertEqual(r.status_code, 401)

    def test_valid_login_redirects_to_dashboard(self):
        r = self.client.post("/login", data={
            "username": "admin", "password": "changeme123"
        }, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/app", r.headers["Location"])

    def test_absolute_next_url_is_stripped_to_path(self):
        """Regression: login with ?next=http://host/app/ must redirect to /app/
        not loop back to /login (this was the production bug)."""
        r = self.client.post(
            "/login?next=http://34.30.196.194:5000/app/",
            data={"username": "admin", "password": "changeme123"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 302)
        location = r.headers["Location"]
        # Must redirect to /app/ not back to /login
        self.assertNotIn("/login", location)
        self.assertIn("/app", location)
        # Must not contain an absolute URL (open-redirect prevention)
        self.assertFalse(location.startswith("http://34."))

    def test_session_survives_after_login_on_http(self):
        """Regression: session cookie must be readable over HTTP (Secure=False)."""
        self.client.post("/login", data={
            "username": "admin", "password": "changeme123"
        }, follow_redirects=True)
        # Subsequent request must be authenticated, not redirected to login
        r = self.client.get("/app/api/summary")
        self.assertEqual(r.status_code, 200)

    def test_invalid_login_stays_on_login_page(self):
        r = self.client.post("/login", data={
            "username": "admin", "password": "wrongpassword"
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Invalid username or password", r.data)

    def test_logout_clears_session(self):
        self._login("admin", "changeme123")
        self.client.get("/logout", follow_redirects=False)
        r = self.client.get("/app/api/summary")
        self.assertEqual(r.status_code, 401)

    def test_analyst_cannot_access_admin_panel(self):
        import auth.auth_routes as _ar; _ar._login_attempts.clear()
        fresh = self.app.test_client()
        fresh.post("/login", data={"username": "lara", "password": "password1234"},
                   follow_redirects=True)
        r = fresh.get("/admin/api/users")
        self.assertEqual(r.status_code, 403)

    def test_admin_can_access_admin_panel(self):
        self._login("admin", "changeme123")
        r = self.client.get("/admin/api/users")
        self.assertEqual(r.status_code, 200)

    def test_analyst_can_access_app_api(self):
        self._login("lara", "password1234")
        r = self.client.get("/app/api/summary")
        self.assertEqual(r.status_code, 200)

    def test_analyst_cannot_trigger_scan(self):
        self._login("lara", "password1234")
        r = self.client.post("/app/api/scan",
                              json={"domains": ["example.com"]},
                              content_type="application/json")
        self.assertEqual(r.status_code, 403)

    def test_admin_can_trigger_scan(self):
        # Scan will fail (no real network) but the route itself should not 403
        self._login("admin", "changeme123")
        r = self.client.post("/app/api/scan",
                              json={"domains": []},
                              content_type="application/json")
        # Empty domains → 400, not 403 — proves route is accessible
        self.assertEqual(r.status_code, 400)

    def test_security_headers_present(self):
        r = self.client.get("/login")
        self.assertIn("X-Content-Type-Options", r.headers)
        self.assertIn("X-Frame-Options", r.headers)
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")


# ═══════════════════════════════════════════════════════════════════
# Admin API endpoints
# ═══════════════════════════════════════════════════════════════════

class TestAdminAPI(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        store, self.db_path = _make_store(self.tmpdir)
        self.store = store
        self.app = _make_app(self.db_path)
        self.client = self.app.test_client()
        import auth.auth_routes as _ar
        _ar._login_attempts.clear()
        self.client.post("/login", data={
            "username": "admin", "password": "changeme123"
        }, follow_redirects=True)

    def test_list_users(self):
        r = self.client.get("/admin/api/users")
        self.assertEqual(r.status_code, 200)
        users = json.loads(r.data)
        self.assertTrue(any(u["username"] == "admin" for u in users))

    def test_create_user(self):
        r = self.client.post("/admin/api/users",
                              json={
                                  "username": "newuser",
                                  "email": "new@e.com",
                                  "password": "newpassword1",
                                  "role": "analyst"
                              }, content_type="application/json")
        self.assertEqual(r.status_code, 201)
        d = json.loads(r.data)
        self.assertEqual(d["username"], "newuser")
        self.assertNotIn("password_hash", d)

    def test_create_user_missing_fields(self):
        r = self.client.post("/admin/api/users",
                              json={"username": "x"},
                              content_type="application/json")
        self.assertEqual(r.status_code, 400)

    def test_create_duplicate_user(self):
        self.client.post("/admin/api/users",
                          json={"username": "dup", "email": "d@e.com",
                                "password": "password123", "role": "analyst"},
                          content_type="application/json")
        r = self.client.post("/admin/api/users",
                              json={"username": "dup", "email": "d2@e.com",
                                    "password": "password123", "role": "analyst"},
                              content_type="application/json")
        self.assertEqual(r.status_code, 409)

    def test_update_user(self):
        cr = self.client.post("/admin/api/users",
                               json={"username": "modme", "email": "m@e.com",
                                     "password": "password123", "role": "analyst"},
                               content_type="application/json")
        uid = json.loads(cr.data)["id"]
        r = self.client.patch(f"/admin/api/users/{uid}",
                               json={"full_name": "Modified User"},
                               content_type="application/json")
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertEqual(d["full_name"], "Modified User")

    def test_cannot_delete_own_account(self):
        users = json.loads(self.client.get("/admin/api/users").data)
        admin = next(u for u in users if u["username"] == "admin")
        r = self.client.delete(f"/admin/api/users/{admin['id']}")
        self.assertEqual(r.status_code, 400)

    def test_delete_user(self):
        cr = self.client.post("/admin/api/users",
                               json={"username": "todelete", "email": "td@e.com",
                                     "password": "password123", "role": "analyst"},
                               content_type="application/json")
        uid = json.loads(cr.data)["id"]
        r = self.client.delete(f"/admin/api/users/{uid}")
        self.assertEqual(r.status_code, 200)
        check = self.client.get(f"/admin/api/users/{uid}")
        self.assertEqual(check.status_code, 404)

    def test_reset_password(self):
        cr = self.client.post("/admin/api/users",
                               json={"username": "pwreset", "email": "pw@e.com",
                                     "password": "oldpassword1", "role": "analyst"},
                               content_type="application/json")
        uid = json.loads(cr.data)["id"]
        r = self.client.post(f"/admin/api/users/{uid}/password",
                              json={"password": "newpassword99"},
                              content_type="application/json")
        self.assertEqual(r.status_code, 200)

    def test_audit_log_endpoint(self):
        r = self.client.get("/admin/api/audit-log")
        self.assertEqual(r.status_code, 200)
        events = json.loads(r.data)
        self.assertIsInstance(events, list)
        # Should contain at least the admin login
        actions = [e["action"] for e in events]
        self.assertIn("login", actions)

    def test_domain_list_assignment(self):
        from data.database import Database
        db = Database(self.db_path)
        list_id = db.save_domain_list("Test List", ["a.com", "b.com"], "")

        cr = self.client.post("/admin/api/users",
                               json={"username": "listuser", "email": "lu@e.com",
                                     "password": "password123", "role": "analyst"},
                               content_type="application/json")
        uid = json.loads(cr.data)["id"]

        r = self.client.put(f"/admin/api/users/{uid}/domain-lists",
                             json={"domain_list_ids": [list_id]},
                             content_type="application/json")
        self.assertEqual(r.status_code, 200)

        # Verify assignment persisted
        check = self.client.get(f"/admin/api/users/{uid}")
        u = json.loads(check.data)
        self.assertIn(list_id, u["domain_list_ids"])

    def test_domain_list_scoping_for_analyst(self):
        """Analyst should only see domains from assigned lists."""
        from data.database import Database
        db   = Database(self.db_path)
        from tests.seed_demo_data import seed_run, DOMAIN_PROFILES
        from scanner.crypto_assessor import CryptoAssessor
        assessor = CryptoAssessor(guidelines_dir=os.path.join(
            os.path.dirname(__file__), "..", "guidelines"))
        seed_run(db, assessor, DOMAIN_PROFILES[:3], "finance", "Spain")

        # Create domain list with only ONE domain
        list_id = db.save_domain_list(
            "Scoped",
            [DOMAIN_PROFILES[0]["domain"]],
            ""
        )
        # Create analyst and assign this list
        cr = self.client.post("/admin/api/users",
                               json={"username": "scoped", "email": "sc@e.com",
                                     "password": "password123", "role": "analyst"},
                               content_type="application/json")
        uid = json.loads(cr.data)["id"]
        self.client.put(f"/admin/api/users/{uid}/domain-lists",
                         json={"domain_list_ids": [list_id]},
                         content_type="application/json")

        # Log in as the analyst
        client2 = self.app.test_client()
        client2.post("/login", data={"username": "scoped", "password": "password123"},
                     follow_redirects=True)

        r = client2.get("/app/api/assessments")
        self.assertEqual(r.status_code, 200)
        assessments = json.loads(r.data)
        domains_seen = {a["domain"] for a in assessments}
        # Should only contain the one allowed domain
        self.assertLessEqual(len(domains_seen), 1)
        if domains_seen:
            self.assertEqual(domains_seen, {DOMAIN_PROFILES[0]["domain"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
