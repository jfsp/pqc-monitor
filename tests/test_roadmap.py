#!/usr/bin/env python3
"""
PQC-Monitor: Unit Tests — PQC Migration Roadmap Generator
Tests for phase assignment, effort estimation, dependency ordering,
score projection, text rendering, and database storage.
All tests are fully offline — no network, no scan activity.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from roadmap.generator import (
    generate_domain_roadmap,
    generate_sector_roadmap,
    render_roadmap_text,
    render_sector_roadmap_text,
    DomainRoadmap, SectorRoadmap, RoadmapItem,
    PHASE_1, PHASE_2, PHASE_3,
    EFFORT_LOW, EFFORT_MEDIUM, EFFORT_HIGH,
    EFFORT_DAYS, _project_scores,
)
from data.database import Database


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _assessment(domain="test.com", score=50, level="weak", has_pqc=False,
                tls_versions=None, cipher_suites=None,
                cert_expiry_days=180, cdn_name="",
                findings=None) -> dict:
    """Build a minimal assessment dict that the generator accepts."""
    if findings is None:
        findings = []
    return {
        "domain":               domain,
        "score":                score,
        "level":                level,
        "has_pqc":              has_pqc,
        "tls_versions":         json.dumps(tls_versions or ["TLSv1.3"]),
        "cipher_suites":        json.dumps(cipher_suites or ["TLS_AES_256_GCM_SHA384"]),
        "cert_expiry_days":     cert_expiry_days,
        "certificate_expiry_days": cert_expiry_days,
        "cdn_name":             cdn_name,
        "findings_json":        json.dumps(findings),
        "assessed_at":          datetime.now(timezone.utc).isoformat(),
    }


def _finding(severity="high", category="tls_version",
             message="Test finding", recommendation="Fix it") -> dict:
    return {"severity": severity, "category": category,
            "message": message, "recommendation": recommendation,
            "guideline": "nist_800_131a"}


# ── Phase assignment tests ────────────────────────────────────────────────────

class TestPhaseAssignment(unittest.TestCase):

    def test_disallowed_tls_goes_to_phase1(self):
        a = _assessment(tls_versions=["TLSv1.0", "TLSv1.1"],
                         findings=[_finding("critical", "tls_version",
                                            "Disallowed TLS version in use: TLSv1.0")])
        dr = generate_domain_roadmap(a)
        phases = {i["phase"] if isinstance(i, dict) else i.phase for i in dr.items}
        self.assertIn(PHASE_1, phases)

    def test_broken_cipher_phase1(self):
        a = _assessment(
            cipher_suites=["TLS_RSA_WITH_RC4_128_SHA"],
            findings=[_finding("critical", "cipher", "Disallowed cipher suite: TLS_RSA_WITH_RC4_128_SHA")]
        )
        dr = generate_domain_roadmap(a)
        p1_items = [i for i in dr.items
                    if (i["phase"] if isinstance(i, dict) else i.phase) == PHASE_1]
        self.assertGreater(len(p1_items), 0)

    def test_enable_tls13_phase2(self):
        a = _assessment(tls_versions=["TLSv1.2"])  # TLS 1.3 absent
        dr = generate_domain_roadmap(a)
        p2_items = [i for i in dr.items
                    if (i["phase"] if isinstance(i, dict) else i.phase) == PHASE_2]
        actions = [i.get("action") if isinstance(i, dict) else i.action for i in p2_items]
        self.assertTrue(any("TLS 1.3" in a for a in actions))

    def test_pqc_items_always_in_phase3(self):
        a = _assessment(has_pqc=False)
        dr = generate_domain_roadmap(a)
        pqc_items = [i for i in dr.items
                     if (i.get("category") if isinstance(i, dict) else i.category) == "pqc"]
        phases = {i.get("phase") if isinstance(i, dict) else i.phase for i in pqc_items}
        # All PQC items must be in phase 3
        self.assertTrue(all(p == PHASE_3 for p in phases))

    def test_expired_cert_is_phase1(self):
        a = _assessment(cert_expiry_days=-5)
        dr = generate_domain_roadmap(a)
        p1_items = [i for i in dr.items
                    if (i["phase"] if isinstance(i, dict) else i.phase) == PHASE_1]
        actions = [i.get("action", "") if isinstance(i, dict) else i.action for i in p1_items]
        self.assertTrue(any("expired" in act.lower() or "Renew" in act for act in actions))

    def test_sha1_cert_is_phase1(self):
        a = _assessment(
            findings=[_finding("critical", "hash",
                                "Certificate uses SHA-1 signature: sha1WithRSAEncryption")]
        )
        dr = generate_domain_roadmap(a)
        p1_items = [i for i in dr.items
                    if (i["phase"] if isinstance(i, dict) else i.phase) == PHASE_1]
        self.assertGreater(len(p1_items), 0)

    def test_hsts_missing_is_phase2(self):
        a = _assessment(
            findings=[_finding("medium", "chain",
                                "HTTP Strict Transport Security (HSTS) header not present")]
        )
        dr = generate_domain_roadmap(a)
        p2_items = [i for i in dr.items
                    if (i["phase"] if isinstance(i, dict) else i.phase) == PHASE_2]
        actions = [i.get("action", "") if isinstance(i, dict) else i.action for i in p2_items]
        self.assertTrue(any("HSTS" in a for a in actions))

    def test_caa_missing_is_phase2(self):
        a = _assessment(
            findings=[_finding("low", "chain",
                                "No DNS CAA record found")]
        )
        dr = generate_domain_roadmap(a)
        p2_items = [i for i in dr.items
                    if (i["phase"] if isinstance(i, dict) else i.phase) == PHASE_2]
        actions = [i.get("action", "") if isinstance(i, dict) else i.action for i in p2_items]
        self.assertTrue(any("CAA" in a for a in actions))

    def test_cdn_note_in_phase3(self):
        a = _assessment(cdn_name="Cloudflare")
        dr = generate_domain_roadmap(a)
        self.assertIn("Cloudflare", dr.cdn_note)
        p3_cdn = [i for i in dr.items
                  if (i["phase"] if isinstance(i, dict) else i.phase) == PHASE_3
                  and "CDN" in (i.get("action","") if isinstance(i,dict) else i.action)]
        self.assertGreater(len(p3_cdn), 0)


# ── Item completeness tests ───────────────────────────────────────────────────

class TestItemCompleteness(unittest.TestCase):

    def _get_items(self, a) -> list[dict]:
        dr = generate_domain_roadmap(a)
        items = []
        for i in dr.items:
            items.append(i if isinstance(i, dict) else i.__dict__)
        return items

    def test_every_item_has_required_fields(self):
        a = _assessment(score=30, tls_versions=["TLSv1.0"])
        items = self._get_items(a)
        required = ["phase", "action", "detail", "effort",
                    "effort_days_min", "effort_days_max",
                    "priority", "target_date", "guideline_refs",
                    "current_state", "target_state"]
        for item in items:
            for field in required:
                self.assertIn(field, item, f"Missing {field!r} in item {item.get('action')!r}")

    def test_effort_days_consistent_with_level(self):
        a = _assessment()
        items = self._get_items(a)
        for item in items:
            level = item.get("effort", EFFORT_LOW)
            expected_min, expected_max = EFFORT_DAYS.get(level, (1, 5))
            self.assertEqual(item["effort_days_min"], expected_min)
            self.assertEqual(item["effort_days_max"], expected_max)

    def test_target_dates_are_valid_iso_dates(self):
        from datetime import date
        a = _assessment()
        items = self._get_items(a)
        for item in items:
            td = item.get("target_date", "")
            self.assertTrue(len(td) >= 10, f"target_date too short: {td!r}")
            # Should parse as date
            try:
                date.fromisoformat(str(td))
            except ValueError:
                self.fail(f"Invalid target_date: {td!r}")

    def test_all_priority_values_positive(self):
        a = _assessment()
        items = self._get_items(a)
        for item in items:
            self.assertGreater(item.get("priority", 0), 0)

    def test_phase1_items_have_earlier_dates_than_phase3(self):
        a = _assessment(tls_versions=["TLSv1.0"])
        items = self._get_items(a)
        p1_dates = [i["target_date"] for i in items if i.get("phase") == PHASE_1]
        p3_dates = [i["target_date"] for i in items if i.get("phase") == PHASE_3]
        if p1_dates and p3_dates:
            self.assertLess(max(p1_dates), min(p3_dates))

    def test_no_duplicate_actions_per_domain(self):
        a = _assessment(
            tls_versions=["TLSv1.0"],
            findings=[
                _finding("critical", "tls_version", "Disallowed TLS version: TLSv1.0"),
                _finding("critical", "tls_version", "Disallowed TLS version: TLSv1.0"),  # duplicate
            ]
        )
        items = self._get_items(a)
        actions = [i.get("action") for i in items]
        # Should be deduplicated
        self.assertEqual(len(actions), len(set(actions)))

    def test_pqc_upgrade_library_depends_on_tls_version(self):
        a = _assessment()
        items = self._get_items(a)
        pqc_lib = next((i for i in items if "Upgrade TLS library" in i.get("action", "")), None)
        self.assertIsNotNone(pqc_lib)
        self.assertIn("tls_version", pqc_lib.get("depends_on", []))


# ── Score projection tests ────────────────────────────────────────────────────

class TestScoreProjection(unittest.TestCase):

    def test_projections_are_monotonically_increasing(self):
        a = _assessment(score=10)
        dr = generate_domain_roadmap(a)
        self.assertLessEqual(dr.current_score, dr.score_after_phase1)
        self.assertLessEqual(dr.score_after_phase1, dr.score_after_phase2)
        self.assertLessEqual(dr.score_after_phase2, dr.score_after_phase3)

    def test_projections_capped_at_100(self):
        a = _assessment(score=95)
        dr = generate_domain_roadmap(a)
        self.assertLessEqual(dr.score_after_phase1, 100)
        self.assertLessEqual(dr.score_after_phase2, 100)
        self.assertLessEqual(dr.score_after_phase3, 100)

    def test_critical_domain_improves_after_phase1(self):
        a = _assessment(score=5, level="critical",
                         tls_versions=["TLSv1.0"],
                         findings=[
                             _finding("critical", "tls_version", "Disallowed TLS"),
                             _finding("critical", "cipher", "RC4"),
                             _finding("critical", "hash", "SHA-1 cert"),
                         ])
        dr = generate_domain_roadmap(a)
        self.assertGreater(dr.score_after_phase1, dr.current_score)

    def test_already_good_score_minimal_phase1_impact(self):
        a = _assessment(score=72, level="moderate", has_pqc=False)
        dr = generate_domain_roadmap(a)
        # Phase 1 should add little if score is already moderate
        self.assertLessEqual(dr.score_after_phase1 - dr.current_score, 30)

    def test_project_scores_helper(self):
        s1, s2, s3 = _project_scores(20, [
            RoadmapItem("d", PHASE_1, "P1", "cat", "act", "det", EFFORT_LOW,
                         1, 5, 1, [], "2025-01-01", ["g"], "cur", "tgt"),
            RoadmapItem("d", PHASE_2, "P2", "cat", "act", "det", EFFORT_LOW,
                         1, 5, 1, [], "2025-06-01", ["g"], "cur", "tgt"),
            RoadmapItem("d", PHASE_3, "P3", "cat", "act", "det", EFFORT_LOW,
                         1, 5, 1, [], "2027-01-01", ["g"], "cur", "tgt"),
        ])
        self.assertGreater(s1, 20)
        self.assertGreater(s2, s1)
        self.assertGreater(s3, s2)
        self.assertLessEqual(s3, 100)


# ── Effort calculation tests ──────────────────────────────────────────────────

class TestEffortCalculation(unittest.TestCase):

    def test_total_effort_is_sum_of_items(self):
        a = _assessment(tls_versions=["TLSv1.0"])
        dr = generate_domain_roadmap(a)
        calc_min = sum(i.get("effort_days_min",0) if isinstance(i,dict) else i.effort_days_min
                       for i in dr.items)
        calc_max = sum(i.get("effort_days_max",0) if isinstance(i,dict) else i.effort_days_max
                       for i in dr.items)
        self.assertEqual(dr.total_effort_days_min, calc_min)
        self.assertEqual(dr.total_effort_days_max, calc_max)

    def test_effort_min_less_than_max(self):
        a = _assessment()
        dr = generate_domain_roadmap(a)
        self.assertLessEqual(dr.total_effort_days_min, dr.total_effort_days_max)

    def test_config_changes_are_low_effort(self):
        a = _assessment(tls_versions=["TLSv1.0"],
                         findings=[_finding("critical", "tls_version", "Disallowed TLS")])
        dr = generate_domain_roadmap(a)
        tls_item = next(
            (i for i in dr.items
             if "TLS" in (i.get("action","") if isinstance(i,dict) else i.action)
             and (i.get("phase") if isinstance(i,dict) else i.phase) == PHASE_1),
            None
        )
        self.assertIsNotNone(tls_item)
        effort = tls_item.get("effort") if isinstance(tls_item,dict) else tls_item.effort
        self.assertEqual(effort, EFFORT_LOW)

    def test_ml_dsa_cert_migration_is_high_effort(self):
        a = _assessment(has_pqc=False)
        dr = generate_domain_roadmap(a)
        ml_dsa_item = next(
            (i for i in dr.items
             if "ML-DSA" in (i.get("action","") if isinstance(i,dict) else i.action)),
            None
        )
        self.assertIsNotNone(ml_dsa_item)
        effort = ml_dsa_item.get("effort") if isinstance(ml_dsa_item,dict) else ml_dsa_item.effort
        self.assertEqual(effort, EFFORT_HIGH)


# ── DomainRoadmap structure tests ─────────────────────────────────────────────

class TestDomainRoadmapStructure(unittest.TestCase):

    def test_phase_counts_sum_to_total_items(self):
        a = _assessment()
        dr = generate_domain_roadmap(a)
        self.assertEqual(
            dr.phase1_items + dr.phase2_items + dr.phase3_items,
            len(dr.items)
        )

    def test_clean_domain_has_no_phase1(self):
        a = _assessment(
            score=80, level="ready", has_pqc=True,
            tls_versions=["TLSv1.3"],
            cipher_suites=["TLS_AES_256_GCM_SHA384"],
            cert_expiry_days=365,
            findings=[]
        )
        dr = generate_domain_roadmap(a)
        self.assertEqual(dr.phase1_items, 0)

    def test_pqc_already_deployed_still_has_phase3_items(self):
        # Even with PQC, application audit and ML-DSA cert items should appear
        a = _assessment(has_pqc=True, score=85)
        dr = generate_domain_roadmap(a)
        # Phase 3 items still include cert migration and app audit
        self.assertGreater(dr.phase3_items, 0)

    def test_estimated_completion_is_iso_date_string(self):
        a = _assessment()
        dr = generate_domain_roadmap(a)
        self.assertTrue(len(dr.estimated_completion) >= 10)

    def test_to_dict_is_json_serialisable(self):
        a = _assessment()
        dr = generate_domain_roadmap(a)
        # Should not raise
        serialised = json.dumps(dr.to_dict(), default=str)
        parsed = json.loads(serialised)
        self.assertEqual(parsed["domain"], a["domain"])

    def test_cdn_note_empty_when_no_cdn(self):
        a = _assessment(cdn_name="")
        dr = generate_domain_roadmap(a)
        self.assertEqual(dr.cdn_note, "")

    def test_cdn_note_present_when_cdn_detected(self):
        a = _assessment(cdn_name="Fastly")
        dr = generate_domain_roadmap(a)
        self.assertIn("Fastly", dr.cdn_note)


# ── Sector roadmap tests ──────────────────────────────────────────────────────

class TestSectorRoadmap(unittest.TestCase):

    def _sector_assessments(self):
        return [
            _assessment("bank1.es", score=7,  level="critical",
                         tls_versions=["TLSv1.0"],
                         findings=[_finding("critical","tls_version","Disallowed TLS")]),
            _assessment("bank2.es", score=50, level="weak"),
            _assessment("bank3.es", score=72, level="moderate"),
            _assessment("bank4.es", score=85, level="ready", has_pqc=True),
            _assessment("bank5.es", score=63, level="moderate",
                         tls_versions=["TLSv1.2"]),
        ]

    def test_sector_domain_count(self):
        assessments = self._sector_assessments()
        sr = generate_sector_roadmap(assessments, "finance", "Spain")
        self.assertEqual(sr.domain_count, len(assessments))

    def test_sector_avg_score_correct(self):
        assessments = self._sector_assessments()
        expected_avg = sum(a["score"] for a in assessments) / len(assessments)
        sr = generate_sector_roadmap(assessments, "finance", "Spain")
        self.assertAlmostEqual(sr.avg_current_score, expected_avg, places=0)

    def test_critical_domains_identified(self):
        assessments = self._sector_assessments()
        sr = generate_sector_roadmap(assessments, "finance", "Spain")
        self.assertIn("bank1.es", sr.critical_domains)
        self.assertNotIn("bank4.es", sr.critical_domains)

    def test_pqc_ready_domains_identified(self):
        assessments = self._sector_assessments()
        sr = generate_sector_roadmap(assessments, "finance", "Spain")
        self.assertIn("bank4.es", sr.pqc_ready_domains)
        self.assertNotIn("bank1.es", sr.pqc_ready_domains)

    def test_action_summary_is_sorted_by_frequency(self):
        assessments = self._sector_assessments()
        sr = generate_sector_roadmap(assessments)
        counts = list(sr.action_summary.values())
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_total_effort_sum_of_domains(self):
        assessments = self._sector_assessments()
        sr = generate_sector_roadmap(assessments)
        domain_roadmaps = [generate_domain_roadmap(a) for a in assessments]
        expected_min = sum(r.total_effort_days_min for r in domain_roadmaps)
        expected_max = sum(r.total_effort_days_max for r in domain_roadmaps)
        self.assertEqual(sr.total_effort_days_min, expected_min)
        self.assertEqual(sr.total_effort_days_max, expected_max)

    def test_empty_assessments_returns_empty_roadmap(self):
        sr = generate_sector_roadmap([])
        self.assertEqual(sr.domain_count, 0)
        self.assertEqual(sr.domains, [])

    def test_domain_summaries_in_sector_roadmap(self):
        assessments = self._sector_assessments()
        sr = generate_sector_roadmap(assessments)
        self.assertEqual(len(sr.domains), len(assessments))
        for d in sr.domains:
            self.assertIn("domain", d)
            self.assertIn("current_score", d)
            self.assertIn("effort_days_min", d)
            self.assertIn("score_after_phase1", d)

    def test_sector_to_dict_json_serialisable(self):
        assessments = self._sector_assessments()
        sr = generate_sector_roadmap(assessments, "finance", "Spain")
        serialised = json.dumps(sr.to_dict(), default=str)
        parsed = json.loads(serialised)
        self.assertEqual(parsed["sector"], "finance")
        self.assertEqual(parsed["domain_count"], len(assessments))


# ── Text rendering tests ──────────────────────────────────────────────────────

class TestTextRendering(unittest.TestCase):

    def test_roadmap_text_contains_domain(self):
        a = _assessment("mybank.es")
        dr = generate_domain_roadmap(a)
        text = render_roadmap_text(dr)
        self.assertIn("mybank.es", text)

    def test_roadmap_text_contains_all_phases(self):
        a = _assessment(tls_versions=["TLSv1.0"])
        dr = generate_domain_roadmap(a)
        text = render_roadmap_text(dr)
        self.assertIn("Phase 1", text)
        self.assertIn("Phase 2", text)
        self.assertIn("Phase 3", text)

    def test_roadmap_text_contains_score_projection(self):
        a = _assessment(score=30)
        dr = generate_domain_roadmap(a)
        text = render_roadmap_text(dr)
        self.assertIn("30", text)
        self.assertIn("Phase 1", text)

    def test_roadmap_text_contains_effort(self):
        a = _assessment()
        dr = generate_domain_roadmap(a)
        text = render_roadmap_text(dr)
        self.assertIn("person-days", text)

    def test_sector_text_contains_domain_list(self):
        assessments = [
            _assessment("a.es", score=10),
            _assessment("b.es", score=70),
        ]
        sr = generate_sector_roadmap(assessments, "finance", "Spain")
        text = render_sector_roadmap_text(sr)
        self.assertIn("a.es", text)
        self.assertIn("b.es", text)
        self.assertIn("Spain", text)

    def test_sector_text_critical_section(self):
        assessments = [_assessment("critical.es", score=5, level="critical")]
        sr = generate_sector_roadmap(assessments)
        text = render_sector_roadmap_text(sr)
        self.assertIn("CRITICAL", text)
        self.assertIn("critical.es", text)

    def test_text_is_string(self):
        a = _assessment()
        dr = generate_domain_roadmap(a)
        text = render_roadmap_text(dr)
        self.assertIsInstance(text, str)
        self.assertGreater(len(text), 100)


# ── Database storage tests ────────────────────────────────────────────────────

class TestRoadmapDatabase(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.tmpdir, "rm_test.db"))

    def test_save_and_retrieve_roadmap(self):
        a = _assessment("save-test.es", score=42)
        dr = generate_domain_roadmap(a)
        self.db.save_roadmap("run001", dr.to_dict())

        results = self.db.get_roadmaps(run_id="run001")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["domain"], "save-test.es")
        self.assertEqual(results[0]["current_score"], 42)

    def test_items_json_preserved(self):
        a = _assessment("items.es")
        dr = generate_domain_roadmap(a)
        self.db.save_roadmap("run001", dr.to_dict())

        results = self.db.get_roadmaps()
        items = results[0].get("items_json") or []
        self.assertIsInstance(items, list)
        self.assertGreater(len(items), 0)

    def test_domain_filter(self):
        for name in ["alpha.es", "beta.es", "gamma.es"]:
            a = _assessment(name)
            dr = generate_domain_roadmap(a)
            self.db.save_roadmap("run001", dr.to_dict())

        results = self.db.get_roadmaps(domain="beta.es")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["domain"], "beta.es")

    def test_upsert_replaces_previous(self):
        a1 = _assessment("upsert.es", score=30)
        a2 = _assessment("upsert.es", score=65)
        self.db.save_roadmap("run001", generate_domain_roadmap(a1).to_dict())
        self.db.save_roadmap("run001", generate_domain_roadmap(a2).to_dict())
        results = self.db.get_roadmaps(run_id="run001")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["current_score"], 65)

    def test_get_roadmap_stats_empty(self):
        stats = self.db.get_roadmap_stats()
        self.assertIsInstance(stats, dict)

    def test_get_roadmap_stats_populated(self):
        for i, name in enumerate(["s1.es", "s2.es", "s3.es"]):
            a = _assessment(name, score=10 + i*20, level="weak")
            a["phase1_items"] = 2
            dr = generate_domain_roadmap(a)
            self.db.save_roadmap("run001", dr.to_dict())

        stats = self.db.get_roadmap_stats()
        self.assertEqual(stats.get("domains"), 3)
        self.assertGreater(stats.get("total_p3_items", 0), 0)

    def test_roadmap_stats_counts_p1_domains(self):
        # Domain with phase1 items
        a = _assessment("bad.es", score=5, level="critical",
                         tls_versions=["TLSv1.0"],
                         findings=[_finding("critical","tls_version","TLSv1.0")])
        dr = generate_domain_roadmap(a)
        self.db.save_roadmap("run001", dr.to_dict())

        stats = self.db.get_roadmap_stats()
        self.assertGreater(stats.get("domains_need_p1", 0), 0)


# ── API endpoint tests ────────────────────────────────────────────────────────

class TestRoadmapAPIEndpoints(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(self.tmpdir, "api_rm.db")
        from dashboard.app import create_app
        self.app = create_app({"db_path": db_path})
        self.client = self.app.test_client()
        self.db = Database(db_path)

        # Seed some assessments
        from tests.seed_demo_data import seed_run, DOMAIN_PROFILES
        from scanner.crypto_assessor import CryptoAssessor
        assessor = CryptoAssessor(
            guidelines_dir=os.path.join(os.path.dirname(__file__), "..", "guidelines")
        )
        self.run_id = seed_run(
            self.db, assessor, DOMAIN_PROFILES[:5],
            sector="finance", region="Spain"
        )
        self._profiles = DOMAIN_PROFILES

    def test_roadmap_stats_endpoint(self):
        r = self.client.get("/api/roadmap/stats")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIsInstance(data, dict)

    def test_roadmap_list_endpoint(self):
        r = self.client.get("/api/roadmap")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIsInstance(data, list)
        # Should generate on-the-fly from assessments
        self.assertGreater(len(data), 0)

    def test_roadmap_domain_endpoint(self):
        domain = self._profiles[0]["domain"]
        r = self.client.get(f"/api/roadmap/domain/{domain}")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertEqual(data.get("domain"), domain)
        self.assertIn("items", data)

    def test_roadmap_domain_404(self):
        r = self.client.get("/api/roadmap/domain/nonexistent.invalid")
        self.assertEqual(r.status_code, 404)

    def test_roadmap_generate_endpoint(self):
        r = self.client.post("/api/roadmap/generate",
                              json={"run_id": self.run_id, "save": True},
                              content_type="application/json")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("domains_processed", data)
        self.assertGreater(data["domains_processed"], 0)
        self.assertTrue(data["saved"])

    def test_roadmap_generate_saves_to_db(self):
        self.client.post("/api/roadmap/generate",
                          json={"run_id": self.run_id, "save": True},
                          content_type="application/json")
        stored = self.db.get_roadmaps(run_id=self.run_id)
        self.assertGreater(len(stored), 0)

    def test_roadmap_generate_no_assessments_400(self):
        r = self.client.post("/api/roadmap/generate",
                              json={"run_id": "nonexistent-run"},
                              content_type="application/json")
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
