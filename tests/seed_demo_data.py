#!/usr/bin/env python3
"""
PQC-Monitor: Demo Data Seeder
Populates the database with realistic synthetic scan results so the
dashboard can be evaluated without live scanning.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2024 PQC-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)

Usage:
    python3 tests/seed_demo_data.py
    python3 tests/seed_demo_data.py --db data/pqc_monitor.db --runs 3
"""

import sys
import os
import json
import random
import argparse
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data.database import Database
from scanner.crypto_assessor import CryptoAssessor

# ─── Synthetic domain profiles ────────────────────────────────────────────────
# Each profile represents a typical real-world configuration

DOMAIN_PROFILES = [
    # Finance – well-configured
    {"domain": "bancosantander.es",    "sector": "finance", "region": "Spain",
     "tls": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
     "key_type": "RSA", "key_size": 4096, "sig_alg": "sha256WithRSAEncryption",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 320},

    {"domain": "bbva.es",              "sector": "finance", "region": "Spain",
     "tls": "TLSv1.3", "cipher": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
     "key_type": "ECDSA", "key_size": 256, "sig_alg": "ecdsa-with-SHA256",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 90},

    {"domain": "caixabank.es",         "sector": "finance", "region": "Spain",
     "tls": "TLSv1.2", "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
     "key_type": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 200},

    {"domain": "bde.es",               "sector": "finance", "region": "Spain",
     "tls": "TLSv1.2", "cipher": "TLS_RSA_WITH_AES_256_CBC_SHA256",
     "key_type": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 150},

    # Old / weak – government portal
    {"domain": "sede.gob.es",          "sector": "government", "region": "Spain",
     "tls": "TLSv1.2", "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
     "key_type": "RSA", "key_size": 2048, "sig_alg": "sha1WithRSAEncryption",
     "hash": "SHA-1", "pqc_kem": False, "expiry": 60},

    {"domain": "administracion.gob.es","sector": "government", "region": "Spain",
     "tls": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256",
     "key_type": "RSA", "key_size": 3072, "sig_alg": "sha256WithRSAEncryption",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 280},

    # Critical – very old
    {"domain": "legacy-intranet.example.es", "sector": "government", "region": "Spain",
     "tls": "TLSv1.0", "cipher": "TLS_RSA_WITH_RC4_128_SHA",
     "key_type": "RSA", "key_size": 1024, "sig_alg": "sha1WithRSAEncryption",
     "hash": "SHA-1", "pqc_kem": False, "expiry": -10},

    # Healthcare
    {"domain": "isciii.es",            "sector": "healthcare", "region": "Spain",
     "tls": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
     "key_type": "RSA", "key_size": 4096, "sig_alg": "sha256WithRSAEncryption",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 400},

    # EU Finance
    {"domain": "ecb.europa.eu",        "sector": "finance", "region": "Europe",
     "tls": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
     "key_type": "ECDSA", "key_size": 384, "sig_alg": "ecdsa-with-SHA384",
     "hash": "SHA-384", "pqc_kem": False, "expiry": 500},

    {"domain": "eba.europa.eu",        "sector": "finance", "region": "Europe",
     "tls": "TLSv1.3", "cipher": "TLS_CHACHA20_POLY1305_SHA256",
     "key_type": "ECDSA", "key_size": 256, "sig_alg": "ecdsa-with-SHA256",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 250},

    # PQC early adopter
    {"domain": "pqc-pilot.example.eu", "sector": "finance", "region": "Europe",
     "tls": "TLSv1.3", "cipher": "X25519MLKEM768",
     "key_type": "ECDSA", "key_size": 256, "sig_alg": "ecdsa-with-SHA256",
     "hash": "SHA-256", "pqc_kem": True, "expiry": 365},

    # Telecom
    {"domain": "telefonica.com",       "sector": "telecom", "region": "Spain",
     "tls": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
     "key_type": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 180},

    {"domain": "orange.es",            "sector": "telecom", "region": "Spain",
     "tls": "TLSv1.2", "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
     "key_type": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 95},

    # Energy
    {"domain": "iberdrola.com",        "sector": "energy", "region": "Spain",
     "tls": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
     "key_type": "RSA", "key_size": 4096, "sig_alg": "sha256WithRSAEncryption",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 310},

    {"domain": "endesa.com",           "sector": "energy", "region": "Spain",
     "tls": "TLSv1.2", "cipher": "TLS_RSA_WITH_AES_256_GCM_SHA384",
     "key_type": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption",
     "hash": "SHA-256", "pqc_kem": False, "expiry": 120},
]


def make_scan_result(profile: dict, port: int = 443,
                     ts_offset_days: int = 0) -> dict:
    """Build a synthetic TLSProbeResult dict from a domain profile."""
    base_ts = datetime.now(timezone.utc) - timedelta(days=ts_offset_days)
    return {
        "domain": profile["domain"],
        "port": port,
        "timestamp": base_ts.isoformat(),
        "success": True,
        "tls_version": profile["tls"],
        "cipher_suite": profile["cipher"],
        "cipher_bits": 256,
        "key_exchange": "TLS1.3" if profile["tls"] == "TLSv1.3" else "ECDHE",
        "has_pqc_kem": profile.get("pqc_kem", False),
        "has_pqc_sig": False,
        "pqc_algorithms": ["ML-KEM-768"] if profile.get("pqc_kem") else [],
        "certificate": {
            "subject_cn": profile["domain"],
            "issuer_cn": "Let's Encrypt R3",
            "key_type": profile["key_type"],
            "key_size_bits": profile["key_size"],
            "signature_algorithm": profile["sig_alg"],
            "hash_algorithm": profile["hash"],
            "days_to_expiry": profile["expiry"],
            "is_self_signed": False,
            "serial_number": hex(random.randint(2**60, 2**64)),
        }
    }


def seed_run(db: Database, assessor: CryptoAssessor,
             profiles: list, sector: str, region: str,
             days_ago: int = 0) -> str:
    """Create one complete scan run from profiles."""
    domains = [p["domain"] for p in profiles]
    run_id = db.create_run(domains, sector=sector, region=region,
                           notes=f"Demo data (seeded {days_ago}d ago)")

    for profile in profiles:
        scan = make_scan_result(profile, ts_offset_days=days_ago)
        db.save_scan_result(run_id, scan)
        assessment = assessor.assess_domain(profile["domain"], [scan])
        db.save_assessment(run_id, assessment.to_dict())

    db.finish_run(run_id, "completed")
    return run_id


def main():
    parser = argparse.ArgumentParser(description="Seed PQC-Monitor with demo data")
    parser.add_argument("--db",   default="data/pqc_monitor.db")
    parser.add_argument("--runs", type=int, default=3,
                        help="Number of historical scan runs to create")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    db = Database(args.db)
    assessor = CryptoAssessor(
        guidelines_dir=os.path.join(os.path.dirname(__file__), "..", "guidelines")
    )

    # Save a domain list
    db.save_domain_list(
        "Spain Financial & Government (demo)",
        [p["domain"] for p in DOMAIN_PROFILES],
        "financial and government institutions in Spain"
    )

    # Simulate historical runs with slight score improvements over time
    # (representing gradual migration progress)
    run_offsets = {3: 270, 2: 180, 1: 90, 0: 0}

    for run_num in range(1, min(args.runs, 4) + 1):
        days_ago = run_offsets.get(4 - run_num, 0)

        # For older runs, downgrade some profiles slightly (less TLS1.3, smaller keys)
        profiles = []
        for p in DOMAIN_PROFILES:
            p2 = dict(p)
            if days_ago > 0 and random.random() < 0.3:
                # Simulate older (slightly worse) configuration
                if p2["tls"] == "TLSv1.3" and random.random() < 0.4:
                    p2["tls"] = "TLSv1.2"
                if p2["key_size"] > 2048 and random.random() < 0.3:
                    p2["key_size"] = 2048
                p2["expiry"] = max(p2["expiry"] - days_ago, 1)
            profiles.append(p2)

        run_id = seed_run(db, assessor, profiles,
                          sector="finance+government", region="Spain",
                          days_ago=days_ago)
        print(f"  Run {run_num}/{args.runs}: run_id={run_id} ({days_ago} days ago)")

    print(f"\n✅ Demo data seeded into {args.db}")
    print("   Launch dashboard: python3 pqc_monitor.py dashboard")


if __name__ == "__main__":
    main()
