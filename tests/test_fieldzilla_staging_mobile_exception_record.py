"""Keep the staging mobile exception a protected dependency approval."""

from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "policy/exceptions/fieldzilla-otp-staging-mobile-audit.json"


class StagingExceptionRecordTests(unittest.TestCase):
    def test_approved_dependency_scope(self) -> None:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        self.assertEqual(
            record["repository"], "Synergie-ITCI/programme-management-platform"
        )
        self.assertEqual(record["environment"], "staging")
        self.assertEqual(record["workflow"], "staging-deploy.yml")
        self.assertEqual(
            record["exception_id"], "fieldzilla-staging-mobile-tooling-2026-10"
        )
        self.assertNotIn("head_sha", record)
        self.assertEqual(record["approver"], "Saurabh Verma")
        self.assertTrue(record["approved_at"])
        self.assertEqual(record["remediation_owner"], "Mobile Platform Lead")
        self.assertTrue(record["reason"] and record["residual_risk"])
        approved = datetime.fromisoformat(record["approved_at"].replace("Z", "+00:00"))
        expiry = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
        self.assertTrue(approved < expiry <= approved + timedelta(days=30))
        self.assertEqual(
            set(record["dependency_sha256"]),
            {"apps/mobile/package.json", "apps/mobile/package-lock.json"},
        )
        self.assertEqual(
            record["audit_script_sha256"],
            hashlib.sha256(b"npm audit --audit-level=high").hexdigest(),
        )
        evidence = RECORD.parent / record["evidence_file"]
        self.assertEqual(
            hashlib.sha256(evidence.read_bytes()).hexdigest(), record["evidence_sha256"]
        )
        self.assertEqual(
            record["baseline_tags"], ["fieldzilla-apply-dispatch-2c8a4015"]
        )
        self.assertEqual(record["baseline_releases"], [])
        advisories = record["advisories"]
        self.assertEqual(len(advisories), 5)
        self.assertEqual(
            len({(item["package"], item["id"]) for item in advisories}),
            len(advisories),
        )
        self.assertTrue(
            all(
                item["severity"] in {"moderate", "high", "critical"}
                for item in advisories
            )
        )
