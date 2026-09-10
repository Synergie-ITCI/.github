"""Completed PR134 can never regain its retired migration authorization."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
import migration_authorization


class Pr134AuthorizationCleanupTests(unittest.TestCase):
    def test_retired_authorization_and_merged_pr_are_absent(self):
        records = migration_authorization.load_authorizations()
        for record in records:
            self.assertNotEqual(
                record["authorization_id"], "17513aff-e5f4-47dd-b976-403bea8df055"
            )
            self.assertNotEqual(
                (record["repository_id"], record["pr_number"]), (1315697868, 134)
            )

    def test_default_limits_and_security_gates_remain_enforced(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        self.assertNotIn("one_time_baseline_alignment", policy)
        for limits in (policy["minimum_thresholds"], policy["defaults"]["thresholds"]):
            self.assertEqual(limits["max_additions"], 5000)
            self.assertEqual(limits["max_changed_files"], 200)
        for gate in (
            "database_safety",
            "review_policy",
            "secrets",
            "dependencies",
            "tests",
        ):
            self.assertIn(gate, policy["mandatory_gates"])
