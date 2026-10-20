"""Keep the temporary RoadSense exception bound to one unchanged PR and gate."""

import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
from baseline_authorization import schema_errors


class RoadSensePr2BaselinePolicyTests(unittest.TestCase):
    def test_exact_scope_and_only_diff_size_relaxation(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        authorization = policy["one_time_baseline_alignment"]

        self.assertEqual(schema_errors(authorization, schema), [])
        self.assertEqual(authorization["repository"], "Synergie-ITCI/roadsense-production-dashboard")
        self.assertEqual(authorization["repository_id"], 1426678649)
        self.assertEqual(authorization["pr_number"], 2)
        self.assertEqual(authorization["expected_head_sha"], "3bb6fd264bfe7540fb2137e9a5880311b505aacf")
        self.assertEqual(authorization["expected_base_sha"], "65e66675ef0db34fa3d38ebd3692589a9da7e03b")
        self.assertEqual(authorization["head_ref"], "feature/roadsense-safety-release")
        self.assertEqual(authorization["base_ref"], "development")
        self.assertEqual(authorization["allowed_effective_additions"], 5155)
        self.assertEqual(authorization["allowed_changed_files"], 28)
        self.assertEqual(authorization["minimum_changed_files"], 28)
        self.assertEqual(authorization["relaxations"], ["diff_size"])
        self.assertEqual(policy["minimum_thresholds"]["max_additions"], 5000)
        issued = datetime.fromisoformat(authorization["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(authorization["expires_after"].replace("Z", "+00:00"))
        self.assertEqual(expires - issued, timedelta(hours=24))


if __name__ == "__main__":
    unittest.main()
