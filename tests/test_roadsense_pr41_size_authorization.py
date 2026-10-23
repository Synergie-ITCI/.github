"""Bound the RoadSense Bengaluru size review to one unchanged pull request."""

import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
from baseline_authorization import schema_errors


class RoadSensePr41SizeAuthorizationTests(unittest.TestCase):
    def test_exact_scope_and_only_diff_size_relaxation(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        matches = [entry for entry in policy["one_time_baseline_alignments"]
                   if entry.get("repository") == "Synergie-ITCI/roadsense-production-dashboard"
                   and entry.get("pr_number") == 41]
        self.assertEqual(len(matches), 1)
        authorization = matches[0]
        self.assertEqual(schema_errors(authorization, schema), [])
        self.assertEqual(authorization["repository_id"], 1426678649)
        self.assertEqual(authorization["expected_head_sha"],
                         "be646aa6a34995f8b8e8889ac6f6bd88afee0640")
        self.assertEqual(authorization["expected_base_sha"],
                         "0a4ea31daa8b840e2318ccc936f26434eb7dc056")
        self.assertEqual(authorization["head_ref"], "feature/bengaluru-coverage-recovery")
        self.assertEqual(authorization["base_ref"], "development")
        self.assertEqual(authorization["allowed_effective_additions"], 5573)
        self.assertEqual(authorization["allowed_changed_files"], 30)
        self.assertEqual(authorization["minimum_changed_files"], 30)
        self.assertEqual(authorization["required_pr_body_marker"],
                         "ROADSENSE-PR41-EXACT-HEAD-SIZE-15579265")
        self.assertEqual(authorization["relaxations"], ["diff_size"])
        self.assertEqual(policy["minimum_thresholds"]["max_additions"], 5000)
        issued = datetime.fromisoformat(authorization["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(authorization["expires_after"].replace("Z", "+00:00"))
        self.assertGreater(expires, issued)
        self.assertLessEqual(expires - issued, timedelta(hours=24))


if __name__ == "__main__":
    unittest.main()
