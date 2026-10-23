"""Bound the RoadSense Bengaluru size review to one unchanged main pull request."""

import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
from baseline_authorization import schema_errors


class RoadSensePr43SizeAuthorizationTests(unittest.TestCase):
    def test_exact_scope_and_only_diff_size_relaxation(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        matches = [entry for entry in policy["one_time_baseline_alignments"]
                   if entry.get("repository") == "Synergie-ITCI/roadsense-production-dashboard"
                   and entry.get("pr_number") == 43]
        self.assertEqual(len(matches), 1)
        authorization = matches[0]
        self.assertEqual(schema_errors(authorization, schema), [])
        self.assertEqual(authorization["repository_id"], 1426678649)
        self.assertEqual(authorization["expected_head_sha"],
                         "df9e2bcd65fd8f714c96dc90c11eb62367efb371")
        self.assertEqual(authorization["expected_base_sha"],
                         "12333690478c34406443b03cae529823e4b8ab9c")
        self.assertEqual(authorization["head_ref"], "promotion/bengaluru-coverage-recovery-main")
        self.assertEqual(authorization["base_ref"], "main")
        self.assertEqual(authorization["allowed_effective_additions"], 5573)
        self.assertEqual(authorization["allowed_changed_files"], 30)
        self.assertEqual(authorization["minimum_changed_files"], 30)
        self.assertEqual(authorization["required_pr_body_marker"],
                         "ROADSENSE-PR43-EXACT-HEAD-SIZE-7415858B")
        self.assertEqual(authorization["relaxations"], ["diff_size"])
        self.assertEqual(policy["minimum_thresholds"]["max_additions"], 5000)
        issued = datetime.fromisoformat(authorization["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(authorization["expires_after"].replace("Z", "+00:00"))
        self.assertGreater(expires, issued)
        self.assertLessEqual(expires - issued, timedelta(hours=24))


if __name__ == "__main__":
    unittest.main()
