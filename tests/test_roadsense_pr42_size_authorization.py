"""The staging promotion uses the original reviewed patch, not a new PR exception."""

import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
from baseline_authorization import schema_errors


class RoadSensePr42SizeAuthorizationTests(unittest.TestCase):
    def test_staging_uses_bounded_shared_promotion_scope(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        matches = [item for item in policy["one_time_baseline_alignments"]
                   if item.get("repository") == "Synergie-ITCI/roadsense-production-dashboard"]
        self.assertEqual(len(matches), 1)
        authorization = matches[0]
        self.assertEqual(schema_errors(authorization, schema), [])
        self.assertEqual(authorization["pr_number"], 41)
        self.assertEqual(authorization["repository_id"], 1426678649)
        self.assertEqual(authorization["relaxations"], ["diff_size"])
        self.assertEqual(authorization["allowed_effective_additions"], 5573)
        self.assertEqual(authorization["allowed_changed_files"], 30)
        scope = authorization["promotion_scope"]
        self.assertIn({"head_ref": "promotion/bengaluru-coverage-recovery-staging", "base_ref": "staging"}, scope["branches"])
        self.assertEqual(scope["reviewed_patch_sha256"], "6923f57b1db7462416a9f343f8a3cb22c0fe480d1bff1d9fc9b19e2d07c932d9")
        issued = datetime.fromisoformat(scope["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(scope["expires_after"].replace("Z", "+00:00"))
        self.assertGreater(expires, issued)
        self.assertLessEqual(expires - issued, timedelta(days=30))
        self.assertEqual(policy["minimum_thresholds"]["max_additions"], 5000)
