"""Keep the PR #95 size decision bound to one reviewed RoadSense diff."""

import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

import pr_qa as qa
from adapters.base import PRContext
from baseline_authorization import schema_errors


class RoadSensePr95SizeAuthorizationTests(unittest.TestCase):
    def test_exact_scope_and_only_diff_size(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        entries = [
            item for item in policy["one_time_baseline_alignments"]
            if item.get("repository") == "Synergie-ITCI/roadsense-production-dashboard"
            and item.get("pr_number") == 95
        ]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(schema_errors(entry, schema), [])
        self.assertEqual(entry["repository_id"], 1426678649)
        self.assertEqual(entry["expected_head_sha"], "940f3484e21ba7738463e3bb50ed48d5bf509b09")
        self.assertEqual(entry["expected_base_sha"], "753ae6e46564f37e81999b7347eb348115558df3")
        self.assertEqual(entry["allowed_effective_additions"], 7671)
        self.assertEqual(entry["allowed_changed_files"], 27)
        self.assertEqual(entry["minimum_changed_files"], 27)
        self.assertEqual(entry["relaxations"], ["diff_size"])
        issued = datetime.fromisoformat(entry["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(entry["expires_after"].replace("Z", "+00:00"))
        self.assertEqual(expires - issued, timedelta(hours=24))

        ctx = PRContext(
            repo=ROOT, config={}, policy=policy, changed_files=[],
            head_ref=entry["head_ref"], base_ref=entry["base_ref"],
            event={
                "repository": {"full_name": entry["repository"]},
                "pull_request": {"number": 95},
            },
        )
        self.assertEqual(qa.baseline_policy(ctx), entry)
        ctx.event["pull_request"]["number"] = 96
        self.assertNotEqual(qa.baseline_policy(ctx), entry)


if __name__ == "__main__":
    unittest.main()
