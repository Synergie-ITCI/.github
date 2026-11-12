"""Bind the Scholarships main promotion size decision to one reviewed PR diff."""

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


class ScholarshipsPr7SizeAuthorizationTests(unittest.TestCase):
    def test_exact_promotion_and_only_size_gates(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        entries = [item for item in policy["one_time_baseline_alignments"]
                   if item.get("repository") == "Synergie-ITCI/scholarships"
                   and item.get("pr_number") == 7]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(schema_errors(entry, schema), [])
        self.assertEqual(entry["repository_id"], 1132519991)
        self.assertEqual(entry["expected_head_sha"], "1379352d5ef26cc7e867e52185315083ec63eebe")
        self.assertEqual(entry["expected_base_sha"], "8dfe82702349202d2eef0f16e12e6484b488cc87")
        self.assertEqual((entry["head_ref"], entry["base_ref"]), ("staging", "main"))
        self.assertEqual(entry["allowed_effective_additions"], 98393)
        self.assertEqual(entry["allowed_changed_files"], 356)
        self.assertEqual(entry["minimum_changed_files"], 356)
        self.assertEqual(entry["relaxations"], ["changed_file_count", "diff_size"])
        issued = datetime.fromisoformat(entry["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(entry["expires_after"].replace("Z", "+00:00"))
        self.assertEqual(expires - issued, timedelta(hours=24))

        ctx = PRContext(repo=ROOT, config={}, policy=policy, changed_files=[],
                        head_ref="staging", base_ref="main",
                        event={"repository": {"full_name": entry["repository"]},
                               "pull_request": {"number": 7}})
        self.assertEqual(qa.baseline_policy(ctx), entry)
        ctx.event["pull_request"]["number"] = 13
        self.assertNotEqual(qa.baseline_policy(ctx), entry)
        ctx.event["repository"]["full_name"] = "Synergie-ITCI/programme-management-platform"
        ctx.event["pull_request"]["number"] = 7
        self.assertNotEqual(qa.baseline_policy(ctx), entry)


if __name__ == "__main__":
    unittest.main()
