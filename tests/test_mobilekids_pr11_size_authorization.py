"""Pin the MobileKids main promotion size allowance to one reviewed PR."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

import pr_qa as qa
from adapters.base import PRContext
from baseline_authorization import schema_errors


class MobileKidsPr11SizeAuthorizationTests(unittest.TestCase):
    def test_exact_pr_and_size_only(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        entries = [item for item in policy["one_time_baseline_alignments"]
                   if item.get("repository") == "Synergie-ITCI/mobilekids.synergieinsights.in"
                   and item.get("pr_number") == 11]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(schema_errors(entry, schema), [])
        self.assertEqual(entry["repository_id"], 1117278219)
        self.assertEqual(entry["expected_head_sha"], "65ec72d353a17f2a858eb3d3d6a2a6d274b47891")
        self.assertEqual(entry["expected_base_sha"], "582c03347247e069678e8dd3c9f5db786db4e833")
        self.assertEqual((entry["head_ref"], entry["base_ref"]),
                         ("codex/mobilekids-pr10-promotion", "main"))
        self.assertEqual(entry["relaxations"], ["diff_size"])
        self.assertEqual(entry["allowed_effective_additions"], 10714)
        self.assertEqual(entry["allowed_changed_files"], 113)

        ctx = PRContext(repo=ROOT, config={}, policy=policy, changed_files=[],
                        head_ref=entry["head_ref"], base_ref="main",
                        event={"repository": {"full_name": entry["repository"]},
                               "pull_request": {"number": 11}})
        self.assertEqual(qa.baseline_policy(ctx), entry)
        ctx.event["pull_request"]["number"] = 12
        self.assertNotEqual(qa.baseline_policy(ctx), entry)


if __name__ == "__main__":
    unittest.main()
