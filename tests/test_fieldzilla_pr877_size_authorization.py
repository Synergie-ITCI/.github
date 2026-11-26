"""Bind the staging dashboard size allowance to one exact reviewed PR."""

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


class FieldzillaPr877SizeAuthorizationTests(unittest.TestCase):
    def test_exact_scope_and_only_diff_size(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        entries = [
            item for item in policy["one_time_baseline_alignments"]
            if item.get("repository") == "Synergie-ITCI/programme-management-platform"
            and item.get("pr_number") == 877
        ]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(schema_errors(entry, schema), [])
        self.assertEqual(entry["repository_id"], 1315697868)
        self.assertEqual(entry["expected_head_sha"], "d59e966cbf1cf4eb96d08168f7052c91825f878c")
        self.assertEqual(entry["expected_base_sha"], "9c2b12d5ab1df8ec804eb50caf697044b577719d")
        self.assertEqual(entry["allowed_effective_additions"], 9813)
        self.assertEqual(entry["allowed_changed_files"], 87)
        self.assertEqual(entry["minimum_changed_files"], 87)
        self.assertEqual(entry["relaxations"], ["diff_size"])
        issued = datetime.fromisoformat(entry["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(entry["expires_after"].replace("Z", "+00:00"))
        self.assertEqual(expires - issued, timedelta(hours=23))

        ctx = PRContext(
            repo=ROOT, config={}, policy=policy, changed_files=[],
            head_ref=entry["head_ref"], base_ref=entry["base_ref"],
            event={
                "repository": {"full_name": entry["repository"]},
                "pull_request": {"number": 877},
            },
        )
        self.assertEqual(qa.baseline_policy(ctx), entry)
        ctx.event["pull_request"]["number"] = 876
        self.assertNotEqual(qa.baseline_policy(ctx), entry)


if __name__ == "__main__":
    unittest.main()
