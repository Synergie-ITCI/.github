"""Bind the LMS staging size allowance to the reviewed promotion patch."""

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

from baseline_authorization import schema_errors


class LmsPr97StagingSizeAuthorizationTests(unittest.TestCase):
    def test_exact_staging_patch_and_size_only(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        entries = [
            entry for entry in policy["one_time_baseline_alignments"]
            if entry.get("repository") == "Synergie-ITCI/synergielms.com"
            and entry.get("pr_number") == 97
        ]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(schema_errors(entry, schema), [])
        self.assertEqual(entry["repository_id"], 1118680062)
        self.assertEqual(entry["expected_base_sha"], "0129d7806fe064e5d59dcc754bb28467bf3ea896")
        self.assertEqual((entry["minimum_changed_files"], entry["allowed_changed_files"]), (660, 660))
        self.assertEqual(entry["allowed_effective_additions"], 37282)
        self.assertEqual(entry["relaxations"], ["changed_file_count", "diff_size"])
        scope = entry["promotion_scope"]
        self.assertEqual(scope["branches"], [{"head_ref": "development", "base_ref": "staging"}])
        self.assertEqual(scope["reviewed_patch_sha256"], "98a55c45eb07ce366eca4ccc025c20a548ea1af6d9f205d5ff7f89d8ed48caa1")
        self.assertEqual(scope["required_pr_body_marker"], "LMS-PR97-STAGING-SIZE-98a55c45")


if __name__ == "__main__":
    unittest.main()
