"""Bind the LMS staging size allowance to the reviewed promotion patch."""

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

from baseline_authorization import schema_errors
from pr_qa import baseline_source_overlay_authorization


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
        self.assertEqual(scope["reviewed_patch_sha256"], "a3b015606170ab2874dc4025a49284c90a3c59cf5d38743e966a327b4d838715")
        self.assertEqual(scope["required_pr_body_marker"], "LMS-PR97-STAGING-SIZE-98a55c45")

    def test_reviewed_promotion_uses_patch_binding_after_merge(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        entry = next(
            row for row in policy["one_time_baseline_alignments"]
            if row.get("repository") == "Synergie-ITCI/synergielms.com"
            and row.get("pr_number") == 97
        )
        merged_head = "42b87f8c852bba52f1fbddfe19bce6c97bfc8b72"
        staging = SimpleNamespace(head_ref="development", base_ref="staging")
        self.assertEqual(
            baseline_source_overlay_authorization(staging, {}, entry, merged_head, entry["expected_base_sha"]),
            [],
        )
        other = SimpleNamespace(head_ref="unreviewed", base_ref="staging")
        self.assertIn(
            "not authorized",
            baseline_source_overlay_authorization(other, {}, entry, merged_head, entry["expected_base_sha"])[0],
        )


if __name__ == "__main__":
    unittest.main()
