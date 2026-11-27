"""Keep the LMS production promotion size allowance bound to exact content."""

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

from baseline_authorization import schema_errors
from pr_qa import baseline_source_overlay_authorization


class LmsPr100SizeAuthorizationTests(unittest.TestCase):
    def test_exact_promotion_and_size_only(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        entries = [
            entry for entry in policy["one_time_baseline_alignments"]
            if entry.get("repository") == "Synergie-ITCI/synergielms.com"
            and entry.get("pr_number") == 101
            and entry.get("promotion_scope", {}).get("branches") == [
                {"head_ref": "staging", "base_ref": "main"}
            ]
        ]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(schema_errors(entry, schema), [])
        self.assertEqual(entry["expected_head_sha"], "70f70f3e842ebea872704a265b1f6de9ae40cc63")
        self.assertEqual(entry["expected_base_sha"], "4c077a47868439d47d3cdf88cf883f58e9da1b1c")
        self.assertEqual((entry["minimum_changed_files"], entry["allowed_changed_files"]), (700, 700))
        self.assertEqual(entry["allowed_effective_additions"], 44935)
        self.assertEqual(entry["relaxations"], ["changed_file_count", "diff_size"])
        self.assertEqual(
            entry["promotion_scope"]["reviewed_patch_sha256"],
            "d9898235811b96ba1ccd68bd87d23fc21033d00c0f9392b1126e4d65b5d882f3",
        )
        self.assertEqual(entry["required_pr_body_marker"], "LMS-PR100-EXACT-PROMOTION-d9898235")

    def test_only_reviewed_branch_pair_can_use_promotion_sha(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        entry = next(
            row for row in policy["one_time_baseline_alignments"]
            if row.get("repository") == "Synergie-ITCI/synergielms.com"
            and row.get("pr_number") == 101
            and row.get("required_pr_body_marker") == "LMS-PR100-EXACT-PROMOTION-d9898235"
        )
        current_head = "ecf5f3e5dcbf246383a62f1dda4de82c88424a51"
        approved = SimpleNamespace(head_ref="staging", base_ref="main")
        self.assertEqual(
            baseline_source_overlay_authorization(approved, {}, entry, current_head, entry["expected_base_sha"]),
            [],
        )
        other = SimpleNamespace(head_ref="unreviewed", base_ref="main")
        self.assertIn(
            "not authorized",
            baseline_source_overlay_authorization(other, {}, entry, current_head, entry["expected_base_sha"])[0],
        )


if __name__ == "__main__":
    unittest.main()
