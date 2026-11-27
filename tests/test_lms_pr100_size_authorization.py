"""Keep the LMS production promotion size allowance bound to exact content."""

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

from baseline_authorization import schema_errors


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
            "1aa7db5bbd642c075757c1323c30b5736a049a9dcfdd14cc7b9a0c5b171e4cd2",
        )
        self.assertEqual(entry["required_pr_body_marker"], "LMS-PR100-EXACT-PROMOTION-1aa7db5b")

    def test_workflow_overlay_is_exact_and_branch_scoped(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        entry = next(
            row for row in policy["one_time_baseline_alignments"]
            if row.get("repository") == "Synergie-ITCI/synergielms.com"
            and row.get("pr_number") == 101
            and row.get("required_pr_body_marker") == "LMS-PR100-EXACT-PROMOTION-1aa7db5b"
        )
        self.assertEqual(entry["promotion_scope"]["branches"], [{"head_ref": "staging", "base_ref": "main"}])
        overlay = entry["source_overlay"]
        self.assertEqual(overlay["approved_application_source_sha"], entry["expected_head_sha"])
        self.assertEqual(overlay["allowed_paths"], [".github/workflows/pr-qa.yml"])
        self.assertEqual(overlay["paths"], {
            ".github/workflows/pr-qa.yml": {
                "source": "present",
                "candidate": "reviewed_sha256",
                "candidate_sha256": "2fd3fecf3ddef641e6058f3df6974c4cdc85e0cafa6bb7b2c3bc01f78fa12193",
                "old_ref": "pr-qa-v1-rc434",
                "new_ref": "pr-qa-v1-rc440",
            }
        })


if __name__ == "__main__":
    unittest.main()
