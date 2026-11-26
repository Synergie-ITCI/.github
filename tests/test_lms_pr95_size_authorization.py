"""Keep LMS PR #95's temporary size allowance bound to one reviewed head."""

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

from baseline_authorization import schema_errors


class LmsPr95SizeAuthorizationTests(unittest.TestCase):
    def test_exact_pr_head_base_and_size_only(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        entries = [
            entry for entry in policy["one_time_baseline_alignments"]
            if entry.get("repository") == "Synergie-ITCI/synergielms.com"
            and entry.get("pr_number") == 95
        ]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(schema_errors(entry, schema), [])
        self.assertEqual(entry["repository_id"], 1118680062)
        self.assertEqual(entry["expected_head_sha"], "9c8821d28ef2869d75077d0041a352098798b529")
        self.assertEqual(entry["expected_base_sha"], "a5e13d18bbe66340366ac8d9d630f0bb1ab7ae72")
        self.assertEqual(
            (entry["head_ref"], entry["base_ref"]),
            ("fix/st-98-lms-part-1-changes", "development"),
        )
        self.assertEqual(
            (entry["minimum_changed_files"], entry["allowed_changed_files"]),
            (754, 754),
        )
        self.assertEqual(entry["allowed_effective_additions"], 47660)
        self.assertEqual(entry["relaxations"], ["changed_file_count", "diff_size"])
        self.assertEqual(entry["required_pr_body_marker"], "LMS-PR95-EXACT-SIZE-02bfe28f")
        self.assertEqual(entry["expires_after"], "2026-11-27T15:52:55Z")


if __name__ == "__main__":
    unittest.main()
