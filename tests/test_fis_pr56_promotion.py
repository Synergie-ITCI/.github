"""Bind FIS's follow-on promotion and QA caller to reviewed content."""

import json
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
ENTRIES = {
    row.get("pr_number"): row
    for row in POLICY["governance"]["critical_infrastructure_paths"]
    if row.get("repository") == "Synergie-ITCI/fis.synergielms.com"
    and row.get("pr_number") in (56, 57)
}


class FisPr56PromotionTests(TestCase):
    def test_caller_is_exact(self):
        entry = ENTRIES[57]
        self.assertEqual(entry["expected_base_sha"],
                         "f03d5ddd8d96280bcf4bd6b6da05b471caee5a1c")
        self.assertEqual(entry["expected_head_sha"],
                         "49af9b879c1a469718aa0da48ddd4d7f88fa08d6")
        self.assertEqual(entry["paths"], [".github/workflows/pr-qa.yml"])
        self.assertEqual(entry["file_sha256"][entry["paths"][0]],
                         "7798b3155b4735c649acde3c6acdf114246ee95ae9304decda50c9080fbb59dc")

    def test_promotion_preserves_all_eleven_reviewed_files(self):
        entry = ENTRIES[56]
        original = next(
            row for row in POLICY["governance"]["critical_infrastructure_paths"]
            if row.get("repository") == entry["repository"]
            and row.get("pr_number") == 55
        )
        self.assertEqual(entry["expected_base_sha"],
                         "80af625e96b515be7b134025934c9e2b581620f3")
        self.assertEqual(entry["protected_staging_ancestor_sha"],
                         "f03d5ddd8d96280bcf4bd6b6da05b471caee5a1c")
        self.assertNotIn("expected_head_sha", entry)
        self.assertEqual(set(entry["paths"]), set(entry["file_sha256"]))
        self.assertEqual(len(entry["paths"]), 11)
        self.assertEqual(entry["required_controls"], original["required_controls"])
        self.assertEqual(entry["required_reviewers"], original["required_reviewers"])
        for path in entry["paths"]:
            expected = (ENTRIES[57]["file_sha256"][path]
                        if path == ".github/workflows/pr-qa.yml"
                        else original["file_sha256"][path])
            self.assertEqual(entry["file_sha256"][path], expected)
