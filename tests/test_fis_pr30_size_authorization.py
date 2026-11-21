"""Keep FIS PR #30's temporary size authorization exact and narrow."""

import json
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parents[1] / "policy/pr-qa-policy.json"


class FisPr30SizeAuthorizationTests(unittest.TestCase):
    def test_exact_pr_and_only_diff_size_relaxed(self):
        policy = json.loads(POLICY.read_text())
        rows = [
            row for row in policy["one_time_baseline_alignments"]
            if row.get("repository") == "Synergie-ITCI/fis.synergielms.com"
            and row.get("pr_number") == 30
        ]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(row["enabled"])
        self.assertEqual(row["repository_id"], 1037338034)
        self.assertEqual(row["expected_head_sha"], "54f39fc0e294c23b6051d48241b88d6a5f8c05be")
        self.assertEqual(row["expected_base_sha"], "27204807a0f92ee0f2f56f0d3f769b603c75abf8")
        self.assertEqual((row["head_ref"], row["base_ref"]), ("staging", "main"))
        self.assertEqual((row["allowed_changed_files"], row["minimum_changed_files"]), (47, 47))
        self.assertEqual(row["allowed_effective_additions"], 13612)
        self.assertEqual(row["relaxations"], ["diff_size"])
        self.assertEqual(row["required_pr_body_marker"], "FIS-PR30-EXACT-HEAD-SIZE-c9acdbc1")
        self.assertEqual(row["expires_after"], "2026-11-22T06:52:05Z")
