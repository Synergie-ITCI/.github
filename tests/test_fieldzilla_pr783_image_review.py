"""Bind FieldZilla's production readback image review to its exact PR source."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FieldzillaPr783ImageReviewTests(unittest.TestCase):
    def test_exact_sql_free_source_and_scope(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        records = [
            row for row in policy["one_time_baseline_alignments"]
            if row.get("repository_id") == 1315697868 and row.get("pr_number") == 783
        ]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["repository"], "Synergie-ITCI/programme-management-platform")
        self.assertEqual(record["head_ref"], "fix/mobile-release-production-readback")
        self.assertEqual(record["base_ref"], "main")
        self.assertEqual(
            (record["expected_head_sha"], record["expected_base_sha"]),
            (
                "2817ab3ad079e7795ca723e9cd6fbbc705f2bc8f",
                "79b9676aac733a9a78a6901af48e76fa93688828",
            ),
        )
        self.assertEqual(record["allowed_changed_files"], 2)
        self.assertEqual(record["allowed_effective_additions"], 227)
        self.assertEqual(record["relaxations"], [])
        self.assertTrue(record["enabled"])


if __name__ == "__main__":
    unittest.main()
