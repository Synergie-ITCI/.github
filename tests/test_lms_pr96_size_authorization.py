"""Keep LMS PR #96's temporary size allowance bound to one reviewed head."""

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

from baseline_authorization import schema_errors


class LmsPr96SizeAuthorizationTests(unittest.TestCase):
    def test_exact_pr_head_base_and_diff_size_only(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        schema = json.loads((ROOT / "schemas/one-time-baseline.schema.json").read_text())
        entries = [
            entry for entry in policy["one_time_baseline_alignments"]
            if entry.get("repository") == "Synergie-ITCI/synergielms.com"
            and entry.get("pr_number") == 96
        ]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(schema_errors(entry, schema), [])
        self.assertEqual(entry["repository_id"], 1118680062)
        self.assertEqual(entry["expected_head_sha"], "cdaf4858f1faff6955e41431cbcd813cbf43236f")
        self.assertEqual(entry["expected_base_sha"], "9d48cdec23574e9c7b8c3f0a957f2d735812a46b")
        self.assertEqual((entry["head_ref"], entry["base_ref"]), ("reconcile/pr95-staging-history", "development"))
        self.assertEqual((entry["minimum_changed_files"], entry["allowed_changed_files"]), (168, 168))
        self.assertEqual(entry["allowed_effective_additions"], 15657)
        self.assertEqual(entry["relaxations"], ["diff_size"])
        self.assertEqual(entry["required_pr_body_marker"], "LMS-PR96-SIZE-3e4eb547")
        self.assertEqual(entry["expires_after"], "2026-11-27T18:01:58Z")


if __name__ == "__main__":
    unittest.main()
