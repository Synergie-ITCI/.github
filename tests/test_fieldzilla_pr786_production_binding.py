"""Pin the PR #786 production image and audited migration review records."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FieldzillaPr786ProductionBindingTests(unittest.TestCase):
    def test_exact_image_and_sql_review(self):
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        sql_records = json.loads((ROOT / "policy/audited-migration-authorizations.json").read_text())
        image = [r for r in policy["one_time_baseline_alignments"] if r.get("pr_number") == 786]
        sql = [r for r in sql_records if r.get("pr_number") == 786]
        self.assertEqual(len(image), 1)
        self.assertEqual(len(sql), 1)
        source = "2b0753f08aaabdacb780d1abd35fc2d5e80bc181"
        base = "576fba59c0d5958cb623351b29201b4d4aef589c"
        for record in (image[0], sql[0]):
            self.assertEqual(record["repository"], "Synergie-ITCI/programme-management-platform")
            self.assertEqual(record["repository_id"], 1315697868)
            self.assertEqual((record["expected_head_sha"], record["expected_base_sha"]), (source, base))
        self.assertTrue(image[0]["enabled"])
        self.assertEqual(image[0]["relaxations"], [])
        self.assertEqual(sql[0]["migration_path"], "apps/api/alembic/versions/20261116_0075_operational_role_permissions.py")
        self.assertEqual(sql[0]["migration_sha256"], "2432a1c42d5a8a65e4e5f67f1535450d77526edaa25c1bb2d96761daae967dc4")
        self.assertEqual(sql[0]["delete_fingerprints"], [
            {"line": 57, "sha256": "3032b0985c7678e126ba338a813e9853ba6d53a29354f2e68d6c778a6f47708c"},
            {"line": 154, "sha256": "dd9408b10f018bfa044a1659986303ebe9f583f36aea6db3de4ffe957cac774c"},
        ])


if __name__ == "__main__":
    unittest.main()
