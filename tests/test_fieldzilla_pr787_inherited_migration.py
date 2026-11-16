"""Exact inherited migration proof for the reviewed PR #787 caller."""

import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/fieldzilla-production"))
from issued_windows import (
    PR786_BASE, PR786_HEAD, PR786_TREE, PR787_BASE, PR787_FILES,
    PR787_MIGRATION, PR787_SOURCE, verify_pr787_inherited_migration,
)

REPO = "Synergie-ITCI/programme-management-platform"


class InheritedMigrationTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "scope": "production", "promotion_pr": 787,
            "application": {"source_sha": PR787_SOURCE}, "base_sha": PR787_BASE,
            "review_authorizations": {"sql": "407d605f-815b-4516-b714-5b72bf6c1422"},
            "database": {
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261113_0074"],
                "after": ["20260909_0041", "20261116_0075"],
            },
        }
        self.migration = b"reviewed migration fixture"
        self.base = {
            "sha": PR787_BASE, "parents": [{"sha": PR786_BASE}, {"sha": PR786_HEAD}],
            "tree": {"sha": PR786_TREE}, "verification": {"verified": True},
        }
        self.original = {"tree": {"sha": PR786_TREE}}
        self.source = {"sha": PR787_SOURCE, "parents": [{"sha": PR787_BASE}]}
        self.files = [{"filename": path} for path in sorted(PR787_FILES)]

    def api(self, path):
        if path == f"repos/{REPO}/git/commits/{PR787_BASE}":
            return self.base
        if path == f"repos/{REPO}/git/commits/{PR786_HEAD}":
            return self.original
        if path == f"repos/{REPO}/git/commits/{PR787_SOURCE}":
            return self.source
        if path == f"repos/{REPO}/contents/{PR787_MIGRATION}?ref={PR787_SOURCE}":
            return {"type": "file", "encoding": "base64", "content": base64.b64encode(self.migration).decode()}
        if path == f"repos/{REPO}/pulls/787/files?per_page=100&page=1":
            return self.files
        raise AssertionError(path)

    def test_exact_inherited_migration_passes(self):
        with patch("issued_windows.PR787_MIGRATION_SHA256", hashlib.sha256(self.migration).hexdigest()):
            verify_pr787_inherited_migration(self.manifest, api=self.api)

    def test_source_db_ancestry_and_file_drift_fail(self):
        mutations = [
            (self.manifest, "base_sha", "a" * 40),
            (self.manifest["database"], "after", ["20260909_0041", "20261113_0074"]),
            (self.base, "parents", [{"sha": PR786_HEAD}, {"sha": PR786_BASE}]),
            (self.base["tree"], "sha", "b" * 40),
            (self.source, "parents", [{"sha": "c" * 40}]),
            (self.files[0], "filename", "apps/api/alembic/versions/other.py"),
        ]
        for target, key, changed in mutations:
            old = copy.deepcopy(target[key])
            target[key] = changed
            with patch("issued_windows.PR787_MIGRATION_SHA256", hashlib.sha256(self.migration).hexdigest()):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    verify_pr787_inherited_migration(self.manifest, api=self.api)
            target[key] = old

    def test_changed_migration_bytes_fail(self):
        with self.assertRaises(ValueError):
            verify_pr787_inherited_migration(self.manifest, api=self.api)

    def test_exact_image_review_record_has_no_relaxations(self):
        policy = json.loads((Path(__file__).resolve().parents[1] / "policy/pr-qa-policy.json").read_text())
        rows = [row for row in policy["one_time_baseline_alignments"] if row.get("pr_number") == 787]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["expected_head_sha"], PR787_SOURCE)
        self.assertEqual(row["expected_base_sha"], PR787_BASE)
        self.assertEqual((row["allowed_changed_files"], row["allowed_effective_additions"]), (3, 29))
        self.assertEqual(row["relaxations"], [])


if __name__ == "__main__":
    unittest.main()
