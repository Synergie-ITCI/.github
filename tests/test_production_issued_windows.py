import base64
import copy
import hashlib
import json
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "scripts/fieldzilla-production")
)
from issued_windows import verify_issued_windows, verify_pr798_inherited_migration


class IssuedWindowTests(unittest.TestCase):
    def test_pr808_sql_free_binding_keeps_current_database(self):
        from issued_windows import (
            SQL_FREE_PR808_BASE, SQL_FREE_PR808_SOURCE,
            SQL_FREE_PR802_REVISIONS, is_sql_free_update,
        )

        manifest = {
            "scope": "production", "operation": "rollout", "promotion_pr": 808,
            "base_sha": SQL_FREE_PR808_BASE,
            "application": {"source_sha": SQL_FREE_PR808_SOURCE},
            "review_authorizations": {"sql": None},
            "database": {
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": SQL_FREE_PR802_REVISIONS,
                "after": SQL_FREE_PR802_REVISIONS,
            },
        }
        self.assertTrue(is_sql_free_update(manifest))
        for field, replacement in (("promotion_pr", 809), ("base_sha", "0" * 40)):
            changed = copy.deepcopy(manifest)
            changed[field] = replacement
            self.assertFalse(is_sql_free_update(changed))
        changed = copy.deepcopy(manifest)
        changed["database"]["after"] = ["20260909_0041", "20261117_0076"]
        self.assertFalse(is_sql_free_update(changed))

    def test_pr806_sql_free_binding_keeps_current_database(self):
        from issued_windows import (
            SQL_FREE_PR806_BASE, SQL_FREE_PR806_SOURCE,
            SQL_FREE_PR802_REVISIONS, is_sql_free_update,
        )

        manifest = {
            "scope": "production", "operation": "rollout", "promotion_pr": 806,
            "base_sha": SQL_FREE_PR806_BASE,
            "application": {"source_sha": SQL_FREE_PR806_SOURCE},
            "review_authorizations": {"sql": None},
            "database": {
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": SQL_FREE_PR802_REVISIONS,
                "after": SQL_FREE_PR802_REVISIONS,
            },
        }
        self.assertTrue(is_sql_free_update(manifest))
        changed = copy.deepcopy(manifest)
        changed["application"]["source_sha"] = "0" * 40
        self.assertFalse(is_sql_free_update(changed))
        changed = copy.deepcopy(manifest)
        changed["database"]["after"] = ["20260909_0041", "20261117_0076"]
        self.assertFalse(is_sql_free_update(changed))

    def test_pr804_sql_free_binding_keeps_current_database(self):
        from issued_windows import (
            SQL_FREE_PR804_BASE, SQL_FREE_PR804_SOURCE,
            SQL_FREE_PR802_REVISIONS, is_sql_free_update,
        )

        manifest = {
            "scope": "production", "operation": "rollout", "promotion_pr": 804,
            "base_sha": SQL_FREE_PR804_BASE,
            "application": {"source_sha": SQL_FREE_PR804_SOURCE},
            "review_authorizations": {"sql": None},
            "database": {
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": SQL_FREE_PR802_REVISIONS,
                "after": SQL_FREE_PR802_REVISIONS,
            },
        }
        self.assertTrue(is_sql_free_update(manifest))
        changed = copy.deepcopy(manifest)
        changed["application"]["source_sha"] = "0" * 40
        self.assertFalse(is_sql_free_update(changed))

    def test_pr802_sql_free_binding_keeps_current_database_and_rejects_other_sources(self):
        from issued_windows import (
            SQL_FREE_PR802_BASE, SQL_FREE_PR802_REVISIONS,
            SQL_FREE_PR802_SOURCE, is_sql_free_update,
        )

        manifest = {
            "scope": "production", "operation": "rollout", "promotion_pr": 802,
            "base_sha": SQL_FREE_PR802_BASE,
            "application": {"source_sha": SQL_FREE_PR802_SOURCE},
            "review_authorizations": {"sql": None},
            "database": {
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": SQL_FREE_PR802_REVISIONS,
                "after": SQL_FREE_PR802_REVISIONS,
            },
        }
        self.assertTrue(is_sql_free_update(manifest))
        for field, replacement in (
            ("promotion_pr", 803), ("base_sha", "0" * 40),
            ("operation", "rehearsal"),
        ):
            altered = copy.deepcopy(manifest)
            altered[field] = replacement
            self.assertFalse(is_sql_free_update(altered))
        altered = copy.deepcopy(manifest)
        altered["database"]["after"] = ["20260909_0041", "20261117_0076"]
        self.assertFalse(is_sql_free_update(altered))

    def test_pr798_inherited_bridge_requires_exact_merges_and_reviewed_bytes(self):
        from issued_windows import (
            PR794_MERGE, PR794_BASE, PR794_HEAD, PR794_TREE,
            PR796_MERGE, PR796_HEAD, PR796_TREE, PR797_HEAD, PR797_TREE,
            PR798_BASE, PR798_SOURCE, PR798_MERGE, PR798_TREE,
            PR798_REVIEWED_FILES, PR798_SQL_REVIEW,
        )
        manifest = {
            "scope": "production", "promotion_pr": 798,
            "application": {"source_sha": PR798_SOURCE}, "base_sha": PR798_BASE,
            "review_authorizations": {"sql": PR798_SQL_REVIEW},
            "database": {
                "name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                "before": ["20260909_0041", "20261117_0076"],
                "after": ["20260909_0041", "20261117_0077"],
            },
        }
        commits = {
            PR794_MERGE: ([PR794_BASE, PR794_HEAD], PR794_TREE),
            PR796_MERGE: ([PR794_MERGE, PR796_HEAD], PR796_TREE),
            PR798_BASE: ([PR796_MERGE, PR797_HEAD], PR797_TREE),
            PR798_MERGE: ([PR798_BASE, PR798_SOURCE], PR798_TREE),
            PR794_HEAD: ([], PR794_TREE), PR796_HEAD: ([], PR796_TREE),
            PR797_HEAD: ([], PR797_TREE), PR798_SOURCE: ([], PR798_TREE),
        }

        def api(path):
            if "/git/commits/" in path:
                sha = path.rsplit("/", 1)[-1]
                parents, tree = commits[sha]
                return {
                    "sha": sha, "parents": [{"sha": parent} for parent in parents],
                    "tree": {"sha": tree}, "verification": {"verified": True},
                }
            if "/contents/" in path:
                name = path.split("/contents/", 1)[1].split("?", 1)[0]
                return {
                    "type": "file", "encoding": "base64",
                    "content": base64.b64encode(name.encode()).decode(),
                }
            if "/pulls/798/files?" in path:
                return [{"filename": f"apps/mobile/file-{n}"} for n in range(37)]
            raise AssertionError(path)

        hashes = {path: hashlib.sha256(path.encode()).hexdigest() for path in PR798_REVIEWED_FILES}
        with patch("issued_windows.PR798_REVIEWED_FILES", hashes):
            verify_pr798_inherited_migration(manifest, api=api)
            commits[PR796_MERGE] = ([PR794_MERGE, PR797_HEAD], PR796_TREE)
            with self.assertRaisesRegex(ValueError, "ancestry"):
                verify_pr798_inherited_migration(manifest, api=api)
            commits[PR796_MERGE] = ([PR794_MERGE, PR796_HEAD], PR796_TREE)
            hashes[next(iter(hashes))] = "0" * 64
            with self.assertRaisesRegex(ValueError, "bridge bytes"):
                verify_pr798_inherited_migration(manifest, api=api)

    def setUp(self):
        self.now = datetime(2026, 11, 10, 12, tzinfo=UTC)
        self.manifest = {
            "promotion_pr": 712,
            "application": {"source_sha": "a" * 40},
            "base_sha": "b" * 40,
            "expires_at": "2026-11-10T13:00:00Z",
            "review_authorizations": {
                "baseline": "11111111-1111-4111-8111-111111111111",
                "sql": "22222222-2222-4222-8222-222222222222",
            },
        }
        binding = {
            "repository": "Synergie-ITCI/programme-management-platform",
            "repository_id": 1315697868,
            "pr_number": 712,
            "base_ref": "main",
            "head_ref": "release/example",
            "expected_head_sha": "a" * 40,
            "expected_base_sha": "b" * 40,
            "issued_at": "2026-11-10T11:00:00Z",
            "purpose": "Synthetic execution-window fixture",
        }
        self.baseline = {
            **binding,
            "authorization_id": self.manifest["review_authorizations"]["baseline"],
            "enabled": True,
            "expires_after": "2026-11-10T14:00:00Z",
            "allowed_effective_additions": 0,
            "allowed_changed_files": 0,
            "relaxations": [],
        }
        self.sql = {
            **binding,
            "authorization_id": self.manifest["review_authorizations"]["sql"],
            "expires_at": "2026-11-10T14:00:00Z",
            "migration_path": "apps/api/alembic/sql/synthetic.sql",
            "migration_sha256": "f" * 64,
            "delete_fingerprints": [],
            "approved_reviewer": {"login": "synthetic-reviewer", "id": 1},
        }
        self.changed_files = [{"filename": "apps/api/app/modules/submissions/service.py"}]

    def api(self, path):
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "c" * 40}}
        if "/contents/apps/api/alembic/versions/20261113_0074_tenant_bootstrap_owner_rls.py?ref=" in path:
            return {"type": "file", "encoding": "base64", "content": base64.b64encode(b"reviewed migration").decode()}
        if f"/pulls/{self.manifest['promotion_pr']}/files?" in path:
            return self.changed_files
        self.assertTrue(path.endswith("?ref=" + "c" * 40))
        payload = (
            {"version": 1, "one_time_baseline_alignments": [self.baseline]}
            if "/pr-qa-policy.json" in path
            else [self.sql]
        )
        return {
            "type": "file",
            "encoding": "base64",
            "content": base64.b64encode(json.dumps(payload).encode()).decode(),
        }

    def verify(self):
        verify_issued_windows(
            self.manifest,
            api=self.api,
            now=self.now,
            activated_policies={
                "policy/pr-qa-policy.json": {
                    "version": 1,
                    "one_time_baseline_alignments": [self.baseline],
                },
                "policy/audited-migration-authorizations.json": [self.sql],
            },
        )

    def test_exact_live_records_cover_the_entire_execution_window(self):
        self.verify()

    def test_review_data_can_advance_without_repinning_the_executor_caller(self):
        self.manifest["central_tag"] = "pr-qa-v1-rc232"
        self.manifest["central_sha"] = "d" * 40
        self.manifest["qa_evidence"] = {
            "policy_release": "pr-qa-v1-rc233",
            "policy_sha": "e" * 40,
        }
        self.verify()

    def test_unknown_activated_review_contract_is_rejected(self):
        self.baseline["unrecognized_execution_constraint"] = "not supported"
        with self.assertRaisesRegex(ValueError, "schema"):
            self.verify()

    def test_old_green_qa_cannot_extend_expired_or_disabled_authority(self):
        for target, key, value in (
            (self.baseline, "expires_after", "2026-11-10T11:30:00Z"),
            (self.sql, "expires_at", "2026-11-10T12:30:00Z"),
            (self.baseline, "enabled", False),
            (self.baseline, "expected_head_sha", "d" * 40),
            (self.sql, "expected_base_sha", "d" * 40),
            (self.sql, "authorization_id", "33333333-3333-4333-8333-333333333333"),
        ):
            with self.subTest(key=key, value=value):
                original = copy.deepcopy(target[key])
                target[key] = value
                try:
                    with self.assertRaises(ValueError):
                        self.verify()
                finally:
                    target[key] = original

    def test_missing_or_substituted_review_identity_cannot_enter(self):
        for identities in (
            {},
            {"baseline": self.baseline["authorization_id"]},
            {"baseline": "not-a-uuid", "sql": self.sql["authorization_id"]},
        ):
            self.manifest["review_authorizations"] = identities
            with self.assertRaises(ValueError):
                self.verify()

    def test_main_only_issuance_cannot_extend_an_immutable_release(self):
        old = copy.deepcopy(self.baseline)
        self.baseline["expires_after"] = "2026-11-10T15:00:00Z"
        with self.assertRaisesRegex(ValueError, "immutable QA release"):
            verify_issued_windows(
                self.manifest,
                api=self.api,
                now=self.now,
                activated_policies={
                    "policy/pr-qa-policy.json": {
                        "version": 1,
                        "one_time_baseline_alignments": [old],
                    }
                },
            )

    def test_image_only_request_can_omit_sql_review_for_sql_free_pr(self):
        self.manifest["scope"] = "production-images"
        self.manifest["review_authorizations"]["sql"] = None
        self.verify()

    def test_only_exact_pr772_source_and_reviewed_db_transition_can_omit_sql(self):
        from issued_windows import SQL_FREE_PRODUCTION_BASE, SQL_FREE_PRODUCTION_SOURCE

        self.manifest.update(
            scope="production", promotion_pr=772, base_sha=SQL_FREE_PRODUCTION_BASE,
            database={"before": ["20260909_0041", "20261109_0073"],
                      "after": ["20260909_0041", "20261113_0074"]},
        )
        self.manifest["application"]["source_sha"] = SQL_FREE_PRODUCTION_SOURCE
        self.manifest["review_authorizations"]["sql"] = None
        self.baseline.update(
            pr_number=772, expected_head_sha=SQL_FREE_PRODUCTION_SOURCE,
            expected_base_sha=SQL_FREE_PRODUCTION_BASE,
        )
        with patch("issued_windows.SQL_FREE_PRODUCTION_MIGRATION_SHA256", hashlib.sha256(b"reviewed migration").hexdigest()):
            self.verify()
            for key, replacement in (
                ("promotion_pr", 773), ("base_sha", "d" * 40),
                ("database", {"before": ["20260909_0041", "20261109_0073"], "after": ["20260909_0041", "20261109_0073"]}),
            ):
                with self.subTest(key=key):
                    old = self.manifest[key]
                    self.manifest[key] = replacement
                    with self.assertRaises(ValueError):
                        self.verify()
                    self.manifest[key] = old
            self.changed_files = [{"filename": "apps/api/alembic/versions/new.py"}]
            with self.assertRaisesRegex(ValueError, "SQL or migration"):
                self.verify()

    def test_exact_pr780_current_database_can_omit_migration(self):
        from issued_windows import SQL_FREE_UPDATE_BASE, SQL_FREE_UPDATE_REVISIONS, SQL_FREE_UPDATE_SOURCE

        self.manifest.update(
            scope="production", operation="rollout", promotion_pr=780,
            base_sha=SQL_FREE_UPDATE_BASE,
            database={"name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                      "before": SQL_FREE_UPDATE_REVISIONS, "after": SQL_FREE_UPDATE_REVISIONS},
        )
        self.manifest["application"]["source_sha"] = SQL_FREE_UPDATE_SOURCE
        self.manifest["review_authorizations"]["sql"] = None
        self.baseline.update(
            pr_number=780, expected_head_sha=SQL_FREE_UPDATE_SOURCE,
            expected_base_sha=SQL_FREE_UPDATE_BASE,
        )
        self.verify()
        for key, invalid in (
            ("promotion_pr", 781), ("base_sha", "d" * 40),
            ("database", {"name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                          "before": SQL_FREE_UPDATE_REVISIONS, "after": ["20260909_0041", "20261109_0073"]}),
        ):
            with self.subTest(key=key):
                old = self.manifest[key]
                self.manifest[key] = invalid
                with self.assertRaises(ValueError):
                    self.verify()
                self.manifest[key] = old
        self.changed_files = [{"filename": "apps/api/alembic/versions/new.py"}]
        with self.assertRaisesRegex(ValueError, "SQL or migration"):
            self.verify()

    def test_exact_pr783_current_database_can_omit_migration(self):
        from issued_windows import SQL_FREE_PR783_BASE, SQL_FREE_PR783_SOURCE, SQL_FREE_UPDATE_REVISIONS

        self.manifest.update(
            scope="production", operation="rollout", promotion_pr=783,
            base_sha=SQL_FREE_PR783_BASE,
            database={"name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                      "before": SQL_FREE_UPDATE_REVISIONS, "after": SQL_FREE_UPDATE_REVISIONS},
        )
        self.manifest["application"]["source_sha"] = SQL_FREE_PR783_SOURCE
        self.manifest["review_authorizations"]["sql"] = None
        self.baseline.update(
            pr_number=783, expected_head_sha=SQL_FREE_PR783_SOURCE,
            expected_base_sha=SQL_FREE_PR783_BASE,
        )
        self.verify()
        for key, invalid in (
            ("promotion_pr", 784), ("base_sha", "d" * 40),
            ("database", {"name": "fieldzilla_production", "role": "pmp_fieldzilla_prod_migrator",
                          "before": SQL_FREE_UPDATE_REVISIONS, "after": ["20260909_0041", "20261109_0073"]}),
        ):
            with self.subTest(key=key):
                old = self.manifest[key]
                self.manifest[key] = invalid
                with self.assertRaises(ValueError):
                    self.verify()
                self.manifest[key] = old
        self.changed_files = [{"filename": "apps/api/alembic/versions/new.py"}]
        with self.assertRaisesRegex(ValueError, "SQL or migration"):
            self.verify()

    def test_sql_review_cannot_be_omitted_for_changed_or_renamed_sql(self):
        self.manifest["scope"] = "production-images"
        self.manifest["review_authorizations"]["sql"] = None
        for row in (
            {"filename": "apps/api/alembic/sql/changed.sql"},
            {"filename": "apps/api/app/service.py", "previous_filename": "old/query.sql"},
            {"filename": "apps/api/alembic/versions/new.py"},
        ):
            self.changed_files = [row]
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "SQL or migration"):
                self.verify()

    def test_sql_review_omission_fails_closed_outside_images_and_without_file_evidence(self):
        self.manifest["review_authorizations"]["sql"] = None
        with self.assertRaisesRegex(ValueError, "Only image publication or the exact reviewed rollout"):
            self.verify()
        self.manifest["scope"] = "production-images"
        for rows in (None, []):
            self.changed_files = rows
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, "changed-file evidence"):
                self.verify()
