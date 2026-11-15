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
from issued_windows import verify_issued_windows


class IssuedWindowTests(unittest.TestCase):
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
