import base64
import copy
import json
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

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

    def api(self, path):
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "c" * 40}}
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
