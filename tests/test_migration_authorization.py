"""Adversarial checks of the governed SQL review boundary, without live mutation."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
import migration_authorization as approval
import pr_qa as engine
from adapters.base import PRContext


class MigrationAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.rel = "database/reviewed.sql"
        (self.repo / "database").mkdir()
        self.sql = b"CREATE TABLE example(id uuid);\n" + b"\n".join(
            f"DELETE FROM private.guard_{i} WHERE tenant_id = p_tenant AND id = p_id;".encode()
            for i in range(5)
        )
        (self.repo / self.rel).write_bytes(self.sql)
        self.now = datetime.now(timezone.utc)
        self.reviewer = {"login": "SaurabhVermaIN", "id": 52234089}
        self.auth = {
            "authorization_id": "00000000-0000-4000-8000-000000000134",
            "repository": "Synergie-ITCI/example",
            "repository_id": 77,
            "pr_number": 134,
            "head_ref": "feature/normalized",
            "base_ref": "development",
            "expected_head_sha": "a" * 40,
            "expected_base_sha": "b" * 40,
            "migration_path": self.rel,
            "migration_sha256": hashlib.sha256(self.sql).hexdigest(),
            "delete_fingerprints": self.fingerprints(self.sql),
            "approved_reviewer": self.reviewer,
            "issued_at": (self.now - timedelta(minutes=1)).isoformat(),
            "expires_at": (self.now + timedelta(hours=1)).isoformat(),
            "purpose": "Audited runtime erasure definitions",
        }
        self.live = {"number": 134, "state": "open", "merged": False, "draft": False}
        for side in ("head", "base"):
            self.live[side] = {
                "sha": self.auth[f"expected_{side}_sha"],
                "ref": self.auth[f"{side}_ref"],
                "repo": {"id": 77, "full_name": self.auth["repository"]},
            }
        self.policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        self.ctx = PRContext(
            repo=self.repo,
            config=copy.deepcopy(self.policy["defaults"]),
            policy=self.policy,
            changed_files=[self.rel],
            head_ref=self.auth["head_ref"],
            base_ref=self.auth["base_ref"],
            event={
                "repository": copy.deepcopy(self.live["base"]["repo"]),
                "pull_request": copy.deepcopy(self.live),
            },
        )
        self.records_path = self.repo / "authorizations.json"
        self.save()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(approval, "AUTH_PATH", self.records_path).start()
        mock.patch.dict(
            os.environ,
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_REPOSITORY": self.auth["repository"],
                "GITHUB_REPOSITORY_ID": "77",
                "GITHUB_REF": "refs/pull/134/merge",
                "GITHUB_WORKSPACE": str(self.repo),
                "GH_TOKEN": "fixture",
            },
            clear=True,
        ).start()
        self.http = mock.patch.object(
            approval, "read_live_pr", return_value=self.live
        ).start()
        self.git = mock.patch.object(
            approval, "git_output", side_effect=self.git_result
        ).start()

    @staticmethod
    def fingerprints(data):
        return [
            {
                "line": data[: m.start()].count(b"\n") + 1,
                "sha256": hashlib.sha256(m.group()).hexdigest(),
            }
            for m in approval.DELETE.finditer(data)
        ]

    def git_result(self, repo, *args):
        return (
            (self.auth["expected_head_sha"] + "\n").encode()
            if args[0] == "rev-parse"
            else self.sql
        )

    def save(self):
        self.records_path.write_text(json.dumps([self.auth]))

    def gate(self):
        return engine.gate_database_safety(self.ctx)[0]

    def test_exact_approval_and_rechecks_allow_only_the_reviewed_file(self):
        for _ in range(2):
            self.assertEqual(self.gate().status, "WARNING")
        self.assertEqual(self.http.call_count, 2)
        self.assertTrue(engine.context_cache(self.ctx)["audited_migration_used"])
        extra = "database/other.sql"
        (self.repo / extra).write_text("DELETE FROM another_table;")
        self.ctx.changed_files.append(extra)
        self.assertEqual(self.gate().status, "FAIL")
        self.assertIn(extra, self.gate().details)

    def test_unmatched_repo_pr_and_absent_authorizations_keep_ordinary_gate(self):
        for field, value in [
            ("GITHUB_REPOSITORY", "other/repo"),
            ("GITHUB_REF", "refs/pull/135/merge"),
        ]:
            with self.subTest(field=field), mock.patch.dict(os.environ, {field: value}):
                self.assertEqual(self.gate().status, "FAIL")
        self.records_path.write_text("[]")
        self.assertEqual(self.gate().status, "FAIL")
        self.assertEqual(self.policy["minimum_thresholds"]["max_additions"], 5000)
        self.assertEqual(self.policy["minimum_thresholds"]["max_changed_files"], 200)
        self.ctx.changed_files = []
        self.assertEqual(self.gate().status, "PASS")

    def test_all_live_binding_changes_and_stale_event_replay_fail(self):
        for field, value in [
            ("number", 135),
            ("number", True),
            ("state", "closed"),
            ("merged", True),
            ("merged", None),
            ("draft", True),
            ("head.sha", "c" * 40),
            ("base.sha", "d" * 40),
            ("head.ref", "feature/other"),
            ("base.ref", "main"),
            ("head.repo.id", 78),
            ("base.repo.id", 78),
            ("head.repo.full_name", "fork/repo"),
            ("base.repo.full_name", "other/repo"),
        ]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.live)
                parts = field.split(".")
                target = changed
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
                self.http.return_value = changed
                self.assertEqual(self.gate().status, "FAIL")
        self.http.return_value = self.live

    def test_live_api_unavailable_or_malformed_fails_closed(self):
        for value in [None, {}, [], {"number": 134}]:
            self.http.return_value = value
            self.assertEqual(self.gate().status, "FAIL")
        self.http.side_effect = ValueError("sensitive response must not escape")
        result = self.gate()
        self.assertEqual(result.status, "FAIL")
        self.assertNotIn("sensitive", str(result))

    def test_reviewer_schema_window_fingerprints_and_uuid_fail_closed(self):
        for field, value in [
            ("approved_reviewer", {"login": "other", "id": 52234089}),
            ("approved_reviewer", {"login": "SaurabhVermaIN", "id": 78}),
            ("issued_at", (self.now + timedelta(hours=1)).isoformat()),
            ("expires_at", (self.now - timedelta(seconds=1)).isoformat()),
            ("expires_at", (self.now + timedelta(hours=24)).isoformat()),
            ("issued_at", "2026-09-10T01:00:00"),
            ("expires_at", "invalid"),
            ("migration_sha256", "0" * 64),
            ("delete_fingerprints", []),
            ("authorization_id", "not-a-uuid"),
            ("unknown", True),
            ("repository_id", True),
            ("migration_path", "../outside.sql"),
        ]:
            with self.subTest(field=field):
                record = {**self.auth, field: value}
                self.records_path.write_text(json.dumps([record]))
                self.assertEqual(self.gate().status, "FAIL")
        self.records_path.write_text(json.dumps([self.auth, self.auth]))
        self.assertEqual(self.gate().status, "FAIL")

    def test_sql_changes_additional_delete_and_untracked_bytes_fail(self):
        for data in [
            self.sql + b"\n",
            self.sql + b"\nDELETE FROM other;",
            self.sql.replace(b"p_tenant", b"other"),
        ]:
            (self.repo / self.rel).write_bytes(data)
            self.assertEqual(self.gate().status, "FAIL")
        (self.repo / self.rel).write_bytes(self.sql)
        self.git.side_effect = lambda repo, *args: (
            b"c" * 40 if args[0] == "rev-parse" else self.sql
        )
        self.assertEqual(self.gate().status, "FAIL")
        self.git.side_effect = lambda repo, *args: (
            (self.auth["expected_head_sha"] + "\n").encode()
            if args[0] == "rev-parse"
            else b"different"
        )
        self.assertEqual(self.gate().status, "FAIL")

    def test_approved_deletes_do_not_mask_other_destructive_operations(self):
        for operation in [
            b"DROP TABLE other;",
            b"TRUNCATE other;",
            b"DROP DATABASE other;",
        ]:
            self.sql += b"\n" + operation
            (self.repo / self.rel).write_bytes(self.sql)
            self.auth["migration_sha256"] = hashlib.sha256(self.sql).hexdigest()
            self.save()
            self.assertEqual(self.gate().status, "FAIL")

    def test_event_and_execution_context_are_not_substitutes_for_live_identity(self):
        for key, value in [
            ("GITHUB_ACTIONS", "false"),
            ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ("GITHUB_REPOSITORY_ID", "78"),
            ("GITHUB_WORKSPACE", "/elsewhere"),
            ("GH_TOKEN", ""),
        ]:
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: value}):
                self.assertEqual(self.gate().status, "FAIL")
        for field in ("head", "base"):
            self.ctx.event["pull_request"][field]["sha"] = "f" * 40
            self.assertEqual(self.gate().status, "FAIL")
            self.ctx.event["pull_request"] = copy.deepcopy(self.live)

    def test_final_governance_rechecks_and_rejects_post_validation_merge(self):
        self.assertEqual(self.gate().status, "WARNING")
        self.http.return_value = {**self.live, "merged": True, "state": "closed"}
        with (
            mock.patch.object(engine, "run_if_enabled", return_value=[]),
            mock.patch.object(engine, "gate_release_drift", return_value=[]),
        ):
            result = engine.run_governance(self.ctx, [], mock.Mock())
        self.assertEqual(result[0].gate, "Migration Risk")
        self.assertEqual(result[0].status, "FAIL")

    def test_final_governance_rejects_expiry_and_repository_reviewer_override(self):
        self.assertEqual(self.gate().status, "WARNING")
        self.auth["expires_at"] = (self.now - timedelta(seconds=1)).isoformat()
        self.save()
        with (
            mock.patch.object(engine, "run_if_enabled", return_value=[]),
            mock.patch.object(engine, "gate_release_drift", return_value=[]),
        ):
            self.assertEqual(
                engine.run_governance(self.ctx, [], mock.Mock())[0].status, "FAIL"
            )
        self.auth["expires_at"] = (self.now + timedelta(hours=1)).isoformat()
        self.auth["approved_reviewer"] = {"login": "unapproved", "id": 78}
        self.ctx.config["governance"] = {
            "migration_sql_reviewers": [self.auth["approved_reviewer"]]
        }
        self.save()
        self.assertEqual(self.gate().status, "FAIL")

    def test_expiry_during_live_lookup_fails_closed(self):
        with mock.patch.object(approval, "datetime", wraps=datetime) as clock:
            clock.now.side_effect = [self.now, self.now + timedelta(hours=2)]
            self.assertEqual(self.gate().status, "FAIL")

    def test_cleanup_rejects_previously_approved_open_pr(self):
        self.assertEqual(self.gate().status, "WARNING")
        self.records_path.write_text("[]")
        self.assertEqual(self.gate().status, "FAIL")

    def test_symlink_and_changed_statement_line_are_rejected(self):
        file = self.repo / self.rel
        file.unlink()
        target = self.repo / "outside.sql"
        target.write_bytes(self.sql)
        file.symlink_to(target)
        self.assertEqual(self.gate().status, "FAIL")
        file.unlink()
        file.write_bytes(self.sql)
        self.auth["delete_fingerprints"][0]["line"] += 1
        self.save()
        self.assertEqual(self.gate().status, "FAIL")


class BundledMigrationAuthorizationTests(unittest.TestCase):
    def test_bundled_record_is_strict_and_defaults_stay_ordinary(self):
        records = approval.load_authorizations()
        self.assertLessEqual(len(records), 1)
        for record in records:
            self.assertEqual(record["pr_number"], 134)
            self.assertEqual(record["repository_id"], 1315697868)
            self.assertEqual(
                record["migration_sha256"],
                "56d29de95cd31ae88509757f414da89a679161761da07693605e0db1a631f773",
            )
            self.assertEqual(
                [item["line"] for item in record["delete_fingerprints"]],
                [375, 388, 389, 390, 391],
            )
            self.assertEqual(
                record["approved_reviewer"], {"login": "SaurabhVermaIN", "id": 52234089}
            )
        policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        self.assertNotIn("one_time_baseline_alignment", policy)
        for limits in (policy["minimum_thresholds"], policy["defaults"]["thresholds"]):
            self.assertEqual(
                (limits["max_additions"], limits["max_changed_files"]), (5000, 200)
            )
