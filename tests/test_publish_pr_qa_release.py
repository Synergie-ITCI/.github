"""Fail-closed checks for the single-command exact-tag release helper."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
release = SourceFileLoader(
    "publish_pr_qa_release", str(ROOT / "scripts/publish-pr-qa-release")
).load_module()


def ruleset(*, organization: bool = False) -> dict:
    conditions = {"ref_name": {"include": ["refs/tags/pr-qa-v1-rc192"], "exclude": []}}
    if organization:
        conditions["repository_name"] = {"include": [".github"], "exclude": []}
    return {
        "id": 42,
        "target": "tag",
        "enforcement": "active",
        "conditions": conditions,
        "bypass_actors": [],
        "rules": [{"type": "update"}, {"type": "deletion"}],
        "updated_at": "2026-10-19T10:39:14.856+05:30",
    }


class PublishReleaseTests(unittest.TestCase):
    def test_exact_ruleset_and_annotation(self) -> None:
        self.assertEqual(
            release.validate_ruleset("pr-qa-v1-rc192", 42, ruleset(organization=True), ruleset()),
            "2026-10-19T10:39:14.856+05:30",
        )
        message = release.annotation("pr-qa-v1-rc192", "a" * 40, 42, "raw timestamp", 123)
        header, payload = message.split("\n", 1)
        self.assertEqual(header, release.EVIDENCE_HEADER)
        self.assertEqual(json.loads(payload), {
            "release": "pr-qa-v1-rc192", "commit": "a" * 40,
            "ruleset_id": 42, "ruleset_updated_at": "raw timestamp",
            "bypass_actors": [], "protection_mode": "legacy_exact",
            "release_workflow_run_id": 123,
        })

    def test_ruleset_security_failures(self) -> None:
        for field, value in (
            ("id", 43), ("target", "branch"), ("enforcement", "disabled"),
            ("bypass_actors", [{"actor_id": 1}]),
            ("rules", [{"type": "update"}]),
            ("rules", [{"type": "update"}, {"type": "deletion"}, {"type": "creation"}]),
            ("updated_at", "different"),
        ):
            with self.subTest(field=field, value=value):
                org, repo = ruleset(organization=True), ruleset()
                repo[field] = value
                with self.assertRaises(ValueError):
                    release.validate_ruleset("pr-qa-v1-rc192", 42, org, repo)
        for field, value in (
            ("repository_name", {"include": ["*"], "exclude": []}),
            ("ref_name", {"include": ["refs/tags/pr-qa-v1-rc*"], "exclude": []}),
        ):
            with self.subTest(field=field):
                org = ruleset(organization=True)
                org["conditions"][field] = value
                with self.assertRaises(ValueError):
                    release.validate_ruleset("pr-qa-v1-rc192", 42, org, ruleset())

    def test_next_release_rejects_missing_history(self) -> None:
        self.assertEqual(release.next_release([
            {"ref": "refs/tags/pr-qa-v1-rc190"},
            {"ref": "refs/tags/pr-qa-v1-rc191"},
        ]), "pr-qa-v1-rc192")
        with self.assertRaises(ValueError):
            release.next_release([])

    def test_provenance_run_identity_and_ambiguity(self) -> None:
        started = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
        valid = {
            "id": 123, "display_title": f"PR-QA release pr-qa-v1-rc192 @ {'a' * 40}",
            "head_sha": "a" * 40, "event": "workflow_dispatch",
            "actor": {"login": "SaurabhVermaIN"}, "created_at": "2026-10-19T12:00:01Z",
        }
        self.assertEqual(release.matching_run([valid], "pr-qa-v1-rc192", "a" * 40,
                                              "SaurabhVermaIN", started)["id"], 123)
        for change in ({"head_sha": "b" * 40}, {"event": "push"},
                       {"actor": {"login": "other"}}, {"created_at": "2026-10-19T11:59:59Z"}):
            with self.subTest(change=change):
                self.assertIsNone(release.matching_run([{**valid, **change}],
                                                        "pr-qa-v1-rc192", "a" * 40,
                                                        "SaurabhVermaIN", started))
        with self.assertRaises(ValueError):
            release.matching_run([valid, {**valid, "id": 124}], "pr-qa-v1-rc192",
                                 "a" * 40, "SaurabhVermaIN", started)


if __name__ == "__main__":
    unittest.main()
