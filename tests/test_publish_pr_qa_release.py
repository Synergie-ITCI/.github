"""Fail-closed checks for the single-command exact-tag release helper."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
release = SourceFileLoader(
    "publish_pr_qa_release", str(ROOT / "scripts/publish-pr-qa-release")
).load_module()


def ruleset(*, organization: bool = False) -> dict:
    conditions = {"ref_name": {"include": ["refs/tags/pr-qa-v1-rc192"], "exclude": []}}
    if organization:
        conditions["repository_name"] = {"include": [".github"], "exclude": [], "protected": False}
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
        self.assertFalse(message.endswith("\n"))

    def test_complete_rc191_annotation_matches_published_tag(self) -> None:
        expected = (
            "SYNERGIE_PR_QA_RELEASE_EVIDENCE_V1\n"
            '{"release":"pr-qa-v1-rc191","commit":"186c1b10d20e249caf0c473f5d7239c31f4d3110",'
            '"ruleset_id":25373314,"ruleset_updated_at":"2026-10-19T10:39:14.856+05:30",'
            '"bypass_actors":[],"protection_mode":"legacy_exact","release_workflow_run_id":39204389576}'
        )
        self.assertEqual(release.annotation(
            "pr-qa-v1-rc191", "186c1b10d20e249caf0c473f5d7239c31f4d3110",
            25373314, "2026-10-19T10:39:14.856+05:30", 39204389576,
        ), expected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args: str) -> bytes:
                return subprocess.run(
                    ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
                    cwd=root, check=True, capture_output=True,
                ).stdout
            git("init", "-q")
            git("commit", "--allow-empty", "-qm", "base")
            (root / "message").write_text(expected, encoding="utf-8")
            git("tag", "-a", "--cleanup=verbatim", "candidate", "-F", "message")
            self.assertEqual(git("cat-file", "-p", "refs/tags/candidate").split(b"\n\n", 1)[1],
                             expected.encode("utf-8"))

    def test_ruleset_security_failures(self) -> None:
        for repository_name in (
            {"include": [".github"], "exclude": [], "protected": True},
            {"include": ["other"], "exclude": [], "protected": False},
            {"include": [".github"], "exclude": []},
        ):
            with self.subTest(repository_name=repository_name):
                org = ruleset(organization=True)
                org["conditions"]["repository_name"] = repository_name
                with self.assertRaisesRegex(ValueError, "scoped only to the central repository"):
                    release.validate_ruleset("pr-qa-v1-rc192", 42, org, ruleset())
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
            "path": ".github/workflows/pr-qa-release.yml", "run_attempt": 1,
            "actor": {"login": "SaurabhVermaIN"}, "created_at": "2026-10-19T12:00:01Z",
        }
        self.assertEqual(release.matching_run([valid], "pr-qa-v1-rc192", "a" * 40,
                                              "SaurabhVermaIN", started)["id"], 123)
        for change in ({"head_sha": "b" * 40}, {"event": "push"},
                       {"path": ".github/workflows/other.yml"}, {"run_attempt": 2},
                       {"display_title": "different release"},
                       {"actor": {"login": "other"}}, {"created_at": "2026-10-19T11:59:59Z"}):
            with self.subTest(change=change):
                self.assertIsNone(release.matching_run([{**valid, **change}],
                                                        "pr-qa-v1-rc192", "a" * 40,
                                                        "SaurabhVermaIN", started))
        with self.assertRaises(ValueError):
            release.matching_run([valid, {**valid, "id": 124}], "pr-qa-v1-rc192",
                                 "a" * 40, "SaurabhVermaIN", started)

    def test_delayed_provenance_visibility_and_failed_runs(self) -> None:
        started = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
        valid = {
            "id": 123, "display_title": f"PR-QA release pr-qa-v1-rc192 @ {'a' * 40}",
            "head_sha": "a" * 40, "event": "workflow_dispatch",
            "path": ".github/workflows/pr-qa-release.yml", "run_attempt": 1,
            "actor": {"login": "SaurabhVermaIN"}, "created_at": "2026-10-19T12:00:01Z",
        }
        responses = iter([
            {"workflow_runs": []}, {"workflow_runs": [valid]},
            {**valid, "status": "completed", "conclusion": "success"},
        ])
        pauses = []
        result = release.wait_for_provenance_run(
            "pr-qa-v1-rc192", "a" * 40, "SaurabhVermaIN", started,
            fetch=lambda _path: next(responses), pause=pauses.append, attempts=3,
        )
        self.assertEqual(result["id"], 123)
        self.assertEqual(pauses, [60])
        for conclusion in ("failure", "cancelled"):
            with self.subTest(conclusion=conclusion), self.assertRaises(ValueError):
                responses = iter([{"workflow_runs": [valid]},
                                  {**valid, "status": "completed", "conclusion": conclusion}])
                release.wait_for_provenance_run(
                    "pr-qa-v1-rc192", "a" * 40, "SaurabhVermaIN", started,
                    fetch=lambda _path: next(responses), pause=lambda _seconds: None, attempts=1,
                )

    def test_api_failure_and_ambiguous_dispatch_never_retry(self) -> None:
        started = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
        calls = []
        def unavailable(path: str) -> dict:
            calls.append(path)
            raise ValueError("API unavailable")
        with self.assertRaisesRegex(ValueError, "API unavailable"):
            release.wait_for_provenance_run(
                "pr-qa-v1-rc192", "a" * 40, "SaurabhVermaIN", started,
                fetch=unavailable, pause=lambda _seconds: self.fail("unexpected retry"),
            )
        self.assertEqual(len(calls), 1)
        with patch.object(release, "command", return_value=subprocess.CompletedProcess([], 1)) as run:
            with self.assertRaisesRegex(ValueError, "uncertain"):
                release.dispatch_provenance("pr-qa-v1-rc192", "a" * 40)
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
