from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PR_QA = ROOT / "pr-qa"
AI_REVIEW = PR_QA / "ai_review.py"
sys.path.insert(0, str(PR_QA))
SPEC = importlib.util.spec_from_file_location("ai_review", AI_REVIEW)
ai_review = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules["ai_review"] = ai_review
SPEC.loader.exec_module(ai_review)


class FakeGitHubClient:
    def __init__(self, files: list[dict], comments: list[dict] | None = None) -> None:
        self.files = files
        self.comments = comments or []
        self.created_reviews: list[dict] = []
        self.updated_comments: list[tuple[int, str]] = []
        self.deleted_comments: list[int] = []

    def list_pull_files(self, pr_number: int) -> list[dict]:
        return self.files

    def list_review_comments(self, pr_number: int) -> list[dict]:
        return self.comments

    def create_review(self, pr_number: int, comments: list[dict], body: str = "") -> dict:
        self.created_reviews.append({"pr_number": pr_number, "comments": comments, "body": body})
        return {"id": 1}

    def update_comment(self, comment_id: int, body: str) -> dict:
        self.updated_comments.append((comment_id, body))
        return {"id": comment_id}

    def delete_comment(self, comment_id: int) -> dict:
        self.deleted_comments.append(comment_id)
        return {}


class FakeProvider(ai_review.AIReviewProvider):
    def __init__(self, payload: dict, status: str = ai_review.COMPLETED) -> None:
        self.payload = payload
        self.status = status
        self.called = False

    def review(self, context: dict) -> ai_review.ProviderResult:
        self.called = True
        if self.status != ai_review.COMPLETED:
            return ai_review.ProviderResult(self.status, "provider unavailable", {})
        return ai_review.ProviderResult(ai_review.COMPLETED, "ok", self.payload)


class AIReviewServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ai-review-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def test_context_filters_non_reviewable_files_and_collects_changed_lines(self) -> None:
        context = ai_review.build_review_context(
            self.args(),
            self.event(),
            [
                {"filename": "src/app.py", "patch": "@@ -0,0 +1,2 @@\n+value = request.get('x')\n+print(value)"},
                {"filename": "node_modules/pkg/index.js", "patch": "@@ -0,0 +1,1 @@\n+module.exports = 1"},
                {"filename": "package-lock.json", "patch": "@@ -0,0 +1,1 @@\n+{}"},
                {"filename": "image.png", "patch": "@@ -0,0 +1,1 @@\n+binary"},
                {"filename": "tests/test_pr_qa_regressions.py", "patch": "@@ -0,0 +1,1 @@\n+TOKEN = 'fixture'"},
            ],
        )

        self.assertEqual([item["path"] for item in context["files"]], ["src/app.py"])
        self.assertEqual(context["reviewable_lines"]["src/app.py"], [1, 2])
        self.assertIn("package-lock.json", context["skipped_files"])

    def test_provider_findings_are_normalized_redacted_and_advisory_only(self) -> None:
        context = {
            "reviewable_lines": {"src/app.py": [1]},
        }
        findings = ai_review.normalize_provider_findings(
            {
                "findings": [
                    {
                        "path": "src/app.py",
                        "line": 1,
                        "severity": "HIGH",
                        "category": "Possible Bug",
                        "observation": "token='ghp_abcdefghijklmnopqrstuvwxyz123456' may be logged.",
                        "why_it_matters": "Credential exposure.",
                        "recommendation": "Avoid logging secrets.",
                        "stable_id": "log-secret",
                    },
                    {
                        "path": "src/app.py",
                        "line": 99,
                        "severity": "CRITICAL",
                        "category": "Possible Bug",
                        "observation": "Not on diff.",
                        "recommendation": "Skip.",
                    },
                ]
            },
            context,
            "codex",
            50,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertFalse(findings[0]["blocking"])
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", json.dumps(findings))
        self.assertIn("[REDACTED]", findings[0]["observation"])

    def test_execute_ai_review_publishes_ai_namespace_without_touching_qa_comments(self) -> None:
        event_path, qa_path = self.write_inputs("PASS")
        ai_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaa"
        client = FakeGitHubClient(
            files=[{"filename": "src/app.py", "patch": "@@ -0,0 +1,1 @@\n+return user.name"}],
            comments=[
                {
                    "id": 10,
                    "path": "src/app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": f"<!-- synergie-ai-review:inline-review fingerprint={ai_fingerprint} -->\nstale",
                },
                {
                    "id": 11,
                    "path": "src/app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": "<!-- synergie-pr-qa:inline-review fingerprint=bbbbbbbbbbbbbbbbbbbbbbbb -->\nqa",
                },
            ],
        )
        provider = FakeProvider(
            {
                "summary": "One possible bug.",
                "findings": [
                    {
                        "path": "src/app.py",
                        "line": 1,
                        "severity": "HIGH",
                        "category": "Possible Bug",
                        "observation": "user may be null before name access.",
                        "why_it_matters": "This can throw in production.",
                        "recommendation": "Guard user before reading name.",
                        "stable_id": "user-null-name",
                    }
                ],
            }
        )

        report = ai_review.execute_ai_review(self.args(event_path=event_path, qa_report_json=qa_path, publish_comments=True), client, provider)

        self.assertEqual(report["status"], ai_review.COMPLETED)
        self.assertEqual(client.deleted_comments, [10])
        self.assertEqual(len(client.created_reviews), 1)
        body = client.created_reviews[0]["comments"][0]["body"]
        self.assertIn("synergie-ai-review:inline-review", body)
        self.assertNotIn("synergie-pr-qa:inline-review", body)
        self.assertEqual(client.created_reviews[0]["body"], "Synergie AI Engineering Review findings.")

    def test_unavailable_provider_does_not_remove_existing_comments(self) -> None:
        event_path, qa_path = self.write_inputs("PASS")
        client = FakeGitHubClient(
            files=[{"filename": "src/app.py", "patch": "@@ -0,0 +1,1 @@\n+return user.name"}],
            comments=[
                {
                    "id": 10,
                    "path": "src/app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": "<!-- synergie-ai-review:inline-review fingerprint=aaaaaaaaaaaaaaaaaaaaaaaa -->\nstale",
                }
            ],
        )
        provider = FakeProvider({}, ai_review.UNAVAILABLE)

        report = ai_review.execute_ai_review(self.args(event_path=event_path, qa_report_json=qa_path, publish_comments=True), client, provider)

        self.assertEqual(report["status"], ai_review.UNAVAILABLE)
        self.assertFalse(client.deleted_comments)
        self.assertFalse(client.created_reviews)

    def test_ai_review_skips_when_enterprise_qa_has_blocking_findings(self) -> None:
        event_path, qa_path = self.write_inputs("FAIL")
        provider = FakeProvider({"findings": []})

        report = ai_review.execute_ai_review(self.args(event_path=event_path, qa_report_json=qa_path), FakeGitHubClient([]), provider)

        self.assertEqual(report["status"], ai_review.SKIPPED)
        self.assertFalse(provider.called)

    def write_inputs(self, qa_status: str) -> tuple[str, str]:
        event_path = self.tmp / "event.json"
        qa_path = self.tmp / "qa.json"
        event_path.write_text(json.dumps(self.event()), encoding="utf-8")
        qa_path.write_text(json.dumps({"summary": {"overall_result": qa_status}}), encoding="utf-8")
        return str(event_path), str(qa_path)

    def event(self) -> dict:
        return {
            "repository": {"full_name": "Synergie-ITCI/example"},
            "pull_request": {
                "number": 6,
                "title": "Example PR",
                "body": "## Business Purpose\nTest\n## Linked Issue\n#1",
                "base": {"ref": "main", "sha": "base"},
                "head": {"ref": "feature/example", "sha": "head"},
            },
        }

    def args(self, **overrides: object) -> argparse.Namespace:
        values = {
            "repo": str(self.tmp),
            "event_path": "",
            "qa_report_json": "",
            "out": str(self.tmp / "ai-review.md"),
            "json_out": str(self.tmp / "ai-review.json"),
            "provider": "codex",
            "model": "codex-review-v1",
            "provider_url": "",
            "provider_token_env": "AI_REVIEW_PROVIDER_TOKEN",
            "github_token_env": "GITHUB_TOKEN",
            "api_url": "https://api.github.com",
            "max_files": 80,
            "max_patch_chars": 120000,
            "max_findings": 50,
            "provider_timeout_seconds": 60,
            "fixture_json": "",
            "publish_comments": False,
        }
        values.update(overrides)
        return argparse.Namespace(**values)


if __name__ == "__main__":
    unittest.main()
