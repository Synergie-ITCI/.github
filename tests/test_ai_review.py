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
import evidence


class FakeGitHubClient:
    def __init__(self, files: list[dict], comments: list[dict] | None = None, *, head_sha: str = "head") -> None:
        self.files = files
        self.comments = comments or []
        self.head_sha = head_sha
        self.created_reviews: list[dict] = []
        self.updated_comments: list[tuple[int, str]] = []
        self.deleted_comments: list[int] = []

    def list_pull_files(self, pr_number: int) -> list[dict]:
        return self.files

    def list_review_comments(self, pr_number: int) -> list[dict]:
        return self.comments

    def get_pull(self, pr_number: int) -> dict:
        return {"head": {"sha": self.head_sha}}

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
                    "user": {"login": "github-actions[bot]"},
                },
                {
                    "id": 11,
                    "path": "src/app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": "<!-- synergie-pr-qa:inline-review fingerprint=bbbbbbbbbbbbbbbbbbbbbbbb -->\nqa",
                    "user": {"login": "github-actions[bot]"},
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
                    "user": {"login": "github-actions[bot]"},
                }
            ],
        )
        provider = FakeProvider({}, ai_review.UNAVAILABLE)

        report = ai_review.execute_ai_review(self.args(event_path=event_path, qa_report_json=qa_path, publish_comments=True), client, provider)

        self.assertEqual(report["status"], ai_review.UNAVAILABLE)
        self.assertFalse(client.deleted_comments)
        self.assertFalse(client.created_reviews)

    def test_ai_review_is_unavailable_when_enterprise_qa_has_blocking_findings(self) -> None:
        event_path, qa_path = self.write_inputs("FAIL")
        provider = FakeProvider({"findings": []})

        report = ai_review.execute_ai_review(self.args(event_path=event_path, qa_report_json=qa_path), FakeGitHubClient([]), provider)

        self.assertEqual(report["status"], ai_review.UNAVAILABLE)
        self.assertFalse(provider.called)

    def test_authoritative_qa_evidence_fail_closed_cases(self) -> None:
        event_path = self.tmp / "event.json"
        event_path.write_text(json.dumps(self.event()), encoding="utf-8")
        cases = {
            "missing": None,
            "empty": "",
            "malformed": "{not-json",
            "unsupported_top_level_field": self.qa_payload(extra={"python_module": "ai_review.py"}),
            "incomplete_report": self.qa_payload(report_complete=False),
            "bad_sanitization": self.qa_payload(sanitization={"status": "FAIL"}),
            "missing_status": self.qa_payload(status_missing=True),
            "null_status": self.qa_payload(status=None),
            "unknown_status": self.qa_payload(status="UNKNOWN"),
            "fail_status": self.qa_payload(status="FAIL"),
            "warning_status": self.qa_payload(status="WARNING"),
            "mismatched_repository": self.qa_payload(repository="Synergie-ITCI/other"),
            "mismatched_pr": self.qa_payload(pr_number=7),
            "mismatched_sha": self.qa_payload(head_sha="other-head"),
            "unsupported_schema": self.qa_payload(schema_version=999),
        }

        for name, payload in cases.items():
            with self.subTest(name=name):
                qa_path = self.tmp / f"{name}" / "pr-quality-report.json"
                qa_path.parent.mkdir()
                if payload is not None:
                    qa_path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
                provider = FakeProvider({"findings": []})

                report = ai_review.execute_ai_review(
                    self.args(event_path=str(event_path), qa_report_json=str(qa_path)),
                    FakeGitHubClient([]),
                    provider,
                )

                self.assertEqual(report["status"], ai_review.UNAVAILABLE)
                self.assertFalse(provider.called)

    def test_authoritative_qa_evidence_requires_pull_request_identity_context(self) -> None:
        qa_path = self.tmp / "identity" / "pr-quality-report.json"
        qa_path.parent.mkdir()
        qa_path.write_text(json.dumps(self.qa_payload(status="PASS")), encoding="utf-8")
        event_path = self.tmp / "event-missing-identity.json"
        event_path.write_text(json.dumps({"repository": {"full_name": "Synergie-ITCI/example"}, "pull_request": {"head": {"sha": "head"}}}), encoding="utf-8")
        provider = FakeProvider({"findings": []})

        report = ai_review.execute_ai_review(
            self.args(event_path=str(event_path), qa_report_json=str(qa_path)),
            FakeGitHubClient([]),
            provider,
        )

        self.assertEqual(report["status"], ai_review.UNAVAILABLE)
        self.assertFalse(provider.called)

    def test_authoritative_qa_pass_evidence_allows_ai_review(self) -> None:
        event_path, qa_path = self.write_inputs("PASS")
        provider = FakeProvider({"findings": []})

        report = ai_review.execute_ai_review(
            self.args(event_path=event_path, qa_report_json=qa_path),
            FakeGitHubClient([{"filename": "src/app.py", "patch": "@@ -0,0 +1,1 @@\n+return 1"}]),
            provider,
        )

        self.assertEqual(report["status"], ai_review.COMPLETED)
        self.assertTrue(provider.called)

    def test_provider_destination_governance(self) -> None:
        cases = [
            ("https://approved.example.com/review", "approved.example.com", "", ""),
            ("https://unapproved.example.com/review", "approved.example.com", "", "not approved"),
            ("http://approved.example.com/review", "approved.example.com", "", "HTTPS"),
            ("ftp://approved.example.com/review", "approved.example.com", "", "HTTPS"),
            ("https://user:pass@approved.example.com/review", "approved.example.com", "", "embedded credentials"),
            ("https://localhost/review", "localhost", "", "localhost"),
            ("https://127.0.0.1/review", "127.0.0.1", "", "loopback"),
            ("https://[::1]/review", "::1", "", "loopback"),
            ("https://169.254.1.1/review", "169.254.1.1", "", "link-local"),
            ("https://10.0.0.10/review", "10.0.0.10", "", "private network"),
            ("https://10.0.0.10/review", "", "10.0.0.10", ""),
            ("https://approved.example.com.attacker.net/review", "approved.example.com", "", "not approved"),
        ]

        for url, approved, internal, expected in cases:
            with self.subTest(url=url):
                error = ai_review.validate_provider_destination(url, approved, internal)
                if expected:
                    self.assertIn(expected, error)
                else:
                    self.assertEqual(error, "")

    def test_redirects_are_disabled_for_provider_requests(self) -> None:
        handler = ai_review.NoRedirectHandler()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://attacker.example/review"))

    def test_malicious_evidence_artifact_files_are_rejected(self) -> None:
        event_path = self.tmp / "event.json"
        event = self.event()
        event_path.write_text(json.dumps(event), encoding="utf-8")
        evidence_dir = self.tmp / "evidence-artifact"
        evidence_dir.mkdir()
        report = evidence_dir / "pr-quality-report.json"
        report.write_text(json.dumps(self.qa_payload(status="PASS")), encoding="utf-8")

        malicious_ai = evidence_dir / "ai_review.py"
        malicious_ai.write_text("print('exfiltrate')\n", encoding="utf-8")
        validation = evidence.validate_qa_evidence(str(report), event, require_pass=True)
        self.assertFalse(validation.valid)
        self.assertIn("unexpected file", validation.reason)

        malicious_ai.unlink()
        malicious_review = evidence_dir / "review_comments.py"
        malicious_review.write_text("print('exfiltrate')\n", encoding="utf-8")
        malicious_review.chmod(0o755)
        validation = evidence.validate_qa_evidence(str(report), event, require_pass=True)
        self.assertFalse(validation.valid)
        self.assertIn("unexpected file", validation.reason)

    def test_symlink_evidence_artifact_is_rejected(self) -> None:
        event = self.event()
        evidence_dir = self.tmp / "symlink-artifact"
        evidence_dir.mkdir()
        report = evidence_dir / "pr-quality-report.json"
        report.write_text(json.dumps(self.qa_payload(status="PASS")), encoding="utf-8")
        (evidence_dir / "gitleaks.json").symlink_to(report)

        validation = evidence.validate_qa_evidence(str(report), event, require_pass=True)

        self.assertFalse(validation.valid)
        self.assertIn("symlink", validation.reason)

    def write_inputs(self, qa_status: str) -> tuple[str, str]:
        event_path = self.tmp / "event.json"
        evidence_dir = self.tmp / f"evidence-{qa_status.lower()}"
        evidence_dir.mkdir()
        qa_path = evidence_dir / "pr-quality-report.json"
        event_path.write_text(json.dumps(self.event()), encoding="utf-8")
        qa_path.write_text(json.dumps(self.qa_payload(status=qa_status)), encoding="utf-8")
        return str(event_path), str(qa_path)

    def qa_payload(
        self,
        *,
        status: str | None = "PASS",
        status_missing: bool = False,
        repository: str = "Synergie-ITCI/example",
        pr_number: int = 6,
        head_sha: str = "head",
        schema_version: int = 1,
        report_complete: bool = True,
        sanitization: dict | None = None,
        extra: dict | None = None,
    ) -> dict:
        summary = {
            "repository": repository,
            "pull_request_number": pr_number,
            "head_sha": head_sha,
        }
        if not status_missing:
            summary["overall_result"] = status
        payload = {
            "schema_version": schema_version,
            "report_complete": report_complete,
            "sanitization": sanitization if sanitization is not None else {"status": "PASS"},
            "summary": summary,
            "inline_review": {"schema_version": 1, "findings": []},
        }
        if extra:
            payload.update(extra)
        return payload

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
            "approved_provider_hosts": "",
            "approved_internal_provider_hosts": "",
            "trusted_comment_authors": "github-actions[bot]",
        }
        values.update(overrides)
        return argparse.Namespace(**values)


if __name__ == "__main__":
    unittest.main()
