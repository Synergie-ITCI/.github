"""Safety contract for the production-only OpenTofu plan verifier."""

import importlib.util
import json
import re
import tempfile
import unittest
from email.message import Message
from urllib.error import HTTPError
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("hosting_authorize", Path(__file__).with_name("authorize.py"))
authorize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authorize)


class PlanSafetyTest(unittest.TestCase):
    def test_api_failure_reports_permission_and_rate_context_without_token(self):
        headers = Message()
        headers["X-Accepted-GitHub-Permissions"] = "pull_requests=read"
        headers["X-RateLimit-Remaining"] = "500"
        path = f"repos/{authorize.REPOSITORY}/issues/comments/123"
        error = HTTPError("https://api.github.com/" + path, 403, "Forbidden", headers, None)
        with patch.dict(authorize.os.environ, {"GITHUB_TOKEN": "private-test-token"}), \
                patch.object(authorize.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(SystemExit) as caught:
                authorize.api(path)
        message = str(caught.exception)
        self.assertIn("HTTP 403", message)
        self.assertIn("pull_requests=read", message)
        self.assertIn("rate limit remaining: 500", message)
        self.assertNotIn("private-test-token", message)

    def test_workflow_checks_pr_read_access_before_aws_identity(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/fieldzilla-production-hosting.yml").read_text()
        permissions = workflow.split("\npermissions:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(re.findall(r"^  pull-requests: (\S+)$", permissions, re.MULTILINE), ["read"])
        probe = workflow.index("- name: Verify hosting PR comment read access")
        identity = workflow.index("- name: Verify GitHub OIDC production identity")
        self.assertLess(probe, identity)
        probe_step = workflow[probe:identity]
        self.assertIn("GH_TOKEN: ${{ github.token }}", probe_step)
        self.assertIn('gh api "repos/${GITHUB_REPOSITORY}/issues/674/comments?per_page=1" --silent', probe_step)

    def verify(self, changes, phase):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            plan.write_text(json.dumps({"resource_changes": changes}))
            authorize.check_plan(plan, phase)

    @staticmethod
    def change(address, kind="aws_s3_bucket", actions=None, after=None):
        return {
            "address": address,
            "mode": "managed",
            "type": kind,
            "change": {"actions": actions or ["create"], "after": after or {}},
        }

    def test_phase_one_accepts_isolated_addition(self):
        self.verify([self.change("aws_s3_bucket.production", after={"bucket": "fieldzilla-production"})], "phase1")

    def test_phase_one_rejects_existing_resource_mutation(self):
        with self.assertRaises(SystemExit):
            self.verify([self.change("aws_db_instance.staging", "aws_db_instance", ["update"])], "phase1")

    def test_phase_one_rejects_shared_listener_addition(self):
        with self.assertRaises(SystemExit):
            self.verify([self.change("aws_lb_listener_rule.hosting_health", "aws_lb_listener_rule")], "phase1")

    def test_phase_one_rejects_staging_reference_in_new_resource(self):
        with self.assertRaises(SystemExit):
            self.verify([self.change("aws_iam_role.production", "aws_iam_role", after={"name": "staging-role"})], "phase1")

    def test_phase_two_accepts_only_three_shared_additions(self):
        self.verify([
            self.change("aws_lb_listener_certificate.production", "aws_lb_listener_certificate"),
            self.change("aws_lb_listener_rule.hosting_health", "aws_lb_listener_rule"),
            self.change("aws_lb_listener_rule.application_pending", "aws_lb_listener_rule"),
        ], "phase2")

    def test_phase_two_rejects_other_addition(self):
        with self.assertRaises(SystemExit):
            self.verify([
                self.change("aws_lb_listener_certificate.production", "aws_lb_listener_certificate"),
                self.change("aws_lb_listener_rule.hosting_health", "aws_lb_listener_rule"),
                self.change("aws_lb_listener_rule.application_pending", "aws_lb_listener_rule"),
                self.change("aws_db_instance.unreviewed", "aws_db_instance"),
            ], "phase2")

    def test_approval_must_be_owner_comment_on_consumer_pr(self):
        args = SimpleNamespace(
            approval_comment_id=123, phase="phase1", source_sha="a" * 40,
            caller_sha="b" * 40, plan_run_id=42, artifact_id=43,
            artifact_digest="c" * 64, plan_sha256="d" * 64,
        )
        body = (
            "APPROVE FIELDZILLA PRODUCTION HOSTING phase1\n"
            f"Source: {args.source_sha}\nCaller: {args.caller_sha}\n"
            "Plan run: 42\nArtifact ID: 43\n"
            f"Artifact SHA-256: {args.artifact_digest}\nPlan SHA-256: {args.plan_sha256}\n"
            f"State key: {authorize.STATE_KEY}"
        )
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        comment = {
            "user": {"login": "SaurabhVermaIN", "id": 52234089},
            "author_association": "OWNER", "body": body,
            "issue_url": f"https://api.github.com/repos/{authorize.REPOSITORY}/issues/674",
            "created_at": now, "updated_at": now,
        }

        def fake_api(path):
            if "/environments/" in path:
                return {"protection_rules": []}
            if "/issues/comments/" in path:
                return comment
            if "/deployments?" in path:
                return []
            raise AssertionError(path)

        with patch.object(authorize, "api", side_effect=fake_api):
            self.assertEqual(authorize.verify_owner_approval(args), "fieldzilla-hosting-approval:123")
            comment["issue_url"] = "https://api.github.com/repos/Synergie-ITCI/.github/issues/437"
            with self.assertRaises(SystemExit):
                authorize.verify_owner_approval(args)


if __name__ == "__main__":
    unittest.main()
