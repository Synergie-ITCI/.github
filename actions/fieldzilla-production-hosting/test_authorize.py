"""Safety contract for the production-only OpenTofu plan verifier."""

import importlib.util
import hashlib
import io
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
    def test_probe_reads_exact_owner_comment_without_authorizing_or_consuming(self):
        comment = {
            "id": 123, "user": {"login": "SaurabhVermaIN", "id": 52234089},
            "author_association": "MEMBER", "body": "existing owner approval",
            "issue_url": f"https://api.github.com/repos/{authorize.REPOSITORY}/issues/674",
        }
        argv = ["authorize.py", "probe", "--source-sha", "a" * 40,
                "--caller-sha", "b" * 40, "--workflow-tag", "refs/tags/pr-qa-v1-rc224",
                "--phase", "phase1", "--approval-comment-id", "123"]
        output = io.StringIO()
        with patch.object(authorize.sys, "argv", argv), \
                patch.object(authorize, "require_identity") as identity, \
                patch.object(authorize, "api", return_value=comment) as api, \
                patch.object(authorize, "verify_artifact", side_effect=AssertionError("artifact validation in probe")), \
                patch.object(authorize, "verify_owner_approval", side_effect=AssertionError("approval in probe")), \
                patch.object(authorize.sys, "stdout", output):
            authorize.main()
        identity.assert_called_once()
        api.assert_called_once_with(f"repos/{authorize.REPOSITORY}/issues/comments/123")
        evidence = json.loads(output.getvalue())
        self.assertEqual(evidence["comment_id"], 123)
        self.assertEqual(evidence["body_sha256"], hashlib.sha256(comment["body"].encode()).hexdigest())
        self.assertFalse(evidence["approval_granted"])
        self.assertFalse(evidence["approval_consumed"])
        comment["issue_url"] = "https://api.github.com/repos/Synergie-ITCI/.github/issues/437"
        with patch.object(authorize, "api", return_value=comment), self.assertRaises(SystemExit):
            authorize.probe_owner_comment(SimpleNamespace(approval_comment_id=123))
        with patch.object(authorize, "api") as api, self.assertRaises(SystemExit):
            authorize.probe_owner_comment(SimpleNamespace(approval_comment_id=0))
        api.assert_not_called()

    def test_probe_skips_every_aws_and_opentofu_step(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/fieldzilla-production-hosting.yml").read_text()
        guarded = []
        for step in re.split(r"\n      - name: ", workflow)[1:]:
            if any(text in step for text in ("aws-actions/configure-aws-credentials", "opentofu/setup-opentofu", "aws ", "tofu -")):
                self.assertTrue(any(guard in step for guard in (
                    "inputs.mode != 'probe'", "inputs.mode == 'plan'", "inputs.mode == 'apply'"
                )), step.splitlines()[0])
                guarded.append(step.splitlines()[0])
        self.assertGreaterEqual(len(guarded), 6)

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
            "change": {"actions": actions or ["create"], "before": (after or {}) if actions == ["no-op"] else None, "after": after or {}},
        }

    def test_phase_one_accepts_isolated_addition(self):
        self.verify([self.change("aws_s3_bucket.production", after={"bucket": "fieldzilla-production"})], "phase1")

    def test_rehearsal_requires_complete_isolated_target_and_rejects_live_changes(self):
        required = [
            self.change("aws_vpc.rehearsal", "aws_vpc", after={"cidr_block": "10.77.0.0/20"}),
            self.change("aws_db_instance.rehearsal", "aws_db_instance", after={"identifier": "fieldzilla-production-rehearsal"}),
            self.change("aws_s3_bucket.attachments", after={"bucket": "syn-fz-rehearsal-attachments-918870682888-aps1"}),
            self.change("aws_s3_bucket_logging.attachments", "aws_s3_bucket_logging"),
            self.change("aws_lb.rehearsal", "aws_lb", after={"name": "fieldzilla-production-rehearsal"}),
            self.change("aws_ecs_cluster.rehearsal", "aws_ecs_cluster", after={"name": "fieldzilla-production-rehearsal"}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps({"resource_changes": required}))
            authorize.check_rehearsal_plan(path)
            for extra in (
                self.change("aws_lb_listener_rule.production", "aws_lb_listener_rule", after={"name": "fieldzilla-production"}),
                self.change("aws_db_instance.staging", "aws_db_instance", actions=["update"]),
                self.change("aws_s3_bucket.attachments", after={"bucket": "fieldzilla-production-live"}),
            ):
                with self.subTest(extra=extra["address"]), self.assertRaises(SystemExit):
                    path.write_text(json.dumps({"resource_changes": required + [extra]}))
                    authorize.check_rehearsal_plan(path)

    def test_rehearsal_cleanup_requires_only_rds_protection_then_owned_deletes(self):
        rds = self.change("aws_db_instance.rehearsal", "aws_db_instance", actions=["update"], after={"deletion_protection": False})
        rds["change"]["before"] = {"deletion_protection": True}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps({"resource_changes": [rds]}))
            authorize.check_rehearsal_plan(path, "cleanup-protection")
            bad = self.change("aws_vpc.rehearsal", "aws_vpc", actions=["update"])
            path.write_text(json.dumps({"resource_changes": [rds, bad]}))
            with self.assertRaises(SystemExit):
                authorize.check_rehearsal_plan(path, "cleanup-protection")
            required = [
                self.change(address, actions=["delete"], after={}) for address in (
                    "aws_vpc.rehearsal", "aws_db_instance.rehearsal",
                    "aws_s3_bucket.attachments", "aws_s3_bucket_logging.attachments",
                    "aws_lb.rehearsal", "aws_ecs_cluster.rehearsal",
                )
            ]
            path.write_text(json.dumps({"resource_changes": required}))
            authorize.check_rehearsal_plan(path, "cleanup-destroy")
            path.write_text(json.dumps({"resource_changes": required[:-1]}))
            with self.assertRaises(SystemExit):
                authorize.check_rehearsal_plan(path, "cleanup-destroy")

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

    def test_partial_recovery_preserves_unchanged_production_resources(self):
        unchanged = self.change("aws_lb_target_group.api", "aws_lb_target_group", ["no-op"], {"name": "pmp-production-api"})
        unchanged["change"]["before"] = unchanged["change"]["after"].copy()
        self.verify([unchanged, self.change("aws_db_instance.production", "aws_db_instance")], "phase1")

    def test_noop_does_not_hide_mutation_move_import_or_staging(self):
        addition = self.change("aws_db_instance.production", "aws_db_instance")
        for patch_value in (
            {"change": {"actions": ["no-op"], "before": {"x": 1}, "after": {"x": 2}}},
            {"previous_address": "aws_s3_bucket.old"},
            {"change": {"actions": ["no-op"], "before": {}, "after": {}, "importing": {"id": "bucket"}}},
            {"address": "aws_s3_bucket.staging"},
        ):
            with self.subTest(patch_value=patch_value), self.assertRaises(SystemExit):
                unchanged = self.change("aws_s3_bucket.production", actions=["no-op"])
                unchanged.update(patch_value)
                self.verify([addition, unchanged], "phase1")

    def test_recovery_rejects_delete_update_and_both_replacement_orders(self):
        for actions in (["update"], ["delete"], ["delete", "create"], ["create", "delete"]):
            with self.subTest(actions=actions), self.assertRaises(SystemExit):
                self.verify([self.change("aws_lb_target_group.api", "aws_lb_target_group", actions)], "phase1")

    def test_phase_two_counts_additions_without_recreating_existing_hosting(self):
        self.verify([
            self.change("aws_s3_bucket.production", actions=["no-op"]),
            self.change("aws_lb_listener_certificate.production", "aws_lb_listener_certificate"),
            self.change("aws_lb_listener_rule.hosting_health", "aws_lb_listener_rule"),
            self.change("aws_lb_listener_rule.application_pending", "aws_lb_listener_rule"),
        ], "phase2")

    def test_phase_one_rejects_shared_alb_even_when_marked_unchanged(self):
        with self.assertRaises(SystemExit):
            self.verify([
                self.change("aws_s3_bucket.production"),
                self.change("aws_lb_listener_rule.hosting_health", "aws_lb_listener_rule", ["no-op"]),
            ], "phase1")

    def test_phase_two_shared_noops_cannot_mask_other_creates(self):
        with self.assertRaises(SystemExit):
            self.verify([
                self.change("aws_lb_listener_certificate.production", "aws_lb_listener_certificate", ["no-op"]),
                self.change("aws_lb_listener_rule.hosting_health", "aws_lb_listener_rule", ["no-op"]),
                self.change("aws_lb_listener_rule.application_pending", "aws_lb_listener_rule", ["no-op"]),
                *[self.change(f"aws_s3_bucket.extra_{i}") for i in range(3)],
            ], "phase2")

    def test_noop_only_plan_cannot_authorize_apply(self):
        with self.assertRaises(SystemExit):
            self.verify([self.change("aws_s3_bucket.production", actions=["no-op"])], "phase1")

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
