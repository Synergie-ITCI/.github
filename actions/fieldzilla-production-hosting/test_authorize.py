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
import verify_partial_state as partial_state


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

    def test_production_network_repair_is_exactly_two_host_scoped_ports(self):
        def rule(name, port):
            return self.change(
                f"aws_vpc_security_group_egress_rule.{name}",
                kind="aws_vpc_security_group_egress_rule",
                after={
                    "security_group_id": "sg-0d86252daff26172b",
                    "referenced_security_group_id": "sg-0d9cdc2a3d5ef9243",
                    "ip_protocol": "tcp", "from_port": port, "to_port": port,
                },
            )

        correct = [rule("production_admin_from_alb", 80), rule("production_api_from_alb", 8000)]
        self.verify(correct, "production-network-repair")
        for unsafe in (
            [correct[0]],
            [correct[0], rule("production_api_from_alb", 8080)],
            [correct[0], self.change("aws_security_group_rule.staging", after={"name": "staging"})],
        ):
            with self.assertRaises(SystemExit):
                self.verify(unsafe, "production-network-repair")

    def test_production_bootstrap_adds_only_six_identities_and_two_dark_targets(self):
        def rule(kind, priority, host, target):
            return self.change(
                f"aws_lb_listener_rule.private_validation_{kind}[0]", "aws_lb_listener_rule",
                after={
                    "priority": priority,
                    "listener_arn": "arn:aws:elasticloadbalancing:ap-south-1:918870682888:listener/app/fieldzilla/abd764c361a9627c/a6e9b94e09bf76f8",
                    "action": [{"type": "forward", "target_group_arn": target}],
                    "condition": [
                        {"host_header": [{"values": [host]}]},
                        {"source_ip": [{"values": ["192.0.2.1/32"]}]},
                    ],
                },
            )
        api = rule("api", 302, "api.fieldzilla-validation.invalid", "arn:aws:elasticloadbalancing:ap-south-1:918870682888:targetgroup/pmp-production-api/07cce0ebb89838ce")
        admin = rule("admin", 303, "admin.fieldzilla-validation.invalid", "arn:aws:elasticloadbalancing:ap-south-1:918870682888:targetgroup/pmp-production-admin/25d953f6c0365619")
        bootstrap = [self.change(address, address.split(".")[0]) for address in (
            "aws_secretsmanager_secret.migration",
            "aws_iam_role.admin_execution",
            "aws_iam_role_policy_attachment.admin_execution",
            "aws_iam_role.migration_execution",
            "aws_iam_role_policy_attachment.migration_execution",
            "aws_iam_role_policy.migration_secret",
        )]
        self.verify([api, admin, *bootstrap], "production-bootstrap")
        for unsafe in (
            [api, admin, *bootstrap[:-1]],
            [api, admin, *bootstrap, self.change("aws_iam_role.production", "aws_iam_role")],
            [{**api, "change": {**api["change"], "after": {**api["change"]["after"], "priority": 299}}}, admin, *bootstrap],
            [{**api, "change": {**api["change"], "after": {**api["change"]["after"], "condition": [{"host_header": [{"values": ["fieldzilla.synergieinsights.in"]}]}, {"source_ip": [{"values": ["0.0.0.0/0"]}]}]}}}, admin, *bootstrap],
        ):
            with self.assertRaises(SystemExit):
                self.verify(unsafe, "production-bootstrap")

        # A failed first apply may leave exactly six reviewed resources in state.
        # The follow-up may create only the secret and its scoped role policy.
        existing = []
        for change in [api, admin, *bootstrap[1:5]]:
            copy = json.loads(json.dumps(change))
            address = copy["address"].split("[")[0]
            after = copy["change"]["after"]
            if address == "aws_iam_role.admin_execution":
                after["name"] = "SynergieFieldzillaProductionAdminExecution"
            if address == "aws_iam_role.migration_execution":
                after["name"] = "SynergieFieldzillaProductionMigrationExecution"
            if address.startswith("aws_iam_role_policy_attachment."):
                suffix = address.split(".")[1]
                after["role"] = ("SynergieFieldzillaProductionAdminExecution" if suffix == "admin_execution"
                                 else "SynergieFieldzillaProductionMigrationExecution")
                after["policy_arn"] = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
            copy["change"]["actions"] = ["no-op"]
            copy["change"]["before"] = json.loads(json.dumps(after))
            existing.append(copy)
        residual = [bootstrap[0], bootstrap[5], *existing]
        self.verify(residual, "production-bootstrap")
        for unsafe in (
            [bootstrap[0], *existing],
            [*residual, self.change("aws_iam_role.unexpected", "aws_iam_role")],
            [*residual[:-1]],
            [{**existing[0], "change": {**existing[0]["change"], "after": {
                **existing[0]["change"]["after"], "priority": 301}}}, *residual[:2], *existing[1:]],
        ):
            with self.assertRaises(SystemExit):
                self.verify(unsafe, "production-bootstrap")

    def test_rehearsal_requires_complete_isolated_target_and_rejects_live_changes(self):
        required = [
            self.change("aws_vpc.rehearsal", "aws_vpc", after={"cidr_block": "10.77.0.0/20"}),
            self.change("aws_db_instance.rehearsal", "aws_db_instance", after={"identifier": "fieldzilla-production-rehearsal"}),
            self.change("aws_s3_bucket.attachments", after={"bucket": "syn-fz-rehearsal-attachments-918870682888-aps1"}),
            self.change("aws_s3_bucket_logging.attachments", "aws_s3_bucket_logging"),
            self.change("aws_lb.rehearsal", "aws_lb", after={"name": "fieldzilla-production-rehearsal"}),
            self.change("aws_ecs_cluster.rehearsal", "aws_ecs_cluster", after={"name": "fieldzilla-production-rehearsal"}),
            self.change("aws_cloudwatch_log_group.container_insights", "aws_cloudwatch_log_group", after={"name": "/aws/ecs/containerinsights/fieldzilla-production-rehearsal/performance"}),
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
                    "aws_cloudwatch_log_group.container_insights",
                )
            ]
            path.write_text(json.dumps({"resource_changes": required}))
            authorize.check_rehearsal_plan(path, "cleanup-destroy")
            path.write_text(json.dumps({"resource_changes": required[:-1]}))
            with self.assertRaises(SystemExit):
                authorize.check_rehearsal_plan(path, "cleanup-destroy")

    def test_partial_rehearsal_cleanup_is_exact_destroy_only(self):
        changes = []
        for base, count in partial_state.PARTIAL_COUNTS.items():
            for index in range(count):
                address = f'{base}["{index}"]' if count > 1 else base
                changes.append(self.change(address, base.split(".")[0], actions=["delete"], after={}))
                changes[-1]["change"]["before"] = {"tags_all": partial_state.EXPECTED_TAGS}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps({"resource_changes": changes}))
            authorize.check_rehearsal_plan(path, "cleanup-partial", partial_state.SOURCE, partial_state.EXPIRY)
            untagged = json.loads(json.dumps(changes))
            untagged[0]["change"]["before"]["tags_all"] = {}
            path.write_text(json.dumps({"resource_changes": untagged}))
            with self.assertRaises(SystemExit):
                authorize.check_rehearsal_plan(path, "cleanup-partial", partial_state.SOURCE, partial_state.EXPIRY)
            for altered in (changes[:-1], changes + [self.change("aws_db_instance.production", actions=["delete"])],
                            [{**changes[0], "change": {**changes[0]["change"], "actions": ["update"]}}, *changes[1:]]):
                with self.assertRaises(SystemExit):
                    path.write_text(json.dumps({"resource_changes": altered}))
                    authorize.check_rehearsal_plan(path, "cleanup-partial", partial_state.SOURCE, partial_state.EXPIRY)
            path.write_text(json.dumps({"resource_changes": changes}))
            with self.assertRaises(SystemExit):
                authorize.check_rehearsal_plan(path, "cleanup-partial", "a" * 40, partial_state.EXPIRY)

    def test_partial_state_verifier_rejects_drift(self):
        resources = []
        for address, count in partial_state.PARTIAL_COUNTS.items():
            typ, name = address.split(".")
            if address == "aws_vpc_endpoint.services":
                keys = sorted(partial_state.ENDPOINTS)
            elif address == "aws_iam_role.execution":
                keys = sorted(partial_state.EXECUTION_ROLES)
            else:
                keys = [None]
            resources.append({"mode": "managed", "type": typ, "name": name,
                              "instances": [{"index_key": key,
                                             **({"status": "tainted"} if key in partial_state.TAINTED.get(address, set()) else {}),
                                             "attributes": {"tags_all": partial_state.EXPECTED_TAGS}} for key in keys]})
        for address in partial_state.DATA_SOURCES:
            typ, name = address.split(".")
            resources.append({"mode": "data", "type": typ, "name": name, "instances": [{}]})
        state = {"lineage": partial_state.LINEAGE, "serial": partial_state.SERIAL,
                 "outputs": {}, "resources": resources}
        partial_state.verify(state, partial_state.SOURCE, partial_state.EXPIRY)
        for changed in ({**state, "serial": state["serial"] + 1},
                        {**state, "outputs": {"target": {"value": {}}}},
                        {**state, "resources": resources[:-1]}):
            with self.assertRaises(ValueError):
                partial_state.verify(changed, partial_state.SOURCE, partial_state.EXPIRY)

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
