"""Exact PR 521 plan evidence and fail-closed mutation tests."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import opentofu_plan_authorization as auth  # noqa: E402


def resource(address: str, before: dict | None, after: dict, actions: list[str], unknown: dict | None = None) -> dict:
    return {
        "mode": "managed", "address": address, "type": auth.PR521_CHANGES[address][0],
        "change": {"actions": actions, "before": before, "after": after, "after_unknown": unknown or {}},
    }


def policy_update(action: str) -> tuple[dict, dict]:
    before = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": action,
        "Resource": ["arn:aws:iam::918870682888:role/ExistingStagingRole"],
    }]}
    after = copy.deepcopy(before)
    after["Statement"][0]["Resource"].append(auth.PR521_ROLE_ARN)
    return {"policy": json.dumps(before), "name": "staging-policy"}, {
        "policy": json.dumps(after), "name": "staging-policy"
    }


def plan() -> dict:
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    }]}
    secrets = [auth.EXACT_RUNTIME_SECRET_ARN, auth.PR521_RDS_SECRET_ARN]
    secret_policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secrets},
        {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": auth.PR521_KMS_KEY_ARN,
         "Condition": {"StringEquals": {
             "kms:ViaService": "secretsmanager.ap-south-1.amazonaws.com",
             "kms:EncryptionContext:SecretARN": secrets,
         }}},
    ]}
    role = resource("aws_iam_role.staging_migration_execution", None, {
        "name": auth.PR521_ROLE_NAME, "arn": auth.PR521_ROLE_ARN,
        "permissions_boundary": auth.PR521_BOUNDARY_ARN,
        "assume_role_policy": json.dumps(trust), "tags": {},
        "tags_all": {"Application": "fieldzilla", "Repository": auth.REPOSITORY,
                     "ManagedBy": "opentofu", "Governance": "synergie-pr-qa"},
    }, ["create"])
    attachment = resource("aws_iam_role_policy_attachment.staging_migration_execution", None, {
        "role": auth.PR521_ROLE_NAME,
        "policy_arn": "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    }, ["create"])
    inline = resource("aws_iam_role_policy.staging_migration_execution_secrets", None, {
        "name": "fieldzilla-staging-migration-execution-secrets", "role": auth.PR521_ROLE_NAME,
        "policy": json.dumps(secret_policy),
    }, ["create"])
    old_secrets = [{"name": name, "valueFrom": f"{auth.EXACT_RUNTIME_SECRET_ARN}:{name}::"}
                   for name in sorted(auth._MIGRATION_SECRET_KEYS)]
    old_container = {"name": "migration", "command": ["alembic", "upgrade", "head"],
                     "image": "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:"
                              + "b1679598ea9dfbbac3b8244887fc113636169e6f", "secrets": old_secrets}
    new_container = copy.deepcopy(old_container)
    new_container["image"] = ("918870682888.dkr.ecr.ap-south-1.amazonaws.com/"
                              "synergie/fieldzilla/staging/api@sha256:" + "a" * 64)
    new_container["secrets"].append({"name": "APP_MIGRATION_DB_PASSWORD",
                                     "valueFrom": auth.PR521_RDS_SECRET_ARN + ":password::"})
    before_task = {"family": "fieldzilla-staging-migration", "execution_role_arn": auth._EXECUTION_ROLE_ARN,
                   "task_role_arn": auth._TASK_ROLE_ARN, "container_definitions": json.dumps([old_container]),
                   "cpu": "256", "memory": "512"}
    after_task = dict(before_task, execution_role_arn=auth.PR521_ROLE_ARN,
                      container_definitions=json.dumps([new_container]))
    task = resource('aws_ecs_task_definition.migration["staging"]', before_task, after_task,
                    ["delete", "create"])
    updates = []
    for address, action in (
        ('aws_iam_role_policy.deploy["staging"]', "iam:PassRole"),
        ("aws_iam_role_policy.staging_infra_plan_discovery", "iam:GetRole"),
        ("aws_iam_policy.staging_infra_ecs_rollout", "iam:PassRole"),
    ):
        before, after = policy_update(action)
        updates.append(resource(address, before, after, ["update"]))
    return {"variables": {"enable_production": {"value": False}, "route53_zone_id": {"value": ""},
                          "image_tag": {"value": "b1679598ea9dfbbac3b8244887fc113636169e6f"}},
            "resource_changes": [role, attachment, inline, task, *updates],
            "resource_drift": [], "output_changes": {}}


class Pr521PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        plan_path = Path(self.temp.name) / "fieldzilla-staging.plan.json"
        (plan_path.parent / "metadata.json").write_text(json.dumps({
            "commit_sha": auth.PR521_SOURCE_SHA, "repository": auth.REPOSITORY,
            "environment": auth.ENVIRONMENT, "state_key": auth.STATE_KEY,
            "image_digest_map": {"synergie/fieldzilla/staging/api": "sha256:" + "a" * 64,
                                 "synergie/fieldzilla/staging/admin-web": "sha256:" + "b" * 64},
        }), encoding="utf-8")
        self.args = Namespace(expected_sha=auth.PR521_SOURCE_SHA, repository=auth.REPOSITORY,
                              environment=auth.ENVIRONMENT, plan_json_path=plan_path)

    def check_fails(self, document: dict) -> None:
        with self.assertRaises(SystemExit):
            auth.verify_pr521_staging_plan(document, self.args)

    def test_exact_known_plan_passes(self) -> None:
        document = plan()
        task = next(item for item in document["resource_changes"] if item["type"] == "aws_ecs_task_definition")
        task["change"]["after_unknown"] = {"arn": True, "revision": True, "id": True}
        auth.verify_pr521_staging_plan(document, self.args)

    def test_create_before_destroy_task_revision_passes(self) -> None:
        document = plan()
        task = next(item for item in document["resource_changes"] if item["type"] == "aws_ecs_task_definition")
        task["change"]["actions"] = ["create", "delete"]
        auth.verify_pr521_staging_plan(document, self.args)

    def test_wrong_commit_repo_and_environment_fail(self) -> None:
        for field, value in (("expected_sha", "f" * 40), ("repository", "Other/repo"),
                             ("environment", "production")):
            with self.subTest(field=field):
                args = copy.copy(self.args)
                setattr(args, field, value)
                with self.assertRaises(SystemExit):
                    auth.verify_pr521_staging_plan(plan(), args)

    def test_unknown_security_fields_fail(self) -> None:
        for address, field in (
            ("aws_iam_role.staging_migration_execution", "arn"),
            ("aws_iam_role.staging_migration_execution", "assume_role_policy"),
            ("aws_iam_role.staging_migration_execution", "permissions_boundary"),
            ("aws_iam_role_policy.staging_migration_execution_secrets", "policy"),
            ("aws_iam_role_policy_attachment.staging_migration_execution", "policy_arn"),
            ('aws_ecs_task_definition.migration["staging"]', "execution_role_arn"),
            ('aws_ecs_task_definition.migration["staging"]', "container_definitions"),
            ('aws_iam_role_policy.deploy["staging"]', "policy"),
            ("aws_iam_role_policy.staging_infra_plan_discovery", "policy"),
            ("aws_iam_policy.staging_infra_ecs_rollout", "policy"),
        ):
            with self.subTest(address=address, field=field):
                document = plan()
                item = next(item for item in document["resource_changes"] if item["address"] == address)
                item["change"]["after_unknown"][field] = True
                self.check_fails(document)

    def test_unreviewed_resources_fail(self) -> None:
        document = plan()
        document["resource_changes"].append({"mode": "managed", "address": "aws_iam_role.production",
            "type": "aws_iam_role", "change": {"actions": ["create"], "before": None, "after": {}}})
        self.check_fails(document)

    def test_image_digest_must_match_ecr_evidence(self) -> None:
        document = plan()
        task = next(item for item in document["resource_changes"] if item["type"] == "aws_ecs_task_definition")
        container = json.loads(task["change"]["after"]["container_definitions"])
        container[0]["image"] = container[0]["image"].replace("a" * 64, "c" * 64)
        task["change"]["after"]["container_definitions"] = json.dumps(container)
        self.check_fails(document)

    def test_wrong_image_tag_or_state_key_fails(self) -> None:
        document = plan()
        document["variables"]["image_tag"]["value"] = "f" * 40
        self.check_fails(document)
        metadata_path = self.args.plan_json_path.parent / "metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["state_key"] = "production/opentofu.tfstate"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        self.check_fails(plan())

    def test_wrong_role_boundary_secret_and_wildcard_fail(self) -> None:
        for change in ("role", "boundary", "secret", "wildcard"):
            with self.subTest(change=change):
                document = plan()
                items = {item["address"]: item["change"] for item in document["resource_changes"]}
                if change == "role":
                    items["aws_iam_role.staging_migration_execution"]["after"]["name"] = "OtherRole"
                elif change == "boundary":
                    items["aws_iam_role.staging_migration_execution"]["after"]["permissions_boundary"] = "*"
                elif change == "secret":
                    policy = json.loads(items["aws_iam_role_policy.staging_migration_execution_secrets"]["after"]["policy"])
                    policy["Statement"][0]["Resource"] = ["*"]
                    items["aws_iam_role_policy.staging_migration_execution_secrets"]["after"]["policy"] = json.dumps(policy)
                else:
                    policy = json.loads(items['aws_iam_role_policy.deploy["staging"]']["after"]["policy"])
                    policy["Statement"][0]["Resource"].append("*")
                    items['aws_iam_role_policy.deploy["staging"]']["after"]["policy"] = json.dumps(policy)
                self.check_fails(document)

    def test_existing_legacy_plan_path_remains(self) -> None:
        self.assertEqual(auth.STAGING_MIGRATION_IAM_SOURCE_SHA, "362109240192e6ac817d180a6d1e6b6a422c469b")
        self.assertEqual(auth.STAGING_MIGRATION_IAM_ADDRESS, "aws_iam_role_policy.staging_migration_task_run")

    def test_workflow_captures_plan_before_safety_and_keeps_apply_closed(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/fieldzilla-staging-opentofu-apply.yml").read_text()
        self.assertIn('APPROVED_SOURCE_SHA}" = "' + auth.PR521_SOURCE_SHA + '"', workflow)
        self.assertIn('[ "${REQUESTED_MODE}" = "plan" ]; then\n                plan_kind_prefix="fieldzilla-pr521-staging-plan"', workflow)
        capture_check = workflow.index("- name: Reject plaintext secrets before PR 521 plan capture")
        upload = workflow.index("- name: Preserve exact PR 521 plan for security review")
        authorization = workflow.index("- name: Verify generated plan safety")
        self.assertLess(capture_check, upload)
        self.assertLess(upload, authorization)
        self.assertIn('[ "${plan_kind_prefix}" != "fieldzilla-staging-migration-iam" ]; then', workflow)
        self.assertIn('run.get("conclusion") != "success"',
                      (Path(__file__).resolve().parents[1] / "tools/opentofu_plan_authorization.py").read_text())

    def test_capture_rejects_plaintext_before_upload(self) -> None:
        document = plan()
        document["resource_changes"][0]["change"]["after"]["api_token"] = "not-a-real-token"
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SystemExit):
            auth.verify_plan_capture(self.args)
        document["resource_changes"][0]["change"]["after"].pop("api_token")
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        auth.verify_plan_capture(self.args)


if __name__ == "__main__":
    unittest.main()
