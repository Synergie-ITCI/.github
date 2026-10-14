"""Exact PR 521 plan evidence and fail-closed mutation tests."""

from __future__ import annotations

import copy
import contextlib
import hashlib
import io
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
        self.assertIn("steps.plan_capture_guard.outcome == 'success'", workflow)
        self.assertIn("Fail closed after plan-capture guard failure", workflow)
        self.assertIn("fieldzilla-plan-capture-diagnostic.json", workflow)
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

    def test_type_aware_ordinary_values_and_string_scanning(self) -> None:
        document = plan()
        values = {"manage_master_user_password": True, "password_rotation_enabled": False,
                  "retry_count": 3, "optional_password": None, "nested": [False, 2, None]}
        document["planned_values"] = {"root_module": {"resources": [{"values": values}]}}
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        auth.verify_plan_capture(self.args)
        values["manage_master_user_password"] = False
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        auth.verify_plan_capture(self.args)
        for field, value in (("manage_master_user_password", "true"),
                             ("comment", "password=synthetic-test-value"),
                             ("nested", ["-----BEGIN PRIVATE KEY----- synthetic"]),
                             ("private_key", "synthetic-private-key-material")):
            with self.subTest(field=field):
                original = values.get(field)
                values[field] = value
                self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_capture(self.args)
                if original is None and field not in ("optional_password",):
                    values.pop(field)
                else:
                    values[field] = original

        values["password"] = 123456
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SystemExit):
            auth.verify_plan_capture(self.args)

    def test_marked_sensitive_structures_still_fail_closed(self) -> None:
        for value in (123456, ["synthetic"], {"nested": "synthetic"}):
            with self.subTest(value_type=type(value).__name__):
                document = plan()
                document["output_changes"]["sensitive_output"] = {"sensitive": True, "value": value}
                self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_capture(self.args)

    def test_capture_failure_diagnostic_contains_no_value(self) -> None:
        document = plan()
        document["planned_values"] = {"root_module": {"resources": [{
            "address": "aws_db_instance.staging", "type": "aws_db_instance",
            "values": {"master_password": "synthetic-secret-do-not-print"},
        }]}}
        self.args.diagnostic_path = self.args.plan_json_path.parent / "diagnostic.json"
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            auth.verify_plan_capture(self.args)
        raw = self.args.diagnostic_path.read_text(encoding="utf-8")
        diagnostic = json.loads(raw)
        self.assertNotIn("synthetic-secret-do-not-print", raw)
        self.assertNotIn("synthetic-secret-do-not-print", stderr.getvalue())
        self.assertEqual(diagnostic, {
            "schema_version": 1,
            "path": "planned_values.root_module.resources.0.values.<key-sha256:"
                    + hashlib.sha256(b"master_password").hexdigest()[:16] + ">",
            "json_type": "string", "reason": "sensitive_key_string",
            "resource_address": "aws_db_instance.<name-sha256:"
                                + hashlib.sha256(b"staging").hexdigest()[:16] + ">",
            "resource_type": "aws_db_instance",
        })

    def test_capture_accepts_secrets_manager_arn_reference(self) -> None:
        document = plan()
        document["planned_values"] = {"root_module": {"resources": [{
            "address": "aws_db_instance.postgres", "type": "aws_db_instance",
            "values": {"manage_master_user_password": True, "master_user_secret": [{
                "secret_arn": "arn:aws:secretsmanager:ap-south-1:123456789012:secret:example-AbCdEf",
            }]},
        }]}}
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        auth.verify_plan_capture(self.args)

    def test_capture_accepts_rds_managed_secrets_manager_arn_reference(self) -> None:
        managed_reference = ":".join((
            "arn", "aws", "secretsmanager", "ap-south-1", "123456789012",
            "secret", "rds!db-033d7456-2c96-450d-9d48-f5de3025e51c-xmJRDx",
        ))
        document = plan()
        document["planned_values"] = {"root_module": {"resources": [{
            "address": "aws_db_instance.postgres", "type": "aws_db_instance",
            "values": {"manage_master_user_password": True, "master_user_secret": [{
                "secret_arn": managed_reference,
            }]},
        }]}}
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        auth.verify_plan_capture(self.args)

    def test_capture_rejects_credentials_and_invalid_secret_arn_references(self) -> None:
        values = (
            "synthetic-plaintext-password",
            "arn:aws:secretsmanager:ap-south-1:123456789012:secret:password=synthetic",
            "arn:aws:secretsmanager:ap-south-1:123456789012:secret:other!name-AbCdEf",
            "arn:aws:secretsmanager:ap-south-1:123456789012:secret:rds!other-AbCdEf",
            "arn:aws:secretsmanager:ap-south-1:123456789012:secret:rds!db-",
            "arn:aws:s3:ap-south-1:123456789012:secret:rds!db-example-AbCdEf",
            "arn:aws:secretsmanager:ap-south-1:12345:secret:rds!db-example-AbCdEf",
            "prefix arn:aws:secretsmanager:ap-south-1:123456789012:secret:rds!db-example-AbCdEf",
            "arn:aws:secretsmanager:ap-south-1:123456789012:secret:rds!db-example-AbCdEf suffix",
            "arn:aws:secretsmanager:ap-south-1:123456789012:secret:example\nplaintext",
            "arn:aws:secretsmanager:ap-south-1:123456789012:secret:",
            "https://user:password@example.invalid/secret",
        )
        for value in values:
            with self.subTest(value=value):
                document = plan()
                document["planned_values"] = {"root_module": {"resources": [{
                    "address": "aws_db_instance.postgres", "type": "aws_db_instance",
                    "values": {"master_user_secret": [{"secret_arn": value}]},
                }]}}
                self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_capture(self.args)

        self.assertIsNotNone(auth.classify_plan_secret({"password": "synthetic-plaintext"}))
        self.assertIsNotNone(auth.classify_plan_secret({
            "password": "arn:aws:secretsmanager:ap-south-1:123456789012:secret:rds!db-example-AbCdEf"
        }))
        self.assertIsNotNone(auth.classify_plan_secret({"secret_arn": "not-an-arn"}))

    def test_diagnostic_redacts_untrusted_map_keys_and_address(self) -> None:
        document = {"planned_values": {"root_module": {"resources": [{
            "address": 'aws_db_instance.example["unsafe-key"]', "type": "aws_db_instance",
            "values": {"https://private.example.invalid/user:secret@host": "password=synthetic-test-value"},
        }]}}}
        finding = auth.classify_plan_secret(document)
        self.assertIsNotNone(finding)
        path = self.args.plan_json_path.parent / "redacted.json"
        auth._write_plan_diagnostic(path, document, finding)
        diagnostic = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("<key-sha256:", diagnostic["path"])
        self.assertIsNone(diagnostic["resource_address"])
        self.assertNotIn("private.example", path.read_text(encoding="utf-8"))

    def test_capture_accepts_only_opentofu_sensitive_markers(self) -> None:
        document = plan()
        document["planned_values"] = {"root_module": {"resources": [{
            "values": {"name": auth.PR521_ROLE_NAME},
            "sensitive_values": {"private_key": True,
                                 "subject_alternative_names": [False, True]},
        }]}}
        document["resource_changes"][0]["change"]["after_sensitive"] = {
            "private_key": True, "nested": [{"names": [False, True]}]
        }
        document["resource_changes"][0]["change"]["before_sensitive"] = False
        original = copy.deepcopy(document)
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        auth.verify_plan_capture(self.args)
        self.assertEqual(json.loads(self.args.plan_json_path.read_text(encoding="utf-8")), original)
        auth.verify_pr521_staging_plan(document, self.args)

    def test_capture_rejects_private_key_material_even_in_metadata(self) -> None:
        for marker in ("synthetic-private-key-material", False, 1):
            with self.subTest(marker_type=type(marker).__name__):
                document = plan()
                document["planned_values"] = {"root_module": {"resources": [{
                    "sensitive_values": {"private_key": marker},
                }]}}
                self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_capture(self.args)

    def test_capture_rejects_malformed_list_markers(self) -> None:
        for marker in ("synthetic-private-key-material", 0, None, {"name": False}):
            with self.subTest(marker_type=type(marker).__name__):
                document = plan()
                document["planned_values"] = {"root_module": {"resources": [{
                    "sensitive_values": {"subject_alternative_names": [marker]},
                }]}}
                self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_capture(self.args)

    def test_capture_rejects_false_map_leaf_and_invalid_root_marker(self) -> None:
        document = plan()
        item = document["resource_changes"][0]["change"]
        item["before_sensitive"] = {"name": False}
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SystemExit):
            auth.verify_plan_capture(self.args)
        item["before_sensitive"] = "synthetic-private-key-material"
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SystemExit):
            auth.verify_plan_capture(self.args)

    def test_list_marker_does_not_hide_plaintext_in_normal_values(self) -> None:
        document = plan()
        document["planned_values"] = {"root_module": {"resources": [{
            "values": {"private_key": "synthetic-private-key-material"},
            "sensitive_values": {"subject_alternative_names": [False]},
        }]}}
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SystemExit):
            auth.verify_plan_capture(self.args)

    def test_capture_rejects_plaintext_in_normal_values(self) -> None:
        document = plan()
        document["planned_values"] = {"root_module": {"resources": [{
            "values": {"private_key": "synthetic-private-key-material"},
            "sensitive_values": {"private_key": True},
        }]}}
        self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SystemExit):
            auth.verify_plan_capture(self.args)

    def test_sensitive_marker_does_not_hide_unknown_iam_or_task_fields(self) -> None:
        for address, field in (
            ("aws_iam_role.staging_migration_execution", "permissions_boundary"),
            ('aws_ecs_task_definition.migration["staging"]', "execution_role_arn"),
        ):
            with self.subTest(address=address):
                document = plan()
                item = next(change for change in document["resource_changes"] if change["address"] == address)
                item["change"]["after_sensitive"] = {"private_key": True}
                item["change"]["after_unknown"][field] = True
                self.args.plan_json_path.write_text(json.dumps(document), encoding="utf-8")
                auth.verify_plan_capture(self.args)
                self.check_fails(document)


if __name__ == "__main__":
    unittest.main()
