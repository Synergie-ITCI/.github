from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import opentofu_plan_authorization as auth  # noqa: E402


VALID_SHA = "a" * 40
DEPLOY_SHA = "ef924580fb690c1e8ec9dc0f27fa1d27b204c111"
IMAGE_DIGEST = "sha256:" + "9" * 64
ECS_FAMILIES = ",".join(sorted(auth.APPROVED_FIELDZILLA_TASK_FAMILIES))
VALID_PLAN = "b" * 64
VALID_IMPORT_MAP = "c" * 64
VALID_WORKFLOW = (
    "Synergie-ITCI/.github/.github/workflows/"
    "fieldzilla-staging-opentofu-apply.yml@refs/tags/pr-qa-v1-rc147"
)
NOW = dt.datetime(2026, 9, 12, 5, 0, tzinfo=dt.UTC)


def valid_args(**overrides: object) -> Namespace:
    values = {
        "actor": "SaurabhVermaIN",
        "repository": "Synergie-ITCI/programme-management-platform",
        "environment": "synergie-app-staging",
        "expected_sha": VALID_SHA,
        "github_sha": VALID_SHA,
        "expected_plan_sha256": VALID_PLAN,
        "expected_import_map_sha256": VALID_IMPORT_MAP,
        "image_digest": "",
        "ecs_families": "",
        "expires_at": "2026-09-12T05:30:00Z",
        "authorization_id": "fieldzilla-20260912-01",
        "native_reviewers_available": "false",
        "job_workflow_ref": VALID_WORKFLOW,
    }
    values.update(overrides)
    return Namespace(**values)


class FieldZillaPlanAuthorizationTests(unittest.TestCase):
    def test_release_action_verifier_matches_tool(self) -> None:
        tool = ROOT / "tools" / "opentofu_plan_authorization.py"
        action = ROOT / "actions" / "opentofu-plan-authorizer" / "opentofu_plan_authorization.py"
        self.assertEqual(tool.read_text(encoding="utf-8"), action.read_text(encoding="utf-8"))

    def test_workflow_uses_remote_state_release_action(self) -> None:
        workflow = (ROOT / ".github/workflows/fieldzilla-staging-opentofu-apply.yml").read_text(encoding="utf-8")
        self.assertIn("uses: Synergie-ITCI/.github/actions/opentofu-plan-authorizer@pr-qa-v1-rc147", workflow)
        self.assertIn("tofu -chdir=infra/aws init -input=false -lockfile=readonly", workflow)
        self.assertIn("dynamodb_table = \"${STATE_LOCK_TABLE}\"", workflow)
        self.assertIn("Backup current remote state object", workflow)
        self.assertIn("Verify approved import map", workflow)
        self.assertIn("Controlled import into locked remote state", workflow)
        self.assertIn("${{ runner.temp }}/approved/${{ inputs.artifact-name }}/${{ inputs.artifact-name }}", workflow)
        self.assertNotIn("-backend=false", workflow)
        self.assertNotIn("devops-audit", workflow)

    def test_fieldzilla_workflow_does_not_mix_release_pins(self) -> None:
        workflow = (ROOT / ".github/workflows/fieldzilla-staging-opentofu-apply.yml").read_text(encoding="utf-8")
        central = re.search(
            r"CENTRAL_WORKFLOW_REF: .*fieldzilla-staging-opentofu-apply\.yml@refs/tags/(pr-qa-v1-rc\d+)",
            workflow,
        )
        self.assertIsNotNone(central)
        internal_pins = set(re.findall(r"opentofu-plan-authorizer@(pr-qa-v1-rc\d+)", workflow))
        self.assertEqual(internal_pins, {central.group(1)})

    def assert_rejected(self, **overrides: object) -> None:
        with self.assertRaises(SystemExit):
            auth.verify_inputs(valid_args(**overrides), now=NOW)

    def test_accepts_exact_reviewed_fallback_inputs(self) -> None:
        auth.verify_inputs(valid_args(), now=NOW)

    def test_rejects_wrong_actor_repo_environment_or_sha(self) -> None:
        self.assert_rejected(actor="another-admin")
        self.assert_rejected(repository="Synergie-ITCI/other")
        self.assert_rejected(environment="production")
        self.assert_rejected(expected_sha="A" * 40)
        self.assert_rejected(github_sha="d" * 40)
        self.assert_rejected(repository_id=999)

    def test_rejects_bad_hashes_expiry_reuse_or_native_reviewers(self) -> None:
        self.assert_rejected(expected_plan_sha256="not-a-hash")
        self.assert_rejected(expected_import_map_sha256="not-a-hash")
        self.assert_rejected(expires_at="2026-09-12T04:59:00Z")
        self.assert_rejected(expires_at="2026-09-12T06:01:00Z")
        self.assert_rejected(authorization_id="../bad")
        self.assert_rejected(native_reviewers_available="true")
        self.assert_rejected(image_digest="not-a-digest")
        self.assert_rejected(ecs_families="fieldzilla-staging-api")

    def test_verifies_native_reviewer_fallback_from_environment_rules(self) -> None:
        with mock.patch.object(auth, "github_api", return_value={"protection_rules": []}):
            auth.verify_native_reviewers(Namespace(native_reviewers_available="false"))

    def test_rejects_native_reviewers_existing_or_unavailable(self) -> None:
        with mock.patch.object(auth, "github_api", return_value={"protection_rules": [{"type": "required_reviewers"}]}):
            with self.assertRaises(SystemExit):
                auth.verify_native_reviewers(Namespace(native_reviewers_available="false"))
        with mock.patch.object(auth, "github_api", return_value={}):
            with self.assertRaises(SystemExit):
                auth.verify_native_reviewers(Namespace(native_reviewers_available="false"))

    def test_verifies_oidc_workflow_identity(self) -> None:
        claims = {
            "aud": "sts.amazonaws.com",
            "repository": "Synergie-ITCI/programme-management-platform",
            "job_workflow_ref": VALID_WORKFLOW,
            "sub": (
                "repo:Synergie-ITCI@209829096/"
                "programme-management-platform@1315697868:environment:synergie-app-staging"
            ),
        }
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / "token.jwt"
            token.write_text(f"header.{payload}.sig", encoding="utf-8")
            auth.verify_oidc(Namespace(token_file=token, job_workflow_ref=VALID_WORKFLOW))

    def test_rejects_wrong_oidc_workflow_identity(self) -> None:
        claims = {
            "aud": "sts.amazonaws.com",
            "repository": "Synergie-ITCI/programme-management-platform",
            "job_workflow_ref": "Synergie-ITCI/.github/.github/workflows/other.yml@refs/tags/pr-qa-v1-rc142",
            "sub": (
                "repo:Synergie-ITCI@209829096/"
                "programme-management-platform@1315697868:environment:synergie-app-staging"
            ),
        }
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / "token.jwt"
            token.write_text(f"header.{payload}.sig", encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_oidc(Namespace(token_file=token, job_workflow_ref=VALID_WORKFLOW))

    def test_verifies_backend_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backend = Path(tmp) / "backend.json"
            backend.write_text(
                json.dumps(
                    {
                        "account_id": "918870682888",
                        "region": "ap-south-1",
                        "bucket": "synergie-fieldzilla-opentofu-state-918870682888-ap-south-1",
                        "key": "programme-management-platform/fieldzilla/staging/opentofu.tfstate",
                        "dynamodb_table": "synergie-fieldzilla-opentofu-locks",
                        "bucket_versioning": "Enabled",
                        "bucket_encryption": "aws:kms",
                        "public_access_blocked": True,
                    }
                ),
                encoding="utf-8",
            )
            auth.verify_backend(Namespace(backend_metadata_path=backend))

    def test_verifies_source_plan_artifact(self) -> None:
        args = valid_args(
            source_run_id="34706513572",
            artifact_id="123456",
            artifact_name=f"fieldzilla-staging-plan-{VALID_SHA}-34706513572",
            expected_artifact_digest="sha256:" + "d" * 64,
        )

        def fake_api(path: str, method: str = "GET", payload: dict[str, object] | None = None):
            if path == "actions/runs/34706513572":
                return {
                    "head_repository": {"full_name": "Synergie-ITCI/programme-management-platform", "id": 1315697868},
                    "head_sha": VALID_SHA,
                    "conclusion": "success",
                    "path": ".github/workflows/fieldzilla-staging-iac.yml",
                    "run_attempt": 1,
                }
            if path == "actions/runs/34706513572/artifacts?per_page=100":
                return {
                    "artifacts": [
                        {
                            "id": 123456,
                            "name": f"fieldzilla-staging-plan-{VALID_SHA}-34706513572",
                            "expired": False,
                            "digest": "sha256:" + "d" * 64,
                        }
                    ]
                }
            raise AssertionError(path)

        with mock.patch.object(auth, "github_api", side_effect=fake_api):
            auth.verify_source_artifact(args)

    def test_verifies_downloaded_artifact_metadata_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            plan = artifact_dir / "fieldzilla-staging.tfplan"
            import_map = artifact_dir / "import-map.json"
            plan.write_bytes(b"approved")
            import_map.write_bytes(b"map")
            plan_sha = hashlib.sha256(b"approved").hexdigest()
            import_sha = hashlib.sha256(b"map").hexdigest()
            artifact_name = f"fieldzilla-staging-plan-{VALID_SHA}-34706513572"
            (artifact_dir / "metadata.json").write_text(
                json.dumps(
                    {
                        "repository": "Synergie-ITCI/programme-management-platform",
                        "repository_id": 1315697868,
                        "environment": "synergie-app-staging",
                        "commit_sha": VALID_SHA,
                        "image_digest": IMAGE_DIGEST,
                        "ecs_families": sorted(auth.APPROVED_FIELDZILLA_TASK_FAMILIES),
                        "workflow_run_id": "34706513572",
                        "artifact_name": artifact_name,
                        "plan_sha256": plan_sha,
                        "state_backend": "s3",
                        "state_bucket": "synergie-fieldzilla-opentofu-state-918870682888-ap-south-1",
                        "state_key": "programme-management-platform/fieldzilla/staging/opentofu.tfstate",
                        "lock_table": "synergie-fieldzilla-opentofu-locks",
                    }
                ),
                encoding="utf-8",
            )
            auth.verify_artifact_metadata(
                Namespace(
                    artifact_dir=artifact_dir,
                    expected_sha=VALID_SHA,
                    expected_plan_sha256=plan_sha,
                    expected_import_map_sha256=import_sha,
                    image_digest=IMAGE_DIGEST,
                    ecs_families=ECS_FAMILIES,
                    source_run_id="34706513572",
                    artifact_id="123456",
                    artifact_name=artifact_name,
                    expected_artifact_digest="e" * 64,
                )
            )

    def test_routine_ecs_authorization_binds_digest_family_and_blocks_non_ecs(self) -> None:
        before_containers = [
            {
                "name": "api",
                "image": "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:774051cf74a7b8ada2f26e5c24959fdc99d6380b",
                "cpu": 256,
                "memory": 512,
                "essential": True,
            }
        ]
        after_containers = [
            {
                **before_containers[0],
                "image": f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:{DEPLOY_SHA}",
                "imageDigest": IMAGE_DIGEST,
            }
        ]
        before = {
            "family": "fieldzilla-staging-api",
            "cpu": "256",
            "memory": "512",
            "network_mode": "bridge",
            "requires_compatibilities": ["EC2"],
            "execution_role_arn": "arn:aws:iam::918870682888:role/SynergieFieldzillaStagingEcsExecution",
            "task_role_arn": "arn:aws:iam::918870682888:role/SynergieFieldzillaStagingTask",
            "container_definitions": json.dumps(before_containers, sort_keys=True),
            "runtime_platform": [],
            "track_latest": False,
            "volume": [],
        }
        after = {**before, "container_definitions": json.dumps(after_containers, sort_keys=True)}
        base = {
            "variables": {
                "enable_production": {"value": False},
                "route53_zone_id": {"value": ""},
                "container_instance_type": {"value": "c6g.medium"},
                "monthly_budget_usd": {"value": "100"},
                "image_tag": {"value": DEPLOY_SHA},
            },
            "resource_changes": [
                {
                    "address": 'aws_ecs_task_definition.api["staging"]',
                    "type": "aws_ecs_task_definition",
                    "change": {"actions": ["delete", "create"], "before": before, "after": after},
                },
                {
                    "address": 'aws_ecs_service.api["staging"]',
                    "type": "aws_ecs_service",
                    "change": {
                        "actions": ["update"],
                        "before": {"task_definition": "arn:aws:ecs:ap-south-1:918870682888:task-definition/fieldzilla-staging-api:3"},
                        "after": {"task_definition": "arn:aws:ecs:ap-south-1:918870682888:task-definition/fieldzilla-staging-api:4"},
                    },
                },
            ],
        }
        args = Namespace(plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest=IMAGE_DIGEST, ecs_families=ECS_FAMILIES)
        with tempfile.TemporaryDirectory() as tmp:
            plan_json = Path(tmp) / "plan.json"
            plan_json.write_text(json.dumps(base), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

            wrong_digest = json.loads(json.dumps(base))
            containers = json.loads(wrong_digest["resource_changes"][0]["change"]["after"]["container_definitions"])
            containers[0]["imageDigest"] = "sha256:" + "8" * 64
            wrong_digest["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(containers)
            plan_json.write_text(json.dumps(wrong_digest), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

            destructive = json.loads(json.dumps(base))
            destructive["resource_changes"].append(
                {"address": "aws_db_instance.fieldzilla", "type": "aws_db_instance", "change": {"actions": ["delete"], "before": {}, "after": None}}
            )
            plan_json.write_text(json.dumps(destructive), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

            role_broadening = json.loads(json.dumps(base))
            role_broadening["resource_changes"][1]["change"]["after"]["desired_count"] = 2
            plan_json.write_text(json.dumps(role_broadening), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

    def test_rejects_artifact_substitution_and_prohibited_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            for name in (
                "fieldzilla-staging.tfplan",
                "fieldzilla-staging.plan.txt",
                "fieldzilla-staging.plan.json",
                "metadata.json",
                "SHA256SUMS",
                "backend.json",
            ):
                (artifact_dir / name).write_text("ok", encoding="utf-8")
            auth.verify_artifact_files(Namespace(artifact_dir=artifact_dir))
            (artifact_dir / "terraform.tfstate").write_text("{}", encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_artifact_files(Namespace(artifact_dir=artifact_dir))

    def test_verifies_plan_safety_and_rejects_dns_or_production(self) -> None:
        def safe_plan(instance_type: str = "t4g.small") -> dict[str, object]:
            return {
                "variables": {
                    "enable_production": {"value": False},
                    "route53_zone_id": {"value": ""},
                    "container_instance_type": {"value": instance_type},
                    "monthly_budget_usd": {"value": "100"},
                },
                "resource_changes": [
                    {
                        "address": "aws_ecs_service.api[\"staging\"]",
                        "type": "aws_ecs_service",
                        "change": {"actions": ["create"], "after": {"environment": "staging"}},
                    }
                ],
            }

        safe = safe_plan()
        with tempfile.TemporaryDirectory() as tmp:
            plan_json = Path(tmp) / "plan.json"
            plan_json.write_text(json.dumps(safe), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))
            plan_json.write_text(json.dumps(safe_plan("c6g.medium")), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))
            plan_json.write_text(json.dumps(safe_plan("m6g.medium")), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))
            unsafe = dict(safe)
            unsafe["resource_changes"] = [
                {"address": "aws_route53_record.validation", "type": "aws_route53_record", "change": {"actions": ["create"], "after": {}}}
            ]
            plan_json.write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))

    def test_remote_state_plan_safety_keeps_c6g_allowance_narrow(self) -> None:
        safe = {
            "variables": {
                "enable_production": {"value": False},
                "route53_zone_id": {"value": ""},
                "container_instance_type": {"value": "c6g.medium"},
                "monthly_budget_usd": {"value": "100"},
            },
            "resource_changes": [
                {
                    "address": "aws_ecs_service.api[\"staging\"]",
                    "type": "aws_ecs_service",
                    "change": {"actions": ["create"], "after": {"environment": "staging"}},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            plan_json = Path(tmp) / "plan.json"
            plan_json.write_text(json.dumps(safe), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))
            safe["variables"]["container_instance_type"]["value"] = "c7g.medium"
            plan_json.write_text(json.dumps(safe), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))

    def test_allows_only_fieldzilla_staging_ecs_task_definition_sha_revision(self) -> None:
        container_before = [
            {
                "name": "api",
                "image": "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:bootstrap",
                "cpu": 256,
                "memory": 512,
                "essential": True,
                "secrets": [{"name": "APP_KEY", "valueFrom": "arn:aws:secretsmanager:ap-south-1:918870682888:secret:/synergie/fieldzilla/staging/runtime:APP_KEY::"}],
            }
        ]
        container_after = [{**container_before[0], "image": f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:{DEPLOY_SHA}"}]
        before = {
            "family": "fieldzilla-staging-api",
            "cpu": "256",
            "memory": "512",
            "network_mode": "bridge",
            "requires_compatibilities": ["EC2"],
            "execution_role_arn": "arn:aws:iam::918870682888:role/SynergieFieldzillaStagingEcsExecution",
            "task_role_arn": "arn:aws:iam::918870682888:role/SynergieFieldzillaStagingTask",
            "container_definitions": json.dumps(container_before, sort_keys=True),
            "runtime_platform": [],
            "track_latest": False,
            "volume": [],
        }
        after = {**before, "container_definitions": json.dumps(container_after, sort_keys=True)}
        plan = {
            "variables": {
                "enable_production": {"value": False},
                "route53_zone_id": {"value": ""},
                "container_instance_type": {"value": "c6g.medium"},
                "monthly_budget_usd": {"value": "100"},
                "image_tag": {"value": DEPLOY_SHA},
            },
            "resource_changes": [
                {
                    "address": 'aws_ecs_task_definition.api["staging"]',
                    "type": "aws_ecs_task_definition",
                    "change": {"actions": ["delete", "create"], "before": before, "after": after},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            plan_json = Path(tmp) / "plan.json"
            plan_json.write_text(json.dumps(plan), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            normalized_empty_fields = json.loads(json.dumps(plan))
            normalized_empty_fields["resource_changes"][0]["change"]["before"]["ipc_mode"] = ""
            normalized_empty_fields["resource_changes"][0]["change"]["after"]["ipc_mode"] = None
            normalized_empty_fields["resource_changes"][0]["change"]["before"]["pid_mode"] = ""
            normalized_empty_fields["resource_changes"][0]["change"]["after"]["pid_mode"] = None
            plan_json.write_text(json.dumps(normalized_empty_fields), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            approved_previous_sha = "774051cf74a7b8ada2f26e5c24959fdc99d6380b"
            approved_previous = json.loads(json.dumps(plan))
            previous_containers = json.loads(approved_previous["resource_changes"][0]["change"]["before"]["container_definitions"])
            previous_containers[0]["image"] = (
                "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:"
                f"{approved_previous_sha}"
            )
            approved_previous["resource_changes"][0]["change"]["before"]["container_definitions"] = json.dumps(previous_containers)
            plan_json.write_text(json.dumps(approved_previous), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            last_deployed = json.loads(json.dumps(plan))
            last_deployed_containers = json.loads(last_deployed["resource_changes"][0]["change"]["before"]["container_definitions"])
            last_deployed_containers[0]["image"] = (
                "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:"
                "774051cf74a7b8ada2f26e5c24959fdc99d6380b"
            )
            last_deployed["resource_changes"][0]["change"]["before"]["container_definitions"] = json.dumps(last_deployed_containers)
            plan_json.write_text(json.dumps(last_deployed), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            wrong_target_sha = json.loads(json.dumps(plan))
            wrong_target_sha["variables"]["image_tag"]["value"] = "1111111111111111111111111111111111111111"
            plan_json.write_text(json.dumps(wrong_target_sha), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(
                    Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families="")
                )

            unsafe_pid_mode = json.loads(json.dumps(plan))
            unsafe_pid_mode["resource_changes"][0]["change"]["before"]["pid_mode"] = ""
            unsafe_pid_mode["resource_changes"][0]["change"]["after"]["pid_mode"] = "task"
            plan_json.write_text(json.dumps(unsafe_pid_mode), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))

            unsafe_role = json.loads(json.dumps(plan))
            unsafe_role["resource_changes"][0]["change"]["after"]["task_role_arn"] = "arn:aws:iam::918870682888:role/Other"
            plan_json.write_text(json.dumps(unsafe_role), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))

            unsafe_container = json.loads(json.dumps(plan))
            containers = json.loads(unsafe_container["resource_changes"][0]["change"]["after"]["container_definitions"])
            containers[0]["secrets"] = []
            unsafe_container["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(containers)
            plan_json.write_text(json.dumps(unsafe_container), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))

            unsafe_s3 = json.loads(json.dumps(plan))
            unsafe_s3["resource_changes"] = [
                {
                    "address": "aws_s3_bucket.evidence",
                    "type": "aws_s3_bucket",
                    "change": {"actions": ["delete", "create"], "before": {"bucket": "old"}, "after": {"bucket": "new"}},
                }
            ]
            plan_json.write_text(json.dumps(unsafe_s3), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))

            retired_revision = json.loads(json.dumps(plan))
            retired_containers = json.loads(before["container_definitions"])
            retired_containers[0]["image"] = (
                "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:"
                "774051cf74a7b8ada2f26e5c24959fdc99d6380b"
            )
            retired_before = {**before, "container_definitions": json.dumps(retired_containers)}
            retired_revision["resource_changes"][0]["change"] = {
                "actions": ["delete"],
                "before": retired_before,
                "after": None,
            }
            plan_json.write_text(json.dumps(retired_revision), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            wrong_family_retirement = json.loads(json.dumps(retired_revision))
            wrong_family_retirement["resource_changes"][0]["change"]["before"]["family"] = "fieldzilla-production-api"
            plan_json.write_text(json.dumps(wrong_family_retirement), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(
                    Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families="")
                )

            wrong_image_retirement = json.loads(json.dumps(retired_revision))
            wrong_image_containers = json.loads(wrong_image_retirement["resource_changes"][0]["change"]["before"]["container_definitions"])
            wrong_image_containers[0]["image"] = (
                "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/other/staging/api:"
                "2222222222222222222222222222222222222222"
            )
            wrong_image_retirement["resource_changes"][0]["change"]["before"]["container_definitions"] = json.dumps(wrong_image_containers)
            plan_json.write_text(json.dumps(wrong_image_retirement), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(
                    Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families="")
                )

    def test_runtime_secret_addition_approved_and_other_mutations_rejected(self) -> None:
        """Narrowly bound: after may add runtime secret refs; all other mutations fail closed."""
        runtime_prefix = auth.RUNTIME_SECRET_ARN_PREFIX
        existing_secret = {"name": "APP_KEY", "valueFrom": f"{runtime_prefix}APP_KEY::"}
        new_secret = {"name": "APP_ADMIN_WEB_BASE_URL", "valueFrom": f"{runtime_prefix}APP_ADMIN_WEB_BASE_URL::"}
        container_before = [
            {
                "name": "api",
                "image": "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:bootstrap",
                "cpu": 256,
                "memory": 512,
                "essential": True,
                "secrets": [existing_secret],
            }
        ]
        container_after_ok = [
            {
                **container_before[0],
                "image": f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:{DEPLOY_SHA}",
                "secrets": [existing_secret, new_secret],
            }
        ]
        base = {
            "family": "fieldzilla-staging-api",
            "cpu": "256",
            "memory": "512",
            "network_mode": "bridge",
            "requires_compatibilities": ["EC2"],
            "execution_role_arn": "arn:aws:iam::918870682888:role/SynergieFieldzillaStagingEcsExecution",
            "task_role_arn": "arn:aws:iam::918870682888:role/SynergieFieldzillaStagingTask",
            "runtime_platform": [],
            "track_latest": False,
            "volume": [],
        }
        before = {**base, "container_definitions": json.dumps(container_before, sort_keys=True)}
        after_ok = {**base, "container_definitions": json.dumps(container_after_ok, sort_keys=True)}
        plan = {
            "variables": {"enable_production": {"value": False}, "route53_zone_id": {"value": ""}, "container_instance_type": {"value": "c6g.medium"}, "monthly_budget_usd": {"value": "100"}, "image_tag": {"value": DEPLOY_SHA}},
            "resource_changes": [{"address": 'aws_ecs_task_definition.api["staging"]', "type": "aws_ecs_task_definition", "change": {"actions": ["delete", "create"], "before": before, "after": after_ok}}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            plan_json = Path(tmp) / "plan.json"

            # Approved: existing secret unchanged, one new runtime secret added.
            plan_json.write_text(json.dumps(plan), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            # Approved: two new runtime secrets added.
            second_new = {"name": "APP_CORS_ORIGINS", "valueFrom": f"{runtime_prefix}APP_CORS_ORIGINS::"}
            two_new = json.loads(json.dumps(plan))
            cs = json.loads(two_new["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [existing_secret, new_secret, second_new]
            two_new["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(two_new), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            # Rejected: existing secret removed from after.
            missing_existing = json.loads(json.dumps(plan))
            cs = json.loads(missing_existing["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [new_secret]
            missing_existing["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(missing_existing), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            # Rejected: new secret's valueFrom references a non-runtime ARN.
            bad_arn = json.loads(json.dumps(plan))
            cs = json.loads(bad_arn["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [existing_secret, {"name": "EVIL_KEY", "valueFrom": "arn:aws:secretsmanager:ap-south-1:918870682888:secret:/other/secret:KEY::"}]
            bad_arn["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(bad_arn), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            # Rejected: new secret references a different account's runtime ARN.
            foreign_arn = json.loads(json.dumps(plan))
            cs = json.loads(foreign_arn["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [existing_secret, {"name": "APP_URL", "valueFrom": "arn:aws:secretsmanager:ap-south-1:999999999999:secret:/synergie/fieldzilla/staging/runtime-xABCDE:APP_URL::"}]
            foreign_arn["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(foreign_arn), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            # Rejected: existing secret's valueFrom mutated.
            mutated_existing = json.loads(json.dumps(plan))
            cs = json.loads(mutated_existing["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [{"name": "APP_KEY", "valueFrom": f"{runtime_prefix}APP_KEY_EVIL::"}, new_secret]
            mutated_existing["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(mutated_existing), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            # Rejected: non-secret container field mutated (essential flag changed) alongside valid secret add.
            mutated_field = json.loads(json.dumps(plan))
            cs = json.loads(mutated_field["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["essential"] = False
            cs[0]["secrets"] = [existing_secret, new_secret]
            mutated_field["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(mutated_field), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

            # Rejected: new secret references the production environment rather than staging.
            prod_env = json.loads(json.dumps(plan))
            cs = json.loads(prod_env["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [existing_secret, {"name": "APP_PROD_KEY", "valueFrom": "arn:aws:secretsmanager:ap-south-1:918870682888:secret:/synergie/fieldzilla/production/runtime-pXXXXX:APP_PROD_KEY::"}]
            prod_env["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(prod_env), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest="", ecs_families=""))

    def test_verifies_import_map_and_rejects_wrong_ownership(self) -> None:
        good_doc = {
            "repository": "Synergie-ITCI/programme-management-platform",
            "environment": "synergie-app-staging",
            "imports": [
                {
                    "address": "aws_vpc.this",
                    "id": "vpc-123",
                    "evidence": {
                        "Application": "fieldzilla",
                        "Repository": "Synergie-ITCI/programme-management-platform",
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            import_map = Path(tmp) / "import-map.json"
            import_map.write_text(json.dumps(good_doc), encoding="utf-8")
            good_sha = hashlib.sha256(import_map.read_bytes()).hexdigest()
            auth.verify_import_map(Namespace(import_map_path=import_map, expected_import_map_sha256=good_sha))
            bad_doc = dict(good_doc)
            bad_doc["imports"] = [{**good_doc["imports"][0], "evidence": {"Application": "other"}}]
            import_map.write_text(json.dumps(bad_doc), encoding="utf-8")
            bad_sha = hashlib.sha256(import_map.read_bytes()).hexdigest()
            with self.assertRaises(SystemExit):
                auth.verify_import_map(Namespace(import_map_path=import_map, expected_import_map_sha256=bad_sha))

    def test_rejects_reused_authorization(self) -> None:
        deployment = {
            "payload": {
                "authorization_id": "fieldzilla-20260912-01",
                "environment": "synergie-app-staging",
            }
        }
        with mock.patch.object(auth, "github_api", return_value=[deployment]):
            with self.assertRaises(SystemExit):
                auth.check_single_use(valid_args())


if __name__ == "__main__":
    unittest.main()
