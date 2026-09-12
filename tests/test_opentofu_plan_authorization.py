from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import opentofu_plan_authorization as auth  # noqa: E402


VALID_SHA = "a" * 40
VALID_PLAN = "b" * 64
VALID_WORKFLOW = (
    "Synergie-ITCI/.github/.github/workflows/"
    "fieldzilla-staging-opentofu-apply.yml@refs/tags/pr-qa-v1-rc120"
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

    def test_workflow_uses_release_action_without_private_central_checkout(self) -> None:
        workflow = ROOT / ".github" / "workflows" / "fieldzilla-staging-opentofu-apply.yml"
        content = workflow.read_text(encoding="utf-8")
        self.assertNotIn("Checkout immutable central workflow tooling", content)
        self.assertNotIn(".synergie-governance", content)
        self.assertIn(
            "uses: Synergie-ITCI/.github/actions/opentofu-plan-authorizer@pr-qa-v1-rc120",
            content,
        )
        self.assertIn("actions/upload-artifact@v4", content)
        self.assertIn("actions/download-artifact@v4", content)
        self.assertIn(
            "${{ runner.temp }}/approved-plan/${{ inputs.artifact-name }}/${{ inputs.artifact-name }}",
            content,
        )
        self.assertNotIn("Regenerate exact OpenTofu plan", content)

    def assert_rejected(self, **overrides: object) -> None:
        with self.assertRaises(SystemExit):
            auth.verify_inputs(valid_args(**overrides), now=NOW)

    def test_accepts_exact_reviewed_fallback_inputs(self) -> None:
        auth.verify_inputs(valid_args(), now=NOW)

    def test_rejects_wrong_actor(self) -> None:
        self.assert_rejected(actor="another-admin")

    def test_rejects_wrong_repository(self) -> None:
        self.assert_rejected(repository="Synergie-ITCI/other")

    def test_rejects_wrong_environment(self) -> None:
        self.assert_rejected(environment="production")

    def test_rejects_wrong_or_mismatched_sha(self) -> None:
        self.assert_rejected(expected_sha="A" * 40)
        self.assert_rejected(github_sha="c" * 40)

    def test_rejects_wrong_plan_hash(self) -> None:
        self.assert_rejected(expected_plan_sha256="not-a-hash")

    def test_rejects_expired_or_long_expiry(self) -> None:
        self.assert_rejected(expires_at="2026-09-12T04:59:00Z")
        self.assert_rejected(expires_at="2026-09-12T06:01:00Z")

    def test_rejects_reuse_id_format(self) -> None:
        self.assert_rejected(authorization_id="../bad")

    def test_rejects_unsupported_native_reviewer_fallback(self) -> None:
        self.assert_rejected(native_reviewers_available="true")

    def test_verifies_native_reviewer_fallback_from_environment_rules(self) -> None:
        with mock.patch.object(auth, "github_api", return_value={"protection_rules": []}):
            auth.verify_native_reviewers(Namespace(native_reviewers_available="false"))

    def test_rejects_native_reviewers_existing_or_unavailable(self) -> None:
        with mock.patch.object(
            auth,
            "github_api",
            return_value={"protection_rules": [{"type": "required_reviewers"}]},
        ):
            with self.assertRaises(SystemExit):
                auth.verify_native_reviewers(Namespace(native_reviewers_available="false"))
        with mock.patch.object(auth, "github_api", return_value={}):
            with self.assertRaises(SystemExit):
                auth.verify_native_reviewers(Namespace(native_reviewers_available="false"))

    def test_rejects_non_immutable_workflow_identity(self) -> None:
        self.assert_rejected(
            job_workflow_ref="Synergie-ITCI/.github/.github/workflows/fieldzilla-staging-opentofu-apply.yml@main"
        )

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
            "job_workflow_ref": "Synergie-ITCI/.github/.github/workflows/other.yml@refs/tags/pr-qa-v1-rc116",
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

    def test_rejects_modified_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan.tfplan"
            plan.write_bytes(b"approved")
            good = hashlib.sha256(b"approved").hexdigest()
            auth.verify_plan(Namespace(plan_path=plan, expected_plan_sha256=good))
            plan.write_bytes(b"modified")
            with self.assertRaises(SystemExit):
                auth.verify_plan(Namespace(plan_path=plan, expected_plan_sha256=good))

    def test_verifies_source_plan_artifact(self) -> None:
        args = valid_args(
            source_run_id="34706513572",
            artifact_id="123456",
            artifact_name=f"fieldzilla-staging-plan-{VALID_SHA}-34706513572",
            expected_artifact_digest="sha256:" + "c" * 64,
        )

        def fake_api(path: str, method: str = "GET", payload: dict[str, object] | None = None):
            if path == "actions/runs/34706513572":
                return {
                    "head_repository": {"full_name": "Synergie-ITCI/programme-management-platform"},
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
                            "digest": "sha256:" + "c" * 64,
                        }
                    ]
                }
            raise AssertionError(path)

        with mock.patch.object(auth, "github_api", side_effect=fake_api):
            auth.verify_source_artifact(args)

    def test_rejects_wrong_source_artifact_identity(self) -> None:
        args = valid_args(
            source_run_id="34706513572",
            artifact_id="123456",
            artifact_name=f"fieldzilla-staging-plan-{VALID_SHA}-34706513572",
            expected_artifact_digest="d" * 64,
        )
        with mock.patch.object(
            auth,
            "github_api",
            return_value={
                "head_repository": {"full_name": "Synergie-ITCI/other"},
                "head_sha": VALID_SHA,
                "conclusion": "success",
                "path": ".github/workflows/fieldzilla-staging-iac.yml",
                "run_attempt": 1,
            },
        ):
            with self.assertRaises(SystemExit):
                auth.verify_source_artifact(args)

    def test_verifies_downloaded_artifact_metadata_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            plan = artifact_dir / "fieldzilla-staging.tfplan"
            plan.write_bytes(b"approved")
            plan_sha = hashlib.sha256(b"approved").hexdigest()
            artifact_name = f"fieldzilla-staging-plan-{VALID_SHA}-34706513572"
            (artifact_dir / "metadata.json").write_text(
                json.dumps(
                    {
                        "repository": "Synergie-ITCI/programme-management-platform",
                        "environment": "synergie-app-staging",
                        "commit_sha": VALID_SHA,
                        "workflow_run_id": "34706513572",
                        "artifact_name": artifact_name,
                        "plan_sha256": plan_sha,
                    }
                ),
                encoding="utf-8",
            )
            auth.verify_artifact_metadata(
                Namespace(
                    artifact_dir=artifact_dir,
                    expected_sha=VALID_SHA,
                    expected_plan_sha256=plan_sha,
                    source_run_id="34706513572",
                    artifact_id="123456",
                    artifact_name=artifact_name,
                    expected_artifact_digest="e" * 64,
                )
            )

    def test_rejects_artifact_substitution_and_prohibited_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            for name in (
                "fieldzilla-staging.tfplan",
                "fieldzilla-staging.plan.txt",
                "fieldzilla-staging.plan.json",
                "metadata.json",
                "SHA256SUMS",
            ):
                (artifact_dir / name).write_text("ok", encoding="utf-8")
            auth.verify_artifact_files(Namespace(artifact_dir=artifact_dir))
            (artifact_dir / "terraform.tfstate").write_text("{}", encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_artifact_files(Namespace(artifact_dir=artifact_dir))

    def test_verifies_plan_safety_and_rejects_dns_or_production(self) -> None:
        safe = {
            "variables": {
                "enable_production": {"value": False},
                "route53_zone_id": {"value": ""},
                "container_instance_type": {"value": "t4g.small"},
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
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json))
            unsafe = dict(safe)
            unsafe["resource_changes"] = [
                {"address": "aws_route53_record.validation", "type": "aws_route53_record", "change": {"actions": ["create"], "after": {}}}
            ]
            plan_json.write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json))

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
