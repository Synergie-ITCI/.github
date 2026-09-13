from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
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
VALID_PLAN = "b" * 64
VALID_IMPORT_MAP = "c" * 64
VALID_WORKFLOW = (
    "Synergie-ITCI/.github/.github/workflows/"
    "fieldzilla-staging-opentofu-apply.yml@refs/tags/pr-qa-v1-rc121"
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
        self.assertIn("uses: Synergie-ITCI/.github/actions/opentofu-plan-authorizer@pr-qa-v1-rc121", workflow)
        self.assertIn("tofu -chdir=infra/aws init -input=false -lockfile=readonly", workflow)
        self.assertIn("dynamodb_table = \"${STATE_LOCK_TABLE}\"", workflow)
        self.assertIn("Backup current remote state object", workflow)
        self.assertIn("Verify approved import map", workflow)
        self.assertIn("Controlled import into locked remote state", workflow)
        self.assertIn("${{ runner.temp }}/approved/${{ inputs.artifact-name }}/${{ inputs.artifact-name }}", workflow)
        self.assertNotIn("-backend=false", workflow)
        self.assertNotIn("devops-audit", workflow)

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

    def test_rejects_bad_hashes_expiry_reuse_or_native_reviewers(self) -> None:
        self.assert_rejected(expected_plan_sha256="not-a-hash")
        self.assert_rejected(expected_import_map_sha256="not-a-hash")
        self.assert_rejected(expires_at="2026-09-12T04:59:00Z")
        self.assert_rejected(expires_at="2026-09-12T06:01:00Z")
        self.assert_rejected(authorization_id="../bad")
        self.assert_rejected(native_reviewers_available="true")

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
            "job_workflow_ref": "Synergie-ITCI/.github/.github/workflows/other.yml@refs/tags/pr-qa-v1-rc121",
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
                        "environment": "synergie-app-staging",
                        "commit_sha": VALID_SHA,
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
                "backend.json",
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
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))
            unsafe = dict(safe)
            unsafe["resource_changes"] = [
                {"address": "aws_route53_record.validation", "type": "aws_route53_record", "change": {"actions": ["create"], "after": {}}}
            ]
            plan_json.write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal"))

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
