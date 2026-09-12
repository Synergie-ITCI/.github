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
    "fieldzilla-staging-opentofu-apply.yml@refs/tags/pr-qa-v1-rc117"
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
            "uses: Synergie-ITCI/.github/actions/opentofu-plan-authorizer@pr-qa-v1-rc117",
            content,
        )

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
