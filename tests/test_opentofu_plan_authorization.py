from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
FIXTURES = ROOT / "tests" / "fixtures"

import opentofu_plan_authorization as auth  # noqa: E402


VALID_SHA = "a" * 40
# Distinct from VALID_SHA (expected-sha, the approved application/IaC source and image
# SHA) on purpose -- exercises the real split this fix introduces: the caller workflow
# dispatch commit can legitimately differ from the approved application commit (e.g. later,
# unrelated governance-only commits landing on top of it), and every test that uses
# valid_args() by default now proves the two are never conflated.
CALLER_SHA = "c" * 40
DEPLOY_SHA = "ef924580fb690c1e8ec9dc0f27fa1d27b204c111"
IMAGE_DIGEST = "sha256:" + "9" * 64
API_REPO = "synergie/fieldzilla/staging/api"
ADMIN_WEB_REPO = "synergie/fieldzilla/staging/admin-web"
DIGEST_MAP = {API_REPO: "sha256:" + "9" * 64, ADMIN_WEB_REPO: "sha256:" + "8" * 64}
DIGEST_MAP_JSON = json.dumps(DIGEST_MAP, sort_keys=True)
ECS_FAMILIES = ",".join(sorted(auth.APPROVED_FIELDZILLA_TASK_FAMILIES))
VALID_PLAN = "b" * 64
VALID_IMPORT_MAP = "c" * 64
VALID_WORKFLOW = (
    "Synergie-ITCI/.github/.github/workflows/"
    "fieldzilla-staging-opentofu-apply.yml@refs/tags/pr-qa-v1-rc152"
)
NOW = dt.datetime(2026, 9, 12, 5, 0, tzinfo=dt.UTC)


def valid_args(**overrides: object) -> Namespace:
    values = {
        "actor": "SaurabhVermaIN",
        "repository": "Synergie-ITCI/programme-management-platform",
        "environment": "synergie-app-staging",
        "expected_sha": VALID_SHA,
        "expected_caller_sha": CALLER_SHA,
        "github_sha": CALLER_SHA,
        "expected_plan_sha256": VALID_PLAN,
        "expected_import_map_sha256": VALID_IMPORT_MAP,
        "image_digest": "",
        "image_digest_map": "",
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
        self.assertIn("uses: ./.central-framework/actions/opentofu-plan-authorizer", workflow)
        self.assertIn("CENTRAL_WORKFLOW_REF: ${{ inputs.expected-workflow-ref }}", workflow)
        self.assertIn("Checkout central framework at workflow SHA", workflow)
        self.assertIn("uses: ./.central-framework/actions/central-framework-guard", workflow)
        self.assertIn("workflow-sha: ${{ job.workflow_sha || github.workflow_sha }}", workflow)
        self.assertIn('tofu -chdir="${TOFU_ROOT}" init -input=false -lockfile=readonly', workflow)
        self.assertIn("dynamodb_table = \"${STATE_LOCK_TABLE}\"", workflow)
        self.assertIn("Backup current remote state object", workflow)
        self.assertIn("Verify approved import map", workflow)
        self.assertIn("Controlled import into locked remote state", workflow)
        self.assertIn("${{ runner.temp }}/approved/${{ inputs.artifact-name }}/${{ inputs.artifact-name }}", workflow)
        self.assertNotIn("-backend=false", workflow)
        self.assertNotIn("devops-audit", workflow)

    def test_fieldzilla_workflow_does_not_mix_release_pins(self) -> None:
        workflow = (ROOT / ".github/workflows/fieldzilla-staging-opentofu-apply.yml").read_text(encoding="utf-8")
        self.assertNotRegex(workflow, r"opentofu-plan-authorizer@pr-qa-v1-rc\d+")
        self.assertIn("ref: ${{ job.workflow_sha || github.workflow_sha }}", workflow)
        self.assertIn("expected-workflow-file: .github/workflows/fieldzilla-staging-opentofu-apply.yml", workflow)

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

    def test_caller_sha_is_independent_of_expected_sha(self) -> None:
        """The core fix: github-sha is checked against expected-caller-sha, never against
        expected-sha (the approved application/IaC source and image SHA) -- so a caller
        workflow dispatched from a commit descended from the approved application commit
        (e.g. a later, unrelated governance-pin-bump commit) is correctly APPROVED as long
        as expected-caller-sha honestly reflects that dispatch commit, and the two SHAs are
        never allowed to silently stand in for each other."""
        # Baseline: expected_sha and expected_caller_sha are genuinely different (the
        # default valid_args() fixture), and this is accepted -- proves the split works.
        auth.verify_inputs(valid_args(), now=NOW)

        # The dispatch commit not matching the DECLARED caller SHA is rejected, regardless
        # of what expected-sha says.
        self.assert_rejected(github_sha="d" * 40)
        self.assert_rejected(expected_caller_sha="d" * 40)

        # A malformed expected-caller-sha is rejected, independent of expected-sha's own
        # (separately checked) format.
        self.assert_rejected(expected_caller_sha="not-a-sha")
        self.assert_rejected(expected_caller_sha="")

        # Legacy-ambiguity guard: an attempt to collapse the two back into "the same value"
        # (expected-caller-sha == expected-sha, but github-sha does NOT match either) is
        # still correctly rejected -- the check is against expected-caller-sha, not against
        # "expected-sha OR expected-caller-sha".
        self.assert_rejected(expected_caller_sha=VALID_SHA, github_sha=CALLER_SHA)

    def test_verify_caller_sha_command(self) -> None:
        auth.verify_caller_sha(Namespace(github_sha=CALLER_SHA, expected_caller_sha=CALLER_SHA))
        with self.assertRaises(SystemExit):
            auth.verify_caller_sha(Namespace(github_sha=VALID_SHA, expected_caller_sha=CALLER_SHA))
        with self.assertRaises(SystemExit):
            auth.verify_caller_sha(Namespace(github_sha=CALLER_SHA, expected_caller_sha="not-a-sha"))
        with self.assertRaises(SystemExit):
            auth.verify_caller_sha(Namespace(github_sha=CALLER_SHA, expected_caller_sha=""))

    def test_rejects_bad_hashes_expiry_reuse_or_native_reviewers(self) -> None:
        self.assert_rejected(expected_plan_sha256="not-a-hash")
        self.assert_rejected(expected_import_map_sha256="not-a-hash")
        self.assert_rejected(expires_at="2026-09-12T04:59:00Z")
        self.assert_rejected(expires_at="2026-09-12T06:01:00Z")
        self.assert_rejected(authorization_id="../bad")
        self.assert_rejected(native_reviewers_available="true")
        self.assert_rejected(image_digest_map="not-a-digest")
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

    def test_verify_oidc_rejects_malformed_expected_workflow_ref(self) -> None:
        """The expected job-workflow-ref passed to verify-oidc must itself be a real,
        validly-shaped immutable tag reference before it is even worth comparing against the
        token -- this is the caller-supplied "actual current tag" value (see
        expected-workflow-ref in the reusable workflow), never the self-referential,
        structurally-one-release-behind CENTRAL_WORKFLOW_REF. A malformed or empty value must
        fail closed without ever reading the token."""
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
            for bad_ref in ("", "not-a-tag-ref", VALID_WORKFLOW + "-extra", "Synergie-ITCI/.github/.github/workflows/other.yml@refs/tags/pr-qa-v1-rc142"):
                with self.subTest(bad_ref=bad_ref):
                    with self.assertRaises(SystemExit):
                        auth.verify_oidc(Namespace(token_file=token, job_workflow_ref=bad_ref))
            # Sanity: the exact same token, with a validly-shaped and matching expectation,
            # still passes -- proves the new format check does not itself reject good input.
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

        # head_sha is the SOURCE (plan-generation) run's actual dispatch commit -- the
        # caller-commit concept -- and is checked against expected_caller_sha (CALLER_SHA),
        # deliberately NOT against expected_sha (VALID_SHA, the approved application/IaC
        # commit baked into the artifact name). Both appear in this one fixture, distinct,
        # proving the fix: the bug this whole change exists to fix was exactly this check
        # comparing head_sha against expected_sha instead.
        def fake_api(path: str, method: str = "GET", payload: dict[str, object] | None = None):
            if path == "actions/runs/34706513572":
                return {
                    "head_repository": {"full_name": "Synergie-ITCI/programme-management-platform", "id": 1315697868},
                    "head_sha": CALLER_SHA,
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

        # Rejected: the OLD (pre-fix) expectation -- head_sha equal to expected_sha instead
        # of expected_caller_sha -- must no longer be accepted. This is the exact scenario
        # that made a real, correct FieldZilla staging apply impossible: the plan-generation
        # run's dispatch commit was the approved application commit itself, not the (later,
        # governance-advanced) caller commit the operator is now dispatching apply from.
        def old_expectation_api(path: str, method: str = "GET", payload: dict[str, object] | None = None):
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

        with mock.patch.object(auth, "github_api", side_effect=old_expectation_api):
            with self.assertRaises(SystemExit):
                auth.verify_source_artifact(args)

        def mismatched_artifact_api(path: str, method: str = "GET", payload: dict[str, object] | None = None):
            if path == "actions/runs/34706513572":
                return {
                    "head_repository": {"full_name": "Synergie-ITCI/programme-management-platform", "id": 1315697868},
                    "head_sha": CALLER_SHA,
                    "conclusion": "success",
                    "path": ".github/workflows/fieldzilla-staging-iac.yml",
                    "run_attempt": 1,
                }
            if path == "actions/runs/34706513572/artifacts?per_page=100":
                return {
                    "artifacts": [
                        {
                            "id": 123456,
                            "name": f"fieldzilla-staging-plan-{'b' * 40}-34706513572",
                            "expired": False,
                            "digest": "sha256:" + "e" * 64,
                        }
                    ]
                }
            raise AssertionError(path)

        with mock.patch.object(auth, "github_api", side_effect=mismatched_artifact_api):
            with self.assertRaises(SystemExit):
                auth.verify_source_artifact(args)

    def test_verify_source_artifact_rejects_malformed_caller_sha(self) -> None:
        args = valid_args(
            source_run_id="34706513572",
            artifact_id="123456",
            artifact_name=f"fieldzilla-staging-plan-{VALID_SHA}-34706513572",
            expected_artifact_digest="sha256:" + "d" * 64,
            expected_caller_sha="not-a-sha",
        )
        with mock.patch.object(auth, "github_api", side_effect=AssertionError("must fail before any API call")):
            with self.assertRaises(SystemExit):
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

            def metadata_doc(**overrides: object) -> dict[str, object]:
                doc = {
                    "repository": "Synergie-ITCI/programme-management-platform",
                    "repository_id": 1315697868,
                    "environment": "synergie-app-staging",
                    "commit_sha": VALID_SHA,
                    "caller_sha": CALLER_SHA,
                    "image_digest_map": DIGEST_MAP,
                    "ecs_families": sorted(auth.APPROVED_FIELDZILLA_TASK_FAMILIES),
                    "workflow_run_id": "34706513572",
                    "artifact_name": artifact_name,
                    "plan_sha256": plan_sha,
                    "state_backend": "s3",
                    "state_bucket": "synergie-fieldzilla-opentofu-state-918870682888-ap-south-1",
                    "state_key": "programme-management-platform/fieldzilla/staging/opentofu.tfstate",
                    "lock_table": "synergie-fieldzilla-opentofu-locks",
                }
                doc.update(overrides)
                return doc

            def write_metadata(doc: dict[str, object]) -> None:
                (artifact_dir / "metadata.json").write_text(json.dumps(doc), encoding="utf-8")

            def base_args(**overrides: object) -> Namespace:
                values = dict(
                    artifact_dir=artifact_dir,
                    expected_sha=VALID_SHA,
                    expected_caller_sha=CALLER_SHA,
                    expected_plan_sha256=plan_sha,
                    expected_import_map_sha256=import_sha,
                    image_digest_map=DIGEST_MAP_JSON,
                    ecs_families=ECS_FAMILIES,
                    source_run_id="34706513572",
                    artifact_id="123456",
                    artifact_name=artifact_name,
                    expected_artifact_digest="e" * 64,
                )
                values.update(overrides)
                return Namespace(**values)

            # Approved: expected_sha and expected_caller_sha both present, distinct, and
            # both bound to the artifact's own recorded metadata.
            write_metadata(metadata_doc())
            auth.verify_artifact_metadata(base_args())

            # Rejected: this apply's claimed expected-caller-sha does not match what the
            # plan was actually generated from -- exactly the "staging advanced between
            # plan and apply" case, which must fail closed and force plan regeneration.
            with self.assertRaises(SystemExit):
                auth.verify_artifact_metadata(base_args(expected_caller_sha="d" * 40))

            # Rejected: a tampered/stale downloaded plan whose bytes no longer match the
            # operator-approved SHA cannot reach the exact apply step.
            with self.assertRaises(SystemExit):
                auth.verify_artifact_metadata(base_args(expected_plan_sha256="0" * 64))

            # Approved: the isolated runtime root's separate state key is accepted only
            # when the apply invocation explicitly expects that key.
            runtime_state_key = "programme-management-platform/fieldzilla/staging/runtime/opentofu.tfstate"
            write_metadata(metadata_doc(state_key=runtime_state_key))
            auth.verify_artifact_metadata(base_args(expected_state_key=runtime_state_key))

            # Rejected: a plan artifact for any other backend key cannot be substituted
            # into the isolated runtime-root apply approval.
            with self.assertRaises(SystemExit):
                auth.verify_artifact_metadata(base_args())

            # Rejected: legacy-ambiguity guard -- an artifact generated before this fix,
            # whose metadata.json has no caller_sha field at all, must never be silently
            # treated as matching (e.g. by defaulting to expected_sha or being skipped).
            write_metadata(metadata_doc())
            legacy_doc = metadata_doc()
            del legacy_doc["caller_sha"]
            write_metadata(legacy_doc)
            with self.assertRaises(SystemExit):
                auth.verify_artifact_metadata(base_args())

            # Rejected: an artifact whose recorded caller_sha was collapsed to equal
            # commit_sha (the pre-fix conflation) is still rejected when it does not equal
            # this apply's actual expected-caller-sha.
            write_metadata(metadata_doc(caller_sha=VALID_SHA))
            with self.assertRaises(SystemExit):
                auth.verify_artifact_metadata(base_args())

            # Restore a valid artifact so the test ends in a known-good state.
            write_metadata(metadata_doc())
            auth.verify_artifact_metadata(base_args())

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
        args = Namespace(plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map=DIGEST_MAP_JSON, ecs_families=ECS_FAMILIES)
        with tempfile.TemporaryDirectory() as tmp:
            plan_json = Path(tmp) / "plan.json"
            plan_json.write_text(json.dumps(base), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

            # Missing digest evidence for the repository this container actually uses.
            missing_repo_digest = json.loads(json.dumps(base))
            plan_json.write_text(json.dumps(missing_repo_digest), encoding="utf-8")
            bad_args = Namespace(**{**vars(args), "image_digest_map": json.dumps({ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]})})
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(bad_args)))

            # Malformed digest map (not valid JSON) must fail closed, not silently pass through.
            malformed_args = Namespace(**{**vars(args), "image_digest_map": "not-json"})
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(malformed_args)))

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

    def test_fieldzilla_runtime_bootstrap_plan_allows_approved_create_subset_for_recovery(self) -> None:
        plan = {
            "planned_values": {
                "outputs": {
                    "runtime_role_arn": {"sensitive": False, "value": "arn:aws:iam::918870682888:role/FieldZillaRuntime"},
                    "activation_code": {"sensitive": True},
                }
            },
            "resource_changes": [
                {"address": "aws_iam_role.ssm_hybrid", "type": "aws_iam_role", "change": {"actions": ["create"], "after": {"name": "fieldzilla-staging-runtime"}}},
                {"address": "aws_iam_role_policy.runtime", "type": "aws_iam_role_policy", "change": {"actions": ["create"], "after": {}}},
                {"address": "aws_iam_role_policy_attachment.ssm_managed_instance_core", "type": "aws_iam_role_policy_attachment", "change": {"actions": ["create"], "after": {}}},
                {
                    "address": "aws_ssm_activation.staging_runtime",
                    "type": "aws_ssm_activation",
                    "change": {
                        "actions": ["create"],
                        "after": {"name": "fieldzilla-staging-runtime"},
                        "after_unknown": {"activation_code": True},
                    },
                },
            ],
        }
        args = Namespace(plan_kind="fieldzilla-runtime-bootstrap", expected_sha=DEPLOY_SHA, image_digest="", image_digest_map="", ecs_families="")
        with tempfile.TemporaryDirectory() as tmp:
            plan_json = Path(tmp) / "plan.json"
            plan_json.write_text(json.dumps(plan), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

            # Real partial-apply recovery case: IAM resources already exist/no-op and
            # only the sensitive SSM activation still needs to be created.
            activation_only = json.loads(json.dumps(plan))
            activation_only["resource_changes"] = [activation_only["resource_changes"][3]]
            plan_json.write_text(json.dumps(activation_only), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

            # Exact sanitized failed-run shape from 35615426649: the three IAM resources
            # are already present/no-op and only the SSM activation remains a create.
            full_partial_recovery = json.loads(
                (FIXTURES / "fieldzilla_runtime_bootstrap_partial_recovery_plan.json").read_text(
                    encoding="utf-8"
                )
            )
            plan_json.write_text(json.dumps(full_partial_recovery), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

            replay = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "actions/opentofu-plan-authorizer/opentofu_plan_authorization.py"),
                    "verify-plan-safety",
                    "--plan-json-path",
                    str(plan_json),
                    "--plan-kind",
                    "fieldzilla-runtime-bootstrap",
                    "--expected-sha",
                    DEPLOY_SHA,
                    "--image-digest",
                    "",
                    "--image-digest-map",
                    "",
                    "--ecs-families",
                    "",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertIn('"create": 1', replay.stdout)
            self.assertIn('"no-op": 3', replay.stdout)

            cases = []
            empty = json.loads(json.dumps(plan))
            empty["resource_changes"] = []
            cases.append(empty)
            all_no_op = json.loads(json.dumps(full_partial_recovery))
            all_no_op["resource_changes"][3]["change"]["actions"] = ["no-op"]
            cases.append(all_no_op)
            extra = json.loads(json.dumps(plan))
            extra["resource_changes"].append({"address": "aws_s3_bucket.bad", "type": "aws_s3_bucket", "change": {"actions": ["create"], "after": {}}})
            cases.append(extra)
            changed = json.loads(json.dumps(plan))
            changed["resource_changes"][0]["change"]["actions"] = ["update"]
            cases.append(changed)
            delete_create = json.loads(json.dumps(plan))
            delete_create["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
            cases.append(delete_create)
            malformed_actions = json.loads(json.dumps(plan))
            malformed_actions["resource_changes"][0]["change"]["actions"] = "create"
            cases.append(malformed_actions)
            duplicate = json.loads(json.dumps(plan))
            duplicate["resource_changes"].append(json.loads(json.dumps(duplicate["resource_changes"][0])))
            cases.append(duplicate)
            wrong_type = json.loads(json.dumps(plan))
            wrong_type["resource_changes"][0]["type"] = "aws_iam_policy"
            cases.append(wrong_type)
            sensitive = json.loads(json.dumps(plan))
            sensitive["planned_values"]["outputs"]["activation_code"]["value"] = "SECRET"
            cases.append(sensitive)
            exposed_activation = json.loads(json.dumps(plan))
            exposed_activation["resource_changes"][3]["change"]["after"]["activation_code"] = "SECRET"
            cases.append(exposed_activation)
            exposed_token = json.loads(json.dumps(plan))
            exposed_token["resource_changes"][3]["change"]["after"]["api_token"] = "SECRET"
            cases.append(exposed_token)

            for case in cases:
                plan_json.write_text(json.dumps(case), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

    def test_legacy_image_digest_input_still_accepted(self) -> None:
        """The deprecated scalar --image-digest input must remain a valid, accepted
        action/CLI input during the staged rollout of image-digest-map -- callers still
        wired to the old interface must not break. It is deliberately NOT an effective
        digest check against real plans (real container_definitions carry no imageDigest
        field), which is why new callers must use image_digest_map instead; this test only
        proves the input contract itself did not regress."""
        auth.verify_inputs(valid_args(image_digest=IMAGE_DIGEST), now=NOW)
        self.assert_rejected(image_digest="not-a-digest")

        containers = [
            {
                "name": "api",
                "image": f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{API_REPO}:{DEPLOY_SHA}",
                "cpu": 256,
                "memory": 512,
                "essential": True,
                # Real plans never carry this -- included here only to exercise the legacy
                # code path's accept case; test_real_pending_fieldzilla_plan_shape covers
                # the real (imageDigest-absent) shape via image_digest_map instead.
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
            "container_definitions": json.dumps([{**containers[0], "image": f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{API_REPO}:774051cf74a7b8ada2f26e5c24959fdc99d6380b"}], sort_keys=True),
            "runtime_platform": [],
            "track_latest": False,
            "volume": [],
        }
        after = {**before, "container_definitions": json.dumps(containers, sort_keys=True)}
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
            # Legacy image_digest alone (no image_digest_map) must not error out the
            # input contract, even though it cannot verify anything against a real plan.
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest=IMAGE_DIGEST, image_digest_map="", ecs_families=""))

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
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            normalized_empty_fields = json.loads(json.dumps(plan))
            normalized_empty_fields["resource_changes"][0]["change"]["before"]["ipc_mode"] = ""
            normalized_empty_fields["resource_changes"][0]["change"]["after"]["ipc_mode"] = None
            normalized_empty_fields["resource_changes"][0]["change"]["before"]["pid_mode"] = ""
            normalized_empty_fields["resource_changes"][0]["change"]["after"]["pid_mode"] = None
            plan_json.write_text(json.dumps(normalized_empty_fields), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            approved_previous_sha = "774051cf74a7b8ada2f26e5c24959fdc99d6380b"
            approved_previous = json.loads(json.dumps(plan))
            previous_containers = json.loads(approved_previous["resource_changes"][0]["change"]["before"]["container_definitions"])
            previous_containers[0]["image"] = (
                "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:"
                f"{approved_previous_sha}"
            )
            approved_previous["resource_changes"][0]["change"]["before"]["container_definitions"] = json.dumps(previous_containers)
            plan_json.write_text(json.dumps(approved_previous), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            last_deployed = json.loads(json.dumps(plan))
            last_deployed_containers = json.loads(last_deployed["resource_changes"][0]["change"]["before"]["container_definitions"])
            last_deployed_containers[0]["image"] = (
                "918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/api:"
                "774051cf74a7b8ada2f26e5c24959fdc99d6380b"
            )
            last_deployed["resource_changes"][0]["change"]["before"]["container_definitions"] = json.dumps(last_deployed_containers)
            plan_json.write_text(json.dumps(last_deployed), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            wrong_target_sha = json.loads(json.dumps(plan))
            wrong_target_sha["variables"]["image_tag"]["value"] = "1111111111111111111111111111111111111111"
            plan_json.write_text(json.dumps(wrong_target_sha), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(
                    Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families="")
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
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            wrong_family_retirement = json.loads(json.dumps(retired_revision))
            wrong_family_retirement["resource_changes"][0]["change"]["before"]["family"] = "fieldzilla-production-api"
            plan_json.write_text(json.dumps(wrong_family_retirement), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(
                    Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families="")
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
                    Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families="")
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
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            # Approved: two new runtime secrets added.
            second_new = {"name": "APP_CORS_ORIGINS", "valueFrom": f"{runtime_prefix}APP_CORS_ORIGINS::"}
            two_new = json.loads(json.dumps(plan))
            cs = json.loads(two_new["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [existing_secret, new_secret, second_new]
            two_new["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(two_new), encoding="utf-8")
            auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            # Rejected: existing secret removed from after.
            missing_existing = json.loads(json.dumps(plan))
            cs = json.loads(missing_existing["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [new_secret]
            missing_existing["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(missing_existing), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            # Rejected: new secret's valueFrom references a non-runtime ARN.
            bad_arn = json.loads(json.dumps(plan))
            cs = json.loads(bad_arn["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [existing_secret, {"name": "EVIL_KEY", "valueFrom": "arn:aws:secretsmanager:ap-south-1:918870682888:secret:/other/secret:KEY::"}]
            bad_arn["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(bad_arn), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            # Rejected: new secret references a different account's runtime ARN.
            foreign_arn = json.loads(json.dumps(plan))
            cs = json.loads(foreign_arn["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [existing_secret, {"name": "APP_URL", "valueFrom": "arn:aws:secretsmanager:ap-south-1:999999999999:secret:/synergie/fieldzilla/staging/runtime-xABCDE:APP_URL::"}]
            foreign_arn["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(foreign_arn), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            # Rejected: existing secret's valueFrom mutated.
            mutated_existing = json.loads(json.dumps(plan))
            cs = json.loads(mutated_existing["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [{"name": "APP_KEY", "valueFrom": f"{runtime_prefix}APP_KEY_EVIL::"}, new_secret]
            mutated_existing["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(mutated_existing), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            # Rejected: non-secret container field mutated (essential flag changed) alongside valid secret add.
            mutated_field = json.loads(json.dumps(plan))
            cs = json.loads(mutated_field["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["essential"] = False
            cs[0]["secrets"] = [existing_secret, new_secret]
            mutated_field["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(mutated_field), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

            # Rejected: new secret references the production environment rather than staging.
            prod_env = json.loads(json.dumps(plan))
            cs = json.loads(prod_env["resource_changes"][0]["change"]["after"]["container_definitions"])
            cs[0]["secrets"] = [existing_secret, {"name": "APP_PROD_KEY", "valueFrom": "arn:aws:secretsmanager:ap-south-1:918870682888:secret:/synergie/fieldzilla/production/runtime-pXXXXX:APP_PROD_KEY::"}]
            prod_env["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(cs)
            plan_json.write_text(json.dumps(prod_env), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=""))

    def test_new_task_definition_create_with_no_prior_state(self) -> None:
        """A task-definition create with no prior Terraform state (e.g. superseding a
        manually created revision) is approved only against an exact, per-family design
        baseline sourced from reviewed IaC -- exercises the exact FieldZilla plan shape for
        all four families and every adversarial rejection of that baseline, including
        cross-family/repository mismatches, incomplete run authorization, the two-repository
        digest map, and exact secret ARN/key-set binding. Container fixtures below carry only
        the keys the reviewed Terraform source actually emits for each family -- no invented
        `imageDigest`, `cpu`, `memory`, or other fields real `tofu show -json` never sets."""
        runtime_arn = auth.EXACT_RUNTIME_SECRET_ARN

        def approved_secrets(keys: frozenset[str]) -> list[dict[str, str]]:
            return [{"name": key, "valueFrom": f"{runtime_arn}:{key}::"} for key in sorted(keys)]

        def make_container(family: str, **overrides: object) -> dict[str, object]:
            family_baseline = auth.FIELDZILLA_TASK_DEFINITION_BASELINE.get(family, auth.FIELDZILLA_TASK_DEFINITION_BASELINE["fieldzilla-staging-api"])
            baseline_container = dict(family_baseline["container"])
            repo = family_baseline["ecr_repository"]
            secret_keys = overrides.pop("secret_keys", baseline_container["secret_keys"])
            container = {k: v for k, v in baseline_container.items() if k != "secret_keys"}
            container["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{repo}:{DEPLOY_SHA}"
            secrets = approved_secrets(secret_keys)
            if secrets:
                container["secrets"] = secrets
            container.update(overrides)
            return container

        def make_after(family: str = "fieldzilla-staging-api", container_overrides: dict[str, object] | None = None, containers: list[dict[str, object]] | None = None, **overrides: object) -> dict[str, object]:
            baseline = auth.FIELDZILLA_TASK_DEFINITION_BASELINE.get(family, auth.FIELDZILLA_TASK_DEFINITION_BASELINE["fieldzilla-staging-api"])
            if containers is None:
                containers = [make_container(family, **(container_overrides or {}))]
            after = {
                "family": family,
                "cpu": baseline["cpu"],
                "memory": baseline["memory"],
                "execution_role_arn": baseline["execution_role_arn"],
                "task_role_arn": baseline["task_role_arn"],
                "network_mode": baseline["network_mode"],
                "requires_compatibilities": baseline["requires_compatibilities"],
                "runtime_platform": baseline["runtime_platform"],
                "volume": baseline["volume"],
                "placement_constraints": baseline["placement_constraints"],
                "proxy_configuration": baseline["proxy_configuration"],
                "ephemeral_storage": baseline["ephemeral_storage"],
                "container_definitions": json.dumps(containers, sort_keys=True),
            }
            after.update(overrides)
            return after

        def plan_for(after: dict[str, object], family_address: str = "api", ecs_families: str | None = None, image_digest_map: str | None = None) -> tuple[dict[str, object], Namespace]:
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
                        "address": f'aws_ecs_task_definition.{family_address}["staging"]',
                        "type": "aws_ecs_task_definition",
                        "change": {"actions": ["create"], "before": None, "after": after},
                    }
                ],
            }
            args = Namespace(
                plan_kind="normal",
                expected_sha=DEPLOY_SHA,
                image_digest_map=DIGEST_MAP_JSON if image_digest_map is None else image_digest_map,
                ecs_families=ECS_FAMILIES if ecs_families is None else ecs_families,
            )
            return plan, args

        def check(after: dict[str, object], **plan_kwargs: object) -> None:
            plan, args = plan_for(after, **plan_kwargs)
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(plan), encoding="utf-8")
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

        def check_rejected(after: dict[str, object], **plan_kwargs: object) -> None:
            plan, args = plan_for(after, **plan_kwargs)
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(plan), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

        # --- Approved: exact FieldZilla plan shape, one per family, matching the reviewed
        # Terraform source at 2c8a4015fd4a97d1c582475a6939cf8fb988b2fb exactly (no invented
        # imageDigest/cpu/memory container keys). ---
        check(make_after("fieldzilla-staging-api"), family_address="api")
        check(make_after("fieldzilla-staging-admin-web"), family_address="admin-web")
        check(make_after("fieldzilla-staging-worker"), family_address="worker")
        check(make_after("fieldzilla-staging-migration"), family_address="migration")

        # --- Rejected: unapproved family / wrong family-to-repository mapping. ---
        check_rejected(make_after(family="fieldzilla-production-api"))
        wrong_repo = make_after("fieldzilla-staging-api")
        containers = json.loads(wrong_repo["container_definitions"])
        containers[0]["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{ADMIN_WEB_REPO}:{DEPLOY_SHA}"
        wrong_repo["container_definitions"] = json.dumps(containers)
        check_rejected(wrong_repo)

        # --- Rejected: incomplete/empty run authorization for the family set. ---
        check_rejected(make_after(), ecs_families="")
        check_rejected(make_after(), ecs_families="fieldzilla-staging-api")
        check_rejected(make_after(), ecs_families="fieldzilla-staging-api,fieldzilla-staging-worker")

        # --- Rejected: absent, malformed, incomplete, or extra-key digest evidence. Real
        # container_definitions never carry an imageDigest field, so evidence is required
        # via the map only -- there is nothing in the container to fall back on. ---
        check_rejected(make_after(), image_digest_map="")
        check_rejected(make_after(), image_digest_map="not-json")
        check_rejected(make_after(), image_digest_map=json.dumps({API_REPO: DIGEST_MAP[API_REPO]}))  # missing admin-web
        check_rejected(make_after(), image_digest_map=json.dumps({**DIGEST_MAP, "synergie/other/staging/api": "sha256:" + "1" * 64}))  # extra key
        check_rejected(make_after(), image_digest_map=json.dumps({API_REPO: "not-a-digest", ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}))
        check_rejected(make_after(), image_digest_map=json.dumps({API_REPO: DIGEST_MAP[API_REPO].upper(), ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}))  # not lowercase hex
        # Duplicate JSON keys are not canonical and must be rejected, not silently collapsed.
        duplicate_key_json = (
            '{"' + API_REPO + '": "' + DIGEST_MAP[API_REPO] + '", "' + ADMIN_WEB_REPO + '": "' + DIGEST_MAP[ADMIN_WEB_REPO]
            + '", "' + API_REPO + '": "' + DIGEST_MAP[API_REPO] + '"}'
        )
        check_rejected(make_after(), image_digest_map=duplicate_key_json)
        # A container carrying a legacy imageDigest field is harmlessly ignored (stripped
        # by _container_base, same as "image" and "secrets") -- it grants no bypass, since
        # digest evidence is read only from image_digest_map, never from the container.
        harmless_legacy_field = make_after()
        containers = json.loads(harmless_legacy_field["container_definitions"])
        containers[0]["imageDigest"] = "sha256:" + "0" * 64  # wrong on purpose -- must not matter
        harmless_legacy_field["container_definitions"] = json.dumps(containers)
        check(harmless_legacy_field)

        # --- Rejected: secret ARN is a prefix-collision, not the exact approved secret. ---
        prefix_collision = make_after()
        containers = json.loads(prefix_collision["container_definitions"])
        containers[0]["secrets"] = [{"name": "APP_SECRET_KEY", "valueFrom": f"{runtime_arn}-evil:APP_SECRET_KEY::"}]
        prefix_collision["container_definitions"] = json.dumps(containers)
        check_rejected(prefix_collision)

        # --- Rejected: arbitrary/extra secret keys, or a missing required key. ---
        extra_key = make_after()
        containers = json.loads(extra_key["container_definitions"])
        containers[0]["secrets"].append({"name": "ARBITRARY_EXTRA_KEY", "valueFrom": f"{runtime_arn}:ARBITRARY_EXTRA_KEY::"})
        extra_key["container_definitions"] = json.dumps(containers)
        check_rejected(extra_key)
        check_rejected(make_after(container_overrides={"secret_keys": frozenset({"APP_SECRET_KEY"})}))
        # Worker's expected key set includes APP_ADMIN_WEB_BASE_URL per the reviewed .tf
        # (unfiltered local.runtime_secret_keys) -- omitting it must be rejected too.
        check_rejected(make_after("fieldzilla-staging-worker", container_overrides={
            "secret_keys": frozenset({"APP_SECRET_KEY", "APP_DATABASE_CONTEXT_SECRET", "APP_DATABASE_URL", "APP_FIELD_ENCRYPTION_MASTER_KEY", "APP_CORS_ORIGINS", "APP_WORKER_TENANT_IDS"})
        }), family_address="worker")

        # --- Rejected: extra container (sidecar). ---
        sidecar = make_after("fieldzilla-staging-api")
        containers = json.loads(sidecar["container_definitions"])
        containers.append(make_container("fieldzilla-staging-api"))
        sidecar["container_definitions"] = json.dumps(containers)
        check_rejected(sidecar)

        # --- Rejected: altered command, environment, logging, networking. ---
        check_rejected(make_after(container_overrides={"command": ["/bin/sh", "-c", "curl evil.example"]}))
        tampered_env = make_after()
        containers = json.loads(tampered_env["container_definitions"])
        containers[0]["environment"] = [{"name": "APP_DEBUG", "value": "true"}]
        tampered_env["container_definitions"] = json.dumps(containers)
        check_rejected(tampered_env)
        check_rejected(make_after(container_overrides={
            "logConfiguration": {"logDriver": "awslogs", "options": {"awslogs-group": "/attacker/group", "awslogs-region": "ap-south-1", "awslogs-stream-prefix": "ecs"}}
        }))
        check_rejected(make_after(container_overrides={"portMappings": [{"containerPort": 22, "hostPort": 22, "protocol": "tcp"}]}))
        check_rejected(make_after(container_overrides={"mountPoints": [{"sourceVolume": "host", "containerPath": "/host"}]}))
        check_rejected(make_after(container_overrides={"volumesFrom": [{"sourceContainer": "other"}]}))
        check_rejected(make_after(container_overrides={"systemControls": [{"namespace": "net.core.somaxconn", "value": "1024"}]}))

        # --- Rejected: any field the reviewed .tf never sets on a container at all --
        # privileged, user, linuxParameters, repositoryCredentials, healthCheck, dependsOn,
        # readonlyRootFilesystem, entrypoint, or per-container cpu/memory -- fails the moment
        # it is present, by construction of the exact-shape equality check. ---
        for extra_field, value in (
            ("privileged", True),
            ("user", "root"),
            ("linuxParameters", {"capabilities": {"add": ["SYS_ADMIN"]}}),
            ("repositoryCredentials", {"credentialsParameter": "arn:aws:secretsmanager:ap-south-1:918870682888:secret:attacker"}),
            ("healthCheck", {"command": ["CMD-SHELL", "exit 1"]}),
            ("dependsOn", [{"containerName": "sidecar", "condition": "START"}]),
            ("readonlyRootFilesystem", True),
            ("entrypoint", ["/bin/sh"]),
            ("cpu", 128),
            ("memory", 256),
        ):
            check_rejected(make_after(container_overrides={extra_field: value}))

        # --- Rejected: under-sized and over-sized task-level CPU/memory -- exact match only. ---
        check_rejected(make_after(cpu="128"))
        check_rejected(make_after(memory="256"))
        check_rejected(make_after(cpu="512"))
        check_rejected(make_after(memory="1024"))

        # --- Rejected: unexpected/unknown container field of any kind. ---
        unknown_field = make_after()
        containers = json.loads(unknown_field["container_definitions"])
        containers[0]["extraHosts"] = [{"hostname": "evil", "ipAddress": "10.0.0.1"}]
        unknown_field["container_definitions"] = json.dumps(containers)
        check_rejected(unknown_field)

        # --- Rejected: task-level fields outside the approved baseline. ---
        check_rejected(make_after(execution_role_arn="arn:aws:iam::918870682888:role/Other"))
        check_rejected(make_after(task_role_arn="arn:aws:iam::918870682888:role/Other"))
        check_rejected(make_after(network_mode="awsvpc"))
        check_rejected(make_after(requires_compatibilities=["FARGATE"]))
        check_rejected(make_after(volume=[{"name": "data"}]))
        check_rejected(make_after(placement_constraints=[{"type": "memberOf", "expression": "attribute:x == y"}]))
        check_rejected(make_after(proxy_configuration={"type": "APPMESH"}))
        check_rejected(make_after(ephemeral_storage={"sizeInGiB": 100}))

        # --- Rejected: malformed plan claims a bare create but still carries a non-null
        # "before" (should never happen from real OpenTofu output, but must fail closed). ---
        with tempfile.TemporaryDirectory() as tmp:
            plan_json = Path(tmp) / "plan.json"
            plan, args = plan_for(make_after())
            plan["resource_changes"][0]["change"]["before"] = {"family": "fieldzilla-staging-api"}
            plan_json.write_text(json.dumps(plan), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

        # --- Rejected: "after" missing/not a dict entirely. ---
        with tempfile.TemporaryDirectory() as tmp:
            plan_json = Path(tmp) / "plan.json"
            plan, args = plan_for(make_after())
            plan["resource_changes"][0]["change"]["after"] = None
            plan_json.write_text(json.dumps(plan), encoding="utf-8")
            with self.assertRaises(SystemExit):
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

    def test_real_pending_fieldzilla_plan_shape(self) -> None:
        """Sanitized fixture matching the actual pending FieldZilla staging plan: all four
        families in one plan, api as a pure create (superseding the manually created
        api:6/worker:6 revisions this pipeline must never import), admin-web/worker/migration
        as normal replacements, two distinct repository digests, and the full range of
        malformed/adversarial variants. No field here was invented -- every key/value in the
        approved fixture matches infra/aws/compute.tf and infra/aws/locals.tf at
        2c8a4015fd4a97d1c582475a6939cf8fb988b2fb, or the live pre-existing revisions for the
        replace-shaped families (5/6/7) that the same reviewed source produced."""
        runtime_arn = auth.EXACT_RUNTIME_SECRET_ARN

        def approved_secrets(keys: frozenset[str]) -> list[dict[str, str]]:
            return [{"name": key, "valueFrom": f"{runtime_arn}:{key}::"} for key in sorted(keys)]

        def container_for(family: str, sha: str) -> dict[str, object]:
            baseline = auth.FIELDZILLA_TASK_DEFINITION_BASELINE[family]
            container = {k: v for k, v in baseline["container"].items() if k != "secret_keys"}
            container["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{baseline['ecr_repository']}:{sha}"
            secrets = approved_secrets(baseline["container"]["secret_keys"])
            if secrets:
                container["secrets"] = secrets
            return container

        def task_def_fields(family: str) -> dict[str, object]:
            baseline = auth.FIELDZILLA_TASK_DEFINITION_BASELINE[family]
            return {
                "family": family,
                "cpu": baseline["cpu"],
                "memory": baseline["memory"],
                "execution_role_arn": baseline["execution_role_arn"],
                "task_role_arn": baseline["task_role_arn"],
                "network_mode": baseline["network_mode"],
                "requires_compatibilities": baseline["requires_compatibilities"],
                "runtime_platform": baseline["runtime_platform"],
                "volume": baseline["volume"],
                "placement_constraints": baseline["placement_constraints"],
                "proxy_configuration": baseline["proxy_configuration"],
                "ephemeral_storage": baseline["ephemeral_storage"],
            }

        PRIOR_SHA = "ab91e3d3ec4efc932363922f6533d0188c010c57"

        def base_plan() -> dict[str, object]:
            # api: pure create -- Terraform has no prior state (the live api:6 was created
            # manually, outside this pipeline, and must be superseded, not imported).
            api_after = {**task_def_fields("fieldzilla-staging-api"), "container_definitions": json.dumps([container_for("fieldzilla-staging-api", DEPLOY_SHA)], sort_keys=True)}
            # admin-web/worker/migration: normal replacements -- Terraform already tracks a
            # prior governed revision for these, only the image tag (and, for worker/
            # migration, the secrets list) changes.
            def replacement(family: str, before_containers: list[dict[str, object]]) -> dict[str, object]:
                before = {**task_def_fields(family), "container_definitions": json.dumps(before_containers, sort_keys=True)}
                after = {**task_def_fields(family), "container_definitions": json.dumps([container_for(family, DEPLOY_SHA)], sort_keys=True)}
                return {"before": before, "after": after}

            admin_before = [{k: v for k, v in container_for("fieldzilla-staging-admin-web", PRIOR_SHA).items()}]
            worker_before_baseline = auth.FIELDZILLA_TASK_DEFINITION_BASELINE["fieldzilla-staging-worker"]
            worker_before = {k: v for k, v in worker_before_baseline["container"].items() if k != "secret_keys"}
            worker_before["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{worker_before_baseline['ecr_repository']}:{PRIOR_SHA}"
            worker_before["secrets"] = approved_secrets(frozenset({"APP_SECRET_KEY", "APP_DATABASE_CONTEXT_SECRET", "APP_DATABASE_URL", "APP_FIELD_ENCRYPTION_MASTER_KEY", "APP_CORS_ORIGINS"}))
            migration_before_baseline = auth.FIELDZILLA_TASK_DEFINITION_BASELINE["fieldzilla-staging-migration"]
            migration_before = {k: v for k, v in migration_before_baseline["container"].items() if k != "secret_keys"}
            migration_before["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{migration_before_baseline['ecr_repository']}:{PRIOR_SHA}"
            migration_before["secrets"] = approved_secrets(frozenset({"APP_SECRET_KEY", "APP_DATABASE_CONTEXT_SECRET", "APP_DATABASE_URL", "APP_FIELD_ENCRYPTION_MASTER_KEY", "APP_CORS_ORIGINS"}))

            admin_rc = replacement("fieldzilla-staging-admin-web", admin_before)
            worker_rc = replacement("fieldzilla-staging-worker", [worker_before])
            migration_rc = replacement("fieldzilla-staging-migration", [migration_before])

            return {
                "variables": {
                    "enable_production": {"value": False},
                    "route53_zone_id": {"value": ""},
                    "container_instance_type": {"value": "c6g.medium"},
                    "monthly_budget_usd": {"value": "100"},
                    "image_tag": {"value": DEPLOY_SHA},
                },
                "resource_changes": [
                    {"address": 'aws_ecs_task_definition.api["staging"]', "type": "aws_ecs_task_definition", "change": {"actions": ["create"], "before": None, "after": api_after}},
                    {"address": 'aws_ecs_task_definition.admin["staging"]', "type": "aws_ecs_task_definition", "change": {"actions": ["delete", "create"], **admin_rc}},
                    {"address": 'aws_ecs_task_definition.worker["staging"]', "type": "aws_ecs_task_definition", "change": {"actions": ["delete", "create"], **worker_rc}},
                    {"address": 'aws_ecs_task_definition.migration["staging"]', "type": "aws_ecs_task_definition", "change": {"actions": ["delete", "create"], **migration_rc}},
                    {
                        "address": 'aws_ecs_service.api["staging"]', "type": "aws_ecs_service",
                        "change": {"actions": ["update"], "before": {"task_definition": "arn:aws:ecs:ap-south-1:918870682888:task-definition/fieldzilla-staging-api:6"}, "after": {"task_definition": None}, "after_unknown": {"task_definition": True}},
                    },
                    {
                        "address": 'aws_ecs_service.admin["staging"]', "type": "aws_ecs_service",
                        "change": {"actions": ["update"], "before": {"task_definition": "arn:aws:ecs:ap-south-1:918870682888:task-definition/fieldzilla-staging-admin-web:6"}, "after": {"task_definition": None}, "after_unknown": {"task_definition": True}},
                    },
                    {
                        "address": 'aws_ecs_service.worker["staging"]', "type": "aws_ecs_service",
                        "change": {"actions": ["update"], "before": {"task_definition": "arn:aws:ecs:ap-south-1:918870682888:task-definition/fieldzilla-staging-worker:5"}, "after": {"task_definition": None}, "after_unknown": {"task_definition": True}},
                    },
                    # infra/aws/compute.tf references several data sources (IAM policy
                    # documents, availability zones, the ECS-optimized AMI parameter) that
                    # OpenTofu legitimately re-evaluates on every plan -- this is exactly
                    # the real-world entry that the routine_ecs_only fix exempts.
                    {
                        "address": 'data.aws_iam_policy_document.task["staging"]', "mode": "data",
                        "type": "aws_iam_policy_document",
                        "change": {"actions": ["read"], "before": None, "after": {"json": "..."}},
                    },
                ],
            }

        args = Namespace(plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", ecs_families=ECS_FAMILIES)

        def check(plan: dict[str, object], **arg_overrides: object) -> None:
            use_args = Namespace(**{**vars(args), **arg_overrides})
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(plan), encoding="utf-8")
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(use_args)))

        def check_rejected(plan: dict[str, object], **arg_overrides: object) -> None:
            use_args = Namespace(**{**vars(args), **arg_overrides})
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(plan), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(use_args)))

        # --- Approved: the real pending plan shape, with mandatory digest evidence for the
        # api family's pure create (the replace-shaped families do not require it since
        # image_digest_map is empty here, matching a non-"routine_ecs_only" review dispatch --
        # routine_ecs_only is opt-in and, once supplied, is exercised by the digest-map tests
        # in test_routine_ecs_authorization_binds_digest_family_and_blocks_non_ecs). ---
        check(base_plan(), image_digest_map=DIGEST_MAP_JSON)

        # --- Rejected: without digest evidence at all, the api pure-create cannot be
        # approved (it always requires it, regardless of routine_ecs_only). ---
        check_rejected(base_plan(), image_digest_map="")

        # --- Rejected: sidecar smuggled into one of the replacement families. ---
        sidecar_plan = base_plan()
        worker_after = json.loads(sidecar_plan["resource_changes"][2]["change"]["after"]["container_definitions"])
        worker_after.append(container_for("fieldzilla-staging-worker", DEPLOY_SHA))
        sidecar_plan["resource_changes"][2]["change"]["after"]["container_definitions"] = json.dumps(worker_after)
        check_rejected(sidecar_plan, image_digest_map=DIGEST_MAP_JSON)

        # --- Rejected: altered role on a replacement family. ---
        altered_role_plan = base_plan()
        altered_role_plan["resource_changes"][1]["change"]["after"]["execution_role_arn"] = "arn:aws:iam::918870682888:role/Other"
        check_rejected(altered_role_plan, image_digest_map=DIGEST_MAP_JSON)

        # --- Rejected: altered CPU/memory on a replacement family. ---
        altered_cpu_plan = base_plan()
        altered_cpu_plan["resource_changes"][3]["change"]["after"]["cpu"] = "512"
        check_rejected(altered_cpu_plan, image_digest_map=DIGEST_MAP_JSON)

        # --- Rejected: altered command on a replacement family. ---
        altered_command_plan = base_plan()
        worker_after = json.loads(altered_command_plan["resource_changes"][2]["change"]["after"]["container_definitions"])
        worker_after[0]["command"] = ["/bin/sh", "-c", "curl evil.example"]
        altered_command_plan["resource_changes"][2]["change"]["after"]["container_definitions"] = json.dumps(worker_after)
        check_rejected(altered_command_plan, image_digest_map=DIGEST_MAP_JSON)

        # --- Rejected: secret pointing outside the approved runtime ARN on a replacement family. ---
        altered_secret_plan = base_plan()
        migration_after = json.loads(altered_secret_plan["resource_changes"][3]["change"]["after"]["container_definitions"])
        migration_after[0]["secrets"] = [{"name": "APP_SECRET_KEY", "valueFrom": "arn:aws:secretsmanager:ap-south-1:918870682888:secret:/other/secret:APP_SECRET_KEY::"}]
        altered_secret_plan["resource_changes"][3]["change"]["after"]["container_definitions"] = json.dumps(migration_after)
        check_rejected(altered_secret_plan, image_digest_map=DIGEST_MAP_JSON)

        # --- Rejected: networking/volume mutation on a replacement family. ---
        altered_network_plan = base_plan()
        altered_network_plan["resource_changes"][1]["change"]["after"]["network_mode"] = "awsvpc"
        check_rejected(altered_network_plan, image_digest_map=DIGEST_MAP_JSON)
        altered_volume_plan = base_plan()
        altered_volume_plan["resource_changes"][1]["change"]["after"]["volume"] = [{"name": "data"}]
        check_rejected(altered_volume_plan, image_digest_map=DIGEST_MAP_JSON)

        # --- Rejected: wrong family, wrong repository, wrong SHA on the api create. ---
        wrong_family_plan = base_plan()
        wrong_family_plan["resource_changes"][0]["change"]["after"]["family"] = "fieldzilla-production-api"
        check_rejected(wrong_family_plan, image_digest_map=DIGEST_MAP_JSON)

        wrong_repo_plan = base_plan()
        api_containers = json.loads(wrong_repo_plan["resource_changes"][0]["change"]["after"]["container_definitions"])
        api_containers[0]["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{ADMIN_WEB_REPO}:{DEPLOY_SHA}"
        wrong_repo_plan["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(api_containers)
        check_rejected(wrong_repo_plan, image_digest_map=DIGEST_MAP_JSON)

        wrong_sha_plan = base_plan()
        api_containers = json.loads(wrong_sha_plan["resource_changes"][0]["change"]["after"]["container_definitions"])
        api_containers[0]["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{API_REPO}:1111111111111111111111111111111111111111"
        wrong_sha_plan["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(api_containers)
        check_rejected(wrong_sha_plan, image_digest_map=DIGEST_MAP_JSON)

        # --- Rejected: missing repository mapping, malformed digest JSON. (A validly
        # formatted but semantically "wrong" digest value cannot be detected here -- the
        # map is independently-attested operator evidence with no in-plan ground truth to
        # compare against; see _parse_image_digest_map / _is_approved_baseline_container.) ---
        check_rejected(base_plan(), image_digest_map=json.dumps({API_REPO: DIGEST_MAP[API_REPO]}))
        check_rejected(base_plan(), image_digest_map="{not valid json")

    def test_new_task_definition_create_tolerates_provider_normalized_shape(self) -> None:
        """Reproduces the exact false-positive found against the real, live FieldZilla
        staging plan for the api family's pure create: `tofu show -json` re-serializes
        `environment` alphabetically by name (not in the order Terraform source or the
        baseline lists it) and represents unset optional nested-block attributes
        (`runtime_platform`, `proxy_configuration`, `ephemeral_storage`) as `[]`, not
        `null`. Neither is a real difference in what will be deployed -- both must still be
        approved -- but a genuine content difference hidden behind either shape (a missing/
        extra/changed environment entry, or a non-empty runtime_platform/proxy_configuration/
        ephemeral_storage block) must still be rejected."""
        runtime_arn = auth.EXACT_RUNTIME_SECRET_ARN
        baseline = auth.FIELDZILLA_TASK_DEFINITION_BASELINE["fieldzilla-staging-api"]
        secrets = [
            {"name": key, "valueFrom": f"{runtime_arn}:{key}::"}
            for key in sorted(baseline["container"]["secret_keys"])
        ]
        # Alphabetically-sorted by name, and NOT in the order compute.tf (or the baseline)
        # lists them -- exactly how `tofu show -json` actually rendered the real plan.
        environment_alphabetical = sorted(
            (dict(item) for item in baseline["container"]["environment"]),
            key=lambda item: item["name"],
        )
        assert environment_alphabetical != baseline["container"]["environment"], (
            "fixture must actually exercise a different order than the baseline"
        )

        def container(environment: list[dict[str, str]]) -> dict[str, object]:
            base = {k: v for k, v in baseline["container"].items() if k not in {"secret_keys", "environment"}}
            base["environment"] = environment
            base["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{baseline['ecr_repository']}:{DEPLOY_SHA}"
            base["secrets"] = secrets
            return base

        def after(environment: list[dict[str, str]], **overrides: object) -> dict[str, object]:
            fields = {
                "family": baseline_family,
                "cpu": baseline["cpu"],
                "memory": baseline["memory"],
                "execution_role_arn": baseline["execution_role_arn"],
                "task_role_arn": baseline["task_role_arn"],
                "network_mode": baseline["network_mode"],
                "requires_compatibilities": baseline["requires_compatibilities"],
                # The real plan JSON's shape for "unset" -- [] -- not the baseline's own
                # (also-[]-post-fix, but a test must not merely assert equality with
                # whatever the baseline currently says).
                "runtime_platform": [],
                "volume": baseline["volume"],
                "placement_constraints": baseline["placement_constraints"],
                "proxy_configuration": [],
                "ephemeral_storage": [],
                "container_definitions": json.dumps([container(environment)], sort_keys=True),
            }
            fields.update(overrides)
            return fields

        baseline_family = "fieldzilla-staging-api"

        def plan_with(task_def_after: dict[str, object]) -> dict[str, object]:
            return {
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
                        "change": {"actions": ["create"], "before": None, "after": task_def_after},
                    }
                ],
            }

        args = Namespace(plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map=DIGEST_MAP_JSON, ecs_families=ECS_FAMILIES)

        def check(task_def_after: dict[str, object]) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(plan_with(task_def_after)), encoding="utf-8")
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

        def check_rejected(task_def_after: dict[str, object]) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(plan_with(task_def_after)), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_safety(Namespace(plan_json_path=plan_json, **vars(args)))

        # --- Approved: alphabetically-reordered environment and []-shaped unset blocks,
        # identical content otherwise -- exactly the real, live FieldZilla plan shape. ---
        check(after(environment_alphabetical))

        # --- Approved: source-order environment is still fine (order truly does not
        # matter either way). ---
        check(after([dict(item) for item in baseline["container"]["environment"]]))

        # --- Rejected: a genuinely missing environment entry, even reordered. ---
        missing_entry = [item for item in environment_alphabetical if item["name"] != "APP_DEBUG"]
        check_rejected(after(missing_entry))

        # --- Rejected: a genuinely changed environment value, even reordered. ---
        altered_value = [dict(item) for item in environment_alphabetical]
        for item in altered_value:
            if item["name"] == "APP_OBJECT_STORAGE_REGION":
                item["value"] = "us-east-1"
        check_rejected(after(altered_value))

        # --- Rejected: a genuinely extra environment entry, even reordered. ---
        extra_entry = [dict(item) for item in environment_alphabetical] + [{"name": "APP_EXTRA", "value": "x"}]
        check_rejected(after(extra_entry))

        # --- Rejected: a non-empty runtime_platform is a real difference, not a shape
        # artifact, and must not be swallowed by the []/None tolerance. ---
        non_empty_runtime_platform = after(environment_alphabetical)
        non_empty_runtime_platform["runtime_platform"] = [{"cpuArchitecture": "ARM64"}]
        check_rejected(non_empty_runtime_platform)

    def test_task_definition_revision_tolerates_only_semantic_representation_drift(self) -> None:
        baseline = auth.FIELDZILLA_TASK_DEFINITION_BASELINE["fieldzilla-staging-api"]
        runtime_arn = auth.EXACT_RUNTIME_SECRET_ARN
        env_source_order = [dict(item) for item in baseline["container"]["environment"]]
        env_provider_order = sorted((dict(item) for item in env_source_order), key=lambda item: item["name"])
        secret_entries = [
            {"name": key, "valueFrom": f"{runtime_arn}:{key}::"}
            for key in sorted(baseline["container"]["secret_keys"])
        ]

        def container(image_tag: str, environment: list[dict[str, str]], **overrides: object) -> dict[str, object]:
            base = {k: v for k, v in baseline["container"].items() if k not in {"secret_keys", "environment"}}
            base["environment"] = environment
            base["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{baseline['ecr_repository']}:{image_tag}"
            base["secrets"] = list(reversed(secret_entries))
            base.update(overrides)
            return base

        before = {
            "family": "fieldzilla-staging-api",
            "cpu": baseline["cpu"],
            "memory": baseline["memory"],
            "execution_role_arn": baseline["execution_role_arn"],
            "task_role_arn": baseline["task_role_arn"],
            "network_mode": baseline["network_mode"],
            "requires_compatibilities": ["EC2"],
            "runtime_platform": None,
            "track_latest": False,
            "volume": None,
            "container_definitions": json.dumps([container("bootstrap", env_source_order)], sort_keys=True),
        }
        after = {
            **before,
            "requires_compatibilities": ["EC2"],
            "runtime_platform": [],
            "volume": [],
            "container_definitions": json.dumps([container(DEPLOY_SHA, env_provider_order)], sort_keys=True),
        }
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
                },
                {
                    "address": 'aws_ecs_service.api["staging"]',
                    "type": "aws_ecs_service",
                    "change": {
                        "actions": ["update"],
                        "before": {"task_definition": "arn:aws:ecs:ap-south-1:918870682888:task-definition/fieldzilla-staging-api:4"},
                        "after": {"task_definition": None},
                        "after_unknown": {"task_definition": True},
                    },
                },
            ],
        }

        def check(payload: dict[str, object]) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(payload), encoding="utf-8")
                auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", image_digest="", ecs_families=""))

        def check_rejected(payload: dict[str, object]) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_safety(Namespace(plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA, image_digest_map="", image_digest="", ecs_families=""))

        check(plan)

        role_change = json.loads(json.dumps(plan))
        role_change["resource_changes"][0]["change"]["after"]["task_role_arn"] = "arn:aws:iam::918870682888:role/Other"
        check_rejected(role_change)

        secret_change = json.loads(json.dumps(plan))
        containers = json.loads(secret_change["resource_changes"][0]["change"]["after"]["container_definitions"])
        containers[0]["secrets"][0]["valueFrom"] = f"{runtime_arn}:OTHER_KEY::"
        secret_change["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(containers)
        check_rejected(secret_change)

        port_change = json.loads(json.dumps(plan))
        containers = json.loads(port_change["resource_changes"][0]["change"]["after"]["container_definitions"])
        containers[0]["portMappings"] = [{"containerPort": 8080, "hostPort": 8080, "protocol": "tcp"}]
        port_change["resource_changes"][0]["change"]["after"]["container_definitions"] = json.dumps(containers)
        check_rejected(port_change)

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

    # -- routine_ecs_only data-source exemption ------------------------------------------

    def test_routine_ecs_data_source_exemption(self) -> None:
        """The rc150/rc151 authorizer's routine_ecs_only mode rejected ANY real FieldZilla
        plan, because infra/aws/compute.tf's ordinary data sources (IAM policy documents,
        availability zones, the ECS AMI SSM parameter) are re-evaluated on every plan and
        appear in resource_changes with actions=["read"] -- which routine_ecs_only treated
        as an unapproved non-ECS change. This is the exact, directly-reproduced defect;
        these are the adversarial cases proving the fix and nothing more than the fix."""

        def plan_with(entries: list[dict[str, object]], **var_overrides: object) -> dict[str, object]:
            variables = {
                "enable_production": {"value": False},
                "route53_zone_id": {"value": ""},
                "container_instance_type": {"value": "c6g.medium"},
                "monthly_budget_usd": {"value": "100"},
                "image_tag": {"value": DEPLOY_SHA},
            }
            variables.update(var_overrides)
            return {"variables": variables, "resource_changes": entries}

        def check(entries: list[dict[str, object]]) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(plan_with(entries)), encoding="utf-8")
                auth.verify_plan_safety(Namespace(
                    plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA,
                    image_digest_map=DIGEST_MAP_JSON, image_digest="", ecs_families=ECS_FAMILIES,
                ))

        def check_rejected(entries: list[dict[str, object]]) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                plan_json = Path(tmp) / "plan.json"
                plan_json.write_text(json.dumps(plan_with(entries)), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    auth.verify_plan_safety(Namespace(
                        plan_json_path=plan_json, plan_kind="normal", expected_sha=DEPLOY_SHA,
                        image_digest_map=DIGEST_MAP_JSON, image_digest="", ecs_families=ECS_FAMILIES,
                    ))

        data_read = {"address": 'data.aws_iam_policy_document.task["staging"]', "mode": "data",
                     "type": "aws_iam_policy_document", "change": {"actions": ["read"], "before": None, "after": {"json": "..."}}}
        data_noop = {**data_read, "change": {"actions": ["no-op"], "before": {"json": "..."}, "after": {"json": "..."}}}
        data_create = {**data_read, "change": {"actions": ["create"], "before": None, "after": {"json": "..."}}}
        data_update = {**data_read, "change": {"actions": ["update"], "before": {"json": "a"}, "after": {"json": "b"}}}
        data_delete = {**data_read, "change": {"actions": ["delete"], "before": {"json": "a"}, "after": None}}
        data_replace = {**data_read, "change": {"actions": ["delete", "create"], "before": {"json": "a"}, "after": {"json": "b"}}}
        managed_read_like = {"address": "aws_s3_bucket.evidence", "mode": "managed", "type": "aws_s3_bucket",
                              "change": {"actions": ["read"], "before": {"bucket": "x"}, "after": {"bucket": "x"}}}
        data_missing_mode = {"address": 'data.aws_availability_zones.available', "type": "aws_availability_zones",
                              "change": {"actions": ["read"], "before": None, "after": {"names": ["a"]}}}
        data_unknown_mode = {**data_missing_mode, "mode": "sometimes"}

        # --- Accepted: a lone data-source read or no-op, alone, is not itself an
        # "unapproved ECS change" (nothing ELSE non-ECS is in the plan). ---
        check([data_read])
        check([data_noop])

        # --- Rejected: any data-source mutation (create/update/delete/replace) is never
        # exempted -- only "read" and "no-op" ever qualify. ---
        check_rejected([data_create])
        check_rejected([data_update])
        check_rejected([data_delete])
        check_rejected([data_replace])

        # --- Rejected: a managed resource is never exempted by this path, even with a
        # (non-real-world, defensive) "read" action -- the exemption checks mode == "data"
        # first, unconditionally. ---
        check_rejected([managed_read_like])

        # --- Rejected: missing or unknown mode always fails closed -- it is never treated
        # as equivalent to "data". ---
        check_rejected([data_missing_mode])
        check_rejected([data_unknown_mode])

        # --- Accepted: harmless data reads alongside the exact approved FieldZilla ECS
        # rollout (the real shape this fix exists for) -- see
        # test_real_pending_fieldzilla_plan_shape for the full positive case; here just the
        # minimal create + its service pointer, plus two data reads. ---
        api_baseline = auth.FIELDZILLA_TASK_DEFINITION_BASELINE["fieldzilla-staging-api"]
        api_container = {k: v for k, v in api_baseline["container"].items() if k != "secret_keys"}
        api_container["image"] = f"918870682888.dkr.ecr.ap-south-1.amazonaws.com/{API_REPO}:{DEPLOY_SHA}"
        api_container["secrets"] = [
            {"name": k, "valueFrom": f"{auth.EXACT_RUNTIME_SECRET_ARN}:{k}::"}
            for k in sorted(api_baseline["container"]["secret_keys"])
        ]
        api_after = {
            "family": "fieldzilla-staging-api",
            "cpu": api_baseline["cpu"], "memory": api_baseline["memory"],
            "execution_role_arn": api_baseline["execution_role_arn"], "task_role_arn": api_baseline["task_role_arn"],
            "network_mode": api_baseline["network_mode"], "requires_compatibilities": api_baseline["requires_compatibilities"],
            "runtime_platform": api_baseline["runtime_platform"], "volume": api_baseline["volume"],
            "placement_constraints": api_baseline["placement_constraints"], "proxy_configuration": api_baseline["proxy_configuration"],
            "ephemeral_storage": api_baseline["ephemeral_storage"],
            "container_definitions": json.dumps([api_container], sort_keys=True),
        }
        harmless_plus_rollout = [
            data_read,
            data_noop,
            {"address": 'aws_ecs_task_definition.api["staging"]', "type": "aws_ecs_task_definition",
             "change": {"actions": ["create"], "before": None, "after": api_after}},
            {"address": 'aws_ecs_service.api["staging"]', "type": "aws_ecs_service",
             "change": {"actions": ["update"],
                        "before": {"task_definition": "arn:aws:ecs:ap-south-1:918870682888:task-definition/fieldzilla-staging-api:6"},
                        "after": {"task_definition": None}, "after_unknown": {"task_definition": True}}},
        ]
        check(harmless_plus_rollout)

        # --- Rejected: an unrelated managed-resource mutation alongside that same
        # otherwise-valid rollout still fails -- the data-source exemption does not widen
        # to cover anything else. ---
        check_rejected([
            *harmless_plus_rollout,
            {"address": "aws_db_instance.fieldzilla", "type": "aws_db_instance",
             "change": {"actions": ["delete"], "before": {}, "after": None}},
        ])

    # -- Inline ECR digest verification tool (embedded in the reusable workflow) --------

    @staticmethod
    def _extract_ecr_script(tmp_dir: Path) -> Path:
        """The reusable workflow embeds the ECR resolve/verify tool as a base64 blob in
        its "Write ECR digest verification tool" step (avoiding a second action release --
        see PR history). Extract and decode the exact deployed bytes, so these tests
        exercise the real embedded code, not a hand-maintained copy that could drift."""
        workflow_path = ROOT / ".github/workflows/fieldzilla-staging-opentofu-apply.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        match = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d >", workflow)
        assert match, "could not find the embedded ECR script in the reusable workflow"
        script_bytes = base64.b64decode(match.group(1))
        script_path = tmp_dir / "resolve_ecr_digests.py"
        script_path.write_bytes(script_bytes)
        # The embedded blob must itself be valid, parseable Python -- a corrupted or
        # truncated base64 edit must fail this test, not silently ship broken YAML.
        compile(script_bytes, str(script_path), "exec")
        return script_path

    @staticmethod
    def _fake_aws_bin(tmp_dir: Path, digests: dict[str, str], *, missing: set[str] = frozenset(), ambiguous: set[str] = frozenset()) -> Path:
        """A fake `aws` executable on PATH standing in for `aws ecr describe-images`,
        matching this repo's established pattern of faking external tools (see
        PrQaRegressionTests.setUp's fake gitleaks) rather than calling real AWS."""
        bin_dir = tmp_dir / "bin"
        bin_dir.mkdir(exist_ok=True)
        aws = bin_dir / "aws"
        # Invocation shape: aws ecr describe-images --repository-name <repo> --image-ids ...
        script = "#!/usr/bin/env bash\nrepo=\"$4\"\ncase \"$repo\" in\n"
        for repo, digest in digests.items():
            if repo in missing:
                body = '{"imageDetails": []}'
            elif repo in ambiguous:
                body = json.dumps({"imageDetails": [{"imageDigest": digest}, {"imageDigest": "sha256:" + "9" * 64}]})
            else:
                body = json.dumps({"imageDetails": [{"imageDigest": digest}]})
            script += f"  {repo!r})\n    echo {body!r}\n    ;;\n"
        script += "esac\nexit 0\n"
        aws.write_text(script, encoding="utf-8")
        aws.chmod(0o755)
        return bin_dir

    def _run_script(self, tmp_dir: Path, *args: str, digests: dict[str, str], missing: set[str] = frozenset(), ambiguous: set[str] = frozenset()) -> subprocess.CompletedProcess:
        script = self._extract_ecr_script(tmp_dir)
        bin_dir = self._fake_aws_bin(tmp_dir, digests, missing=missing, ambiguous=ambiguous)
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}"}
        return subprocess.run(["python3", str(script), *args], capture_output=True, text=True, env=env)

    def test_ecr_script_resolves_two_distinct_repository_digests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            digests = {API_REPO: DIGEST_MAP[API_REPO], ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}
            out = tmp_dir / "resolved.json"
            result = self._run_script(tmp_dir, "resolve", "--image-tag", DEPLOY_SHA, "--out", str(out), digests=digests)
            self.assertEqual(result.returncode, 0, result.stderr)
            resolved = json.loads(out.read_text())
            self.assertEqual(resolved, digests)
            self.assertNotEqual(resolved[API_REPO], resolved[ADMIN_WEB_REPO])

    def test_ecr_script_rejects_forged_but_well_formed_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            real = {API_REPO: DIGEST_MAP[API_REPO], ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}
            forged = {API_REPO: "sha256:" + "7" * 64, ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}
            evidence = tmp_dir / "evidence.json"
            evidence.write_text(json.dumps(forged))
            result = self._run_script(tmp_dir, "verify", "--image-tag", DEPLOY_SHA, "--evidence-path", str(evidence), digests=real)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("do not match", result.stderr)

    def test_ecr_script_rejects_missing_ecr_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            digests = {API_REPO: DIGEST_MAP[API_REPO], ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}
            out = tmp_dir / "resolved.json"
            result = self._run_script(tmp_dir, "resolve", "--image-tag", DEPLOY_SHA, "--out", str(out), digests=digests, missing={API_REPO})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected exactly 1", result.stderr)

    def test_ecr_script_rejects_multiple_ambiguous_ecr_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            digests = {API_REPO: DIGEST_MAP[API_REPO], ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}
            out = tmp_dir / "resolved.json"
            result = self._run_script(tmp_dir, "resolve", "--image-tag", DEPLOY_SHA, "--out", str(out), digests=digests, ambiguous={ADMIN_WEB_REPO})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected exactly 1", result.stderr)

    def test_ecr_script_rejects_moved_tag_between_plan_and_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            plan_time = {API_REPO: DIGEST_MAP[API_REPO], ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}
            apply_time = {API_REPO: "sha256:" + "4" * 64, ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}
            approved = tmp_dir / "approved.json"
            approved.write_text(json.dumps(plan_time))
            result = self._run_script(tmp_dir, "verify", "--image-tag", DEPLOY_SHA, "--evidence-path", str(approved), digests=apply_time)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("do not match", result.stderr)

    def test_ecr_script_rejects_wrong_repository_or_image_sha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            script = self._extract_ecr_script(tmp_dir)
            bin_dir = self._fake_aws_bin(tmp_dir, {API_REPO: DIGEST_MAP[API_REPO], ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]})
            env = {**os.environ, "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}"}
            result = subprocess.run(
                ["python3", str(script), "resolve", "--image-tag", "not-a-real-sha", "--out", str(tmp_dir / "x.json")],
                capture_output=True, text=True, env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("40-character lowercase hex", result.stderr)

    def test_ecr_script_rejects_metadata_mismatch_missing_or_extra_repository(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            digests = {API_REPO: DIGEST_MAP[API_REPO], ADMIN_WEB_REPO: DIGEST_MAP[ADMIN_WEB_REPO]}
            partial = tmp_dir / "partial.json"
            partial.write_text(json.dumps({API_REPO: DIGEST_MAP[API_REPO]}))
            result = self._run_script(tmp_dir, "verify", "--image-tag", DEPLOY_SHA, "--evidence-path", str(partial), digests=digests)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exactly the two approved repositories", result.stderr)

    def test_ecr_script_never_prints_credentials(self) -> None:
        script_text = (ROOT / ".github/workflows/fieldzilla-staging-opentofu-apply.yml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            script = self._extract_ecr_script(Path(tmp))
            decoded = script.read_text(encoding="utf-8")
        for forbidden in ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "aws_secret", "password"):
            self.assertNotIn(forbidden, decoded)

    # -- Workflow input-contract consistency --------------------------------------------

    def test_workflow_with_blocks_match_exact_pinned_action_contract(self) -> None:
        """Every `with:` key passed to opentofu-plan-authorizer anywhere in the reusable
        workflow must be a key the exact pinned action version actually declares. This is
        exactly the class of bug that broke exact-head CI earlier in this series (a
        workflow passing an input the pinned immutable action release did not know) --
        this test catches that class of mismatch locally, before it reaches GitHub."""
        workflow_path = ROOT / ".github/workflows/fieldzilla-staging-opentofu-apply.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        action_yml = (ROOT / "actions/opentofu-plan-authorizer/action.yml").read_text(encoding="utf-8")

        declared_inputs = set(re.findall(r"^  ([a-z][a-z0-9-]*):\n", action_yml, re.MULTILINE))
        self.assertIn("image-digest-map", declared_inputs)

        lines = workflow.splitlines()
        blocks: list[list[str]] = []
        current: list[str] | None = None
        for line in lines:
            if re.match(r"^\s*uses: \./\.central-framework/actions/opentofu-plan-authorizer\s*$", line):
                current = []
                blocks.append(current)
                continue
            if current is not None:
                if re.match(r"^\s*with:\s*$", line):
                    continue
                match = re.match(r"^\s{10,}([a-z][a-z0-9-]*):", line)
                if match:
                    current.append(match.group(1))
                elif line.strip() == "" or not line.startswith("          "):
                    current = None

        self.assertTrue(blocks, "expected at least one opentofu-plan-authorizer invocation")
        for block in blocks:
            unknown = set(block) - declared_inputs
            self.assertFalse(unknown, f"with: keys not declared by action.yml: {unknown}")


if __name__ == "__main__":
    unittest.main()
