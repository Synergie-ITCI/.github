from __future__ import annotations

import contextlib
import copy
import io
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

FIXTURES = ROOT / "tests" / "fixtures" / "fieldzilla_reviewed_plan"
PLAN_ID = "synthetic-reviewed-plan"
SOURCE_SHA = "1" * 40
WORKFLOW = ROOT / ".github/workflows/fieldzilla-staging-opentofu-apply.yml"
ACTION = ROOT / "actions/opentofu-plan-authorizer/action.yml"


def staging_compare(status: str = "ahead", merge_base: str = SOURCE_SHA):
    return lambda path, *a, **k: {"status": status, "merge_base_commit": {"sha": merge_base}}


class ReviewedPlanTestCase(unittest.TestCase):
    """Fixture provenance: the plan is a sanitized real-plan subset (seven reviewed changes and three
    deferred policy documents from the failed staging plan); every variant below is synthetic."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        (self.workspace / ".github/opentofu-plans").mkdir(parents=True)
        self.spec = json.loads((FIXTURES / "real_derived_spec.json").read_text(encoding="utf-8"))
        self.write_spec(self.spec)
        self.plan = json.loads((FIXTURES / "real_derived_plan.json").read_text(encoding="utf-8"))

    @property
    def spec_path(self) -> Path:
        return self.workspace / ".github/opentofu-plans" / f"{PLAN_ID}.json"

    def write_spec(self, spec: dict | str, plan_id: str = PLAN_ID) -> Path:
        path = self.workspace / ".github/opentofu-plans" / f"{plan_id}.json"
        path.write_text(spec if isinstance(spec, str) else json.dumps(spec), encoding="utf-8")
        return path

    def plan_args(self) -> Namespace:
        return Namespace(repository=auth.REPOSITORY, environment=auth.ENVIRONMENT,
                         plan_id=PLAN_ID, plan_workspace=self.workspace)

    def file_args(self, **overrides) -> Namespace:
        values = dict(plan_id=PLAN_ID, plan_workspace=self.workspace, expected_sha=SOURCE_SHA,
                      repository=auth.REPOSITORY, image_tag=self.spec["image_tag"],
                      metadata_path=None, spec_out_dir=None)
        values.update(overrides)
        return Namespace(**values)

    def dies(self, call, contains: str | None = None) -> str:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                call()
        if contains is not None:
            self.assertIn(contains, stderr.getvalue())
        return stderr.getvalue()

    def check_plan(self, plan: dict | None = None) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            auth.verify_reviewed_staging_plan(plan if plan is not None else self.plan, self.plan_args())

    def change(self, address: str) -> dict:
        return next(item for item in self.plan["resource_changes"] if item["address"] == address)

    @staticmethod
    def new_change(address: str, resource_type: str, actions: list[str], after: dict | None = None) -> dict:
        return {"address": address, "mode": "managed", "type": resource_type,
                "change": {"actions": actions, "before": None, "after": after or {}, "after_unknown": {}}}


class ReviewedPlanVerificationTests(ReviewedPlanTestCase):
    def test_real_derived_plan_passes_with_replace_and_preexisting_wildcards(self) -> None:
        self.check_plan()
        self.assertEqual(auth._iam_wildcards_introduced(self.plan["resource_changes"]), [])
        replace = self.change('aws_ecs_task_definition.migration["staging"]')
        self.assertEqual(sorted(replace["change"]["actions"]), ["create", "delete"])

    def test_extra_change_fails(self) -> None:
        self.plan["resource_changes"].append(self.new_change("aws_iam_user.extra", "aws_iam_user", ["create"]))
        self.dies(self.check_plan, "unexpected: aws_iam_user.extra")

    def test_missing_change_fails(self) -> None:
        self.plan["resource_changes"].remove(self.change("aws_iam_role.staging_migration_execution"))
        self.dies(self.check_plan, "missing: aws_iam_role.staging_migration_execution")

    def test_action_mismatch_fails(self) -> None:
        self.change("aws_iam_policy.staging_infra_ecs_rollout")["change"]["actions"] = ["create"]
        self.dies(self.check_plan, "action mismatch: aws_iam_policy.staging_infra_ecs_rollout")

    def test_noop_and_read_entries_are_ignored(self) -> None:
        self.plan["resource_changes"].append(self.new_change("aws_vpc.app", "aws_vpc", ["no-op"]))
        self.plan["resource_changes"].append(self.new_change("data.aws_caller_identity.current", "aws_caller_identity", ["read"]))
        self.check_plan()

    def test_delete_action_fails_even_when_listed_by_the_consumer(self) -> None:
        self.plan["resource_changes"].append(self.new_change("aws_iam_user.gone", "aws_iam_user", ["delete"]))
        self.dies(self.check_plan, "delete action: aws_iam_user.gone")
        self.spec["expected_changes"].append({"address": "aws_iam_user.gone", "actions": ["delete"]})
        self.write_spec(self.spec)
        self.dies(self.check_plan)  # the file schema itself rejects a delete expectation

    def test_replace_of_stateful_type_fails_even_when_listed_by_the_consumer(self) -> None:
        for resource_type in sorted(auth.STATEFUL_RESOURCE_TYPES):
            with self.subTest(resource_type=resource_type):
                spec = copy.deepcopy(self.spec)
                spec["expected_changes"].append({"address": f"{resource_type}.main", "actions": ["create", "delete"]})
                self.write_spec(spec)
                plan = copy.deepcopy(self.plan)
                plan["resource_changes"].append(
                    self.new_change(f"{resource_type}.main", resource_type, ["delete", "create"]))
                self.dies(lambda: self.check_plan(plan), f"replaces a stateful resource: {resource_type}.main")

    def test_new_wildcard_iam_action_or_resource_fails(self) -> None:
        def widen_resource(plan: dict) -> None:
            change = next(c for c in plan["resource_changes"]
                          if c["address"] == "aws_iam_role_policy.staging_migration_execution_secrets")
            policy = json.loads(change["change"]["after"]["policy"])
            policy["Statement"][0]["Resource"] = "*"
            change["change"]["after"]["policy"] = json.dumps(policy)

        def widen_action(plan: dict) -> None:
            change = next(c for c in plan["resource_changes"]
                          if c["address"] == "aws_iam_role_policy.staging_migration_execution_secrets")
            policy = json.loads(change["change"]["after"]["policy"])
            policy["Statement"][0]["Action"] = ["*"]
            change["change"]["after"]["policy"] = json.dumps(policy)

        def widen_deferred_document(plan: dict) -> None:
            document = next(c for c in plan["resource_changes"]
                            if c["address"] == 'data.aws_iam_policy_document.deploy["staging"]')
            document["change"]["after"]["statement"][0]["actions"] = ["*"]

        for name, mutate, address in (
            ("resource", widen_resource, "staging_migration_execution_secrets"),
            ("action", widen_action, "staging_migration_execution_secrets"),
            ("deferred document", widen_deferred_document, 'deploy["staging"]'),
        ):
            with self.subTest(wildcard=name):
                plan = copy.deepcopy(self.plan)
                mutate(plan)
                self.dies(lambda: self.check_plan(plan), "wildcard IAM action or resource")

    def test_partial_wildcards_are_not_rejected(self) -> None:
        change = self.change("aws_iam_role_policy.staging_migration_execution_secrets")
        policy = json.loads(change["change"]["after"]["policy"])
        policy["Statement"][0]["Action"] = ["secretsmanager:Get*"]
        policy["Statement"][0]["Resource"] = ["arn:aws:secretsmanager:ap-south-1:123456789012:secret:app/*"]
        change["change"]["after"]["policy"] = json.dumps(policy)
        self.check_plan()

    def test_plaintext_secret_scanner_still_runs(self) -> None:
        self.change("aws_iam_role.staging_migration_execution")["change"]["after"]["api_token"] = "synthetic-plaintext"
        self.dies(self.check_plan, "reviewed plan rejected")

    def test_plan_must_use_the_reviewed_image_tag_and_staging_scope(self) -> None:
        for name, mutate in (
            ("image tag", lambda p: p["variables"]["image_tag"].update(value="2" * 40)),
            ("production", lambda p: p["variables"]["enable_production"].update(value=True)),
            ("dns", lambda p: p["variables"].setdefault("route53_zone_id", {}).update(value="Z123")),
        ):
            with self.subTest(case=name):
                plan = copy.deepcopy(self.plan)
                mutate(plan)
                self.dies(lambda: self.check_plan(plan))

    def test_wrong_repository_or_environment_fails(self) -> None:
        args = self.plan_args()
        args.environment = "production"
        self.dies(lambda: auth.verify_reviewed_staging_plan(self.plan, args), "identity mismatch")

    def test_existing_hardcoded_kinds_are_untouched_and_new_kind_hardcodes_nothing(self) -> None:
        self.assertEqual(auth.PR521_SOURCE_SHA, "a06e6f827d540a716b155ace2b33bb65491c29cf")
        self.assertEqual(auth.STAGING_MIGRATION_IAM_SOURCE_SHA, "362109240192e6ac817d180a6d1e6b6a422c469b")
        source = (ROOT / "tools/opentofu_plan_authorization.py").read_text(encoding="utf-8")
        section = source[source.index("# --- Reviewed staging plan kind"):source.index("class PlanSecretFinding")]
        self.assertIsNone(re.search(r"[0-9a-f]{40}", section))
        for forbidden in ("918870682888", "pr521", "PR521", "arn:aws"):
            self.assertNotIn(forbidden, section)


class ReviewedPlanFileTests(ReviewedPlanTestCase):
    def verify_file(self, **overrides) -> str:
        output = io.StringIO()
        with mock.patch.object(auth, "github_api", staging_compare()), contextlib.redirect_stdout(output):
            auth.verify_reviewed_plan_file(self.file_args(**overrides))
        return output.getvalue()

    def file_dies(self, contains: str | None = None, **overrides) -> str:
        with mock.patch.object(auth, "github_api", staging_compare()):
            return self.dies(lambda: auth.verify_reviewed_plan_file(self.file_args(**overrides)), contains)

    def test_valid_file_reports_sha256_and_writes_targets(self) -> None:
        out_dir = Path(self.temp.name) / "out"
        out_dir.mkdir()
        output = self.verify_file(spec_out_dir=out_dir)
        digest = auth.hashlib.sha256(self.spec_path.read_bytes()).hexdigest()
        self.assertIn(f"REVIEWED_PLAN_FILE_SHA256={digest}", output)
        self.assertEqual((out_dir / "reviewed-plan-file.sha256").read_text().strip(), digest)
        self.assertEqual((out_dir / "reviewed-plan-targets.txt").read_text().splitlines(), self.spec["targets"])

    def test_missing_file_fails(self) -> None:
        self.spec_path.unlink()
        self.file_dies("reviewed plan file is missing")

    def test_malformed_files_fail(self) -> None:
        for name, text in (("not json", "{"), ("array", "[]"), ("nan", '{"plan_id": NaN}'),
                           ("duplicate key", '{"plan_id": "a", "plan_id": "b"}')):
            with self.subTest(case=name):
                self.write_spec(text)
                self.file_dies("reviewed plan file")

    def test_unknown_missing_and_mismatched_keys_fail(self) -> None:
        cases = {
            "unknown key": {**self.spec, "approved_by": "someone"},
            "missing key": {k: v for k, v in self.spec.items() if k != "targets"},
            "plan id mismatch": {**self.spec, "plan_id": "another-plan"},
            "bad image tag": {**self.spec, "image_tag": "latest"},
            "bad change entry": {**self.spec, "expected_changes": [{"address": "aws_vpc.app"}]},
            "extra change key": {**self.spec, "expected_changes": [
                {"address": "aws_vpc.app", "actions": ["update"], "note": "x"}]},
            "duplicate address": {**self.spec, "expected_changes": [
                {"address": "aws_vpc.app", "actions": ["update"]}] * 2},
            "unsupported action": {**self.spec, "expected_changes": [
                {"address": "aws_vpc.app", "actions": ["forget"]}]},
        }
        for name, spec in cases.items():
            with self.subTest(case=name):
                self.write_spec(spec)
                self.file_dies()

    def test_malicious_or_malformed_targets_fail(self) -> None:
        for target in ("-target=aws_vpc.app", "aws_vpc.app; rm -rf /", "aws_vpc", "aws_vpc.app extra",
                       "aws_vpc.app\n-destroy", "../aws_vpc.app", ""):
            with self.subTest(target=target):
                self.write_spec({**self.spec, "targets": [target]})
                self.file_dies()
        self.write_spec({**self.spec, "targets": [self.spec["targets"][0]] * 2})
        self.file_dies("unique")

    def test_oversized_and_symlinked_files_fail(self) -> None:
        self.write_spec(json.dumps({**self.spec, "pad": "x" * (auth.REVIEWED_PLAN_MAX_BYTES + 1)}))
        self.file_dies("too large")
        self.spec_path.unlink()
        real = Path(self.temp.name) / "elsewhere.json"
        real.write_text(json.dumps(self.spec), encoding="utf-8")
        self.spec_path.symlink_to(real)
        self.file_dies("missing")

    def test_too_many_items_fail(self) -> None:
        targets = [f"aws_vpc.v{i}" for i in range(auth.REVIEWED_PLAN_MAX_ITEMS + 1)]
        self.write_spec({**self.spec, "targets": targets})
        self.file_dies("at most")

    def test_invalid_plan_ids_fail(self) -> None:
        for plan_id in ("", "../escape", "UPPER-case", "a/b", "ab", "x" * 80):
            with self.subTest(plan_id=plan_id):
                self.file_dies("plan id", plan_id=plan_id)

    def test_dispatched_image_tag_must_match_the_file(self) -> None:
        self.file_dies("image_tag does not match", image_tag="3" * 40)

    def test_source_sha_must_be_reachable_from_staging(self) -> None:
        for name, compare in (
            ("diverged", staging_compare("diverged")),
            ("behind", staging_compare("behind")),
            ("not an ancestor", staging_compare("ahead", merge_base="9" * 40)),
        ):
            with self.subTest(case=name), mock.patch.object(auth, "github_api", compare):
                self.dies(lambda: auth.verify_reviewed_plan_file(self.file_args()), "not reachable from the protected staging")
        with mock.patch.object(auth, "github_api", staging_compare("identical")), contextlib.redirect_stdout(io.StringIO()):
            auth.verify_reviewed_plan_file(self.file_args())
        self.dies(lambda: auth.verify_reviewed_plan_file(self.file_args(expected_sha="nonsense")), "40-character")

    def test_approved_artifact_must_carry_the_same_file_hash(self) -> None:
        digest = auth.hashlib.sha256(self.spec_path.read_bytes()).hexdigest()
        metadata = Path(self.temp.name) / "metadata.json"
        metadata.write_text(json.dumps({"reviewed_plan_id": PLAN_ID, "reviewed_plan_file_sha256": digest}))
        self.verify_file(metadata_path=metadata)
        for case in ({"reviewed_plan_id": PLAN_ID, "reviewed_plan_file_sha256": "0" * 64},
                     {"reviewed_plan_id": "other-plan", "reviewed_plan_file_sha256": digest}, {}):
            with self.subTest(metadata=case):
                metadata.write_text(json.dumps(case))
                self.file_dies("not generated from this reviewed plan file", metadata_path=metadata)

    def test_cli_wiring_and_workflow_structure(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        action = ACTION.read_text(encoding="utf-8")
        for needle in ("plan-id:", "fieldzilla-staging-reviewed-plan", '-target=${target}',
                       "reviewed_plan_file_sha256", "Verify approved artifact matches the reviewed plan file",
                       "plan-workspace: ${{ github.workspace }}"):
            self.assertIn(needle, workflow)
        self.assertLess(workflow.index("Verify reviewed plan file and source commit"),
                        workflow.index("Configure AWS credentials"))
        self.assertLess(workflow.index("Verify approved artifact matches the reviewed plan file"),
                        workflow.index("Apply exact approved plan artifact"))
        self.assertIn("plan-id is valid only for infra/aws plan or apply", workflow)
        self.assertIn("verify-reviewed-plan-file", action)
        self.assertEqual(
            (ROOT / "tools/opentofu_plan_authorization.py").read_bytes(),
            (ROOT / "actions/opentofu-plan-authorizer/opentofu_plan_authorization.py").read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
