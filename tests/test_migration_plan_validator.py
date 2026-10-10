from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "actions" / "migration-plan-validator"
spec = importlib.util.spec_from_file_location("migration_plan_validator", ACTION / "migration_plan_validator.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)
SHA = "a" * 40
DIGEST = "sha256:" + "c" * 64
BASE = "b" * 40
REGISTRY = "example.dkr.ecr.ap-south-1.amazonaws.com"
REPO = "synergie/example/api"


def plan() -> dict:
    return {
        "schema_version": 1, "plan_id": "migration-0060",
        "repository": "Synergie-ITCI/example", "environment": "staging",
        "service": "api", "migration_tool": "alembic",
        "expected_pre_head": "revision_0059", "expected_post_head": "revision_0060",
        "allowed_changed_paths": ["apps/api/alembic/versions/*", "apps/api/app/modules/**",
                                  ".github/migration-plans/migration-0060.json"],
        "allowed_non_runtime_paths": [],
        "forbidden_paths": ["deploy/legacy/compose.yml", "deploy/legacy/ssm.sh"],
        "migration_runner": "example-staging-migration", "allowed_services": ["api"],
        "image_rule": {"registries": [REGISTRY], "repositories": {"api": REPO},
                       "task_definition_families": {"api": "example-staging-api"}},
        "rollback_note": "Restore the pre-migration backup.",
    }


def evidence() -> dict:
    return {
        "evidence_schema_version": 1, "plan_id": "migration-0060",
        "workflow_sha": SHA, "artifact_sha": SHA,
        "artifact_is_ancestor_of_workflow": True,
        "paths_changed_between_artifact_and_workflow": [], "repository": "Synergie-ITCI/example",
        "environment": "staging", "service": "api", "migration_tool": "alembic",
        "migration_runner": "example-staging-migration", "base_sha": BASE,
        "changed_paths": [
            {"status": "added", "path": "apps/api/alembic/versions/0060.py"},
            {"status": "modified", "path": "apps/api/app/modules/projects/api.py"},
        ],
        "live_db_head": "revision_0059", "target_head": "revision_0060",
        "image_evidence": [{"service": "api", "registry": REGISTRY,
                            "repository": REPO, "tag": SHA, "digest": DIGEST}],
        "task_definition_diff": [{"service": "api", "family": "example-staging-api",
                                  "changes": [{"path": "/containerDefinitions/0/image",
                                               "before": "old", "after": f"{REGISTRY}/{REPO}@{DIGEST}"}]}],
    }


class MigrationPlanValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tree = Path(self.temp.name)
        self.plan_dir = self.tree / ".github" / "migration-plans"
        self.plan_dir.mkdir(parents=True)

    def run_case(self, p=None, e=None, *, trusted_sha=SHA, trusted_base=BASE,
                 tree_head=SHA, plan_id="migration-0060") -> dict:
        if p is not None:
            (self.plan_dir / f"{plan_id}.json").write_text(json.dumps(p))
        evidence_file = self.tree / "evidence.json"
        evidence_file.write_text(json.dumps(e if e is not None else evidence()))
        def local_plan(_tree: Path, _sha: str, identity: str) -> dict:
            path = self.plan_dir / f"{identity}.json"
            if not path.is_file():
                raise ValueError("plan not found in workflow commit tree")
            return json.loads(path.read_text())

        with mock.patch.object(validator, "load_plan_from_commit", side_effect=local_plan), \
             mock.patch.object(validator, "check_ancestor", return_value=True), \
             mock.patch.object(validator, "actual_artifact_paths", return_value=[]):
            return validator.run(Namespace(tree=str(self.tree), plan_id=plan_id,
                                           evidence=str(evidence_file), workflow_sha=trusted_sha,
                                           tree_head=tree_head, base_sha=trusted_base,
                                           repository="Synergie-ITCI/example", environment="staging",
                                           service="api"))

    def test_valid_plan_passes(self) -> None:
        result = self.run_case(plan())
        self.assertTrue(result["pass"], result)
        self.assertEqual(result["validator_version"], "1")
        self.assertEqual(result["evidence_schema_version"], 1)

    def test_missing_plan_and_bad_id_fail(self) -> None:
        self.assertFalse(self.run_case()["pass"])
        self.assertFalse(self.run_case(plan(), plan_id="../escape")["pass"])

    def test_unknown_and_malformed_plan_fail(self) -> None:
        p = plan(); p["new_field"] = True
        self.assertFalse(self.run_case(p)["pass"])
        p = plan(); p["schema_version"] = 2
        self.assertFalse(self.run_case(p)["pass"])
        self.assertFalse(self.run_case({"bad": True})["pass"])

    def test_unknown_evidence_version_and_fields_fail(self) -> None:
        e = evidence(); e["evidence_schema_version"] = 2
        self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e["surprise"] = True
        self.assertFalse(self.run_case(plan(), e)["pass"])

    def test_each_identity_binding_fails(self) -> None:
        for key in ("plan_id", "repository", "environment", "service", "migration_tool"):
            with self.subTest(key=key):
                e = evidence(); e[key] = "different"
                self.assertFalse(self.run_case(plan(), e)["pass"])

    def test_deploy_and_base_sha_fail(self) -> None:
        e = evidence(); e["workflow_sha"] = BASE
        self.assertFalse(self.run_case(plan(), e)["pass"])
        self.assertFalse(self.run_case(plan(), trusted_sha=BASE)["pass"])
        self.assertFalse(self.run_case(plan(), tree_head=BASE)["pass"])
        e = evidence(); e["base_sha"] = SHA
        self.assertFalse(self.run_case(plan(), e)["pass"])

    def test_artifact_binding_and_non_runtime_policy(self) -> None:
        e = evidence(); e["artifact_sha"] = BASE
        self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e.pop("artifact_sha")
        self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e["artifact_is_ancestor_of_workflow"] = False
        self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e.pop("paths_changed_between_artifact_and_workflow")
        self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e["paths_changed_between_artifact_and_workflow"] = ["apps/api/app/main.py"]
        self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e["paths_changed_between_artifact_and_workflow"] = ["unknown/file.txt"]
        self.assertFalse(self.run_case(plan(), e)["pass"])
        for disallowed in ("deploy/**", "infra/**", "apps/api/alembic/versions/*",
                           "apps/api/Dockerfile", "apps/api/app/main.py"):
            p = plan(); p["allowed_non_runtime_paths"] = [disallowed]
            self.assertFalse(self.run_case(p)["pass"], disallowed)
        p = plan(); p["allowed_non_runtime_paths"] = ["docs/**"]
        e = evidence(); e["paths_changed_between_artifact_and_workflow"] = ["docs/readme.md"]
        with mock.patch.object(validator, "actual_artifact_paths", return_value=["docs/readme.md"]), \
             mock.patch.object(validator, "check_ancestor", return_value=True):
            # Direct semantic validation confirms the centrally allowed category.
            self.assertTrue(validator.validate(p, e, tree=self.tree, workflow_sha=SHA,
                                               base_sha=BASE, repository=p["repository"],
                                               environment=p["environment"], service="api")["pass"])

    def test_git_evidence_mismatch_fails_closed(self) -> None:
        def git(*args: str) -> str:
            return subprocess.check_output(["git", "-C", str(self.tree), *args], text=True).strip()

        git("init", "-q")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "Test")
        p = plan()
        p["allowed_non_runtime_paths"] = ["docs/**"]
        (self.plan_dir / "migration-0060.json").write_text(json.dumps(p))
        git("add", ".github/migration-plans/migration-0060.json")
        git("commit", "-qm", "artifact")
        artifact = git("rev-parse", "HEAD")
        (self.tree / "docs").mkdir()
        (self.tree / "docs" / "guide.md").write_text("docs change\n")
        git("add", "docs/guide.md")
        git("commit", "-qm", "workflow")
        workflow = git("rev-parse", "HEAD")
        e = evidence()
        e.update(workflow_sha=workflow, artifact_sha=artifact,
                 paths_changed_between_artifact_and_workflow=["docs/guide.md"])
        e["image_evidence"][0]["tag"] = artifact
        evidence_file = self.tree / "evidence.json"
        args = Namespace(tree=str(self.tree), tree_head=workflow,
                         plan_id="migration-0060", evidence=str(evidence_file),
                         workflow_sha=workflow, base_sha=BASE,
                         repository="Synergie-ITCI/example", environment="staging", service="api")
        evidence_file.write_text(json.dumps(e))
        self.assertTrue(validator.run(args)["pass"])
        e["paths_changed_between_artifact_and_workflow"] = []
        evidence_file.write_text(json.dumps(e))
        self.assertFalse(validator.run(args)["pass"])
        e["paths_changed_between_artifact_and_workflow"] = ["docs/guide.md"]
        e["artifact_sha"] = BASE
        evidence_file.write_text(json.dumps(e))
        self.assertFalse(validator.run(args)["pass"])

    def test_heads_and_multiple_heads_fail(self) -> None:
        for key in ("live_db_head", "target_head"):
            e = evidence(); e[key] = "wrong"
            self.assertFalse(self.run_case(plan(), e)["pass"])
            e[key] = ["revision_0059", "revision_0060"]
            self.assertFalse(self.run_case(plan(), e)["pass"])
        p = plan(); p["expected_post_head"] = p["expected_pre_head"]
        self.assertFalse(self.run_case(p)["pass"])

    def test_changed_path_and_forbidden_path_fail(self) -> None:
        for path in ("docs/other.md", "deploy/legacy/compose.yml", "deploy/legacy/ssm.sh",
                     "../escape", "/absolute", "apps/api/../secret"):
            with self.subTest(path=path):
                e = evidence(); e["changed_paths"].append({"status": "modified", "path": path})
                self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e["changed_paths"] = []
        self.assertFalse(self.run_case(plan(), e)["pass"])

    def test_glob_escape_rename_and_delete(self) -> None:
        for pattern in ("**", "apps/**", "apps/api/../secret/*", "/apps/api/*"):
            p = plan(); p["allowed_changed_paths"] = [pattern]
            self.assertFalse(self.run_case(p)["pass"])
        e = evidence(); e["changed_paths"] = [{"status": "renamed", "path": "apps/api/app/modules/new.py",
                                               "previous_path": "deploy/legacy/compose.yml"}]
        self.assertFalse(self.run_case(plan(), e)["pass"])
        e["changed_paths"] = [{"status": "deleted", "path": "docs/other.md"}]
        self.assertFalse(self.run_case(plan(), e)["pass"])
        e["changed_paths"] = [{"status": "renamed", "path": "apps/api/app/modules/new.py"}]
        self.assertFalse(self.run_case(plan(), e)["pass"])

    def test_image_and_service_failures(self) -> None:
        for key, value in (("tag", BASE), ("repository", "other"), ("registry", "other"),
                           ("service", "other"), ("digest", "sha256:" + "d" * 64)):
            e = evidence(); e["image_evidence"][0][key] = value
            self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e["image_evidence"] = []
        self.assertFalse(self.run_case(plan(), e)["pass"])
        p = plan(); p["allowed_services"] = ["admin"]
        self.assertFalse(self.run_case(p)["pass"])

    def test_runner_and_non_image_task_diff_fail(self) -> None:
        e = evidence(); e["migration_runner"] = "other"
        self.assertFalse(self.run_case(plan(), e)["pass"])
        for path in ("/cpu", "/containerDefinitions/0/environment", "/containerDefinitions/0/image/extra"):
            e = evidence(); e["task_definition_diff"][0]["changes"][0]["path"] = path
            self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e["task_definition_diff"][0]["changes"][0]["after"] = "other:sha"
        self.assertFalse(self.run_case(plan(), e)["pass"])
        e = evidence(); e["task_definition_diff"][0]["family"] = "other"
        self.assertFalse(self.run_case(plan(), e)["pass"])

    def test_action_is_composite_not_reusable_workflow(self) -> None:
        action = (ACTION / "action.yml").read_text()
        self.assertIn("using: composite", action)
        self.assertNotIn("workflow_call", action)
        self.assertNotIn("job_workflow_ref", action)
        self.assertFalse((ROOT / ".github/workflows/migration-plan-validator.yml").exists())

    def test_fieldzilla_staging_replays_and_single_field_mutations(self) -> None:
        # Run 37567604112: 0059 -> 0060; run 37940736156: 0060 -> 0061.
        # Paths and SHAs are from GitHub compare; image/task records are the
        # normalized v1 representation of the reviewed staging deployment lane.
        source = ROOT / "tests" / "fixtures" / "migration_plan_replay"
        for label in ("0059-0060", "0060-0061"):
            with self.subTest(replay=label):
                p = json.loads((source / f"{label}-plan.json").read_text())
                e = json.loads((source / f"{label}-evidence.json").read_text())
                self.assertEqual(validator.valid_plan(p), [])
                self.assertEqual(validator.valid_evidence(e), [])
                result = validator.validate(p, e, tree=self.tree,
                                            workflow_sha=e["workflow_sha"], base_sha=e["base_sha"],
                                            repository=p["repository"], environment=p["environment"],
                                            service=p["service"])
                self.assertEqual(result["pass"], label == "0060-0061", result)
                if label == "0059-0060":
                    self.assertFalse(result["checks"]["artifact_paths"]["pass"])
                    continue
                mutations = {
                    "evidence_schema_version": 2,
                    "plan_id": "other", "workflow_sha": SHA, "artifact_sha": BASE,
                    "artifact_is_ancestor_of_workflow": False,
                    "paths_changed_between_artifact_and_workflow": ["deploy/unknown.py"],
                    "repository": "other/repo", "environment": "other",
                    "service": "other", "migration_tool": "other",
                    "migration_runner": "other", "base_sha": BASE,
                    "changed_paths": [{"status": "modified", "path": "docs/outside.md"}],
                    "live_db_head": "other", "target_head": "other",
                    "image_evidence": [], "task_definition_diff": [],
                }
                for key, replacement in mutations.items():
                    with self.subTest(replay=label, field=key):
                        changed = copy.deepcopy(e); changed[key] = replacement
                        if key == "base_sha" and replacement == e["base_sha"]:
                            changed[key] = SHA
                        if validator.valid_evidence(changed):
                            continue  # structural rejection already proves fail closed
                        changed_result = validator.validate(
                            p, changed, tree=self.tree, workflow_sha=e["workflow_sha"],
                            base_sha=e["base_sha"], repository=p["repository"],
                            environment=p["environment"], service=p["service"])
                        self.assertFalse(changed_result["pass"], (label, key, changed_result))


if __name__ == "__main__":
    unittest.main()
