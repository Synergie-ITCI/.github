import importlib.util
import json
import subprocess
import sys
import unittest
from unittest.mock import patch
from pathlib import Path
from typing import Any

MODULE = Path(__file__).resolve().parents[1] / "tools" / "onboard_repo.py"
spec = importlib.util.spec_from_file_location("onboard_repo", MODULE)
mod = importlib.util.module_from_spec(spec)
assert spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class WorkflowClassificationTests(unittest.TestCase):
    OWNER = "SaurabhVermaIN"

    def test_controlled_gate_d_requires_full_shape(self):
        text = """
name: Production Gate D
on:
  workflow_dispatch:
    inputs:
      deploy_ref:
        required: true
      rollback_ref:
        required: true
      approval_reference:
        required: true
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    environment: production
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/example
      - run: |
          test "$GITHUB_ACTOR" = "SaurabhVermaIN"
          DEPLOY_REF="${{ inputs.deploy_ref }}"
          ROLLBACK_REF="${{ inputs.rollback_ref }}"
          APPROVAL="${{ inputs.approval_reference }}"
          test -n "$APPROVAL"
          echo "$DEPLOY_REF" | grep -Eq '^[0-9a-f]{40}$'
          echo "$ROLLBACK_REF" | grep -Eq '^[0-9a-f]{40}$'
          MAIN_SHA="$(git rev-parse HEAD)"
          test "$DEPLOY_REF" = "$MAIN_SHA"
          CURRENT_SHA="$(git rev-parse HEAD)"
          test "$ROLLBACK_REF" = "$CURRENT_SHA" || git reset --hard "$ROLLBACK_REF"
          aws ssm send-command --document-name AWS-RunShellScript
"""
        self.assertTrue(mod.rc50_controlled_gate_d(".github/workflows/production-deploy.yml", text))
        self.assertFalse(mod.classify_workflow(".github/workflows/production-deploy.yml", text, self.OWNER)["production_auto_deploy"])

    def test_gate_d_without_owner_restriction_does_not_pass(self):
        text = """
on:
  workflow_dispatch:
permissions:
  id-token: write
jobs:
  x:
    environment: production
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
      - run: echo "$deploy_ref $rollback_ref DEPLOY_PRODUCTION" && aws ssm send-command
"""
        self.assertFalse(mod.rc50_controlled_gate_d("x.yml", text))

    def test_auto_production_deploy_blocks(self):
        text = """
name: deploy production
on:
  push:
    branches:
      - main
jobs:
  deploy:
    steps:
      - run: echo production
"""
        self.assertTrue(mod.classify_workflow(".github/workflows/deploy.yml", text, self.OWNER)["production_auto_deploy"])

    def test_staging_only(self):
        text = """
name: deploy staging
on:
  push:
    branches:
      - staging
jobs:
  deploy:
    steps:
      - run: ssh staging-host
"""
        row = mod.classify_workflow(".github/workflows/deploy.yml", text, self.OWNER)
        self.assertTrue(row["staging_only"])
        self.assertFalse(row["production_auto_deploy"])


class RulesetMatchingTests(unittest.TestCase):
    def test_branch_pattern_exact_and_wildcard(self):
        self.assertTrue(mod.branch_pattern_matches("refs/heads/main", "main", "main"))
        self.assertFalse(mod.branch_pattern_matches("refs/heads/main", "staging", "main"))
        self.assertTrue(mod.branch_pattern_matches("refs/heads/release/*", "release/1", "main"))
        self.assertTrue(mod.branch_pattern_matches("~DEFAULT_BRANCH", "main", "main"))

    def test_ruleset_branch_scope(self):
        detail = {"conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}}
        self.assertTrue(mod.ruleset_applies_to_branch(detail, "main", "main"))
        self.assertFalse(mod.ruleset_applies_to_branch(detail, "staging", "main"))

    def test_required_context_is_exact(self):
        detail = {"rules": [{"type": "required_status_checks", "parameters": {"required_status_checks": [
            {"context": "pr-qa / Pull Request Quality Assurance"},
            {"context": "Architecture Governance"},
        ]}}]}
        self.assertIn("pr-qa / Pull Request Quality Assurance", mod.required_check_contexts(detail))
        self.assertNotIn("Pull Request Quality Assurance", mod.required_check_contexts(detail))

    def test_additional_check_is_not_called_prqa_match(self):
        names = {"pr-qa / Pull Request Quality Assurance", "Architecture Governance"}
        prqa = sorted(name for name in names if "Pull Request Quality Assurance" in name)
        self.assertEqual(prqa, ["pr-qa / Pull Request Quality Assurance"])


class GateCReviewTests(unittest.TestCase):
    def test_latest_review_semantics(self):
        # Exercise ordering logic independently of GitHub by reproducing the tiny reducer contract.
        reviews = [
            {"user": {"login": "SaurabhVermaIN"}, "state": "APPROVED"},
            {"user": {"login": "SaurabhVermaIN"}, "state": "COMMENTED"},
        ]
        latest = {}
        for review in reviews:
            latest[review["user"]["login"]] = review["state"]
        self.assertEqual(latest["SaurabhVermaIN"], "COMMENTED")


class InputTests(unittest.TestCase):
    def test_repo_slug(self):
        mod.validate_repo_slug("Synergie-ITCI/Castrol")
        with self.assertRaises(SystemExit):
            mod.validate_repo_slug("not a repo")


class StatelessnessTests(unittest.TestCase):
    def test_no_persistent_state_constants(self):
        source = MODULE.read_text()
        forbidden = ["sqlite", "state.json", "registry.json", "candidate_id", "enrollment_id", "last_audit"]
        for token in forbidden:
            self.assertNotIn(token, source.lower())


class ModernizedRecoveryTests(unittest.TestCase):
    def test_dynamic_topology_detection(self):
        self.assertEqual(mod.classify_topology({"development", "staging", "main"}, "main"), "STANDARD_SYNERGIE_FLOW")
        self.assertEqual(mod.classify_topology({"main"}, "main"), "TRUNK_ONLY")
        self.assertEqual(mod.classify_topology({"development", "main"}, "main"), "TWO_STAGE")
        self.assertEqual(mod.classify_topology({"main", "staging"}, "main"), "TWO_STAGE")
        self.assertEqual(mod.classify_topology({"production", "qa"}, "production"), "CUSTOM_RELEASE_TOPOLOGY")
        self.assertEqual(mod.branch_for_bootstrap({"staging", "main"}, "main"), "staging")
        self.assertEqual(mod.release_topology_branches({"main"}, "main"), ["main"])
        self.assertEqual(mod.release_topology_branches({"development", "main"}, "main"), ["development", "main"])
        self.assertEqual(mod.release_topology_branches({"staging", "main"}, "main"), ["staging", "main"])
        self.assertEqual(mod.release_topology_branches({"development", "staging", "main"}, "main"), ["development", "staging", "main"])

    def test_gate_c_exists_only_for_staging_to_main(self):
        self.assertFalse(mod.has_gate_c_path({"main"}))
        self.assertFalse(mod.has_gate_c_path({"development", "main"}))
        self.assertTrue(mod.has_gate_c_path({"staging", "main"}))
        with patch.object(mod, "gh_json") as gh_json:
            result = mod.gate_c_status("Synergie-ITCI/example", "SaurabhVermaIN", create=True, branches={"main"})
        gh_json.assert_not_called()
        self.assertEqual(result.status, "PASS")
        self.assertIn("Not applicable", result.detail)

    def test_ruleset_audit_uses_only_discovered_branches(self):
        detail = {"conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}, "rules": []}
        with patch.object(mod, "active_ruleset_details", return_value=[detail]), \
             patch.object(mod, "expected_prqa_context", return_value=(mod.GENERIC_CALLER_CONTEXT, "test")) as expected:
            findings = mod.ruleset_audit("Synergie-ITCI/example", Path("."), "main", {"main"})
        expected.assert_called_once_with("Synergie-ITCI/example", Path("."), "main")
        self.assertTrue(all("DEVELOPMENT" not in finding.key and "STAGING" not in finding.key for finding in findings))

    def test_deployment_audit_uses_discovered_branches_and_warns_without_gate_d(self):
        with patch.object(mod, "workflow_files", side_effect=lambda _repo, ref: {".github/workflows/ci.yml": "on: pull_request\n"} if ref == "origin/main" else {}) as workflow_files:
            findings, rows = mod.deployment_audit(Path("."), "SaurabhVermaIN", {"main"}, "main")
        workflow_files.assert_called_once_with(Path("."), "origin/main")
        gate_d = [finding for finding in findings if finding.key == "GATE_D_SHAPE"][0]
        self.assertEqual(gate_d.status, "WARNING")
        self.assertEqual([row["observed_on"] for row in rows], ["main"])

    def test_standard_topology_non_regression(self):
        calls = []
        def fake_workflow_files(_repo, ref):
            calls.append(ref)
            return {}
        with patch.object(mod, "workflow_files", side_effect=fake_workflow_files):
            mod.deployment_audit(Path("."), "SaurabhVermaIN", {"development", "staging", "main"}, "main")
        self.assertEqual(calls, ["origin/development", "origin/staging", "origin/main"])

    def test_technology_profile_and_criticality_detection(self):
        paths = [
            "composer.json",
            "artisan",
            "database/migrations/2026_01_01_000000_create_table.php",
            ".github/workflows/production-deploy.yml",
            "Dockerfile",
        ]
        technologies = mod.detect_technologies(paths)
        self.assertIn("PHP/Laravel", technologies)
        self.assertIn("migrations", technologies)
        self.assertEqual(mod.classify_profile(paths, technologies, "auto"), "application")
        self.assertEqual(mod.classify_profile(paths, technologies, "infrastructure"), "infrastructure")
        self.assertEqual(mod.classify_criticality("application", technologies, "auto", paths), "high")
        self.assertEqual(mod.classify_criticality("application", technologies, "critical"), "critical")

    def test_documentation_is_low_criticality(self):
        paths = ["README.md", "docs/onboarding.md"]
        technologies = mod.detect_technologies(paths)
        self.assertEqual(mod.classify_profile(paths, technologies, "auto"), "documentation")
        self.assertEqual(mod.classify_criticality("documentation", technologies, "auto"), "low")

    def test_ordinary_app_with_ci_is_medium(self):
        paths = ["app/Http/Controller.php", "composer.json", ".github/workflows/pr-qa.yml"]
        technologies = mod.detect_technologies(paths)
        self.assertEqual(mod.classify_profile(paths, technologies, "auto"), "application")
        self.assertEqual(mod.classify_criticality("application", technologies, "auto", paths), "medium")

    def test_deployable_app_is_high(self):
        paths = ["app/Http/Controller.php", "composer.json", ".github/workflows/production-deploy.yml"]
        technologies = mod.detect_technologies(paths)
        self.assertEqual(mod.classify_profile(paths, technologies, "auto"), "application")
        self.assertEqual(mod.classify_criticality("application", technologies, "auto", paths), "high")

    def test_python_service_is_application(self):
        paths = ["pyproject.toml", "app/main.py", ".github/workflows/pr-qa.yml"]
        technologies = mod.detect_technologies(paths)
        self.assertEqual(mod.classify_profile(paths, technologies, "auto"), "application")

    def test_go_service_is_application(self):
        paths = ["go.mod", "cmd/server/main.go", ".github/workflows/pr-qa.yml"]
        technologies = mod.detect_technologies(paths)
        self.assertEqual(mod.classify_profile(paths, technologies, "auto"), "application")

    def test_clear_package_is_library(self):
        paths = ["pyproject.toml", "src/synergie_package/__init__.py", "README.md"]
        technologies = mod.detect_technologies(paths)
        self.assertEqual(mod.classify_profile(paths, technologies, "auto"), "library")

    def test_gate_d_uses_shared_rc50_classifier(self):
        text = """
name: Production Gate D
on:
  workflow_dispatch:
    inputs:
      deploy_ref:
        required: true
      rollback_ref:
        required: true
      approval_reference:
        required: true
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    environment: production
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/example
      - run: |
          test "$GITHUB_ACTOR" = "SaurabhVermaIN"
          DEPLOY_REF="${{ inputs.deploy_ref }}"
          ROLLBACK_REF="${{ inputs.rollback_ref }}"
          APPROVAL="${{ inputs.approval_reference }}"
          test -n "$APPROVAL"
          echo "$DEPLOY_REF" | grep -Eq '^[0-9a-f]{40}$'
          echo "$ROLLBACK_REF" | grep -Eq '^[0-9a-f]{40}$'
          MAIN_SHA="$(git rev-parse HEAD)"
          test "$DEPLOY_REF" = "$MAIN_SHA"
          CURRENT_SHA="$(git rev-parse HEAD)"
          test "$ROLLBACK_REF" = "$CURRENT_SHA" || git reset --hard "$ROLLBACK_REF"
          aws ssm send-command --document-name AWS-RunShellScript
"""
        self.assertTrue(mod.rc50_controlled_gate_d(".github/workflows/production-deploy.yml", text))

    def test_gate_d_shared_classifier_rejects_unsafe_shapes(self):
        fixtures = [
            """
on:
  push:
    branches: [main]
jobs:
  deploy:
    steps:
      - run: aws ssm send-command
""",
            """
on:
  workflow_dispatch:
permissions:
  id-token: write
jobs:
  deploy:
    environment: production
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
      - run: aws ssm send-command
""",
            """
on:
  workflow_dispatch:
    inputs:
      deploy_ref:
        required: true
      rollback_ref:
        required: true
      approval_reference:
        required: true
permissions:
  id-token: write
jobs:
  deploy:
    environment: production
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/example
      - run: |
          DEPLOY_REF="${{ inputs.deploy_ref }}"
          ROLLBACK_REF="${{ inputs.rollback_ref }}"
          APPROVAL="${{ inputs.approval_reference }}"
          test -n "$APPROVAL"
          echo "$DEPLOY_REF" | grep -Eq '^[0-9a-f]{40}$'
          echo "$ROLLBACK_REF" | grep -Eq '^[0-9a-f]{40}$'
          MAIN_SHA="$(git rev-parse HEAD)"
          test "$DEPLOY_REF" = "$MAIN_SHA"
          CURRENT_SHA="$(git rev-parse HEAD)"
          test "$ROLLBACK_REF" = "$CURRENT_SHA" || git reset --hard "$ROLLBACK_REF"
          aws ssm send-command
""",
        ]
        for text in fixtures:
            with self.subTest(text=text):
                self.assertFalse(mod.rc50_controlled_gate_d(".github/workflows/production-deploy.yml", text))

    def test_gate_d_single_source_output_has_no_local_gate_d_field(self):
        row = mod.classify_workflow(".github/workflows/production-deploy.yml", "on: workflow_dispatch\n", "SaurabhVermaIN")
        self.assertNotIn("controlled_gate_d_shape", row)
        with patch.object(mod, "workflow_files", return_value={".github/workflows/production-deploy.yml": "on: workflow_dispatch\n"}):
            _, rows = mod.deployment_audit(Path("."), "SaurabhVermaIN", {"main"}, "main")
        self.assertIn("gate_d_rc50", rows[0])
        self.assertNotIn("controlled_gate_d_shape", rows[0])

    def test_fresh_bootstrap_guard_and_scope_are_preserved(self):
        source = MODULE.read_text()
        self.assertIn("Refusing to introduce or normalize .github/pr-qa.yml during bootstrap", source)
        self.assertIn("central immutable defaults are authoritative for fresh onboarding", source)
        self.assertIn('".github/workflows/pr-qa.yml"', source)
        self.assertIn('".github/pull_request_template.md"', source)
        self.assertNotIn('".github/pr-qa.yml":', source)

    def test_apply_path_has_no_auto_merge_call(self):
        source = MODULE.read_text()
        bootstrap = source.split("def bootstrap_apply", 1)[1].split("def latest_reviews", 1)[0]
        self.assertNotIn("merge_pr(", bootstrap)
        self.assertIn("CLI does not auto-merge or auto-approve", bootstrap)

    def test_verify_pass(self):
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": "app/Http/Controller.php"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[{"name": "pr-qa / Pull Request Quality Assurance", "status": "completed", "conclusion": "success"}]):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "PASS")

    def test_verify_onboarding_file_failure_requires_report_evidence(self):
        report = {"results": [{"gate": "Protected Resources", "status": "FAIL", "message": ".github/workflows/pr-qa.yml changed", "details": [], "blocking": True}]}
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": ".github/workflows/pr-qa.yml"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[{"name": "pr-qa / Pull Request Quality Assurance", "status": "completed", "conclusion": "failure"}]), \
             patch.object(mod, "latest_prqa_report", return_value=report):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_ON_ONBOARDING_FILE")

    def test_verify_legacy_failure_uses_report_evidence(self):
        report = {"results": [{"gate": "Secrets", "status": "FAIL", "message": "legacy/config.php contains inherited secret-like content", "details": [], "blocking": True}]}
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": "app/file.php"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[{"name": "pr-qa / Pull Request Quality Assurance", "status": "completed", "conclusion": "failure"}]), \
             patch.object(mod, "latest_prqa_report", return_value=report):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_ON_EXISTING_LEGACY_FINDING")

    def test_verify_ambiguous_failure_is_unknown(self):
        report = {"results": [{"gate": "Tests", "status": "FAIL", "message": "Tests failed", "details": [], "blocking": True}]}
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": ".github/workflows/pr-qa.yml"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[{"name": "pr-qa / Pull Request Quality Assurance", "status": "completed", "conclusion": "failure"}]), \
             patch.object(mod, "latest_prqa_report", return_value=report):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_UNKNOWN")

    def artifact_run(self, available: dict[str, dict]) -> dict[str, Any] | None:
        def fake_run(cmd, **_kwargs):
            if cmd[:3] == ["gh", "run", "download"]:
                name = cmd[cmd.index("--name") + 1]
                out = Path(cmd[cmd.index("--dir") + 1])
                if name not in available:
                    return subprocess.CompletedProcess(cmd, 1, "", "missing")
                (out / "pr-quality-report.json").write_text(json.dumps(available[name]), encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(mod, "check_runs_for_sha", return_value=[{"name": mod.GENERIC_CALLER_CONTEXT, "details_url": "https://github.com/o/r/actions/runs/123"}]), \
             patch.object(mod, "run", side_effect=fake_run):
            return mod.latest_prqa_report("Synergie-ITCI/example", "abc")

    def test_latest_prqa_report_prefers_final_artifact(self):
        final = {"results": [{"gate": "Tests", "status": "FAIL", "message": "final failure"}]}
        phase1 = {"results": [{"gate": "Secrets", "status": "FAIL", "message": "phase1 failure"}]}
        self.assertEqual(self.artifact_run({"pr-qa-results": final, "pr-qa-phase-1-results": phase1}), final)

    def test_latest_prqa_report_falls_back_to_phase1(self):
        phase1 = {"results": [{"gate": "Secrets", "status": "FAIL", "message": "phase1 failure"}]}
        self.assertEqual(self.artifact_run({"pr-qa-phase-1-results": phase1}), phase1)

    def test_missing_or_unreadable_evidence_is_unknown(self):
        self.assertIsNone(self.artifact_run({}))
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": ".github/workflows/pr-qa.yml"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[{"name": "pr-qa / Pull Request Quality Assurance", "status": "completed", "conclusion": "failure"}]), \
             patch.object(mod, "latest_prqa_report", return_value=None):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_UNKNOWN")

    def test_gate_c_wait(self):
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "main", "headRefName": "staging", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": "app/file.php"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[{"name": "pr-qa / Pull Request Quality Assurance", "status": "completed", "conclusion": "success"}]), \
             patch.object(mod, "latest_reviews", return_value={"other": "APPROVED"}):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 2, "SaurabhVermaIN"), "WAITING_FOR_HUMAN_APPROVAL")


if __name__ == "__main__":
    unittest.main()
