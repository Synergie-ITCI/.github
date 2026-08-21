import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
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
    def repo_with_origin_branch(self, files_by_branch: dict[str, dict[str, str]]) -> tuple[tempfile.TemporaryDirectory, Path]:
        tmp = tempfile.TemporaryDirectory(prefix="onboard-audit-")
        repo = Path(tmp.name)
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "remote", "add", "origin", str(repo)], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "qa@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "QA"], cwd=repo, check=True)
        for branch, files in files_by_branch.items():
            subprocess.run(["git", "checkout", "-q", "--orphan", branch], cwd=repo, check=True)
            subprocess.run(["git", "rm", "-qrf", "."], cwd=repo, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for rel, content in files.items():
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", f"seed {branch}"], cwd=repo, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            subprocess.run(["git", "update-ref", f"refs/remotes/origin/{branch}", sha], cwd=repo, check=True)
        return tmp, repo

    def prqa_ruleset(self, context: str = mod.GENERIC_CALLER_CONTEXT) -> dict[str, Any]:
        return {
            "conditions": {"ref_name": {"include": ["refs/heads/*"], "exclude": []}},
            "rules": [
                {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": context}]}},
                {"type": "pull_request", "parameters": {"required_approving_review_count": 0, "require_last_push_approval": False}},
            ],
        }

    def ruleset_without_prqa_context(self) -> dict[str, Any]:
        return {
            "conditions": {"ref_name": {"include": ["refs/heads/*"], "exclude": []}},
            "rules": [
                {"type": "pull_request", "parameters": {"required_approving_review_count": 0, "require_last_push_approval": False}},
            ],
        }

    def onboard_args(self, *, apply: bool = True) -> argparse.Namespace:
        return argparse.Namespace(repo="Synergie-ITCI/example", json=True, profile="auto", criticality="auto", apply=apply, wait=False)

    def canonical_caller(self) -> str:
        return mod.PR_QA_TEMPLATE.read_text(encoding="utf-8")

    def check_run(
        self,
        name: str = mod.GENERIC_CALLER_CONTEXT,
        *,
        status: str = "completed",
        conclusion: str | None = "success",
        started_at: str = "2026-08-21T10:00:00Z",
        check_id: int = 1,
        run_id: int = 100,
    ) -> dict[str, Any]:
        return {
            "id": check_id,
            "name": name,
            "status": status,
            "conclusion": conclusion,
            "started_at": started_at,
            "details_url": f"https://github.com/o/r/actions/runs/{run_id}/job/{check_id}",
        }

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

    def test_false_prqa_branch_names_are_not_release_branches(self):
        branches = {"main", "fix/pr-qa-v1-rc3", "rollout/pr-qa-v1-rc2", "feature/qa-fix", "chore/update-production-docs"}
        self.assertEqual(mod.classify_topology(branches, "main"), "TOPOLOGY_REVIEW_REQUIRED")
        self.assertEqual(mod.release_topology_branches(branches, "main"), ["main"])

    def test_genuine_release_environment_branches_are_detected(self):
        for branch in ("release/1.2.0", "release-2026-08", "production", "prod", "uat", "qa", "qa/release", "uat/app", "prod/hotfix", "production/cutover"):
            self.assertTrue(mod.is_release_environment_branch(branch), branch)
        for branch in ("fix/pr-qa-v1-rc3", "rollout/pr-qa-v1-rc2", "feature/qa-fix", "chore/update-production-docs"):
            self.assertFalse(mod.is_release_environment_branch(branch), branch)

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
             patch.object(mod, "prqa_context_expectation", return_value=mod.PrqaContextExpectation(mod.GENERIC_CALLER_CONTEXT, "test", "GENERIC")) as expected:
            findings = mod.ruleset_audit("Synergie-ITCI/example", Path("."), "main", {"main"})
        expected.assert_called_once_with("Synergie-ITCI/example", Path("."), "main")
        self.assertTrue(all("DEVELOPMENT" not in finding.key and "STAGING" not in finding.key for finding in findings))

    def test_ruleset_zero_active_rulesets_warns(self):
        with patch.object(mod, "active_ruleset_details", return_value=[]):
            findings = mod.ruleset_audit("Synergie-ITCI/example", Path("."), "main", {"main"})
        self.assertEqual(findings[0].status, "WARNING")

    def test_ruleset_list_api_failure_fails_closed(self):
        with patch.object(mod, "rulesets", side_effect=mod.CmdError("Unable to read repository rulesets through GitHub API; failing closed.")):
            findings = mod.ruleset_audit("Synergie-ITCI/example", Path("."), "main", {"main"})
        self.assertEqual(findings[0].status, "BLOCKED")

    def test_malformed_ruleset_response_fails_closed(self):
        def fake_run(cmd, **_kwargs):
            return subprocess.CompletedProcess(cmd, 0, "{not-json", "")

        with patch.object(mod, "run", side_effect=fake_run):
            findings = mod.ruleset_audit("Synergie-ITCI/example", Path("."), "main", {"main"})
        self.assertEqual(findings[0].status, "BLOCKED")

    def test_partial_ruleset_detail_failure_fails_closed(self):
        with patch.object(mod, "rulesets", return_value=[{"id": 1, "enforcement": "active"}]), \
             patch.object(mod, "ruleset_detail", side_effect=mod.CmdError("Unable to read active ruleset detail 1; failing closed.")):
            findings = mod.ruleset_audit("Synergie-ITCI/example", Path("."), "main", {"main"})
        self.assertEqual(findings[0].status, "BLOCKED")

    def test_deployment_audit_uses_discovered_branches_and_warns_without_gate_d(self):
        with patch.object(mod, "workflow_files", side_effect=lambda _repo, ref: {".github/workflows/ci.yml": "on: pull_request\n"} if ref == "origin/main" else {}) as workflow_files:
            findings, rows = mod.deployment_audit(Path("."), "SaurabhVermaIN", {"main"}, "main")
        workflow_files.assert_called_once_with(Path("."), "origin/main")
        gate_d = [finding for finding in findings if finding.key == "GATE_D_SHAPE"][0]
        self.assertEqual(gate_d.status, "WARNING")
        self.assertEqual([row["observed_on"] for row in rows], ["main"])

    def test_workflow_tree_read_failure_blocks_deployment_audit(self):
        with patch.object(mod, "workflow_files", side_effect=mod.CmdError("Unable to inspect workflow tree for origin/main; failing closed.")):
            findings, rows = mod.deployment_audit(Path("."), "SaurabhVermaIN", {"main"}, "main")
        self.assertEqual(rows, [])
        self.assertEqual(findings[0].status, "BLOCKED")

    def test_workflow_blob_read_failure_blocks_deployment_audit(self):
        with patch.object(mod, "workflow_files", side_effect=mod.CmdError("Unable to read workflow file .github/workflows/deploy.yml at origin/main; failing closed.")):
            findings, rows = mod.deployment_audit(Path("."), "SaurabhVermaIN", {"main"}, "main")
        self.assertEqual(rows, [])
        self.assertEqual(findings[0].status, "BLOCKED")

    def test_workflow_files_tree_read_failure_raises(self):
        def fake_run(cmd, **_kwargs):
            if cmd[:4] == ["git", "ls-tree", "-r", "--name-only"]:
                return subprocess.CompletedProcess(cmd, 1, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(mod, "run", side_effect=fake_run):
            with self.assertRaises(mod.CmdError):
                mod.workflow_files(Path("."), "origin/main")

    def test_workflow_files_blob_read_failure_raises(self):
        def fake_run(cmd, **_kwargs):
            if cmd[:4] == ["git", "ls-tree", "-r", "--name-only"]:
                return subprocess.CompletedProcess(cmd, 0, ".github/workflows/deploy.yml\n", "")
            if cmd[:2] == ["git", "show"]:
                return subprocess.CompletedProcess(cmd, 1, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(mod, "run", side_effect=fake_run):
            with self.assertRaises(mod.CmdError):
                mod.workflow_files(Path("."), "origin/main")

    def test_standard_topology_non_regression(self):
        calls = []
        def fake_workflow_files(_repo, ref):
            calls.append(ref)
            return {}
        with patch.object(mod, "workflow_files", side_effect=fake_workflow_files):
            mod.deployment_audit(Path("."), "SaurabhVermaIN", {"development", "staging", "main"}, "main")
        self.assertEqual(calls, ["origin/development", "origin/staging", "origin/main"])

    def test_fresh_repo_without_caller_allows_bootstrap_context(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "observed_check_names", return_value=set()):
            self.assertEqual(
                mod.expected_prqa_context("Synergie-ITCI/example", repo, "development"),
                (mod.GENERIC_CALLER_CONTEXT, "fresh bootstrap fallback; no PR-QA caller workflow exists yet"),
            )

    def test_no_observed_check_history_does_not_block_genuinely_fresh_repo(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "active_ruleset_details", return_value=[self.prqa_ruleset()]), \
             patch.object(mod, "observed_check_names", return_value=set()):
            findings = mod.ruleset_audit("Synergie-ITCI/example", repo, "main", {"development"})
        self.assertTrue(any(f.key == "RULESET_DEVELOPMENT_PRQA" and f.status == "PASS" for f in findings))

    def test_absent_caller_without_prqa_context_warns_and_is_bootstrap_safe(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "active_ruleset_details", return_value=[self.ruleset_without_prqa_context()]), \
             patch.object(mod, "observed_check_names", return_value=set()):
            findings = mod.ruleset_audit("Synergie-ITCI/example", repo, "main", {"development"})
        prqa = [f for f in findings if f.key == "RULESET_DEVELOPMENT_PRQA"][0]
        self.assertEqual(prqa.status, "WARNING")
        self.assertIn("Onboarding can proceed", prqa.detail)

    def test_fresh_warning_uses_structured_state_not_detail_text(self):
        result = mod.PrqaContextExpectation(mod.GENERIC_CALLER_CONTEXT, "wording changed completely", "ABSENT")
        with patch.object(mod, "active_ruleset_details", return_value=[self.ruleset_without_prqa_context()]), \
             patch.object(mod, "prqa_context_expectation", return_value=result):
            findings = mod.ruleset_audit("Synergie-ITCI/example", Path("."), "main", {"development"})
        prqa = [f for f in findings if f.key == "RULESET_DEVELOPMENT_PRQA"][0]
        self.assertEqual(prqa.status, "WARNING")

    def test_absent_caller_with_exact_generic_context_passes(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "active_ruleset_details", return_value=[self.prqa_ruleset()]), \
             patch.object(mod, "observed_check_names", return_value=set()):
            findings = mod.ruleset_audit("Synergie-ITCI/example", repo, "main", {"development"})
        self.assertTrue(any(f.key == "RULESET_DEVELOPMENT_PRQA" and f.status == "PASS" for f in findings))

    def test_absent_caller_with_wrong_prqa_like_context_blocks(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "active_ruleset_details", return_value=[self.prqa_ruleset("Pull Request Quality Assurance / Pull Request Quality Assurance")]), \
             patch.object(mod, "observed_check_names", return_value=set()):
            findings = mod.ruleset_audit("Synergie-ITCI/example", repo, "main", {"development"})
        prqa = [f for f in findings if f.key == "RULESET_DEVELOPMENT_PRQA"][0]
        self.assertEqual(prqa.status, "BLOCKED")
        self.assertIn("Mismatched PR-QA-like contexts", prqa.detail)

    def test_existing_exact_caller_with_context_missing_blocks(self):
        caller = self.canonical_caller()
        tmp, repo = self.repo_with_origin_branch({"development": {".github/workflows/pr-qa.yml": caller}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "active_ruleset_details", return_value=[self.ruleset_without_prqa_context()]), \
             patch.object(mod, "observed_check_names", return_value=set()):
            findings = mod.ruleset_audit("Synergie-ITCI/example", repo, "main", {"development"})
        prqa = [f for f in findings if f.key == "RULESET_DEVELOPMENT_PRQA"][0]
        self.assertEqual(prqa.status, "BLOCKED")

    def test_existing_caller_context_mismatch_remains_blocked(self):
        caller = self.canonical_caller()
        tmp, repo = self.repo_with_origin_branch({"main": {".github/workflows/pr-qa.yml": caller}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "active_ruleset_details", return_value=[self.prqa_ruleset("Pull Request Quality Assurance / Pull Request Quality Assurance")]), \
             patch.object(mod, "observed_check_names", return_value=set()):
            findings = mod.ruleset_audit("Synergie-ITCI/example", repo, "main", {"main"})
        prqa = [f for f in findings if f.key == "RULESET_MAIN_PRQA"][0]
        self.assertEqual(prqa.status, "BLOCKED")
        self.assertIn("Mismatched PR-QA-like contexts", prqa.detail)

    def test_castrol_style_context_mismatch_is_not_onboarding_needed(self):
        caller = self.canonical_caller()
        tmp, repo = self.repo_with_origin_branch({"main": {".github/workflows/pr-qa.yml": caller}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "observed_check_names", return_value=set()):
            expected, source = mod.expected_prqa_context("Synergie-ITCI/Castrol", repo, "main")
        self.assertEqual(expected, mod.GENERIC_CALLER_CONTEXT)
        self.assertNotIn("fresh bootstrap", source)

    def test_canonical_template_classifies_as_generic(self):
        tmp, repo = self.repo_with_origin_branch({"development": {".github/workflows/pr-qa.yml": self.canonical_caller()}})
        self.addCleanup(tmp.cleanup)
        state, text = mod.caller_workflow_text(repo, "development")
        self.assertEqual(state, "PRESENT")
        self.assertEqual(text, self.canonical_caller())
        with patch.object(mod, "observed_check_names", return_value=set()):
            expectation = mod.prqa_context_expectation("Synergie-ITCI/example", repo, "development")
        self.assertEqual(expectation.caller_state, "GENERIC")
        self.assertEqual(expectation.expected, mod.GENERIC_CALLER_CONTEXT)

    def test_modified_trigger_with_same_job_and_uses_is_custom(self):
        caller = self.canonical_caller().replace("pull_request:", "workflow_dispatch:", 1)
        tmp, repo = self.repo_with_origin_branch({"development": {".github/workflows/pr-qa.yml": caller}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "observed_check_names", return_value={mod.GENERIC_CALLER_CONTEXT}):
            expectation = mod.prqa_context_expectation("Synergie-ITCI/example", repo, "development")
        self.assertEqual(expectation.caller_state, "CUSTOM")
        self.assertIsNone(expectation.expected)

    def test_modified_permissions_with_same_job_and_uses_is_custom(self):
        caller = self.canonical_caller().replace("issues: write", "issues: read", 1)
        tmp, repo = self.repo_with_origin_branch({"development": {".github/workflows/pr-qa.yml": caller}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "observed_check_names", return_value={mod.GENERIC_CALLER_CONTEXT}):
            expectation = mod.prqa_context_expectation("Synergie-ITCI/example", repo, "development")
        self.assertEqual(expectation.caller_state, "CUSTOM")
        self.assertIsNone(expectation.expected)

    def test_custom_caller_requires_review(self):
        custom = "name: custom qa\non: pull_request\njobs:\n  quality:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo custom\n"
        tmp, repo = self.repo_with_origin_branch({"development": {".github/workflows/pr-qa.yml": custom}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "observed_check_names", return_value=set()):
            expected, source = mod.expected_prqa_context("Synergie-ITCI/example", repo, "development")
        self.assertIsNone(expected)
        self.assertIn("CUSTOM_CALLER_REQUIRES_REVIEW", source)

    def test_custom_caller_ruleset_audit_blocks_review_path(self):
        custom = "name: custom qa\non: pull_request\njobs:\n  quality:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo custom\n"
        tmp, repo = self.repo_with_origin_branch({"development": {".github/workflows/pr-qa.yml": custom}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "active_ruleset_details", return_value=[self.prqa_ruleset()]), \
             patch.object(mod, "observed_check_names", return_value=set()):
            findings = mod.ruleset_audit("Synergie-ITCI/example", repo, "main", {"development"})
        prqa = [f for f in findings if f.key == "RULESET_DEVELOPMENT_PRQA"][0]
        self.assertEqual(prqa.status, "BLOCKED")
        self.assertIn("CUSTOM_CALLER_REQUIRES_REVIEW", prqa.detail)

    def test_custom_caller_with_valid_history_still_requires_review(self):
        custom = "name: custom qa\non: pull_request\njobs:\n  quality:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo custom\n"
        tmp, repo = self.repo_with_origin_branch({"development": {".github/workflows/pr-qa.yml": custom}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "observed_check_names", return_value={mod.GENERIC_CALLER_CONTEXT}):
            expected, source = mod.expected_prqa_context("Synergie-ITCI/example", repo, "development")
        self.assertIsNone(expected)
        self.assertIn("CUSTOM_CALLER_REQUIRES_REVIEW", source)

    def test_generic_caller_with_multiple_observed_contexts_remains_blocked(self):
        caller = self.canonical_caller()
        tmp, repo = self.repo_with_origin_branch({"main": {".github/workflows/pr-qa.yml": caller}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "observed_check_names", return_value={mod.GENERIC_CALLER_CONTEXT, "Pull Request Quality Assurance / Pull Request Quality Assurance"}):
            expected, source = mod.expected_prqa_context("Synergie-ITCI/example", repo, "main")
        self.assertIsNone(expected)
        self.assertIn("multiple PR-QA check contexts observed", source)

    def test_unresolved_ref_fails_closed_without_fresh_bootstrap_fallback(self):
        tmp, repo = self.repo_with_origin_branch({"main": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "observed_check_names", return_value=set()):
            expected, source = mod.expected_prqa_context("Synergie-ITCI/example", repo, "development")
        self.assertIsNone(expected)
        self.assertIn("Unable to prove PR-QA caller workflow state", source)
        self.assertNotIn("fresh bootstrap", source)

    def test_caller_read_error_fails_closed_without_fresh_bootstrap_fallback(self):
        calls = []

        def fake_run(cmd, **_kwargs):
            calls.append(cmd)
            if cmd[:3] == ["git", "rev-parse", "--verify"]:
                return subprocess.CompletedProcess(cmd, 0, "abc\n", "")
            if cmd[:3] == ["git", "ls-tree", "-z"]:
                return subprocess.CompletedProcess(cmd, 0, ".github/workflows/pr-qa.yml\0", "")
            if cmd[:2] == ["git", "show"]:
                return subprocess.CompletedProcess(cmd, 1, "", "")
            return subprocess.CompletedProcess(cmd, 1, "", "")

        with patch.object(mod, "run", side_effect=fake_run), \
             patch.object(mod, "observed_check_names", return_value=set()):
            expected, source = mod.expected_prqa_context("Synergie-ITCI/example", Path("."), "development")
        self.assertIsNone(expected)
        self.assertIn("Unable to prove PR-QA caller workflow state", source)
        self.assertNotIn("fresh bootstrap", source)

    def test_ambiguous_caller_state_ruleset_audit_blocks(self):
        with patch.object(mod, "caller_workflow_text", return_value=("ERROR", None)), \
             patch.object(mod, "active_ruleset_details", return_value=[self.prqa_ruleset()]):
            findings = mod.ruleset_audit("Synergie-ITCI/example", Path("."), "main", {"development"})
        prqa = [f for f in findings if f.key == "RULESET_DEVELOPMENT_PRQA"][0]
        self.assertEqual(prqa.status, "BLOCKED")
        self.assertIn("Unable to prove", prqa.detail)

    def test_native_review_deadlock_blocks(self):
        tmp, repo = self.repo_with_origin_branch({"main": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        ruleset = self.prqa_ruleset()
        ruleset["rules"][1]["parameters"]["required_approving_review_count"] = 1
        with patch.object(mod, "active_ruleset_details", return_value=[ruleset]), \
             patch.object(mod, "observed_check_names", return_value=set()):
            findings = mod.ruleset_audit("Synergie-ITCI/example", repo, "main", {"main"})
        reviews = [f for f in findings if f.key == "RULESET_MAIN_REVIEWS"][0]
        self.assertEqual(reviews.status, "BLOCKED")

    def test_resolved_ref_with_absent_caller_still_bootstraps(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        state, text = mod.caller_workflow_text(repo, "development")
        self.assertEqual(state, "ABSENT")
        self.assertIsNone(text)
        with patch.object(mod, "observed_check_names", return_value=set()):
            expected, source = mod.expected_prqa_context("Synergie-ITCI/example", repo, "development")
        self.assertEqual(expected, mod.GENERIC_CALLER_CONTEXT)
        self.assertIn("fresh bootstrap fallback", source)

    def test_caller_absence_detection_does_not_parse_git_stderr(self):
        source = MODULE.read_text(encoding="utf-8")
        caller_source = source.split("def caller_workflow_text", 1)[1].split("def generic_caller_present", 1)[0]
        self.assertNotIn(".stderr", caller_source)
        self.assertIn("git\", \"rev-parse\", \"--verify\"", caller_source)
        self.assertIn("git\", \"ls-tree\", \"-z\"", caller_source)

    def test_already_onboarded_valid_repo_retains_strict_audit(self):
        caller = self.canonical_caller()
        tmp, repo = self.repo_with_origin_branch({"staging": {".github/workflows/pr-qa.yml": caller}})
        self.addCleanup(tmp.cleanup)
        with patch.object(mod, "active_ruleset_details", return_value=[self.prqa_ruleset()]), \
             patch.object(mod, "observed_check_names", return_value=set()):
            findings = mod.ruleset_audit("Synergie-ITCI/example", repo, "main", {"staging"})
        self.assertTrue(any(f.key == "RULESET_STAGING_PRQA" and f.status == "PASS" and "generic caller" in f.detail for f in findings))

    def test_repository_tree_read_failure_prevents_apply(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}, "main": {"README.md": "fresh\n"}})
        with patch.object(mod, "require_tools"), \
             patch.object(mod, "repo_metadata", return_value={"defaultBranchRef": {"name": "main"}}), \
             patch.object(mod, "central_owner_login", return_value="SaurabhVermaIN"), \
             patch.object(mod, "clone_repo", return_value=tmp), \
             patch.object(mod, "repository_files", side_effect=mod.CmdError("tree read failed")), \
             patch.object(mod, "bootstrap_apply") as bootstrap:
            self.assertEqual(mod.onboard(self.onboard_args(apply=True)), 2)
        bootstrap.assert_not_called()

    def test_profile_uses_audited_bootstrap_base_not_default_main(self):
        tmp, repo = self.repo_with_origin_branch({
            "main": {"README.md": "docs only\n"},
            "development": {"README.md": "app\n", "composer.json": "{}", "artisan": "#!/usr/bin/env php\n"},
        })
        seen_refs = []
        development_sha = mod.local_branch_sha(repo, "development")
        real_repository_files = mod.repository_files

        def tracking_repository_files(repo_dir: Path, ref: str) -> list[str]:
            seen_refs.append(ref)
            return real_repository_files(repo_dir, ref)

        with patch.object(mod, "require_tools"), \
             patch.object(mod, "repo_metadata", return_value={"defaultBranchRef": {"name": "main"}}), \
             patch.object(mod, "central_owner_login", return_value="SaurabhVermaIN"), \
             patch.object(mod, "clone_repo", return_value=tmp), \
             patch.object(mod, "repository_files", side_effect=tracking_repository_files), \
             patch.object(mod, "active_ruleset_details", return_value=[self.ruleset_without_prqa_context()]), \
             patch.object(mod, "observed_check_names", return_value=set()), \
             patch.object(mod, "deployment_audit", return_value=([], [])), \
             patch.object(mod, "bootstrap_apply", return_value=[mod.Finding("GATE_A_PR", "READY", "#1")]):
            self.assertEqual(mod.onboard(self.onboard_args(apply=True)), 0)
        self.assertEqual(seen_refs, [development_sha])

    def test_missing_default_branch_metadata_fails_closed_before_apply(self):
        with patch.object(mod, "require_tools"), \
             patch.object(mod, "repo_metadata", return_value={"defaultBranchRef": None}), \
             patch.object(mod, "bootstrap_apply") as bootstrap:
            with self.assertRaises(mod.CmdError):
                mod.onboard(self.onboard_args(apply=True))
        bootstrap.assert_not_called()

    def test_onboard_apply_ruleset_blocker_prevents_bootstrap(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}, "main": {"README.md": "fresh\n"}})
        with patch.object(mod, "require_tools"), \
             patch.object(mod, "repo_metadata", return_value={"defaultBranchRef": {"name": "main"}}), \
             patch.object(mod, "central_owner_login", return_value="SaurabhVermaIN"), \
             patch.object(mod, "clone_repo", return_value=tmp), \
             patch.object(mod, "active_ruleset_details", return_value=[self.prqa_ruleset("Pull Request Quality Assurance / Pull Request Quality Assurance")]), \
             patch.object(mod, "observed_check_names", return_value=set()), \
             patch.object(mod, "deployment_audit", return_value=([], [])), \
             patch.object(mod, "bootstrap_apply") as bootstrap:
            self.assertEqual(mod.onboard(self.onboard_args(apply=True)), 3)
        bootstrap.assert_not_called()

    def test_onboard_apply_ruleset_evidence_failure_prevents_bootstrap(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}, "main": {"README.md": "fresh\n"}})
        with patch.object(mod, "require_tools"), \
             patch.object(mod, "repo_metadata", return_value={"defaultBranchRef": {"name": "main"}}), \
             patch.object(mod, "central_owner_login", return_value="SaurabhVermaIN"), \
             patch.object(mod, "clone_repo", return_value=tmp), \
             patch.object(mod, "active_ruleset_details", side_effect=mod.CmdError("ruleset evidence missing")), \
             patch.object(mod, "deployment_audit", return_value=([], [])), \
             patch.object(mod, "bootstrap_apply") as bootstrap:
            self.assertEqual(mod.onboard(self.onboard_args(apply=True)), 3)
        bootstrap.assert_not_called()

    def test_onboard_apply_deployment_blocker_prevents_bootstrap(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}, "main": {"README.md": "fresh\n"}})
        with patch.object(mod, "require_tools"), \
             patch.object(mod, "repo_metadata", return_value={"defaultBranchRef": {"name": "main"}}), \
             patch.object(mod, "central_owner_login", return_value="SaurabhVermaIN"), \
             patch.object(mod, "clone_repo", return_value=tmp), \
             patch.object(mod, "active_ruleset_details", return_value=[self.ruleset_without_prqa_context()]), \
             patch.object(mod, "observed_check_names", return_value=set()), \
             patch.object(mod, "deployment_audit", return_value=([mod.Finding("PRODUCTION_AUTO_DEPLOY", "BLOCKED", "unsafe")], [])), \
             patch.object(mod, "bootstrap_apply") as bootstrap:
            self.assertEqual(mod.onboard(self.onboard_args(apply=True)), 3)
        bootstrap.assert_not_called()

    def test_onboard_apply_safe_fresh_warning_calls_bootstrap_once(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}, "main": {"README.md": "fresh\n"}})
        with patch.object(mod, "require_tools"), \
             patch.object(mod, "repo_metadata", return_value={"defaultBranchRef": {"name": "main"}}), \
             patch.object(mod, "central_owner_login", return_value="SaurabhVermaIN"), \
             patch.object(mod, "clone_repo", return_value=tmp), \
             patch.object(mod, "active_ruleset_details", return_value=[self.ruleset_without_prqa_context()]), \
             patch.object(mod, "observed_check_names", return_value=set()), \
             patch.object(mod, "deployment_audit", return_value=([], [])), \
            patch.object(mod, "bootstrap_apply", return_value=[mod.Finding("GATE_A_PR", "READY", "#1")]) as bootstrap:
            self.assertEqual(mod.onboard(self.onboard_args(apply=True)), 0)
        bootstrap.assert_called_once()

    def test_onboard_apply_wait_does_not_create_gate_c(self):
        args = self.onboard_args(apply=True)
        args.wait = True
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}, "staging": {"README.md": "fresh\n"}, "main": {"README.md": "fresh\n"}})
        with patch.object(mod, "require_tools"), \
             patch.object(mod, "repo_metadata", return_value={"defaultBranchRef": {"name": "main"}}), \
             patch.object(mod, "central_owner_login", return_value="SaurabhVermaIN"), \
             patch.object(mod, "clone_repo", return_value=tmp), \
             patch.object(mod, "active_ruleset_details", return_value=[self.ruleset_without_prqa_context()]), \
             patch.object(mod, "observed_check_names", return_value=set()), \
             patch.object(mod, "deployment_audit", return_value=([], [])), \
             patch.object(mod, "bootstrap_apply", return_value=[mod.Finding("GATE_A_PR", "READY", "#1")]), \
             patch.object(mod, "gate_c_status") as gate_c:
            self.assertEqual(mod.onboard(args), 0)
        gate_c.assert_not_called()

    def test_bootstrap_apply_allows_unchanged_audited_base(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        audited = mod.local_branch_sha(repo, "development")
        with patch.object(mod, "install_bootstrap_files", return_value=[]), \
             patch.object(mod, "run", wraps=mod.run), \
             patch.object(mod, "open_or_find_pr") as open_pr:
            findings = mod.bootstrap_apply("Synergie-ITCI/example", repo, False, "development", audited)
        open_pr.assert_not_called()
        self.assertEqual(findings[0].key, "BOOTSTRAP")
        self.assertEqual(findings[0].status, "PASS")
        self.assertIn("already present", findings[0].detail)

    def test_already_onboarded_with_stale_remote_branch_returns_without_pr(self):
        tmp, repo = self.repo_with_origin_branch({
            "development": {
                ".github/workflows/pr-qa.yml": self.canonical_caller(),
                ".github/pull_request_template.md": mod.PR_TEMPLATE.read_text(encoding="utf-8"),
            },
            "chore/governance-onboarding": {"README.md": "stale\n"},
        })
        self.addCleanup(tmp.cleanup)
        audited = mod.local_branch_sha(repo, "development")
        with patch.object(mod, "open_or_find_pr") as open_pr:
            findings = mod.bootstrap_apply("Synergie-ITCI/example", repo, False, "development", audited)
        open_pr.assert_not_called()
        self.assertEqual(findings[0].status, "PASS")
        self.assertIn("already present", findings[0].detail)

    def test_bootstrap_apply_blocks_moved_base_before_mutation(self):
        tmp, repo = self.repo_with_origin_branch({"development": {"README.md": "fresh\n"}})
        self.addCleanup(tmp.cleanup)
        audited = mod.local_branch_sha(repo, "development")
        with patch.object(mod, "remote_branch_sha", return_value="0" * 40), \
             patch.object(mod, "install_bootstrap_files") as install:
            with self.assertRaises(mod.CmdError):
                mod.bootstrap_apply("Synergie-ITCI/example", repo, False, "development", audited)
        install.assert_not_called()

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

    def test_onboarding_decision_table_is_documented(self):
        doc = (MODULE.parents[1] / "docs" / "onboarding-guide.md").read_text(encoding="utf-8")
        self.assertIn("Fresh-Onboarding PR-QA Decision Table", doc)
        self.assertIn("Caller workflow proven absent | No PR-QA-like context required | WARNING", doc)
        self.assertIn("Custom caller exists | Any ruleset state | BLOCKED", doc)
        self.assertIn("Caller/ref state ambiguous or unreadable | Any ruleset state | BLOCKED", doc)

    def test_apply_path_has_no_auto_merge_call(self):
        source = MODULE.read_text()
        bootstrap = source.split("def bootstrap_apply", 1)[1].split("def latest_reviews", 1)[0]
        self.assertNotIn("merge_pr(", bootstrap)
        self.assertIn("CLI does not auto-merge or auto-approve", bootstrap)

    def test_verify_pass(self):
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": "app/Http/Controller.php"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[self.check_run()]):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "PASS")

    def test_verify_no_checks_is_not_pass(self):
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[]), \
             patch.object(mod, "check_runs_for_sha", return_value=[]):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_UNKNOWN")

    def test_verify_check_api_failure_is_not_pass(self):
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[]), \
             patch.object(mod, "check_runs_for_sha", return_value=None):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_UNKNOWN")

    def test_verify_missing_exact_prqa_is_not_pass(self):
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[]), \
             patch.object(mod, "check_runs_for_sha", return_value=[self.check_run("Pull Request Quality Assurance")]):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_UNKNOWN")

    def test_verify_pending_exact_prqa_is_not_pass(self):
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[]), \
             patch.object(mod, "check_runs_for_sha", return_value=[self.check_run(status="in_progress", conclusion=None)]):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_UNKNOWN")

    def test_verify_merge_conflict_is_not_pass(self):
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "CONFLICTING"}), \
             patch.object(mod, "pr_files", return_value=[]), \
             patch.object(mod, "check_runs_for_sha", return_value=[self.check_run()]):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_UNKNOWN")

    def test_verify_unrelated_pending_or_failing_check_is_not_pass(self):
        checks = [
            self.check_run(check_id=1),
            self.check_run("Architecture Governance", conclusion="failure", check_id=2),
        ]
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[]), \
             patch.object(mod, "check_runs_for_sha", return_value=checks):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_UNKNOWN")

    def status_for_checks(self, checks: list[dict[str, Any]]) -> str:
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[]), \
             patch.object(mod, "check_runs_for_sha", return_value=checks):
            return mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN")

    def test_verify_prqa_old_fail_new_success_passes(self):
        checks = [
            self.check_run(conclusion="failure", started_at="2026-08-21T10:00:00Z", check_id=1, run_id=101),
            self.check_run(conclusion="success", started_at="2026-08-21T11:00:00Z", check_id=2, run_id=102),
        ]
        self.assertEqual(self.status_for_checks(checks), "PASS")

    def test_verify_prqa_old_success_new_fail_blocks(self):
        checks = [
            self.check_run(conclusion="success", started_at="2026-08-21T10:00:00Z", check_id=1, run_id=101),
            self.check_run(conclusion="failure", started_at="2026-08-21T11:00:00Z", check_id=2, run_id=102),
        ]
        with patch.object(mod, "latest_prqa_report", return_value={"results": [{"gate": "Tests", "status": "FAIL", "message": "Tests failed", "details": [], "blocking": True}]}):
            self.assertEqual(self.status_for_checks(checks), "BLOCKED_UNKNOWN")

    def test_verify_prqa_old_success_new_pending_blocks_unknown(self):
        checks = [
            self.check_run(conclusion="success", started_at="2026-08-21T10:00:00Z", check_id=1, run_id=101),
            self.check_run(status="in_progress", conclusion=None, started_at="2026-08-21T11:00:00Z", check_id=2, run_id=102),
        ]
        self.assertEqual(self.status_for_checks(checks), "BLOCKED_UNKNOWN")

    def test_verify_prqa_old_fail_new_pending_blocks_unknown(self):
        checks = [
            self.check_run(conclusion="failure", started_at="2026-08-21T10:00:00Z", check_id=1, run_id=101),
            self.check_run(status="in_progress", conclusion=None, started_at="2026-08-21T11:00:00Z", check_id=2, run_id=102),
        ]
        self.assertEqual(self.status_for_checks(checks), "BLOCKED_UNKNOWN")

    def test_historical_unrelated_failure_superseded_by_success_does_not_block(self):
        checks = [
            self.check_run(check_id=1),
            self.check_run("Architecture Governance", conclusion="failure", started_at="2026-08-21T10:00:00Z", check_id=2),
            self.check_run("Architecture Governance", conclusion="success", started_at="2026-08-21T11:00:00Z", check_id=3),
        ]
        self.assertEqual(self.status_for_checks(list(reversed(checks))), "PASS")

    def test_latest_unrelated_failure_blocks(self):
        checks = [
            self.check_run(check_id=1),
            self.check_run("Architecture Governance", conclusion="success", started_at="2026-08-21T10:00:00Z", check_id=2),
            self.check_run("Architecture Governance", conclusion="failure", started_at="2026-08-21T11:00:00Z", check_id=3),
        ]
        self.assertEqual(self.status_for_checks(checks), "BLOCKED_UNKNOWN")

    def test_latest_unrelated_pending_blocks(self):
        checks = [
            self.check_run(check_id=1),
            self.check_run("Architecture Governance", conclusion="success", started_at="2026-08-21T10:00:00Z", check_id=2),
            self.check_run("Architecture Governance", status="queued", conclusion=None, started_at="2026-08-21T11:00:00Z", check_id=3),
        ]
        self.assertEqual(self.status_for_checks(checks), "BLOCKED_UNKNOWN")

    def test_check_run_ordering_uses_timestamp_not_api_order(self):
        checks = [
            self.check_run(conclusion="success", started_at="2026-08-21T11:00:00Z", check_id=2),
            self.check_run(conclusion="failure", started_at="2026-08-21T10:00:00Z", check_id=1),
        ]
        self.assertEqual(self.status_for_checks(list(reversed(checks))), "PASS")
        self.assertEqual(self.status_for_checks(checks), "PASS")

    def test_check_run_equal_timestamp_uses_id_tiebreak(self):
        checks = [
            self.check_run(conclusion="failure", started_at="2026-08-21T10:00:00Z", check_id=1),
            self.check_run(conclusion="success", started_at="2026-08-21T10:00:00Z", check_id=2),
        ]
        self.assertEqual(self.status_for_checks(checks), "PASS")

    def test_malformed_timestamp_fails_closed(self):
        checks = [self.check_run(started_at="not-a-time")]
        self.assertEqual(self.status_for_checks(checks), "BLOCKED_UNKNOWN")

    def test_malformed_check_evidence_fails_closed(self):
        checks = [self.check_run(), {"status": "completed", "conclusion": "success", "started_at": "2026-08-21T10:00:00Z", "id": 2}]
        self.assertEqual(self.status_for_checks(checks), "BLOCKED_UNKNOWN")

    def test_verify_onboarding_file_failure_requires_report_evidence(self):
        report = {"results": [{"gate": "Protected Resources", "status": "FAIL", "message": ".github/workflows/pr-qa.yml changed", "details": [], "blocking": True}]}
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": ".github/workflows/pr-qa.yml"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[self.check_run(conclusion="failure")]), \
             patch.object(mod, "latest_prqa_report", return_value=report):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_ON_ONBOARDING_FILE")

    def test_verify_legacy_failure_uses_report_evidence(self):
        report = {"results": [{"gate": "Secrets", "status": "FAIL", "message": "legacy/config.php contains inherited secret-like content", "details": [], "blocking": True}]}
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": "app/file.php"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[self.check_run(conclusion="failure")]), \
             patch.object(mod, "latest_prqa_report", return_value=report):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_ON_EXISTING_LEGACY_FINDING")

    def test_verify_ambiguous_failure_is_unknown(self):
        report = {"results": [{"gate": "Tests", "status": "FAIL", "message": "Tests failed", "details": [], "blocking": True}]}
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": ".github/workflows/pr-qa.yml"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[self.check_run(conclusion="failure")]), \
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

        with patch.object(mod, "check_runs_for_sha", return_value=[self.check_run(run_id=123)]), \
             patch.object(mod, "run", side_effect=fake_run):
            return mod.latest_prqa_report("Synergie-ITCI/example", "abc")

    def test_latest_prqa_report_uses_authoritative_latest_prqa_run(self):
        checks = [
            self.check_run(conclusion="failure", started_at="2026-08-21T10:00:00Z", check_id=1, run_id=111),
            self.check_run(conclusion="success", started_at="2026-08-21T11:00:00Z", check_id=2, run_id=222),
        ]
        selected = mod.latest_check_runs_by_name(list(reversed(checks)))
        self.assertIsNotNone(selected)
        self.assertIn("/actions/runs/222/", selected[mod.GENERIC_CALLER_CONTEXT]["details_url"])
        downloaded_runs = []

        def fake_run(cmd, **_kwargs):
            if cmd[:3] == ["gh", "run", "download"]:
                downloaded_runs.append(cmd[3])
                out = Path(cmd[cmd.index("--dir") + 1])
                (out / "pr-quality-report.json").write_text(json.dumps({"run": cmd[3]}), encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(mod, "check_runs_for_sha", return_value=list(reversed(checks))), \
             patch.object(mod, "run", side_effect=fake_run):
            self.assertEqual(mod.latest_prqa_report("Synergie-ITCI/example", "abc"), {"run": "222"})
        self.assertEqual(downloaded_runs, ["222"])

    def test_verify_paths_call_shared_latest_run_selector(self):
        checks = [self.check_run()]

        def fake_run(cmd, **_kwargs):
            if cmd[:3] == ["gh", "run", "download"]:
                out = Path(cmd[cmd.index("--dir") + 1])
                (out / "pr-quality-report.json").write_text(json.dumps({"results": []}), encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(mod, "latest_check_runs_by_name", wraps=mod.latest_check_runs_by_name) as selector, \
             patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "development", "headRefName": "feature/x", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[]), \
             patch.object(mod, "check_runs_for_sha", return_value=checks), \
             patch.object(mod, "run", side_effect=fake_run):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "PASS")
            self.assertEqual(mod.latest_prqa_report("Synergie-ITCI/example", "abc"), {"results": []})
        self.assertEqual(selector.call_count, 2)

    def test_no_second_independent_latest_run_implementation_exists(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("def latest_check_runs_by_name", source)
        self.assertIn("latest = latest_check_runs_by_name(checks)", source.split("def pr_status", 1)[1].split("def verify", 1)[0])
        self.assertIn("latest = latest_check_runs_by_name(checks)", source.split("def latest_prqa_report", 1)[1].split("def failed_report_entries", 1)[0])
        self.assertNotIn("exact_prqa = [", source)

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
             patch.object(mod, "check_runs_for_sha", return_value=[self.check_run(conclusion="failure")]), \
             patch.object(mod, "latest_prqa_report", return_value=None):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 1, "SaurabhVermaIN"), "BLOCKED_UNKNOWN")

    def test_gate_c_wait(self):
        with patch.object(mod, "gh_json", return_value={"author": {"login": "dev"}, "baseRefName": "main", "headRefName": "staging", "headRefOid": "abc", "mergeable": "MERGEABLE"}), \
             patch.object(mod, "pr_files", return_value=[{"path": "app/file.php"}]), \
             patch.object(mod, "check_runs_for_sha", return_value=[self.check_run()]), \
             patch.object(mod, "latest_reviews", return_value={"other": "APPROVED"}):
            self.assertEqual(mod.pr_status("Synergie-ITCI/example", 2, "SaurabhVermaIN"), "WAITING_FOR_HUMAN_APPROVAL")


if __name__ == "__main__":
    unittest.main()
