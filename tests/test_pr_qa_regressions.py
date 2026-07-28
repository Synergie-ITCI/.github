from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "pr-qa" / "pr_qa.py"
sys.path.insert(0, str(ROOT / "pr-qa"))
import pr_qa  # noqa: E402


class PrQaRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="prqa-regression-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        fake_gitleaks = self.bin / "gitleaks"
        fake_gitleaks.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        fake_gitleaks.chmod(0o755)
        fake_python = self.bin / "python"
        fake_python.write_text("#!/usr/bin/env bash\nexec python3 \"$@\"\n", encoding="utf-8")
        fake_python.chmod(0o755)
        self.env = dict(os.environ)
        for key in ["GITHUB_ACTOR", "GITHUB_BASE_REF", "GITHUB_EVENT_PATH", "GITHUB_HEAD_REF", "GITHUB_REF", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_TRIGGERING_ACTOR"]:
            self.env.pop(key, None)
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env.get("PATH", "")
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def init_repo(self, name: str, *, profile: str = "application") -> tuple[Path, str]:
        repo = self.tmp / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "qa@example.invalid")
        self.git(repo, "config", "user.name", "QA Regression")
        self.write(repo / ".github" / "pr-qa.yml", self.base_config(profile=profile))
        self.write(repo / ".github" / "CODEOWNERS", "* @synergie/security\n.github/** @synergie/devops\n")
        self.write(repo / "README.md", "# regression\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: baseline")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "feature/regression")
        return repo, base

    def run_engine(self, repo: Path, base: str, *, static_only: bool = False) -> tuple[int, str]:
        code, report, _, _ = self.run_engine_with_artifacts(repo, base, static_only=static_only)
        return code, report

    def run_engine_with_artifacts(
        self,
        repo: Path,
        base: str,
        *,
        static_only: bool = False,
        actor: str = "",
        pr_author: str = "SaurabhVermaIN",
        override_reason: str = "",
    ) -> tuple[int, str, dict, Path]:
        event = repo / "event.json"
        event.write_text(
            json.dumps(
                {
                    "pull_request": {
                        "number": 123,
                        "user": {"login": pr_author},
                        "base": {"sha": base, "ref": "main"},
                        "head": {"sha": "HEAD", "ref": "feature/regression"},
                        "body": (
                            "## Business Purpose\nRegression test.\n"
                            "## Testing Performed\nLocal automated regression.\n"
                            "## Rollback Strategy\nRevert this PR.\n"
                            "## Linked Issue\n#123\n"
                            "## Screenshots\nN/A\n"
                        ),
                    }
                }
            ),
            encoding="utf-8",
        )
        report = repo / "report.md"
        json_report = repo / "report.json"
        audit = repo / "emergency-override-audit.json"
        args = [
            "python3",
            str(ENGINE),
            "--repo",
            str(repo),
            "--event-path",
            str(event),
            "--out",
            str(report),
            "--json-out",
            str(json_report),
        ]
        if static_only:
            args.append("--static-only")
        env = dict(self.env)
        if actor:
            env["GITHUB_ACTOR"] = actor
        if override_reason:
            args.extend(["--emergency-override-reason", override_reason, "--emergency-override-out", str(audit)])
        completed = subprocess.run(args, text=True, capture_output=True, env=env, check=False)
        report_text = report.read_text(encoding="utf-8") if report.exists() else completed.stdout
        parsed_json = json.loads(json_report.read_text(encoding="utf-8")) if json_report.exists() else {}
        return completed.returncode, report_text, parsed_json, audit

    def test_pr_cannot_disable_mandatory_gates(self) -> None:
        repo, base = self.init_repo("config-disable")
        self.write(repo / ".github" / "pr-qa.yml", "version: 1\ngates:\n  secrets: false\n  tests: false\n  protected_resources: false\n")
        self.write(repo / ".env", "TOKEN=\"super-secret-value\"\n")
        self.commit(repo, "chore: attempt qa bypass")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("Mandatory gate `secrets` cannot be disabled", report)

    def test_env_file_is_blocking_secret_failure(self) -> None:
        repo, base = self.init_repo("env-secret")
        self.write(repo / ".env", "PASSWORD=\"super-secret-value\"\n")
        self.commit(repo, "feat: add env")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("environment file committed", report)

    def test_base64_secret_is_detected(self) -> None:
        repo, base = self.init_repo("encoded-secret")
        self.write(repo / "app.py", "TOKEN_B64 = 'Z2hwX2Zha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2VmYWtl'\n")
        self.commit(repo, "feat: encoded token")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("base64-encoded GitHub token", report)

    def test_nested_node_modules_is_generated_artifact_failure(self) -> None:
        repo, base = self.init_repo("nested-generated")
        self.write(repo / "frontend" / "node_modules" / "left-pad" / "index.js", "module.exports = 1\n")
        self.commit(repo, "feat: add cached dependency")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("generated artifact path changed", report)

    def test_approved_governance_hidden_asset_is_not_integrity_failure(self) -> None:
        repo, base = self.init_repo("approved-governance-asset")
        self.write(repo / ".gitleaks.toml", "[allowlist]\ndescription = \"test config\"\n")
        self.commit(repo, "chore: add gitleaks governance config")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertEqual(code, 0)
        self.assertNotIn("unexpected hidden file or directory `.gitleaks.toml`", report)
        self.assertIn("Protected resources changed", report)

    def test_unknown_hidden_file_still_fails(self) -> None:
        repo, base = self.init_repo("unknown-hidden")
        self.write(repo / ".unknownrc", "setting=true\n")
        self.commit(repo, "chore: add unknown hidden config")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("unexpected hidden file or directory `.unknownrc`", report)

    def test_codeowners_modification_fails(self) -> None:
        repo, base = self.init_repo("codeowners-change")
        self.write(repo / ".github" / "CODEOWNERS", "* @attacker\n")
        self.commit(repo, "chore: change owners")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("CODEOWNERS changes are not allowed", report)

    def test_framework_profile_classifies_approved_regression_fixture(self) -> None:
        repo, base = self.init_repo("framework-fixture", profile="framework")
        self.write(repo / "tests" / "test_pr_qa_regressions.py", "TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz123456'\n")
        self.commit(repo, "test: add approved regression fixture")
        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)
        self.assertEqual(code, 0)
        self.assertNotIn("High-confidence secret indicators found", report)
        self.assertTrue(
            any(
                result["gate"] == "Secrets"
                and result["status"] == "PASS"
                and result["message"] == "Approved framework regression fixtures remain detectable and isolated."
                for result in report_json["results"]
            )
        )

    def test_framework_profile_classifies_gitleaks_fixture_manifest(self) -> None:
        repo, base = self.init_repo("framework-gitleaks-fixture", profile="framework")
        self.write(
            repo / ".gitleaks.toml",
            "regexes = [\n  '''Z2hwX2Zha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2VmYWtl'''\n]\n",
        )
        self.commit(repo, "test: add approved fixture manifest")
        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)
        self.assertEqual(code, 0)
        self.assertNotIn("High-confidence secret indicators found", report)
        self.assertTrue(
            any(
                result["gate"] == "Secrets"
                and result["status"] == "PASS"
                and result["message"] == "Approved framework regression fixtures remain detectable and isolated."
                for result in report_json["results"]
            )
        )

    def test_application_profile_does_not_inherit_regression_fixture_allowance(self) -> None:
        repo, base = self.init_repo("application-fixture")
        self.write(repo / "tests" / "test_pr_qa_regressions.py", "TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz123456'\n")
        self.commit(repo, "test: add production token regression")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("High-confidence secret indicators found", report)
        self.assertIn("tests/test_pr_qa_regressions.py: GitHub token", report)

    def test_hash_issue_reference_counts_as_linked_issue_evidence(self) -> None:
        body = (
            "## Business Purpose\nRegression test.\n"
            "## Testing Performed\nLocal automated regression.\n"
            "## Rollback Strategy\nRevert this PR.\n"
            "## Linked Issue\n#123\n"
            "## Screenshots\nN/A\n"
        )
        self.assertTrue(pr_qa.field_has_value(body, "linked issue"))

    def test_python_without_dependency_manifest_does_not_audit_runner_environment(self) -> None:
        repo, base = self.init_repo("python-no-deps")
        self.write(repo / "app.py", "print('ok')\n")
        self.commit(repo, "feat: add python script")
        code, report = self.run_engine(repo, base)
        self.assertEqual(code, 0, report)
        self.assertIn("No Python dependency manifest found; pip-audit is not applicable.", report)
        self.assertNotIn("pip-audit is mandatory and is not installed", report)

    def test_obfuscated_destructive_migration_fails(self) -> None:
        repo, base = self.init_repo("migration")
        self.write(repo / "database" / "migrations" / "2026_01_01_000001_drop.php", "<?php\nDB::statement('DR' . 'OP TABLE users');\n")
        self.commit(repo, "feat: migration")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("CRITICAL migration risk", report)

    def test_unknown_executable_language_fails(self) -> None:
        repo, base = self.init_repo("unknown-exec")
        self.write(repo / "src" / "server.js", "module.exports = () => 1\n")
        self.commit(repo, "feat: unclassified js")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("Executable code changed without a supported technology adapter", report)

    def test_malicious_install_hook_does_not_execute_when_static_fails(self) -> None:
        repo, base = self.init_repo("install-hook")
        self.write(repo / ".github" / "pr-qa.yml", "version: 1\ngates:\n  secrets: false\n")
        self.write(
            repo / "package.json",
            json.dumps({"scripts": {"preinstall": "touch SHOULD_NOT_EXIST", "test": "echo ok"}, "dependencies": {}}),
        )
        self.commit(repo, "chore: malicious hook")
        code, _ = self.run_engine(repo, base)
        self.assertNotEqual(code, 0)
        self.assertFalse((repo / "SHOULD_NOT_EXIST").exists())

    def test_workflow_has_no_framework_override_or_checkout_credentials(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "pr-qa.yml").read_text(encoding="utf-8")
        self_workflow = (ROOT / ".github" / "workflows" / "pr-qa-self.yml").read_text(encoding="utf-8")
        caller = (ROOT / "examples" / "caller-workflow.yml").read_text(encoding="utf-8")
        self.assertNotIn("framework-ref", workflow + caller + self_workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("repository: ${{ job.workflow_repository }}", workflow)
        self.assertIn("ref: ${{ job.workflow_sha }}", workflow)
        self.assertIn("PR_QA_GITLEAKS_LINUX_X64_SHA256", workflow)
        self.assertIn("Install mandatory Gitleaks", workflow)
        self.assertIn("PR_QA_PIP_AUDIT_VERSION", workflow)
        self.assertIn("PR_QA_PYTEST_VERSION", workflow)
        self.assertIn("Install Python QA tooling", workflow)
        self.assertIn("--repository-profile \"${{ inputs.repository-profile }}\"", workflow)
        self.assertIn("@pr-qa-v1.1", caller)
        self.assertIn("github.event.pull_request.number || github.ref", caller)
        self.assertNotIn("repository-profile: framework", caller)
        self.assertIn("uses: ./.github/workflows/pr-qa.yml", self_workflow)
        self.assertIn("repository-profile: framework", self_workflow)
        self.assertIn("merge_group:", self_workflow)
        self.assertIn("github.event.pull_request.number || github.ref", self_workflow)
        self.assertIn("publisher:", workflow)
        self.assertIn("pull-requests: write", workflow.split("publisher:", 1)[1])
        qa_job = workflow.split("  qa:", 1)[1].split("  publisher:", 1)[0]
        self.assertNotIn("AI_REVIEW_PROVIDER_TOKEN", qa_job)
        self.assertNotIn("GITHUB_TOKEN", qa_job)
        self.assertNotIn("Checkout pull request", workflow.split("publisher:", 1)[1])
        self.assertIn("pr-qa-results/pr-quality-report.json", qa_job)
        self.assertIn("pr-qa-results/pr-quality-report.md", qa_job)
        self.assertNotIn("path: pr-qa-results/\n          retention-days", qa_job)

    def test_output_redaction_removes_fake_tokens(self) -> None:
        code = "from adapters.base import redact; print(redact('token=\"ghp_abcdefghijklmnopqrstuvwxyz123456\"'))"
        completed = subprocess.run(["python3", "-c", code], cwd=ROOT / "pr-qa", text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0)
        self.assertIn("[REDACTED]", completed.stdout)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", completed.stdout)

    def test_emergency_override_rejects_normal_user_without_changing_findings(self) -> None:
        repo, base = self.init_repo("override-normal-user")
        self.write(repo / ".env", "PASSWORD=\"super-secret-value\"\n")
        self.commit(repo, "feat: add env")
        baseline_code, _, baseline_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)
        override_code, _, override_json, audit_path = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            actor="ordinary-user",
            pr_author="ordinary-user",
            override_reason="Emergency production continuity request.",
        )

        self.assertNotEqual(baseline_code, 0)
        self.assertEqual(override_code, baseline_code)
        self.assertEqual(override_json["summary"], baseline_json["summary"])
        self.assertEqual(override_json["results"], baseline_json["results"])
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        self.assertFalse(audit["authorized"])
        self.assertEqual(audit["decision"], "REJECTED_UNAUTHORIZED_ACTOR")
        self.assertEqual(audit["actor"], "ordinary-user")
        self.assertEqual(audit["pr_author"], "ordinary-user")

    def test_emergency_override_requires_admin_bypass_for_saurabh_authored_pr(self) -> None:
        repo, base = self.init_repo("override-authorised-user")
        self.write(repo / ".env", "PASSWORD=\"super-secret-value\"\n")
        self.commit(repo, "feat: add env")
        baseline_code, _, baseline_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)
        code, _, report_json, audit_path = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            actor="SaurabhVermaIN",
            pr_author="SaurabhVermaIN",
            override_reason="Emergency production continuity request.",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(code, baseline_code)
        self.assertEqual(report_json["summary"], baseline_json["summary"])
        self.assertEqual(report_json["results"], baseline_json["results"])
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        self.assertTrue(audit["authorized"])
        self.assertTrue(audit["actor_authorized"])
        self.assertTrue(audit["administrator_bypass_required"])
        self.assertFalse(audit["self_approval_allowed"])
        self.assertFalse(audit["self_merge_authorized"])
        self.assertEqual(audit["decision"], "ADMINISTRATOR_BYPASS_REQUIRED")
        self.assertEqual(audit["actor"], "SaurabhVermaIN")
        self.assertEqual(audit["pr_author"], "SaurabhVermaIN")
        self.assertEqual(audit["repository"], repo.name)
        self.assertEqual(audit["branch"], "feature/regression")
        self.assertEqual(audit["pr_number"], 123)
        self.assertRegex(audit["commit_sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(audit["qa_summary"]["overall_result"], report_json["summary"]["overall_result"])
        self.assertEqual(audit["qa_summary"]["gate_statuses"], report_json["summary"]["gate_statuses"])
        self.assertTrue(any(finding["gate"] == "Repository Integrity" for finding in audit["qa_summary"]["failed_findings"]))
        self.assertEqual(audit["record_sha256"], self.override_digest(audit))

    def test_emergency_override_records_executive_review_for_developer_pr(self) -> None:
        repo, base = self.init_repo("override-other-author")
        self.write(repo / ".env", "PASSWORD=\"super-secret-value\"\n")
        self.commit(repo, "feat: add env")
        code, _, report_json, audit_path = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            actor="SaurabhVermaIN",
            pr_author="another-author",
            override_reason="Emergency production continuity request.",
        )

        self.assertNotEqual(code, 0)
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        self.assertTrue(audit["authorized"])
        self.assertTrue(audit["actor_authorized"])
        self.assertFalse(audit["administrator_bypass_required"])
        self.assertFalse(audit["self_approval_allowed"])
        self.assertFalse(audit["self_merge_authorized"])
        self.assertEqual(audit["decision"], "EXECUTIVE_RELEASE_AUTHORITY_REVIEW_RECORDED")
        self.assertEqual(audit["actor"], "SaurabhVermaIN")
        self.assertEqual(audit["pr_author"], "another-author")
        self.assertEqual(audit["qa_summary"]["gate_statuses"], report_json["summary"]["gate_statuses"])

    def test_inline_review_maps_git_diff_check_to_offending_line(self) -> None:
        repo, base = self.init_repo("inline-formatting")
        self.write(repo / "notes.txt", "clean\ntrailing whitespace   \n")
        self.commit(repo, "docs: add whitespace fixture")
        code, _, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        finding = self.inline_finding(report_json, "Git Validation", "notes.txt")
        self.assertEqual(finding["line"], 2)
        self.assertEqual(finding["severity"], "BLOCKING")
        self.assertIn("DIFF FORMATTING ISSUE", finding["title"])

    def test_inline_review_maps_secret_without_exposing_secret_value(self) -> None:
        repo, base = self.init_repo("inline-secret")
        raw_secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        self.write(repo / "app.py", f"TOKEN = '{raw_secret}'\n")
        self.commit(repo, "feat: add token fixture")
        code, _, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        finding = self.inline_finding(report_json, "Secrets", "app.py")
        self.assertEqual(finding["line"], 1)
        self.assertEqual(finding["severity"], "BLOCKING")
        self.assertNotIn(raw_secret, json.dumps(finding))
        self.assertIn("approved secrets management", finding["recommendation"])

    def test_inline_review_maps_destructive_migration_to_line(self) -> None:
        repo, base = self.init_repo("inline-migration")
        self.write(repo / "database" / "migrations" / "2026_01_01_000001_drop.sql", "CREATE TABLE users(id int);\nDROP TABLE users;\n")
        self.commit(repo, "feat: add migration fixture")
        code, _, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        finding = self.inline_finding(report_json, "Migration Risk", "database/migrations/2026_01_01_000001_drop.sql")
        self.assertEqual(finding["line"], 2)
        self.assertEqual(finding["severity"], "BLOCKING")

    def test_inline_review_maps_deployment_workflow_to_changed_line(self) -> None:
        repo, base = self.init_repo("inline-deployment")
        self.write(repo / ".github" / "workflows" / "deploy.yml", "name: deploy\nsteps:\n  - run: kubectl apply -f k8s/prod.yaml\n")
        self.commit(repo, "ci: add deployment workflow")
        code, _, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0)
        finding = self.inline_finding(report_json, "Deployment Risk", ".github/workflows/deploy.yml")
        self.assertEqual(finding["line"], 3)
        self.assertEqual(finding["severity"], "WARNING")

    def test_inline_review_maps_documentation_warning_to_env_line(self) -> None:
        repo, base = self.init_repo("inline-documentation")
        self.write(repo / ".env.example", "NEW_REQUIRED_SETTING=true\n")
        self.commit(repo, "chore: add config fixture")
        code, _, report_json, _ = self.run_engine_with_artifacts(repo, base)

        self.assertEqual(code, 0)
        finding = self.inline_finding(report_json, "Documentation", ".env.example")
        self.assertEqual(finding["line"], 1)
        self.assertEqual(finding["severity"], "WARNING")
        self.assertEqual(
            1,
            sum(
                1
                for item in report_json.get("inline_review", {}).get("findings", [])
                if item["gate"] == "Documentation" and item["path"] == ".env.example" and item["line"] == 1
            ),
        )

    def inline_finding(self, report_json: dict, gate: str, path: str) -> dict:
        findings = report_json.get("inline_review", {}).get("findings", [])
        matches = [finding for finding in findings if finding["gate"] == gate and finding["path"] == path]
        self.assertTrue(matches, f"No inline finding for {gate} at {path}. Got: {findings}")
        return matches[0]

    def override_digest(self, record: dict) -> str:
        payload = {key: value for key, value in record.items() if key != "record_sha256"}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)

    def commit(self, repo: Path, message: str) -> None:
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", message)

    def write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def base_config(self, *, profile: str = "application") -> str:
        return f"""version: 1
repository:
  profile: {profile}
  criticality: medium
gates:
  repository_hygiene: true
  formatting: true
  lint: true
  build: true
  tests: true
  git_validation: true
  secrets: true
  dependencies: true
  licence: true
  deployment_safety: true
  database_safety: true
  documentation: true
  protected_resources: true
  advisory_review: true
  risk: true
  evidence: true
"""


if __name__ == "__main__":
    unittest.main()
