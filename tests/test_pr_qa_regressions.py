from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "pr-qa" / "pr_qa.py"
NODE_RESOLVER = ROOT / "pr-qa" / "resolve_node_version.py"


class PrQaRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="prqa-regression-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        fake_gitleaks = self.bin / "gitleaks"
        fake_gitleaks.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        fake_gitleaks.chmod(0o755)
        self.env = dict(os.environ)
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
        base_ref: str = "main",
        head_ref: str = "feature/regression",
        actor: str = "",
        pr_author: str = "SaurabhVermaIN",
        override_reason: str = "",
        review_policy: dict | None = None,
    ) -> tuple[int, str, dict, Path]:
        event = repo / "event.json"
        event.write_text(
            json.dumps(
                {
                    "pull_request": {
                        "number": 123,
                        "user": {"login": pr_author},
                        "base": {"sha": base, "ref": base_ref},
                        "head": {"sha": "HEAD", "ref": head_ref},
                        "body": (
                            "## Business Purpose\nRegression test.\n"
                            "## Testing Performed\nLocal automated regression.\n"
                            "## Rollback Strategy\nRevert this PR.\n"
                            "## Linked Issue\nhttps://github.com/Synergie-ITCI/.github/issues/123\n"
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
        review_policy_input = repo / "review-policy-input.json"
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
        if review_policy is not None:
            review_policy_input.write_text(json.dumps(review_policy), encoding="utf-8")
            args.extend(["--review-policy-input", str(review_policy_input)])
        env = dict(self.env)
        if actor:
            env["GITHUB_ACTOR"] = actor
        if override_reason:
            args.extend(["--emergency-override-reason", override_reason, "--emergency-override-out", str(audit)])
        completed = subprocess.run(args, text=True, capture_output=True, env=env, check=False)
        report_text = report.read_text(encoding="utf-8") if report.exists() else completed.stdout
        parsed_json = json.loads(json_report.read_text(encoding="utf-8")) if json_report.exists() else {}
        return completed.returncode, report_text, parsed_json, audit

    def test_saurabh_authored_pr_allows_green_without_independent_review(self) -> None:
        repo, base = self.init_repo("saurabh-no-review-green")
        self.write(repo / "README.md", "# regression\n\nSaurabh-authored governance correction.\n")
        self.commit(repo, "docs: update regression readme")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            pr_author="SaurabhVermaIN",
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "PASS")
        self.assertTrue(any("SaurabhVermaIN is exempt from independent human review" in result["message"] for result in report_json["results"]))

    def test_saurabh_authored_pr_remains_blocked_when_qa_fails(self) -> None:
        repo, base = self.init_repo("saurabh-qa-fail")
        self.write(repo / ".github" / "pr-qa.yml", "version: 1\ngates:\n  tests: false\n")
        self.commit(repo, "chore: attempt mandatory qa bypass")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            pr_author="SaurabhVermaIN",
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["overall_result"], "FAIL")
        self.assertIn("Mandatory gate `tests` cannot be disabled", report)

    def test_saurabh_authored_pr_remains_blocked_when_security_fails(self) -> None:
        repo, base = self.init_repo("saurabh-security-fail")
        self.write(repo / ".env", "PASSWORD=\"super-secret-value\"\n")
        self.commit(repo, "feat: add env")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            pr_author="SaurabhVermaIN",
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["overall_result"], "FAIL")
        self.assertIn("environment file committed", report)

    def test_saurabh_authored_pr_remains_blocked_with_merge_conflict(self) -> None:
        repo, base = self.init_repo("saurabh-conflict")
        self.write(repo / "README.md", "# regression\n\nConflicting change.\n")
        self.commit(repo, "docs: update conflict fixture")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            pr_author="SaurabhVermaIN",
            review_policy={"mergeable": False, "merge_conflict": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "FAIL")
        self.assertIn("Pull request has merge conflicts", report)

    def test_feature_pr_still_blocks_accidental_merge_commit(self) -> None:
        repo, base = self.init_repo("feature-merge-commit")
        self.write(repo / "feature.txt", "feature change\n")
        self.commit(repo, "feat: add feature change")
        self.git(repo, "checkout", "-q", "-b", "feature/side-branch", base)
        self.write(repo / "side.txt", "side change\n")
        self.commit(repo, "feat: add side change")
        self.git(repo, "checkout", "-q", "feature/regression")
        self.git(repo, "merge", "--no-ff", "-m", "Merge side branch", "feature/side-branch")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_development_to_staging_allows_governed_noop_merge_commit(self) -> None:
        repo, base = self.init_repo("development-staging-promotion", profile="framework")
        self.write(repo / "README.md", "# regression\n\nGoverned promotion content.\n")
        self.commit(repo, "feat(governance): add promotion content")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        self.git(repo, "merge", "--no-ff", "-m", "promote(governance): merge reviewed feature to development", "feature/regression")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="staging",
            head_ref="development",
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "PASS")
        self.assertTrue(
            any(
                result["gate"] == "Repository Hygiene"
                and result["message"] == "Only governed branch-promotion merge commits detected."
                for result in report_json["results"]
            )
        )

    def test_development_to_staging_blocks_contentful_merge_commit(self) -> None:
        repo, base = self.init_repo("development-staging-contentful-merge", profile="framework")
        self.write(repo / "feature.txt", "feature change\n")
        self.commit(repo, "feat(governance): add feature change")
        self.git(repo, "checkout", "-q", "-b", "feature/side-branch", base)
        self.write(repo / "side.txt", "side change\n")
        self.commit(repo, "feat(governance): add side change")
        self.git(repo, "checkout", "-q", "-b", "development", "feature/regression")
        self.git(repo, "merge", "--no-ff", "-m", "feat(governance): merge side branch", "feature/side-branch")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="staging",
            head_ref="development",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_non_saurabh_authored_pr_blocks_without_independent_review(self) -> None:
        repo, base = self.init_repo("developer-no-review")
        self.write(repo / "README.md", "# regression\n\nDeveloper-authored change.\n")
        self.commit(repo, "docs: update developer fixture")
        for author in ["dev.ravi.ranjan", "dev.raveesh.yadav", "mohit.tiwari"]:
            with self.subTest(author=author):
                code, report, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    base,
                    pr_author=author,
                    review_policy={"mergeable": True, "reviews": []},
                )
                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "FAIL")
                self.assertIn("Independent human approval is required", report)

    def test_non_saurabh_authored_pr_allows_green_with_independent_review(self) -> None:
        repo, base = self.init_repo("developer-reviewed-green")
        self.write(repo / "README.md", "# regression\n\nReviewed developer change.\n")
        self.commit(repo, "docs: update reviewed developer fixture")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            pr_author="dev.raveesh.yadav",
            review_policy={
                "mergeable": True,
                "reviews": [
                    {"user": {"login": "SaurabhVermaIN"}, "state": "APPROVED"},
                ],
            },
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "PASS")
        self.assertTrue(any("Independent human review requirement is satisfied" in result["message"] for result in report_json["results"]))

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

    def test_react_native_bootstrap_files_are_narrowly_allowed(self) -> None:
        repo, base = self.init_repo("react-native-bootstrap")
        self.write(
            repo / "package.json",
            json.dumps({"dependencies": {"react-native": "0.87.0"}, "devDependencies": {}}),
        )
        self.write(repo / ".watchmanconfig", "{}\n")
        self.write(repo / ".bundle" / "config", 'BUNDLE_PATH: "vendor/bundle"\nBUNDLE_FORCE_RUBY_PLATFORM: 1\n')
        self.write(repo / "ios" / ".xcode.env", "export NODE_BINARY=$(command -v node)\n")
        self.write(
            repo / "android" / "gradle" / "wrapper" / "gradle-wrapper.properties",
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.4.1-bin.zip\n",
        )
        self.write_bytes(repo / "android" / "gradle" / "wrapper" / "gradle-wrapper.jar", b"PK\x03\x04\x00gradle-wrapper")
        self.write(
            repo / "android" / "app" / "build.gradle",
            "signingConfigs { debug { storeFile file('debug.keystore') storePassword 'android' keyAlias 'androiddebugkey' keyPassword 'android' } }\n",
        )
        self.write_bytes(repo / "android" / "app" / "debug.keystore", b"\x00android-debug-keystore")
        self.write(repo / "android" / "gradlew.bat", "@rem Gradle wrapper script \r\nset DIRNAME=%~dp0\r\n")
        self.commit(repo, "chore: add react native bootstrap files")

        code, report = self.run_engine(repo, base, static_only=True)

        self.assertEqual(code, 0, report)
        self.assertNotIn("unexpected hidden file or directory", report)
        self.assertNotIn("binary file type is not allowed", report)

    def test_react_native_release_keystore_remains_blocked(self) -> None:
        repo, base = self.init_repo("react-native-release-keystore")
        self.write(
            repo / "package.json",
            json.dumps({"dependencies": {"react-native": "0.87.0"}, "devDependencies": {}}),
        )
        self.write(repo / "android" / "settings.gradle", "pluginManagement {}\n")
        self.write(repo / "ios" / "README.md", "native project marker\n")
        self.write_bytes(repo / "android" / "app" / "release.keystore", b"\x00production-signing")
        self.commit(repo, "chore: add release keystore")

        code, report = self.run_engine(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertIn("android/app/release.keystore: binary file type is not allowed", report)

    def test_react_native_secret_bearing_hidden_config_remains_blocked(self) -> None:
        repo, base = self.init_repo("react-native-hidden-secret")
        self.write(
            repo / "package.json",
            json.dumps({"dependencies": {"react-native": "0.87.0"}, "devDependencies": {}}),
        )
        self.write(repo / "android" / "settings.gradle", "pluginManagement {}\n")
        self.write(repo / "ios" / ".xcode.env", 'API_TOKEN="super-secret-value"\n')
        self.commit(repo, "chore: add secret-bearing xcode env")

        code, report = self.run_engine(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertIn("unexpected hidden file or directory `.xcode.env`", report)
        self.assertIn("generic credential assignment", report)

    def test_watchmanconfig_without_react_native_markers_still_fails(self) -> None:
        repo, base = self.init_repo("watchman-non-react-native")
        self.write(repo / ".watchmanconfig", "{}\n")
        self.commit(repo, "chore: add watchman config")

        code, report = self.run_engine(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertIn("unexpected hidden file or directory `.watchmanconfig`", report)

    def test_codeowners_modification_fails(self) -> None:
        repo, base = self.init_repo("codeowners-change")
        self.write(repo / ".github" / "CODEOWNERS", "* @attacker\n")
        self.commit(repo, "chore: change owners")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("CODEOWNERS changes are not allowed", report)

    def test_codeowners_bootstrap_allows_pr_qa_caller_recovery(self) -> None:
        repo = self.tmp / "codeowners-bootstrap"
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "qa@example.invalid")
        self.git(repo, "config", "user.name", "QA Regression")
        self.write(repo / ".github" / "pr-qa.yml", self.base_config())
        self.write(repo / "README.md", "# regression\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: baseline")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "fix/pr-qa-v1-rc5")

        self.write(repo / ".github" / "CODEOWNERS", ".github/** @Synergie-ITCI/saurabh-pr-review-bypass\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non: [pull_request]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc5\n",
        )
        self.commit(repo, "ci: enable pr qa governance")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertEqual(code, 0)
        self.assertIn("Base CODEOWNERS bootstrap detected", report)

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

    def test_workflow_only_pr_does_not_execute_unrelated_app_commands(self) -> None:
        composer_marker = self.tmp / "composer-was-run"
        fake_composer = self.bin / "composer"
        fake_composer.write_text(f"#!/usr/bin/env bash\ntouch {composer_marker}\nexit 42\n", encoding="utf-8")
        fake_composer.chmod(0o755)

        repo, base = self.init_repo("workflow-only-governance")
        self.write(repo / "composer.json", json.dumps({"require": {}, "scripts": {"test": "exit 42"}}))
        self.write(repo / "composer.lock", json.dumps({"packages": [], "packages-dev": []}))
        self.write(repo / ".github" / "workflows" / "existing.yml", "name: Existing\non: push\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: add app markers")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.write(repo / ".github" / "workflows" / "pr-qa.yml", "name: PR Quality Assurance\non: pull_request\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n")
        self.commit(repo, "ci: add pr qa workflow")
        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base)

        self.assertEqual(code, 0, report)
        self.assertFalse(composer_marker.exists())
        self.assertTrue(
            any(
                result["gate"] == "Build"
                and result["technology"] == "PHP/Laravel"
                and result["status"] == "SKIP"
                and "No PHP/Laravel-relevant files changed" in result["message"]
                for result in report_json["results"]
            )
        )
        self.assertTrue(
            any(
                result["gate"] == "Build"
                and result["technology"] == "GitHub Actions"
                and result["status"] == "PASS"
                for result in report_json["results"]
            )
        )

    def test_framework_profile_allows_reviewed_governance_workflow_changes(self) -> None:
        repo, base = self.init_repo("framework-governance-workflow", profile="framework")
        self.write(
            repo / ".github" / "workflows" / "synergie-production-gate.yml",
            """
name: Synergie Production Gate
on:
  workflow_call:
jobs:
  production-policy:
    runs-on: ubuntu-latest
    steps:
      - run: echo production policy check
""",
        )
        self.commit(repo, "ci: add central production governance workflow")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0, report)
        self.assertTrue(
            any(
                result["gate"] == "Deployment Risk"
                and result["status"] == "WARNING"
                and "Approved central governance workflow/template changes" in result["message"]
                for result in report_json["results"]
            )
        )

    def test_application_profile_does_not_inherit_framework_workflow_exemption(self) -> None:
        repo, base = self.init_repo("application-production-workflow")
        self.write(
            repo / ".github" / "workflows" / "production-deploy.yml",
            """
name: Production Deploy
on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ssh deployer@production.example.invalid ./deploy-production.sh
""",
        )
        self.commit(repo, "ci: add production deploy workflow")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0, report)
        self.assertNotIn("Approved central governance workflow/template changes", report)
        self.assertTrue(
            any(
                result["gate"] == "Deployment Risk"
                and result["status"] == "WARNING"
                and "Deployment-sensitive changes detected" in result["message"]
                for result in report_json["results"]
            )
        )

    def test_workflow_has_no_framework_override_or_checkout_credentials(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "pr-qa.yml").read_text(encoding="utf-8")
        caller = (ROOT / "examples" / "caller-workflow.yml").read_text(encoding="utf-8")
        self.assertNotIn("framework-ref", workflow + caller)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("@pr-qa-v1-rc2", caller)
        self.assertIn("resolve_node_version.py", workflow)
        self.assertIn("opentofu/setup-opentofu@v1", workflow)
        self.assertIn("tfsec_${TFSEC_VERSION}_linux_amd64.tar.gz", workflow)

    def test_node_version_resolver_honors_supported_engine_major(self) -> None:
        repo = self.tmp / "node-version-24"
        repo.mkdir()
        self.write(
            repo / "package.json",
            json.dumps({"engines": {"node": "^24.3.0 || >=26.0.0"}}),
        )

        completed = subprocess.run(["python3", str(NODE_RESOLVER), str(repo)], text=True, capture_output=True, check=False)

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), "node-version=24")

    def test_node_version_resolver_preserves_default_without_engine(self) -> None:
        repo = self.tmp / "node-version-default"
        repo.mkdir()
        self.write(repo / "package.json", json.dumps({"dependencies": {}}))

        completed = subprocess.run(["python3", str(NODE_RESOLVER), str(repo)], text=True, capture_output=True, check=False)

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), "node-version=20")

    def test_terraform_adapter_uses_opentofu_without_apply(self) -> None:
        tofu_log = self.tmp / "tofu.log"
        fake_tofu = self.bin / "tofu"
        fake_tofu.write_text(
            f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> {tofu_log}
if printf '%s\\n' "$*" | grep -q 'apply'; then
  exit 99
fi
exit 0
""",
            encoding="utf-8",
        )
        fake_tofu.chmod(0o755)
        fake_tfsec = self.bin / "tfsec"
        fake_tfsec.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        fake_tfsec.chmod(0o755)

        repo, base = self.init_repo("opentofu-validation")
        self.write(repo / "aws" / "main.tf", 'terraform {\n  required_version = ">= 1.6.0"\n}\n')
        self.commit(repo, "feat: add infrastructure skeleton")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base)
        commands = tofu_log.read_text(encoding="utf-8")

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Build"], "PASS")
        self.assertIn("fmt -check -recursive", commands)
        self.assertIn("init -input=false -no-color -backend=false", commands)
        self.assertIn("validate -no-color", commands)
        self.assertNotIn("apply", commands)

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

    def test_emergency_override_records_saurabh_author_exception(self) -> None:
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
        self.assertFalse(audit["administrator_bypass_required"])
        self.assertTrue(audit["saurabh_author_exception"])
        self.assertFalse(audit["self_approval_allowed"])
        self.assertTrue(audit["self_merge_authorized"])
        self.assertEqual(audit["decision"], "SAURABH_AUTHOR_EXCEPTION_RECORDED")
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

    def write_bytes(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

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
