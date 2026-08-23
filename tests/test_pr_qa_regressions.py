from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "pr-qa" / "pr_qa.py"
NODE_RESOLVER = ROOT / "pr-qa" / "resolve_node_version.py"
PHP_RESOLVER = ROOT / "pr-qa" / "resolve_php_version.py"


def load_engine_module():
    spec = importlib.util.spec_from_file_location("pr_qa_engine", ENGINE)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.path.insert(0, str(ENGINE.parent))
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrQaRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="prqa-regression-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        fake_gitleaks = self.bin / "gitleaks"
        fake_gitleaks.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        fake_gitleaks.chmod(0o755)
        self.env = dict(os.environ)
        for key in ["GITHUB_REPOSITORY", "GITHUB_WORKSPACE", "GITHUB_ACTOR", "GITHUB_TRIGGERING_ACTOR"]:
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

    def init_repo_with_migration_protection(self, name: str) -> tuple[Path, str]:
        repo = self.tmp / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "qa@example.invalid")
        self.git(repo, "config", "user.name", "QA Regression")
        self.write(
            repo / ".github" / "pr-qa.yml",
            """version: 1
repository:
  profile: application
  criticality: medium
  protected_paths:
    - .github/**
    - apps/api/alembic/**
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
""",
        )
        self.write(repo / ".github" / "CODEOWNERS", ".github/** @Synergie-ITCI/saurabh-pr-review-bypass\n")
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
        head_sha: str = "HEAD",
        actor: str = "",
        pr_author: str = "SaurabhVermaIN",
        override_reason: str = "",
        review_policy: dict | None = None,
        policy_path: Path | None = None,
        repository: str = "",
        baseline_alignment: bool = False,
        body_extra: str = "",
        event_labels: list[str] | None = None,
        body_override: str | None = None,
        pr_number: int = 123,
        extra_args: list[str] | None = None,
    ) -> tuple[int, str, dict, Path]:
        event = repo / "event.json"
        labels = [{"name": label} for label in (event_labels or [])]
        body = (
            "## Business Purpose\nRegression test.\n"
            "## Testing Performed\nLocal automated regression.\n"
            "## Rollback Strategy\nRevert this PR.\n"
            "## Linked Issue\nhttps://github.com/Synergie-ITCI/.github/issues/123\n"
            "## Screenshots\nN/A\n"
            f"{body_extra}"
        )
        event.write_text(
            json.dumps(
                {
                    "pull_request": {
                        "number": pr_number,
                        "user": {"login": pr_author},
                        "base": {"sha": base, "ref": base_ref},
                        "head": {"sha": head_sha, "ref": head_ref},
                        "labels": labels,
                        "body": body_override if body_override is not None else body,
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
        if policy_path is not None:
            args.extend(["--policy", str(policy_path)])
        if static_only:
            args.append("--static-only")
        if review_policy is not None:
            review_policy_input.write_text(json.dumps(review_policy), encoding="utf-8")
            args.extend(["--review-policy-input", str(review_policy_input)])
        if extra_args:
            args.extend(extra_args)
        env = dict(self.env)
        env["GITHUB_WORKSPACE"] = str(repo)
        if repository:
            env["GITHUB_REPOSITORY"] = repository
        if baseline_alignment:
            env["PR_QA_BASELINE_ALIGNMENT"] = "true"
        if actor:
            env["GITHUB_ACTOR"] = actor
        if override_reason:
            args.extend(["--emergency-override-reason", override_reason, "--emergency-override-out", str(audit)])
        completed = subprocess.run(args, text=True, capture_output=True, env=env, check=False)
        report_text = report.read_text(encoding="utf-8") if report.exists() else completed.stdout
        parsed_json = json.loads(json_report.read_text(encoding="utf-8")) if json_report.exists() else {}
        return completed.returncode, report_text, parsed_json, audit

    def test_staging_base_reports_developer_handoff_ready_from_overall_result(self) -> None:
        repo, base = self.init_repo("staging-handoff-ready")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="staging",
            head_ref="development",
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["overall_result"], "PASS")
        self.assertEqual(report_json["summary"]["developer_handoff_ready"], "YES")
        self.assertIn("DEVELOPER_HANDOFF_READY: YES", report)

    def test_staging_base_reports_developer_handoff_not_ready_when_qa_fails(self) -> None:
        repo, base = self.init_repo("staging-handoff-blocked")
        self.write(repo / ".env", "APP_TOKEN=placeholder\n")
        self.git(repo, "add", ".env")
        self.git(repo, "commit", "-q", "-m", "test: add unsafe env file")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="staging",
            head_ref="development",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["overall_result"], "FAIL")
        self.assertEqual(report_json["summary"]["developer_handoff_ready"], "NO")
        self.assertIn("DEVELOPER_HANDOFF_READY: NO", report)

    def test_technical_pass_persists_and_reuses_after_evidence_only_fix(self) -> None:
        repo, base = self.init_repo("technical-baseline-reuse")
        self.write(repo / "app.py", "def answer():\n    return 42\n")
        self.write(repo / "tests" / "test_app.py", "from app import answer\n\n\ndef test_answer():\n    assert answer() == 42\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "feat: add app code")

        baseline = repo / ".pr-qa-technical-baseline" / "technical-baseline.json"
        packet = repo / "qa-packet.json"
        bad_body = (
            "## Business Purpose\nRegression test.\n"
            "## Testing Performed\nLocal automated regression.\n"
            "## Rollback Strategy\nRevert this PR.\n"
            "## Linked Issue\nTBD\n"
        )
        code, _, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            body_override=bad_body,
            extra_args=[
                "--no-command-runs",
                "--technical-baseline-out",
                str(baseline),
                "--qa-packet-out",
                str(packet),
            ],
        )
        self.assertEqual(code, 0)
        self.assertTrue(baseline.exists())
        persisted = json.loads(baseline.read_text(encoding="utf-8"))
        self.assertEqual(persisted["status"], "PASS")
        self.assertEqual(report_json["summary"]["technical_baseline"]["status"], "CREATED")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Evidence"], "WARNING")

        packet_reuse = repo / "qa-packet-reuse.json"
        code, _, reused_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=[
                "--no-command-runs",
                "--technical-baseline-in",
                str(baseline),
                "--qa-packet-out",
                str(packet_reuse),
            ],
        )
        self.assertEqual(code, 0)
        self.assertEqual(reused_json["summary"]["technical_baseline"]["status"], "REUSED")
        commands = "\n".join(item["command"] for item in reused_json["commands"])
        self.assertNotIn("compileall", commands)
        self.assertNotIn("pytest", commands)
        self.assertNotIn("pip_audit", commands)
        self.assertTrue(packet_reuse.exists())
        qa_packet = json.loads(packet_reuse.read_text(encoding="utf-8"))
        self.assertTrue(qa_packet["technical_validation"]["reused"])
        self.assertEqual(qa_packet["current_evidence"]["gate_statuses"]["Evidence"], "PASS")

    def test_technical_baseline_invalidates_on_content_or_policy_change(self) -> None:
        repo, base = self.init_repo("technical-baseline-invalidates")
        self.write(repo / "app.py", "def answer():\n    return 42\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "feat: add app code")
        baseline = repo / ".pr-qa-technical-baseline" / "technical-baseline.json"
        code, _, _, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs", "--technical-baseline-out", str(baseline)],
        )
        self.assertEqual(code, 0)
        original_head = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.write(repo / "app.py", "def answer():\n    return 43\n")
        self.git(repo, "add", "app.py")
        self.git(repo, "commit", "-q", "-m", "fix: change app code")
        code, _, content_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs", "--technical-baseline-in", str(baseline)],
        )
        self.assertEqual(code, 0)
        self.assertEqual(content_json["summary"]["technical_baseline"]["status"], "NONE")
        self.assertTrue(content_json["summary"]["technical_baseline"]["reuse_details"])

        policy = json.loads((ROOT / "policy" / "pr-qa-policy.json").read_text(encoding="utf-8"))
        policy["policy_id"] = "changed-policy-for-regression"
        policy_path = repo / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        self.git(repo, "checkout", "-q", "-B", "feature/regression", original_head)
        code, _, policy_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            policy_path=policy_path,
            extra_args=["--no-command-runs", "--technical-baseline-in", str(baseline)],
        )
        self.assertEqual(code, 0)
        self.assertEqual(policy_json["summary"]["technical_baseline"]["status"], "NONE")
        self.assertTrue(policy_json["summary"]["technical_baseline"]["reuse_details"])

    def test_technical_fail_and_cross_repo_baselines_are_rejected(self) -> None:
        repo, base = self.init_repo("technical-baseline-rejects")
        self.write(repo / "app.py", "def answer():\n    return 42\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "feat: add app code")
        baseline = repo / ".pr-qa-technical-baseline" / "technical-baseline.json"
        code, _, _, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs", "--technical-baseline-out", str(baseline)],
        )
        self.assertEqual(code, 0)

        failed_baseline = json.loads(baseline.read_text(encoding="utf-8"))
        failed_baseline["status"] = "FAIL"
        failed_path = repo / "failed-baseline.json"
        failed_path.write_text(json.dumps(failed_baseline), encoding="utf-8")
        code, _, failed_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs", "--technical-baseline-in", str(failed_path)],
        )
        self.assertEqual(code, 0)
        self.assertEqual(failed_json["summary"]["technical_baseline"]["status"], "NONE")
        self.assertIn("PASS status", "\n".join(failed_json["summary"]["technical_baseline"]["reuse_details"]))

        cross_repo = json.loads(baseline.read_text(encoding="utf-8"))
        cross_repo["binding"]["repository"] = "Synergie-ITCI/other"
        cross_repo_path = repo / "cross-repo-baseline.json"
        cross_repo_path.write_text(json.dumps(cross_repo), encoding="utf-8")
        code, _, cross_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs", "--technical-baseline-in", str(cross_repo_path)],
        )
        self.assertEqual(code, 0)
        self.assertEqual(cross_json["summary"]["technical_baseline"]["status"], "NONE")
        self.assertIn("repository", "\n".join(cross_json["summary"]["technical_baseline"]["reuse_details"]))

    def baseline_policy_for(
        self,
        *,
        base_sha: str,
        head_sha: str,
        enabled: bool = True,
        expires_after: str = "2099-12-31T23:59:59Z",
        minimum_changed_files: int = 1,
        gitleaks_allowlist: list[dict] | None = None,
    ) -> Path:
        policy = json.loads((ROOT / "policy" / "pr-qa-policy.json").read_text(encoding="utf-8"))
        policy["one_time_baseline_alignment"] = {
            "enabled": enabled,
            "repository": "Synergie-ITCI/telemedicine-backend",
            "base_ref": "main",
            "head_ref": "release/production-baseline-alignment-20260812",
            "expected_base_sha": base_sha,
            "expected_head_sha": head_sha,
            "expires_after": expires_after,
            "minimum_changed_files": minimum_changed_files,
            "required_pr_body_marker": "ONE-TIME TELEMEDICINE PRODUCTION BASELINE AUTHORIZATION",
            "relaxations": [
                "diff_size",
                "changed_file_count",
                "historical_commit_volume",
                "historical_migration_count",
                "generated_static_baseline_content",
                "baseline_binary_assets",
                "environment_fixture_classification",
                "exact_gitleaks_fingerprint_allowlist",
                "exact_secret_fallback_allowlist",
            ],
            "environment_files": {
                "safe_paths": [".env.testing"],
                "required_markers_by_path": {
                    ".env.testing": [
                        "APP_ENV=testing",
                        "APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    ]
                },
                "forbidden_patterns": [
                    "AKIA[0-9A-Z]{16}",
                    "gh[pousr]_[A-Za-z0-9_]{30,}",
                    "(?im)^(DB_PASSWORD|JWT_SECRET)\\s*=\\s*['\\\" ]*(?!$|null$|<required_|\\$\\{|base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=)[^#\\s>]+",
                ],
            },
            "binary_assets": {"safe_paths": ["baseline.docx"], "max_file_bytes": 1024},
            "fallback_secret_allowlist": [],
            "gitleaks_allowlist": gitleaks_allowlist or [],
        }
        path = self.tmp / f"policy-{head_sha[:8]}.json"
        path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
        return path

    def source_overlay_policy_from_base(
        self,
        *,
        base_policy: Path,
        base_sha: str,
        source_sha: str,
        allowed_paths: list[str] | None = None,
    ) -> Path:
        data = json.loads(base_policy.read_text(encoding="utf-8"))
        data["one_time_baseline_alignment"]["expected_base_sha"] = base_sha
        data["one_time_baseline_alignment"]["expected_head_sha"] = source_sha
        data["one_time_baseline_alignment"]["source_overlay"] = {
            "approved_application_source_sha": source_sha,
            "allowed_paths": allowed_paths or [
                ".github/CODEOWNERS",
                ".github/actionlint.yaml",
                ".github/workflows/pr-qa.yml",
            ],
            "paths": {
                ".github/CODEOWNERS": {"source": "absent", "candidate": "base"},
                ".github/actionlint.yaml": {"source": "present", "candidate": "base"},
                ".github/workflows/pr-qa.yml": {
                    "source": "absent",
                    "old_ref": "pr-qa-v1-rc5",
                    "new_ref": "pr-qa-v1-rc13",
                    "uses": "Synergie-ITCI/.github/.github/workflows/pr-qa.yml",
                },
            },
        }
        data["one_time_baseline_alignment"]["environment_files"]["safe_paths"] = sorted(
            set(data["one_time_baseline_alignment"]["environment_files"].get("safe_paths", []))
            | {".env.testing.example", ".env.uat.template"}
        )
        data["one_time_baseline_alignment"]["environment_files"]["required_markers_by_path"].update(
            {
                ".env.testing.example": [
                    "APP_ENV=testing",
                    "APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "HEALTH_WORKER_GOOGLE_ROUTES_API_KEY=",
                ],
                ".env.uat.template": [
                    "Placeholder-only. Do not commit real UAT secrets.",
                    "APP_KEY=<required_laravel_app_key>",
                    "JWT_SECRET=<required_jwt_secret>",
                ],
            }
        )
        data["one_time_baseline_alignment"]["fallback_secret_inherited_false_positive_paths"] = [
            "public/assest/plugins/codemirror/**",
            "tests/Feature/InheritedFixturePasswordTest.php",
        ]
        data["one_time_baseline_alignment"]["fallback_secret_inherited_false_positive_labels"] = [
            "generic credential assignment"
        ]
        path = self.tmp / f"policy-source-overlay-{source_sha[:8]}.json"
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    def baseline_overlay_policy_for(
        self,
        *,
        base_sha: str,
        source_sha: str,
        new_ref: str = "pr-qa-v1-rc13",
        enabled: bool = True,
        expires_after: str = "2099-12-31T23:59:59Z",
    ) -> Path:
        policy = self.baseline_policy_for(
            base_sha=base_sha,
            head_sha=source_sha,
            enabled=enabled,
            expires_after=expires_after,
            minimum_changed_files=1,
        )
        data = json.loads(policy.read_text(encoding="utf-8"))
        data["one_time_baseline_alignment"]["source_overlay"] = {
            "approved_application_source_sha": source_sha,
            "allowed_paths": [
                ".github/CODEOWNERS",
                ".github/actionlint.yaml",
                ".github/workflows/pr-qa.yml",
            ],
            "paths": {
                ".github/CODEOWNERS": {"source": "absent", "candidate": "base"},
                ".github/actionlint.yaml": {"source": "present", "candidate": "base"},
                ".github/workflows/pr-qa.yml": {
                    "source": "absent",
                    "old_ref": "pr-qa-v1-rc5",
                    "new_ref": new_ref,
                    "uses": "Synergie-ITCI/.github/.github/workflows/pr-qa.yml",
                },
            },
        }
        path = self.tmp / f"policy-overlay-{source_sha[:8]}.json"
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    def branch_alignment_policy_for(
        self,
        *,
        base_sha: str,
        head_sha: str,
        merge_sha: str,
        target_sha: str,
        source_branch: str = "chore/align-main-into-development",
        target_branch: str = "development",
        expires_after: str = "2099-12-31T23:59:59Z",
    ) -> Path:
        policy = self.baseline_overlay_policy_for(base_sha=base_sha, source_sha=target_sha, new_ref="pr-qa-v1-rc24")
        data = json.loads(policy.read_text(encoding="utf-8"))
        baseline = data["one_time_baseline_alignment"]
        data["one_time_branch_alignment"] = {
            **baseline,
            "enabled": True,
            "base_ref": target_branch,
            "head_ref": source_branch,
            "expected_base_sha": base_sha,
            "expected_head_sha": head_sha,
            "approved_target_tree_sha": target_sha,
            "expected_merge_commit_sha": merge_sha,
            "expected_merge_first_parent_sha": base_sha,
            "expected_merge_second_parent_sha": target_sha,
            "expires_after": expires_after,
            "minimum_changed_files": 1,
            "required_pr_body_marker": "ONE-TIME TELEMEDICINE BRANCH ANCESTRY ALIGNMENT AUTHORIZATION",
        }
        data["one_time_branch_alignment"]["source_overlay"] = {
            "approved_application_source_sha": target_sha,
            "allowed_paths": [
                ".github/workflows/pr-qa.yml",
            ],
            "paths": {
                ".github/workflows/pr-qa.yml": {
                    "source": "present",
                    "old_ref": "pr-qa-v1-rc13",
                    "new_ref": "pr-qa-v1-rc24",
                    "uses": "Synergie-ITCI/.github/.github/workflows/pr-qa.yml",
                },
            },
        }
        path = self.tmp / f"policy-branch-alignment-{head_sha[:8]}.json"
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    def init_telemedicine_overlay_repo(self, name: str = "telemedicine-source-overlay") -> tuple[Path, str, str]:
        repo = self.tmp / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "qa@example.invalid")
        self.git(repo, "config", "user.name", "QA Regression")
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n")
        self.write(repo / ".github" / "actionlint.yaml", "self-hosted-runner:\n  labels:\n    - fleetos-uat\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review, edited]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc5\n",
        )
        self.write(repo / "README.md", "# old governance shell\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: governance shell")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.git(repo, "checkout", "-q", "-b", "staging-source")
        self.git(repo, "rm", "-q", ".github/CODEOWNERS", ".github/workflows/pr-qa.yml")
        (repo / "README.md").unlink()
        self.write(repo / ".github" / "actionlint.yaml", "self-hosted-runner:\n  labels:\n    - fleetos-uat\n")
        self.write(repo / "app" / "Http" / "Controllers" / "BaselineController.php", "<?php\nclass BaselineController {}\n")
        self.write(repo / "routes" / "api.php", "<?php\nRoute::get('/baseline', fn () => 'ok');\n")
        self.write(repo / "composer.json", json.dumps({"require": {}, "scripts": {"test": "echo ok"}}))
        self.write(repo / "composer.lock", json.dumps({"packages": [], "packages-dev": []}))
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: staging application source")
        source = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.git(repo, "checkout", "-q", "-b", "release/production-baseline-alignment-20260812")
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review, edited]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n",
        )
        self.git(repo, "add", ".github")
        self.git(repo, "commit", "-q", "-m", "ci: apply governed baseline overlay")
        return repo, base, source

    def init_inherited_content_repo(self, name: str = "telemedicine-inherited-content") -> tuple[Path, str, str]:
        repo, base, _ = self.init_telemedicine_overlay_repo(name)
        self.git(repo, "checkout", "-q", "staging-source")
        self.write(repo / ".env.testing.example", "APP_ENV=testing\nAPP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nHEALTH_WORKER_GOOGLE_ROUTES_API_KEY=\n")
        self.write(repo / ".env.uat.template", "Placeholder-only. Do not commit real UAT secrets.\nAPP_KEY=<required_laravel_app_key>\nJWT_SECRET=<required_jwt_secret>\n")
        self.write(repo / ".github" / "workflows" / "deploy.yml", "name: Deploy\non: workflow_dispatch\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo production deploy review only\n")
        self.write(repo / "public" / "assest" / "plugins" / "bootstrap-slider" / "bootstrap-slider.js", "<<<<<<< not-a-real-conflict-in-vendored-fixture\n")
        self.write(repo / "app" / "LegacyWhitespace.php", "<?php\nclass LegacyWhitespace {    \n}\n")
        self.write(repo / "public" / "assest" / "plugins" / "codemirror" / "mode" / "factor" / "factor.js", "const token = \"not-a-live-secret-static-language-fixture\";\n")
        self.write(repo / "tests" / "Feature" / "InheritedFixturePasswordTest.php", "<?php\nconst PASSWORD = 'TelepathyReference#2026';\n")
        self.write_bytes(repo / "public" / "assest" / "plugins" / "fontawesome-free" / "webfonts" / "fa-solid-900.woff2", b"\x00font-fixture")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "legacy inherited content import")
        source = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.git(repo, "checkout", "-q", "-B", "release/production-baseline-alignment-20260812")
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review, edited]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n",
        )
        self.git(repo, "add", ".github")
        self.git(repo, "commit", "-q", "-m", "ci: apply governed baseline overlay")
        return repo, base, source

    def baseline_marker(self) -> str:
        return "\nONE-TIME TELEMEDICINE PRODUCTION BASELINE AUTHORIZATION\n"

    def branch_alignment_marker(self) -> str:
        return "\nONE-TIME TELEMEDICINE BRANCH ANCESTRY ALIGNMENT AUTHORIZATION\n"

    def programme_platform_marker(self) -> str:
        return "\nONE-TIME PROGRAMME PLATFORM DEVELOPMENT TO STAGING BASELINE AUTHORIZATION\n"

    def programme_platform_policy_for(
        self,
        *,
        base_sha: str,
        head_sha: str,
        base_ref: str = "staging",
        head_ref: str = "development",
        repository: str = "Synergie-ITCI/programme-management-platform",
        expires_after: str = "2099-12-31T23:59:59Z",
    ) -> Path:
        policy = json.loads((ROOT / "policy" / "pr-qa-policy.json").read_text(encoding="utf-8"))
        policy["one_time_baseline_alignment"] = {
            "enabled": True,
            "repository": repository,
            "base_ref": base_ref,
            "head_ref": head_ref,
            "expected_base_sha": base_sha,
            "expected_head_sha": head_sha,
            "expires_after": expires_after,
            "minimum_changed_files": 1,
            "required_pr_body_marker": "ONE-TIME PROGRAMME PLATFORM DEVELOPMENT TO STAGING BASELINE AUTHORIZATION",
            "relaxations": [
                "diff_size",
                "changed_file_count",
                "historical_branch_name",
                "historical_commit_volume",
                "historical_migration_count",
                "historical_protected_resources",
            ],
        }
        path = self.tmp / f"programme-platform-policy-{head_sha[:8]}.json"
        path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
        return path

    def install_fake_composer(self, *, audit_exit: int = 0, test_exit: int = 0) -> None:
        fake_composer = self.bin / "composer"
        fake_composer.write_text(
            f"""#!/usr/bin/env bash
case "$1" in
  install|validate|licenses)
    exit 0
    ;;
  audit)
    echo '{{"advisories":{{"demo/package":[{{"title":"Demo advisory"}}]}}}}'
    exit {audit_exit}
    ;;
  run)
    exit {test_exit}
    ;;
  *)
    exit 0
    ;;
esac
""",
            encoding="utf-8",
        )
        fake_composer.chmod(0o755)

    def install_fake_gitleaks_report(self, findings: list[dict]) -> None:
        fake_gitleaks = self.bin / "gitleaks"
        payload = json.dumps(findings)
        fake_gitleaks.write_text(
            f"""#!/usr/bin/env bash
report=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then
    report="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$(dirname "$report")"
printf '%s\n' '{payload}' > "$report"
exit 1
""",
            encoding="utf-8",
        )
        fake_gitleaks.chmod(0o755)

    def install_fake_gitleaks_asserting_log_opts(self, expected: str) -> None:
        fake_gitleaks = self.bin / "gitleaks"
        fake_gitleaks.write_text(
            f"""#!/usr/bin/env bash
args="$*"
case "$args" in
  *"--log-opts {expected}"*)
    exit 0
    ;;
  *)
    echo "missing expected log opts: {expected}" >&2
    echo "$args" >&2
    exit 1
    ;;
esac
""",
            encoding="utf-8",
        )
        fake_gitleaks.chmod(0o755)

    def install_fake_gitleaks_asserting_content_delta_scan(self) -> None:
        fake_gitleaks = self.bin / "gitleaks"
        fake_gitleaks.write_text(
            """#!/usr/bin/env bash
args="$*"
case "$args" in
  *"--no-git"* )
    ;;
  *)
    echo "missing --no-git content scan mode" >&2
    echo "$args" >&2
    exit 1
    ;;
esac
case "$args" in
  *"--log-opts"* )
    echo "unexpected history log opts for canonical promotion content scan" >&2
    echo "$args" >&2
    exit 1
    ;;
esac
exit 0
""",
            encoding="utf-8",
        )
        fake_gitleaks.chmod(0o755)

    def test_saurabh_authored_pr_allows_green_without_independent_review(self) -> None:
        repo, base = self.init_repo("saurabh-no-review-green")
        self.write(repo / "README.md", "# regression\n\nSaurabh-authored governance correction.\n")
        self.commit(repo, "docs: update regression readme")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="staging",
            pr_author="SaurabhVermaIN",
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "PASS")
        self.assertTrue(any("SaurabhVermaIN is exempt from independent human review for Gate C" in result["message"] for result in report_json["results"]))

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
            base_ref="main",
            head_ref="staging",
            pr_author="SaurabhVermaIN",
            review_policy={"mergeable": False, "merge_conflict": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "FAIL")
        self.assertIn("Pull request has merge conflicts", report)

    def test_feature_to_development_requires_no_human_review(self) -> None:
        repo, base = self.init_repo("feature-development-no-review")
        self.write(repo / "README.md", "# regression\n\nFeature to development.\n")
        self.commit(repo, "docs: update feature fixture")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="development",
            head_ref="feature/regression",
            pr_author="dev.raveesh.yadav",
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "PASS")
        self.assertTrue(any("Human review is not required for this branch transition" in result["message"] for result in report_json["results"]))

    def test_development_to_staging_requires_no_human_review(self) -> None:
        repo, base = self.init_repo("development-staging-no-review")
        self.write(repo / "README.md", "# regression\n\nDevelopment to staging.\n")
        self.commit(repo, "docs: update staging fixture")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="staging",
            head_ref="development",
            pr_author="dev.raveesh.yadav",
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "PASS")
        self.assertTrue(any("Human review is not required for this branch transition" in result["message"] for result in report_json["results"]))

    def test_feature_pr_still_blocks_accidental_merge_commit(self) -> None:
        repo, base = self.init_repo("feature-merge-commit")
        self.write(repo / "feature.txt", "feature change\n")
        self.commit(repo, "feat: add feature change")
        self.git(repo, "checkout", "-q", "-b", "feature/side-branch", base)
        self.write(repo / "side.txt", "side change\n")
        self.commit(repo, "feat: add side change")
        self.git(repo, "checkout", "-q", "feature/regression")
        self.git(repo, "merge", "--no-ff", "-m", "Merge side branch", "feature/side-branch")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_tree_neutral_ancestry_merge_commit_is_allowed(self) -> None:
        repo, base = self.init_repo("tree-neutral-ancestry-merge")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "staging-lineage.txt", "historical staging lineage\n")
        self.commit(repo, "chore: preserve staging lineage")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.attach_origin_with_staging(repo, "tree-neutral-origin.git")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        development_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "chore/resolve-pr82-prqa-conflict", "development")
        self.git(repo, "merge", "--no-ff", "-s", "ours", "-m", "chore: record staging ancestry", "staging")
        merge_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.assertEqual(self.git(repo, "show", "-s", "--format=%P", merge_sha).stdout.count(" "), 1)
        self.assertEqual(self.git(repo, "diff", "--name-only", f"{merge_sha}^1..{merge_sha}").stdout.strip(), "")
        self.assertEqual(self.git(repo, "show", "-s", "--format=%P", merge_sha).stdout.split()[1], staging_sha)
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            development_sha,
            static_only=True,
            base_ref="development",
            head_ref="chore/resolve-pr82-prqa-conflict",
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "PASS")
        self.assertTrue(
            any(
                result["gate"] == "Repository Hygiene"
                and result["message"] == "Only intentional tree-neutral ancestry reconciliation merge commits detected."
                for result in report_json["results"]
            )
        )

    def test_tree_neutral_ancestry_merge_blocks_arbitrary_second_parent(self) -> None:
        repo, base = self.init_repo("tree-neutral-arbitrary-second-parent")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "staging-lineage.txt", "expected staging lineage\n")
        self.commit(repo, "chore: preserve staging lineage")
        self.attach_origin_with_staging(repo, "tree-neutral-arbitrary-origin.git")
        self.git(repo, "checkout", "-q", "-b", "unrelated-lineage", base)
        self.write(repo / "unrelated.txt", "unrelated second-parent lineage\n")
        self.commit(repo, "chore: preserve unrelated lineage")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        development_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "chore/resolve-pr82-prqa-conflict", "development")
        self.git(repo, "merge", "--no-ff", "-s", "ours", "-m", "chore: record unrelated ancestry", "unrelated-lineage")
        merge_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.assertEqual(self.git(repo, "diff", "--name-only", f"{merge_sha}^1..{merge_sha}").stdout.strip(), "")
        self.assertNotEqual(self.git(repo, "show", "-s", "--format=%P", merge_sha).stdout.split()[1], self.git(repo, "rev-parse", "origin/staging").stdout.strip())
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            development_sha,
            static_only=True,
            base_ref="development",
            head_ref="chore/resolve-pr82-prqa-conflict",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_tree_neutral_ancestry_merge_blocks_stale_staging_parent(self) -> None:
        repo, base = self.init_repo("tree-neutral-stale-staging")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "staging-lineage.txt", "old staging lineage\n")
        self.commit(repo, "chore: preserve old staging lineage")
        old_staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.attach_origin_with_staging(repo, "tree-neutral-stale-origin.git")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        development_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "chore/resolve-pr82-prqa-conflict", "development")
        self.git(repo, "merge", "--no-ff", "-s", "ours", "-m", "chore: record stale staging ancestry", "staging")
        merge_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "staging")
        self.write(repo / "new-staging-tip.txt", "new staging lineage\n")
        self.commit(repo, "chore: advance staging lineage")
        self.git(repo, "push", "-q", "origin", "staging")
        self.git(repo, "checkout", "-q", "chore/resolve-pr82-prqa-conflict")

        self.assertEqual(self.git(repo, "show", "-s", "--format=%P", merge_sha).stdout.split()[1], old_staging_sha)
        self.assertNotEqual(old_staging_sha, self.git(repo, "rev-parse", "origin/staging").stdout.strip())
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            development_sha,
            static_only=True,
            base_ref="development",
            head_ref="chore/resolve-pr82-prqa-conflict",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_tree_neutral_ancestry_merge_fails_closed_without_staging_ref(self) -> None:
        repo, base = self.init_repo("tree-neutral-no-staging-ref")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "staging-lineage.txt", "local staging lineage only\n")
        self.commit(repo, "chore: preserve local staging lineage")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        development_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "chore/resolve-pr82-prqa-conflict", "development")
        self.git(repo, "merge", "--no-ff", "-s", "ours", "-m", "chore: record local staging ancestry", "staging")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            development_sha,
            static_only=True,
            base_ref="development",
            head_ref="chore/resolve-pr82-prqa-conflict",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_main_to_staging_alignment_allows_current_gate_c_merge(self) -> None:
        repo, base = self.init_repo("main-staging-gate-c-alignment")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add reviewed staging content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge reviewed staging Gate C", "staging")
        gate_c_sha = self.git(repo, "rev-parse", "main").stdout.strip()
        self.attach_origin_with_main_and_staging(repo, "main-staging-gate-c-origin.git")

        self.assertEqual(self.git(repo, "diff", "--name-only", f"{gate_c_sha}^2..{gate_c_sha}").stdout.strip(), "")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="main",
            head_sha=gate_c_sha,
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "PASS")
        self.assertTrue(
            any(
                result["gate"] == "Repository Hygiene"
                and result["message"] == "Only expected Gate C main-to-staging alignment merge commits detected."
                for result in report_json["results"]
            )
        )

    def test_temp_branch_to_staging_alignment_allows_current_main_gate_c_merge(self) -> None:
        repo, base = self.init_repo("temp-main-staging-gate-c-alignment")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add reviewed staging content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge reviewed staging Gate C", "staging")
        main_sha = self.git(repo, "rev-parse", "main").stdout.strip()
        self.attach_origin_with_main_and_staging(repo, "temp-main-staging-gate-c-origin.git")
        self.git(repo, "checkout", "-q", "-b", "chore/align-main-into-staging", "staging")
        self.git(repo, "merge", "--no-ff", "-m", "chore: align main into staging", "main")
        alignment_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.assertEqual(self.git(repo, "show", "-s", "--format=%P", alignment_sha).stdout.split()[1], main_sha)
        self.assertEqual(self.git(repo, "diff", "--name-only", f"{alignment_sha}^1..{alignment_sha}").stdout.strip(), "")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-main-into-staging",
            head_sha=alignment_sha,
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "PASS")

    def test_main_to_staging_alignment_blocks_content_changing_gate_c_merge(self) -> None:
        repo, base = self.init_repo("main-staging-content-changing-gate-c")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add reviewed staging content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.write(repo / "main-only.txt", "unexpected main content\n")
        self.commit(repo, "feat: add unexpected main content")
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge reviewed staging Gate C", "staging")
        gate_c_sha = self.git(repo, "rev-parse", "main").stdout.strip()
        self.attach_origin_with_main_and_staging(repo, "main-staging-content-changing-origin.git")

        self.assertNotEqual(self.git(repo, "diff", "--name-only", f"{gate_c_sha}^2..{gate_c_sha}").stdout.strip(), "")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="main",
            head_sha=gate_c_sha,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_temp_branch_to_staging_alignment_blocks_content_change(self) -> None:
        repo, base = self.init_repo("temp-main-staging-content-change")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add reviewed staging content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge reviewed staging Gate C", "staging")
        self.attach_origin_with_main_and_staging(repo, "temp-main-staging-content-change-origin.git")
        self.git(repo, "checkout", "-q", "-b", "chore/align-main-into-staging", "staging")
        self.git(repo, "merge", "--no-ff", "--no-commit", "main")
        self.write(repo / "unexpected.txt", "unexpected alignment content\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: align main into staging")
        alignment_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.assertNotEqual(self.git(repo, "diff", "--name-only", f"{alignment_sha}^1..{alignment_sha}").stdout.strip(), "")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-main-into-staging",
            head_sha=alignment_sha,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_main_to_staging_alignment_blocks_unrelated_second_parent(self) -> None:
        repo, base = self.init_repo("main-staging-unrelated-second-parent")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add reviewed staging content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "unrelated", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add unrelated matching content")
        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge unrelated branch", "unrelated")
        main_sha = self.git(repo, "rev-parse", "main").stdout.strip()
        self.attach_origin_with_main_and_staging(repo, "main-staging-unrelated-origin.git")

        self.assertEqual(self.git(repo, "diff", "--name-only", f"{main_sha}^2..{main_sha}").stdout.strip(), "")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="main",
            head_sha=main_sha,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_temp_branch_to_staging_alignment_blocks_unrelated_second_parent(self) -> None:
        repo, base = self.init_repo("temp-main-staging-unrelated-second-parent")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add reviewed staging content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge reviewed staging Gate C", "staging")
        self.attach_origin_with_main_and_staging(repo, "temp-main-staging-unrelated-origin.git")
        self.git(repo, "checkout", "-q", "-b", "unrelated", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add unrelated matching content")
        self.git(repo, "checkout", "-q", "-b", "chore/align-main-into-staging", "staging")
        self.git(repo, "merge", "--no-ff", "-m", "chore: align unrelated into staging", "unrelated")
        alignment_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-main-into-staging",
            head_sha=alignment_sha,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_main_to_staging_alignment_blocks_stale_gate_c_merge(self) -> None:
        repo, base = self.init_repo("main-staging-stale-gate-c")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add reviewed staging content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge reviewed staging Gate C", "staging")
        stale_gate_c_sha = self.git(repo, "rev-parse", "main").stdout.strip()
        self.attach_origin_with_main_and_staging(repo, "main-staging-stale-origin.git")
        self.write(repo / "main-advanced.txt", "main advanced\n")
        self.commit(repo, "chore: advance main after Gate C")
        self.git(repo, "push", "-q", "origin", "main")
        self.git(repo, "checkout", "-q", stale_gate_c_sha)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="main",
            head_sha=stale_gate_c_sha,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_temp_branch_to_staging_alignment_blocks_stale_main_second_parent(self) -> None:
        repo, base = self.init_repo("temp-main-staging-stale-main")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add reviewed staging content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge reviewed staging Gate C", "staging")
        self.attach_origin_with_main_and_staging(repo, "temp-main-staging-stale-main-origin.git")
        self.git(repo, "checkout", "-q", "-b", "chore/align-main-into-staging", "staging")
        self.git(repo, "merge", "--no-ff", "-m", "chore: align main into staging", "main")
        alignment_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "main")
        self.write(repo / "main-advanced.txt", "main advanced\n")
        self.commit(repo, "chore: advance main after alignment")
        self.git(repo, "push", "-q", "origin", "main")
        self.git(repo, "checkout", "-q", "chore/align-main-into-staging")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-main-into-staging",
            head_sha=alignment_sha,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_temp_branch_to_staging_alignment_blocks_non_staging_first_parent(self) -> None:
        repo, base = self.init_repo("temp-main-staging-wrong-first-parent")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add reviewed staging content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge reviewed staging Gate C", "staging")
        self.attach_origin_with_main_and_staging(repo, "temp-main-staging-wrong-first-origin.git")
        self.git(repo, "checkout", "-q", "-b", "chore/align-main-into-staging", base)
        self.write(repo / "release.txt", "reviewed staging content\n")
        self.commit(repo, "feat: add same content outside staging lineage")
        self.git(repo, "merge", "--no-ff", "-m", "chore: align main into staging", "main")
        alignment_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-main-into-staging",
            head_sha=alignment_sha,
        )

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

    def test_tree_neutral_exception_blocks_moving_development_merge(self) -> None:
        repo, base = self.init_repo("moving-development-merge", profile="framework")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        self.write(repo / "app" / "ImportedFromDevelopment.php", "<?php\nreturn 'development';\n")
        self.commit(repo, "feat(governance): add development content")
        development_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "feature/gate-d-delivery", base)
        self.git(repo, "merge", "--no-ff", "-m", "chore: merge development into feature", "development")
        merge_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.assertNotEqual(self.git(repo, "diff", "--name-only", f"{merge_sha}^1..{merge_sha}").stdout.strip(), "")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            development_sha,
            static_only=True,
            base_ref="development",
            head_ref="feature/gate-d-delivery",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_canonical_promotion_classifies_inherited_first_parent_history(self) -> None:
        repo, base = self.init_repo("canonical-promotion-inherited-history", profile="framework")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "feature.txt", "feature change\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "Legacy feature import")
        self.git(repo, "checkout", "-q", "-b", "feature/side-branch", base)
        self.write(repo / "side.txt", "side change\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "feat: add side branch content")
        self.git(repo, "checkout", "-q", "staging")
        self.git(repo, "merge", "--no-ff", "-m", "Merge side branch", "feature/side-branch")
        self.install_fake_gitleaks_asserting_content_delta_scan()

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="main",
            head_ref="staging",
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "PASS")
        self.assertIn("Inherited branch-promotion commit messages predate current convention", report)
        self.assertIn("Inherited branch-promotion merge commits predate current promotion policy", report)
        self.assertTrue(
            any(
                result["gate"] == "Secrets"
                and result["message"] == "Gitleaks content-delta scan passed for canonical branch promotion."
                for result in report_json["results"]
            )
        )

    def test_canonical_promotion_content_delta_secret_still_fails(self) -> None:
        repo, base = self.init_repo("canonical-promotion-secret-delta", profile="framework")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "secret.txt", "token fixture\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "feat: add staged application content")
        self.install_fake_gitleaks_report(
            [
                {
                    "Description": "Generic API Key",
                    "File": "secret.txt",
                    "StartLine": 1,
                    "Fingerprint": "HEAD:secret.txt:generic-api-key",
                }
            ]
        )

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="main",
            head_ref="staging",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")
        self.assertIn("Gitleaks detected secrets", report)

    def test_alignment_pr_uses_first_parent_history_for_inherited_baseline_ancestry(self) -> None:
        repo, base = self.init_repo("alignment-first-parent-history", profile="framework")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        self.write(repo / "tests" / "Feature" / "InheritedHistorySecretTest.php", "<?php\nconst TOKEN_FIXTURE = 'historical-secret-token-value';\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "telemedicine-main baseline alignment (#30)")
        self.git(repo, "checkout", "-q", "-b", "chore/align-development-into-staging", base)
        self.git(repo, "merge", "--no-ff", "--no-commit", "development")
        self.git(repo, "rm", "-q", "-f", "tests/Feature/InheritedHistorySecretTest.php")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non: pull_request\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc26\n",
        )
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "Merge development baseline into staging")
        self.install_fake_gitleaks_asserting_log_opts(f"--first-parent {base}..HEAD")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging",
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "PASS")
        self.assertTrue(
            any(
                result["gate"] == "Repository Hygiene"
                and result["message"] == "Only governed ancestry-alignment merge commits detected."
                for result in report_json["results"]
            )
        )

    def test_alignment_pr_blocks_contentful_merge_commit(self) -> None:
        repo, base = self.init_repo("alignment-contentful-merge", profile="framework")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        self.write(repo / "app" / "Feature.php", "<?php\nreturn 'feature';\n")
        self.commit(repo, "feat: add application feature")
        self.git(repo, "checkout", "-q", "-b", "chore/align-development-into-staging", base)
        self.git(repo, "merge", "--no-ff", "-m", "Merge development into staging", "development")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_development_to_staging_tree_neutral_alignment_allows_inherited_history(self) -> None:
        repo, staging_sha, development_sha, historical_merge, alignment_sha = self.development_staging_alignment_repo(
            "development-staging-tree-neutral-alignment"
        )

        self.assertEqual(self.git(repo, "show", "-s", "--format=%P", alignment_sha).stdout.split(), [staging_sha, development_sha])
        self.assertEqual(self.git(repo, "diff", "--name-only", f"{alignment_sha}^1..{alignment_sha}").stdout.strip(), "")
        self.assertNotEqual(self.git(repo, "diff", "--name-only", f"{historical_merge}^1..{historical_merge}").stdout.strip(), "")
        self.assertNotEqual(self.git(repo, "diff", "--name-only", f"{historical_merge}^2..{historical_merge}").stdout.strip(), "")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging",
            head_sha=alignment_sha,
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "PASS")
        self.assertTrue(
            any(
                result["gate"] == "Repository Hygiene"
                and result["message"] == "Only current development-to-staging tree-neutral alignment merge commits detected."
                for result in report_json["results"]
            )
        )

        # The historical content-changing merge remains auditable and still fails if proposed directly.
        self.git(repo, "checkout", "-q", historical_merge)
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            self.git(repo, "rev-parse", f"{historical_merge}^1").stdout.strip(),
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging",
            head_sha=historical_merge,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

        # After the tree-neutral alignment is merged, the same production first-parent range has no new merge commits.
        self.git(repo, "checkout", "-q", "staging")
        self.git(repo, "merge", "--ff-only", alignment_sha)
        self.git(repo, "push", "-q", "origin", "staging")
        self.git(repo, "checkout", "-q", "development")
        self.assertEqual(self.git(repo, "merge-base", "development", "origin/staging").stdout.strip(), development_sha)
        self.assertEqual(
            self.git(repo, "rev-list", "--first-parent", "--merges", "origin/staging..development").stdout.strip(),
            "",
        )

    def test_development_to_staging_alignment_fetch_failure_rejects_stale_staging_ref(self) -> None:
        repo, staging_sha, _, _, alignment_sha = self.development_staging_alignment_repo(
            "development-staging-stale-cached-staging-ref"
        )
        engine = load_engine_module()
        self.assertEqual(engine.resolve_fresh_origin_staging_tip(repo), staging_sha)
        self.git(repo, "push", "-q", "origin", ":staging")

        self.assertEqual(engine.resolve_fresh_origin_staging_tip(repo), "")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging",
            head_sha=alignment_sha,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_development_to_staging_alignment_fetch_failure_rejects_stale_development_ref(self) -> None:
        repo, staging_sha, development_sha, _, alignment_sha = self.development_staging_alignment_repo(
            "development-staging-stale-cached-development-ref"
        )
        engine = load_engine_module()
        self.assertEqual(engine.resolve_fresh_origin_development_tip(repo), development_sha)
        self.git(repo, "push", "-q", "origin", ":development")

        self.assertEqual(engine.resolve_fresh_origin_development_tip(repo), "")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging",
            head_sha=alignment_sha,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

    def test_github_https_tip_fetch_uses_ephemeral_auth_and_does_not_persist_token(self) -> None:
        repo, base = self.init_repo("github-https-auth-fetch")
        self.git(repo, "remote", "add", "origin", "https://github.com/Synergie-ITCI/example.git")
        self.git(repo, "update-ref", "refs/remotes/origin/staging", base)
        engine = load_engine_module()
        original_run = engine.subprocess.run
        fetch_commands: list[list[str]] = []
        old_token = os.environ.get("GH_TOKEN")
        os.environ["GH_TOKEN"] = "ghs_example_secret_token"

        def fake_run(args, *popenargs, **kwargs):
            if isinstance(args, list) and "fetch" in args:
                fetch_commands.append(args)
                return subprocess.CompletedProcess(args, 0, "", "")
            return original_run(args, *popenargs, **kwargs)

        try:
            with mock.patch.object(engine.subprocess, "run", side_effect=fake_run):
                self.assertEqual(engine.resolve_fresh_origin_staging_tip(repo), base)
        finally:
            if old_token is None:
                os.environ.pop("GH_TOKEN", None)
            else:
                os.environ["GH_TOKEN"] = old_token

        self.assertEqual(len(fetch_commands), 1)
        fetch_command = fetch_commands[0]
        self.assertIn("-c", fetch_command)
        self.assertTrue(any("http.https://github.com/.extraheader=AUTHORIZATION: basic " in arg for arg in fetch_command))
        self.assertFalse(any("ghs_example_secret_token" in arg for arg in fetch_command))
        self.assertNotIn("extraheader", self.git(repo, "config", "--get-regexp", "extraheader").stdout.lower())

    def test_github_https_tip_fetch_missing_or_failed_auth_rejects_stale_refs_without_token_leak(self) -> None:
        repo, base = self.init_repo("github-https-auth-fetch-fail-closed")
        self.git(repo, "remote", "add", "origin", "https://github.com/Synergie-ITCI/example.git")
        for branch in ("main", "staging", "development"):
            self.git(repo, "update-ref", f"refs/remotes/origin/{branch}", base)
        engine = load_engine_module()
        old_token = os.environ.pop("GH_TOKEN", None)
        try:
            self.assertEqual(engine.resolve_fresh_origin_main_tip(repo), "")
            self.assertEqual(engine.resolve_fresh_origin_staging_tip(repo), "")
            self.assertEqual(engine.resolve_fresh_origin_development_tip(repo), "")
        finally:
            if old_token is not None:
                os.environ["GH_TOKEN"] = old_token

        secret = "ghs_failed_secret_token"
        encoded = base64.b64encode(f"x-access-token:{secret}".encode("utf-8")).decode("ascii")
        os.environ["GH_TOKEN"] = secret
        original_run = engine.subprocess.run

        def fake_failed_fetch(args, *popenargs, **kwargs):
            if isinstance(args, list) and "fetch" in args:
                return subprocess.CompletedProcess(args, 1, f"stdout {secret}", f"stderr {encoded}")
            return original_run(args, *popenargs, **kwargs)

        stdout = StringIO()
        stderr = StringIO()
        try:
            with mock.patch.object(engine.subprocess, "run", side_effect=fake_failed_fetch):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(engine.resolve_fresh_origin_staging_tip(repo), "")
        finally:
            if old_token is None:
                os.environ.pop("GH_TOKEN", None)
            else:
                os.environ["GH_TOKEN"] = old_token

        leaked = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(secret, leaked)
        self.assertNotIn(encoded, leaked)
        self.assertNotIn("extraheader", self.git(repo, "config", "--get-regexp", "extraheader").stdout.lower())

    def test_local_tip_fetch_still_works_without_github_token(self) -> None:
        repo, staging_sha, development_sha, _, _ = self.development_staging_alignment_repo(
            "local-tip-fetch-without-github-token"
        )
        old_token = os.environ.pop("GH_TOKEN", None)
        try:
            engine = load_engine_module()
            self.assertEqual(engine.resolve_fresh_origin_staging_tip(repo), staging_sha)
            self.assertEqual(engine.resolve_fresh_origin_development_tip(repo), development_sha)
        finally:
            if old_token is not None:
                os.environ["GH_TOKEN"] = old_token

    def test_development_to_staging_alignment_blocks_content_changes_and_stale_tips(self) -> None:
        repo, base = self.init_repo("development-staging-alignment-blockers", profile="framework")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        self.write(repo / "app" / "Feature.php", "<?php\nreturn 'development';\n")
        self.commit(repo, "feat: add development-only content")
        development_sha = self.git(repo, "rev-parse", "development").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.attach_origin_with_development_and_staging(repo, "development-staging-alignment-blockers-origin.git")

        self.git(repo, "checkout", "-q", "-b", "chore/align-development-into-staging", "staging")
        self.git(repo, "merge", "--no-ff", "-m", "chore: align development into staging", "development")
        content_changing_alignment = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.assertNotEqual(self.git(repo, "diff", "--name-only", f"{content_changing_alignment}^1..{content_changing_alignment}").stdout.strip(), "")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging",
            head_sha=content_changing_alignment,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

        repo, staging_sha, development_sha, _, alignment_sha = self.development_staging_alignment_repo(
            "development-staging-stale-tip-blockers"
        )
        self.git(repo, "checkout", "-q", "development")
        self.write(repo / "app" / "CurrentDevelopment.php", "<?php\nreturn 'current';\n")
        self.commit(repo, "feat: advance current development")
        self.git(repo, "push", "-q", "origin", "development")
        self.git(repo, "checkout", "-q", alignment_sha)
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging",
            head_sha=alignment_sha,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")
        self.assertIn("Accidental merge commits detected", report)

        repo, staging_sha, _, _, alignment_sha = self.development_staging_alignment_repo(
            "development-staging-stale-staging-blocker"
        )
        self.git(repo, "checkout", "-q", "staging")
        self.git(repo, "commit", "-q", "--allow-empty", "-m", "chore: advance current staging")
        self.git(repo, "push", "-q", "origin", "staging")
        self.git(repo, "checkout", "-q", alignment_sha)
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging",
            head_sha=alignment_sha,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")

    def test_development_to_staging_alignment_blocks_wrong_parent_shape(self) -> None:
        repo, staging_sha, development_sha, _, alignment_sha = self.development_staging_alignment_repo(
            "development-staging-wrong-parent-shape"
        )
        self.git(repo, "checkout", "-q", "-b", "unrelated", staging_sha)
        self.git(repo, "commit", "-q", "--allow-empty", "-m", "chore: unrelated lineage")
        self.git(repo, "checkout", "-q", "-B", "chore/align-unrelated-into-staging", "staging")
        self.git(repo, "merge", "--no-ff", "-s", "ours", "-m", "chore: align unrelated into staging", "unrelated")
        unrelated_alignment = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-unrelated-into-staging",
            head_sha=unrelated_alignment,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")

        self.git(repo, "checkout", "-q", "-B", "chore/reversed-development-staging-alignment", development_sha)
        self.git(repo, "merge", "--no-ff", "-s", "ours", "-m", "chore: reversed alignment", "staging")
        reversed_alignment = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/reversed-development-staging-alignment",
            head_sha=reversed_alignment,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")

        self.git(repo, "checkout", "-q", alignment_sha)
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="development",
            head_ref="chore/align-development-into-staging",
            head_sha=alignment_sha,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")

        self.git(repo, "checkout", "-q", "-B", "chore/align-development-into-staging-extra", alignment_sha)
        self.git(repo, "commit", "-q", "--allow-empty", "-m", "chore: extra commit after alignment")
        extra_head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            staging_sha,
            static_only=True,
            base_ref="staging",
            head_ref="chore/align-development-into-staging-extra",
            head_sha=extra_head,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "FAIL")

    def test_normal_development_to_staging_merge_hygiene_still_blocks_contentful_merge(self) -> None:
        repo, base = self.init_repo("normal-development-staging-contentful-merge", profile="framework")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        self.write(repo / "app" / "ExistingDevelopment.php", "<?php\nreturn 'first';\n")
        self.commit(repo, "feat: add first development content")
        self.git(repo, "checkout", "-q", "-b", "feature/history", base)
        self.write(repo / "app" / "MergedFeature.php", "<?php\nreturn 'second';\n")
        self.commit(repo, "feat: add merged feature")
        self.git(repo, "checkout", "-q", "development")
        self.git(repo, "merge", "--no-ff", "-m", "feat: merge historical feature", "feature/history")
        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.attach_origin_with_development_and_staging(repo, "normal-development-staging-contentful-origin.git")
        self.git(repo, "checkout", "-q", "development")
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

    def test_first_parent_commit_message_policy_warns_for_new_bad_message(self) -> None:
        repo, base = self.init_repo("bad-first-parent-message", profile="framework")
        self.write(repo / "README.md", "# regression\n\nBad subject.\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "Update README.md")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "WARNING")
        self.assertIn("Commit messages do not match convention", report)

    def test_branch_name_policy_warns_for_bad_branch_name(self) -> None:
        repo, base = self.init_repo("bad-branch-name", profile="framework")
        self.write(repo / "README.md", "# regression\n\nBad branch.\n")
        self.commit(repo, "docs: update readme")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            head_ref="bad_branch_name",
        )

        self.assertEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "WARNING")
        self.assertIn("Branch name `bad_branch_name` does not match allowed convention", report)

    def test_new_secret_content_remains_blocking(self) -> None:
        repo, base = self.init_repo("new-secret-content", profile="framework")
        self.write(repo / "app" / "NewSecret.php", "<?php\n$password = 'new-super-secret-value';\n")
        self.commit(repo, "feat: add secret content")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")
        self.assertIn("High-confidence secret indicators found", report)

    def test_changed_inherited_secret_like_line_remains_blocking(self) -> None:
        repo, base = self.init_repo("changed-inherited-secret-line", profile="framework")
        self.git(repo, "checkout", "-q", "-b", "staging-secret-base", base)
        self.write(repo / "tests" / "Feature" / "InheritedSecretFixtureTest.php", "<?php\n$password = 'old-fixture-secret-value';\n")
        self.commit(repo, "test: add inherited secret-like fixture")
        inherited_base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "feature/change-inherited-secret", inherited_base)
        self.write(repo / "tests" / "Feature" / "InheritedSecretFixtureTest.php", "<?php\n$password = 'changed-fixture-secret-value';\n")
        self.commit(repo, "test: change inherited secret-like fixture")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, inherited_base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")
        self.assertIn("High-confidence secret indicators found", report)

    def test_one_time_branch_alignment_allows_exact_main_tree_plus_caller_overlay(self) -> None:
        repo, development_sha = self.init_repo("branch-alignment-exact-tree")
        self.git(repo, "checkout", "-q", "-b", "main", development_sha)
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", "jobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n")
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n.github/** @SaurabhVermaIN\n")
        self.write(repo / ".env.testing", "APP_ENV=testing\nAPP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nDB_DATABASE=telepathy_test\n")
        self.write(repo / "app" / "Http" / "Controllers" / "BaselineController.php", "<?php\nclass BaselineController {}\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "legacy import before conventions")
        main_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.git(repo, "checkout", "-q", "-b", "chore/align-main-into-development", development_sha)
        self.git(repo, "merge", "--no-ff", "-X", "theirs", "-m", "Merge main baseline into development", main_sha)
        merge_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", "jobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc24\n")
        self.commit(repo, "ci: consume pr qa rc24")
        head_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        policy = self.branch_alignment_policy_for(
            base_sha=development_sha,
            head_sha=head_sha,
            merge_sha=merge_sha,
            target_sha=main_sha,
        )

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            development_sha,
            static_only=True,
            base_ref="development",
            head_ref="chore/align-main-into-development",
            head_sha=head_sha,
            repository="Synergie-ITCI/telemedicine-backend",
            policy_path=policy,
            body_extra=self.branch_alignment_marker(),
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "WARNING")
        self.assertTrue(report_json["summary"]["baseline_alignment"]["authorized"])

    def test_one_time_branch_alignment_blocks_candidate_tree_drift(self) -> None:
        repo, development_sha = self.init_repo("branch-alignment-tree-drift")
        self.git(repo, "checkout", "-q", "-b", "main", development_sha)
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", "jobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n")
        self.write(repo / "app" / "Http" / "Controllers" / "BaselineController.php", "<?php\nclass BaselineController {}\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "legacy import before conventions")
        main_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.git(repo, "checkout", "-q", "-b", "chore/align-main-into-development", development_sha)
        self.git(repo, "merge", "--no-ff", "-X", "theirs", "-m", "Merge main baseline into development", main_sha)
        merge_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", "jobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc24\n")
        self.write(repo / "app" / "Http" / "Controllers" / "BaselineController.php", "<?php\nclass BaselineController { public function drift() {} }\n")
        self.commit(repo, "ci: consume pr qa rc24")
        head_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        policy = self.branch_alignment_policy_for(
            base_sha=development_sha,
            head_sha=head_sha,
            merge_sha=merge_sha,
            target_sha=main_sha,
        )

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            development_sha,
            static_only=True,
            base_ref="development",
            head_ref="chore/align-main-into-development",
            head_sha=head_sha,
            repository="Synergie-ITCI/telemedicine-backend",
            policy_path=policy,
            body_extra=self.branch_alignment_marker(),
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "FAIL")
        self.assertIn("candidate differs from approved application source outside the governance overlay", report)

    def test_sql_migration_is_classified_by_sql_adapter(self) -> None:
        repo, base = self.init_repo("sql-migration")
        self.write(
            repo / "migrations" / "001_identity.sql",
            "create table user_identities (id uuid primary key, normalized_email text not null unique);\n",
        )
        self.commit(repo, "feat: add identity migration")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Executable Classification"], "PASS")
        self.assertTrue(any(result.get("technology") == "SQL/PostgreSQL" for result in report_json["results"]))

    def test_large_normal_feature_pr_exceeds_size_thresholds(self) -> None:
        repo, base = self.init_repo("large-normal-feature")
        for index in range(205):
            self.write(repo / "docs" / f"note-{index:03d}.md", ("ordinary docs change\n" * 30))
        self.commit(repo, "docs: add large feature fixture")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Risk Engine"], "FAIL")
        self.assertIn("PR exceeds central size thresholds", report)

    def test_generated_npm_lockfile_bulk_does_not_fail_additions_threshold(self) -> None:
        repo, base = self.init_repo("npm-lockfile-bulk")
        self.write(repo / "package.json", json.dumps({"scripts": {"production": "echo build"}, "dependencies": {}}))
        self.write(repo / "package-lock.json", self.large_package_lock())
        self.commit(repo, "fix: add reproducible npm lockfile")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs"],
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertNotEqual(report_json["summary"]["gate_statuses"]["Risk Engine"], "FAIL")
        self.assertGreater(report_json["summary"]["raw_additions"], 5000)
        self.assertGreater(report_json["summary"]["generated_lockfile_additions_excluded"], 5000)
        self.assertLess(report_json["summary"]["effective_additions"], 5000)
        risk_result = next(result for result in report_json["results"] if result["gate"] == "Risk Engine")
        self.assertIn("RAW_ADDITIONS", "\n".join(risk_result["details"]))
        self.assertIn("EFFECTIVE_ADDITIONS", "\n".join(risk_result["details"]))

    def test_authored_source_bulk_still_fails_with_generated_npm_lockfile(self) -> None:
        repo, base = self.init_repo("npm-lockfile-plus-source-bulk")
        self.write(repo / "package.json", json.dumps({"scripts": {"production": "echo build"}, "dependencies": {}}))
        self.write(repo / "package-lock.json", self.large_package_lock())
        self.write(repo / "src" / "bulk.js", "console.log('line');\n" * 6000)
        self.commit(repo, "feat: add oversized authored source")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs"],
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Risk Engine"], "FAIL")
        self.assertIn("EFFECTIVE_ADDITIONS", report)

    def test_large_arbitrary_json_counts_normally_for_risk_size(self) -> None:
        repo, base = self.init_repo("arbitrary-json-bulk")
        self.write(repo / "data" / "bulk.json", "{\n" + "\n".join(f'  \"k{index}\": {index},' for index in range(10000)) + "\n  \"done\": true\n}\n")
        self.commit(repo, "feat: add large json fixture")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs"],
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["generated_lockfile_additions_excluded"], 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Risk Engine"], "FAIL")
        self.assertIn("EFFECTIVE_ADDITIONS", report)

    def test_package_lock_without_package_json_counts_normally_for_risk_size(self) -> None:
        repo, base = self.init_repo("lockfile-without-package-json")
        self.write(repo / "package-lock.json", self.large_package_lock())
        self.commit(repo, "chore: add orphan npm lockfile")

        code, _, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs"],
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["generated_lockfile_additions_excluded"], 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Risk Engine"], "FAIL")

    def test_malformed_package_lock_counts_normally_for_risk_size(self) -> None:
        repo, base = self.init_repo("malformed-lockfile")
        self.write(repo / "package.json", json.dumps({"dependencies": {}}))
        self.write(repo / "package-lock.json", "{\n" + ("not json\n" * 10000))
        self.commit(repo, "chore: add malformed npm lockfile")

        code, _, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs"],
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["generated_lockfile_additions_excluded"], 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Risk Engine"], "FAIL")

    def test_valid_npm_lockfile_remains_in_changed_file_count(self) -> None:
        repo, base = self.init_repo("lockfile-changed-file-count")
        self.write(repo / "package.json", json.dumps({"dependencies": {}}))
        self.write(repo / "package-lock.json", self.large_package_lock())
        self.commit(repo, "fix: add npm package metadata")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs"],
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["changed_files"], 2)
        self.assertGreater(report_json["summary"]["generated_lockfile_additions_excluded"], 0)

    def test_npm_lockfile_version_three_is_excluded_from_risk_size(self) -> None:
        repo, base = self.init_repo("lockfile-version-three")
        self.write(repo / "package.json", json.dumps({"dependencies": {}}))
        self.write(repo / "package-lock.json", self.large_package_lock(lockfile_version=3))
        self.commit(repo, "fix: add npm lockfile")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            extra_args=["--no-command-runs"],
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertGreater(report_json["summary"]["generated_lockfile_additions_excluded"], 0)

    def test_invalid_npm_lockfile_versions_are_not_excluded_from_risk_size(self) -> None:
        cases = [
            ("zero", 0),
            ("float", 1.5),
            ("string", "3"),
            ("unknown", 999),
        ]
        for name, version in cases:
            with self.subTest(name=name):
                repo, base = self.init_repo(f"lockfile-version-{name}")
                self.write(repo / "package.json", json.dumps({"dependencies": {}}))
                self.write(repo / "package-lock.json", self.large_package_lock(lockfile_version=version))
                self.commit(repo, "fix: add npm lockfile")

                code, _, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    base,
                    extra_args=["--no-command-runs"],
                    review_policy={"mergeable": True, "reviews": []},
                )

                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["generated_lockfile_additions_excluded"], 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Risk Engine"], "FAIL")

    def test_generated_npm_lockfile_does_not_bypass_dependency_gate(self) -> None:
        npm_log = self.tmp / "npm-lockfile-risk.log"
        fake_npm = self.bin / "npm"
        fake_npm.write_text(
            f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> {npm_log}
if [ "$1" = "audit" ]; then
  printf '{{"metadata":{{"vulnerabilities":{{"high":0,"critical":0}}}}}}\\n'
fi
exit 0
""",
            encoding="utf-8",
        )
        fake_npm.chmod(0o755)
        repo, base = self.init_repo("lockfile-dependency-gate")
        self.write(repo / "package.json", json.dumps({"scripts": {"production": "echo build"}, "dependencies": {}}))
        self.write(repo / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {}}))
        self.commit(repo, "fix: add npm lockfile")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        npm_commands = npm_log.read_text(encoding="utf-8")
        self.assertIn("ci", npm_commands)
        self.assertIn("audit --audit-level=high --json", npm_commands)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Dependencies"], "PASS")

    def test_canonical_development_to_staging_branch_name_is_allowed(self) -> None:
        repo, base = self.init_repo("canonical-development-to-staging")
        self.write(repo / "README.md", "# canonical promotion\n")
        self.commit(repo, "docs: update promotion fixture")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="staging",
            head_ref="development",
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "PASS")

    def init_programme_platform_baseline_repo(self, name: str, *, include_secret: bool = False) -> tuple[Path, str, str]:
        fake_pip_audit = self.bin / "pip-audit"
        fake_pip_audit.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        fake_pip_audit.chmod(0o755)
        repo = self.tmp / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "qa@example.invalid")
        self.git(repo, "config", "user.name", "QA Regression")
        self.write(
            repo / ".github" / "pr-qa.yml",
            self.base_config()
            + "branch_naming:\n"
            + "  allowed_patterns:\n"
            + "    - '^(feature|fix|hotfix|release|chore|docs|test|refactor|security|codex)/[a-zA-Z0-9._/-]+$'\n",
        )
        self.write(repo / "README.md", "# staging shell\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: staging shell")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "development")
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n.github/** @SaurabhVermaIN\n")
        self.write(repo / ".github" / "pull_request_template.md", "## Business Purpose\n\n## Testing Performed\n\n## Rollback Strategy\n\n## Linked Issue\n")
        self.write(repo / ".github" / "workflows" / "architecture-governance.yml", "name: architecture\non: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n")
        self.write(repo / "apps" / "api" / "alembic" / "versions" / "20260815_0016_sign_authenticated_database_context.py", "revision = '20260815_0016'\ndown_revision = '20260815_0015'\n")
        for index in range(205):
            self.write(repo / "docs" / f"baseline-{index:03d}.md", ("verified baseline evidence\n" * 30))
        if include_secret:
            self.write(repo / "apps" / "api" / "app" / "secret_fixture.py", "password = 'real-secret-password-value'\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "Merge pull request #13 from feature/p1a-config-driven-case-lifecycle")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        return repo, base, head

    def test_programme_platform_one_time_baseline_allows_only_exact_verified_development_to_staging(self) -> None:
        repo, base, head = self.init_programme_platform_baseline_repo("programme-platform-baseline")
        policy = self.programme_platform_policy_for(base_sha=base, head_sha=head)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="staging",
            head_ref="development",
            head_sha=head,
            repository="Synergie-ITCI/programme-management-platform",
            baseline_alignment=True,
            body_extra=self.programme_platform_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "PASS")
        self.assertIn(report_json["summary"]["gate_statuses"]["Risk Engine"], {"PASS", "WARNING"})
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "WARNING")
        self.assertIn("Inherited baseline protected resources match the exact approved source", report)
        self.assertNotIn("PR exceeds central size thresholds", report)

    def test_programme_platform_one_time_baseline_rejects_wrong_scope_or_reuse(self) -> None:
        repo, base, head = self.init_programme_platform_baseline_repo("programme-platform-baseline-scope")
        policy = self.programme_platform_policy_for(base_sha=base, head_sha=head)
        cases = [
            {
                "name": "another repository",
                "repository": "Synergie-ITCI/another-repo",
                "base_ref": "staging",
                "head_ref": "development",
                "head_sha": head,
                "base": base,
                "needle": "is not authorized",
            },
            {
                "name": "another development sha",
                "repository": "Synergie-ITCI/programme-management-platform",
                "base_ref": "staging",
                "head_ref": "development",
                "head_sha": base,
                "base": base,
                "needle": "source SHA",
            },
            {
                "name": "another source branch",
                "repository": "Synergie-ITCI/programme-management-platform",
                "base_ref": "staging",
                "head_ref": "release/programme-platform-baseline",
                "head_sha": head,
                "base": base,
                "needle": "source branch",
            },
            {
                "name": "another target branch",
                "repository": "Synergie-ITCI/programme-management-platform",
                "base_ref": "main",
                "head_ref": "development",
                "head_sha": head,
                "base": base,
                "needle": "target branch",
            },
            {
                "name": "reuse after staging moved",
                "repository": "Synergie-ITCI/programme-management-platform",
                "base_ref": "staging",
                "head_ref": "development",
                "head_sha": head,
                "base": head,
                "needle": "destination SHA",
            },
        ]
        for case in cases:
            with self.subTest(case=case["name"]):
                code, report, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    case["base"],
                    static_only=True,
                    base_ref=case["base_ref"],
                    head_ref=case["head_ref"],
                    head_sha=case["head_sha"],
                    repository=case["repository"],
                    baseline_alignment=True,
                    body_extra=self.programme_platform_marker(),
                    policy_path=policy,
                    review_policy={"mergeable": True, "reviews": []},
                )

                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "FAIL")
                self.assertIn(case["needle"], report)

    def test_programme_platform_one_time_baseline_does_not_waive_evidence_or_secrets(self) -> None:
        repo, base, head = self.init_programme_platform_baseline_repo("programme-platform-baseline-evidence")
        policy = self.programme_platform_policy_for(base_sha=base, head_sha=head)

        missing_evidence_code, missing_evidence_report, missing_evidence_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="staging",
            head_ref="development",
            head_sha=head,
            repository="Synergie-ITCI/programme-management-platform",
            baseline_alignment=True,
            body_override=self.programme_platform_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(missing_evidence_code, 0)
        self.assertEqual(missing_evidence_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(missing_evidence_json["summary"]["gate_statuses"]["Evidence"], "WARNING")
        self.assertIn("Administrative PR template evidence is missing", missing_evidence_report)

        repo, base, head = self.init_programme_platform_baseline_repo("programme-platform-baseline-secret", include_secret=True)
        policy = self.programme_platform_policy_for(base_sha=base, head_sha=head)
        secret_code, secret_report, secret_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="staging",
            head_ref="development",
            head_sha=head,
            repository="Synergie-ITCI/programme-management-platform",
            baseline_alignment=True,
            body_extra=self.programme_platform_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(secret_code, 0)
        self.assertEqual(secret_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(secret_json["summary"]["gate_statuses"]["Secrets"], "FAIL")
        self.assertIn("High-confidence secret indicators found", secret_report)

    def test_authorized_telemedicine_baseline_relaxes_size_history_and_safe_fixtures(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base = self.init_repo("telemedicine-authorized-baseline")
        self.write(repo / "composer.json", json.dumps({"require": {}, "scripts": {"test": "echo ok"}}))
        self.write(repo / "composer.lock", json.dumps({"packages": [], "packages-dev": []}))
        self.write(repo / ".env.testing", "APP_ENV=testing\nAPP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
        self.write(repo / "baseline.docx", "baseline binary fixture\x00\n")
        for index in range(205):
            self.write(repo / "docs" / f"baseline-{index:03d}.md", ("baseline docs change\n" * 30))
        self.write(repo / "database" / "migrations" / "2026_08_12_000001_create_baseline_table.php", "<?php\nreturn new class { public function up() { Schema::create('baseline', function ($table) {}); } public function down() { Schema::dropIfExists('baseline'); } };\n")
        self.commit(repo, "legacy baseline import")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        policy = self.baseline_policy_for(base_sha=base, head_sha=head, minimum_changed_files=200)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=True,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Integrity"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Migration Risk"], "WARNING")
        self.assertIn("BASELINE ALIGNMENT PREFLIGHT", report)
        self.assertIn("Baseline-only repository integrity relaxations applied", report)
        self.assertNotIn("PR exceeds central size thresholds", report)

    def test_authorized_telemedicine_source_overlay_accepts_exact_governance_overlay(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_telemedicine_overlay_repo()
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        policy = self.baseline_overlay_policy_for(base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=True,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertTrue(report_json["summary"]["baseline_alignment"]["authorized"])
        self.assertIn("BASELINE ALIGNMENT PREFLIGHT", report)

    def test_authorized_telemedicine_baseline_classifies_inherited_content_findings(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_inherited_content_repo()
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        base_policy = self.baseline_policy_for(base_sha=base, head_sha=source, minimum_changed_files=1)
        policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=True,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Integrity"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Git Validation"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Deployment Risk"], "WARNING")
        self.assertIn("INHERITED_BASELINE", report)
        self.assertIn("AUTHORIZED_OVERLAY", report)
        self.assertIn("Inherited baseline deployment-sensitive content requires human review", report)

    def test_authorized_telemedicine_baseline_marker_activates_inherited_classification(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_inherited_content_repo()
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        base_policy = self.baseline_policy_for(base_sha=base, head_sha=source, minimum_changed_files=1)
        policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=False,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertTrue(report_json["summary"]["baseline_alignment"]["requested"])
        self.assertTrue(report_json["summary"]["baseline_alignment"]["authorized"])
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Integrity"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Repository Hygiene"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Git Validation"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "WARNING")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Deployment Risk"], "WARNING")
        self.assertIn("INHERITED_BASELINE", report)

    def test_source_overlay_authorizes_main_ancestry_candidate_by_final_tree(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_inherited_content_repo()
        self.git(repo, "checkout", "-q", "-B", "release/production-baseline-alignment-20260812", base)
        self.git(repo, "rm", "-qr", ".")
        completed = subprocess.run(
            ["git", "checkout", source, "--", "."],
            cwd=repo,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review, edited]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n",
        )
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: rebuild baseline candidate on main ancestry")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        base_policy = self.baseline_policy_for(base_sha=base, head_sha=source, minimum_changed_files=1)
        policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=False,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertTrue(report_json["summary"]["baseline_alignment"]["authorized"])
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")

    def test_source_overlay_accepts_inherited_gitleaks_fingerprint_commit_drift(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_inherited_content_repo()
        secret_path = "tests/Feature/InheritedGitleaksFixtureTest.php"
        self.git(repo, "checkout", "-q", "staging-source")
        self.write(repo / secret_path, "<?php\nconst TOKEN_FIXTURE = 'test-fixture-token-value';\n")
        self.git(repo, "add", secret_path)
        self.git(repo, "commit", "-q", "-m", "test: add inherited gitleaks fixture")
        source = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "release/production-baseline-alignment-20260812", base)
        self.git(repo, "rm", "-qr", ".")
        completed = subprocess.run(["git", "checkout", source, "--", "."], cwd=repo, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review, edited]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n",
        )
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: rebuild baseline candidate on main ancestry")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.install_fake_gitleaks_report(
            [
                {
                    "RuleID": "generic-api-key",
                    "File": secret_path,
                    "StartLine": 2,
                    "Fingerprint": f"{head}:{secret_path}:generic-api-key:2",
                }
            ]
        )
        base_policy = self.baseline_policy_for(
            base_sha=base,
            head_sha=source,
            minimum_changed_files=1,
            gitleaks_allowlist=[
                {
                    "rule_id": "generic-api-key",
                    "path": secret_path,
                    "line": 2,
                    "fingerprint": f"{source}:{secret_path}:generic-api-key:2",
                    "expires_after": "2099-12-31T23:59:59Z",
                }
            ],
        )
        policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=False,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "WARNING")
        self.assertIn("Gitleaks executed and returned only centrally allowlisted baseline fixture fingerprints", report)

    def test_source_overlay_rejects_new_gitleaks_fingerprint_despite_commit_drift_logic(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_inherited_content_repo()
        self.write(repo / "tests" / "Feature" / "NewSecretFixtureTest.php", "<?php\nconst TOKEN_FIXTURE = 'new-secret-token-value';\n")
        self.commit(repo, "test: add non inherited gitleaks fixture")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.install_fake_gitleaks_report(
            [
                {
                    "RuleID": "generic-api-key",
                    "File": "tests/Feature/NewSecretFixtureTest.php",
                    "StartLine": 2,
                    "Fingerprint": f"{head}:tests/Feature/NewSecretFixtureTest.php:generic-api-key:2",
                }
            ]
        )
        base_policy = self.baseline_policy_for(
            base_sha=base,
            head_sha=source,
            minimum_changed_files=1,
            gitleaks_allowlist=[
                {
                    "rule_id": "generic-api-key",
                    "path": "tests/Feature/NewSecretFixtureTest.php",
                    "line": 2,
                    "fingerprint": f"{source}:tests/Feature/NewSecretFixtureTest.php:generic-api-key:2",
                    "expires_after": "2099-12-31T23:59:59Z",
                }
            ],
        )
        policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=False,
            body_extra=self.baseline_marker(),
            policy_path=policy,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")
        self.assertIn("Gitleaks detected secrets", report)

    def test_source_overlay_accepts_inherited_gitleaks_stale_line_coordinates_for_fixture_shape(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_inherited_content_repo()
        secret_path = "tests/Feature/InheritedGitleaksFixtureTest.php"
        self.git(repo, "checkout", "-q", "staging-source")
        self.write(
            repo / secret_path,
            "<?php\n// harmless test fixture padding\nconfig(['jwt.secret' => 'baseline-fixture-test-secret']);\n",
        )
        self.git(repo, "add", secret_path)
        self.git(repo, "commit", "-q", "-m", "test: add inherited stale-coordinate gitleaks fixture")
        source = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "release/production-baseline-alignment-20260812", base)
        self.git(repo, "rm", "-qr", ".")
        completed = subprocess.run(["git", "checkout", source, "--", "."], cwd=repo, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review, edited]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n",
        )
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: rebuild baseline candidate on main ancestry")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.install_fake_gitleaks_report(
            [
                {
                    "RuleID": "generic-api-key",
                    "File": secret_path,
                    "StartLine": 3,
                    "Fingerprint": f"{head}:{secret_path}:generic-api-key:3",
                }
            ]
        )
        base_policy = self.baseline_policy_for(
            base_sha=base,
            head_sha=source,
            minimum_changed_files=1,
            gitleaks_allowlist=[
                {
                    "rule_id": "generic-api-key",
                    "path": secret_path,
                    "line": 2,
                    "fingerprint": f"{source}:{secret_path}:generic-api-key:2",
                    "expires_after": "2099-12-31T23:59:59Z",
                }
            ],
        )
        policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=False,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "WARNING")
        self.assertIn("Gitleaks executed and returned only centrally allowlisted baseline fixture fingerprints", report)

    def test_source_overlay_rejects_inherited_gitleaks_real_token_shape(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_inherited_content_repo()
        secret_path = "tests/Feature/InheritedRealTokenShapeTest.php"
        self.git(repo, "checkout", "-q", "staging-source")
        self.write(repo / secret_path, "<?php\nconst TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz123456';\n")
        self.git(repo, "add", secret_path)
        self.git(repo, "commit", "-q", "-m", "test: add inherited real token-shaped fixture")
        source = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "release/production-baseline-alignment-20260812", base)
        self.git(repo, "rm", "-qr", ".")
        completed = subprocess.run(["git", "checkout", source, "--", "."], cwd=repo, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review, edited]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n",
        )
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: rebuild baseline candidate on main ancestry")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.install_fake_gitleaks_report(
            [
                {
                    "RuleID": "generic-api-key",
                    "File": secret_path,
                    "StartLine": 2,
                    "Fingerprint": f"{head}:{secret_path}:generic-api-key:2",
                }
            ]
        )
        base_policy = self.baseline_policy_for(
            base_sha=base,
            head_sha=source,
            minimum_changed_files=1,
            gitleaks_allowlist=[
                {
                    "rule_id": "generic-api-key",
                    "path": secret_path,
                    "line": 1,
                    "fingerprint": f"{source}:{secret_path}:generic-api-key:1",
                    "expires_after": "2099-12-31T23:59:59Z",
                }
            ],
        )
        policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=False,
            body_extra=self.baseline_marker(),
            policy_path=policy,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")
        self.assertIn("Gitleaks detected secrets", report)

    def test_source_overlay_accepts_inherited_config_reference_fallback_secret(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_inherited_content_repo()
        fixture_path = "app/Services/Security/SmsGatewayService.php"
        self.git(repo, "checkout", "-q", "staging-source")
        self.write(
            repo / fixture_path,
            "<?php\n$this->line('Reference password: '.$result['admin']['password']);\n",
        )
        self.git(repo, "add", fixture_path)
        self.git(repo, "commit", "-q", "-m", "test: add inherited config-reference fixture")
        source = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "release/production-baseline-alignment-20260812", base)
        self.git(repo, "rm", "-qr", ".")
        completed = subprocess.run(["git", "checkout", source, "--", "."], cwd=repo, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review, edited]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n",
        )
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: rebuild baseline candidate on main ancestry")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        base_policy = self.baseline_policy_for(base_sha=base, head_sha=source, minimum_changed_files=1)
        policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=False,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "WARNING")
        self.assertIn("Inherited baseline secret-like false positives were classified", report)
        self.assertIn("app/Services/Security/SmsGatewayService.php: generic credential assignment", report)

    def test_source_overlay_rejects_inherited_literal_fallback_secret_without_exact_allowance(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_inherited_content_repo()
        fixture_path = "app/Services/Security/SmsGatewayService.php"
        self.git(repo, "checkout", "-q", "staging-source")
        self.write(repo / fixture_path, "<?php\n$password = 'literal-production-secret';\n")
        self.git(repo, "add", fixture_path)
        self.git(repo, "commit", "-q", "-m", "test: add inherited literal secret fixture")
        source = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-B", "release/production-baseline-alignment-20260812", base)
        self.git(repo, "rm", "-qr", ".")
        completed = subprocess.run(["git", "checkout", source, "--", "."], cwd=repo, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.write(repo / ".github" / "CODEOWNERS", "* @SaurabhVermaIN\n")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            "name: PR Quality Assurance\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review, edited]\njobs:\n  pr-qa:\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc13\n",
        )
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: rebuild baseline candidate on main ancestry")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        base_policy = self.baseline_policy_for(base_sha=base, head_sha=source, minimum_changed_files=1)
        policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=False,
            body_extra=self.baseline_marker(),
            policy_path=policy,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")
        self.assertIn("generic credential assignment", report)

    def test_authorized_telemedicine_baseline_blocks_new_non_inherited_findings(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        cases = [
            ("app/NewWhitespace.php", "<?php\nclass NewWhitespace {    \n}\n", "Git Validation", "trailing whitespace"),
            ("app/NewConflict.php", "<?php\n<<<<<<< HEAD\n", "Repository Hygiene", "Merge conflict markers found"),
            (".env.testing.example", "APP_ENV=testing\nAPP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nDB_PASSWORD=live-password\nHEALTH_WORKER_GOOGLE_ROUTES_API_KEY=\n", "Baseline Alignment", "candidate differs from approved application source outside the governance overlay"),
            ("public/assest/plugins/codemirror/mode/factor/factor.js", "const token = \"new-static-change-not-in-source\";\n", "Baseline Alignment", "candidate differs from approved application source outside the governance overlay"),
            (".github/workflows/new-deploy.yml", "name: new deploy\non: workflow_dispatch\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo production\n", "Baseline Alignment", "candidate differs from approved application source outside the governance overlay"),
            ("database/migrations/2026_08_12_000099_tamper.php", "<?php\nreturn new class { public function up() { Schema::dropIfExists('users'); } };\n", "Baseline Alignment", "candidate differs from approved application source outside the governance overlay"),
            ("composer.lock", json.dumps({"packages": [{"name": "unexpected/package", "version": "1.0.0"}]}), "Baseline Alignment", "candidate differs from approved application source outside the governance overlay"),
            ("docs/unexpected.md", "unexpected docs\n", "Baseline Alignment", "candidate differs from approved application source outside the governance overlay"),
        ]
        for path, content, expected_gate, needle in cases:
            with self.subTest(path=path):
                repo, base, source = self.init_inherited_content_repo(f"inherited-new-finding-{abs(hash(path))}")
                self.write(repo / path, content)
                self.commit(repo, "chore: introduce non inherited finding")
                head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
                base_policy = self.baseline_policy_for(base_sha=base, head_sha=source, minimum_changed_files=1)
                policy = self.source_overlay_policy_from_base(base_policy=base_policy, base_sha=base, source_sha=source)

                code, report, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    base,
                    base_ref="main",
                    head_ref="release/production-baseline-alignment-20260812",
                    head_sha=head,
                    repository="Synergie-ITCI/telemedicine-backend",
                    baseline_alignment=True,
                    body_extra=self.baseline_marker(),
                    policy_path=policy,
                )

                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"][expected_gate], "FAIL")
                self.assertIn(needle, report)

    def test_telemedicine_source_overlay_rejects_tamper_cases(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        cases = [
            ("app/Demo.php", "<?php\nclass Tampered {}\n", "candidate differs from approved application source outside the governance overlay"),
            ("routes/api.php", "<?php\nRoute::get('/tampered', fn () => 'bad');\n", "candidate differs from approved application source outside the governance overlay"),
            ("config/app.php", "<?php\nreturn ['debug' => true];\n", "candidate differs from approved application source outside the governance overlay"),
            ("database/migrations/2026_08_12_000002_tamper.php", "<?php\nreturn new class {};\n", "candidate differs from approved application source outside the governance overlay"),
            ("composer.json", json.dumps({"require": {"evil/package": "*"}}), "candidate differs from approved application source outside the governance overlay"),
            (".env.testing", "APP_ENV=testing\nDB_PASSWORD=real-password\n", "candidate differs from approved application source outside the governance overlay"),
            (".github/workflows/deploy.yml", "name: deploy\non: push\njobs: {}\n", "candidate differs from approved application source outside the governance overlay"),
            (".github/workflows/uat-operations.yml", "name: uat\non: workflow_dispatch\njobs: {}\n", "candidate differs from approved application source outside the governance overlay"),
            ("docs/extra.md", "extra\n", "candidate differs from approved application source outside the governance overlay"),
        ]
        for path, content, needle in cases:
            with self.subTest(path=path):
                repo, base, source = self.init_telemedicine_overlay_repo(f"telemedicine-tamper-{len(path)}-{abs(hash(path))}")
                self.write(repo / path, content)
                self.commit(repo, "chore: tamper with baseline candidate")
                head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
                policy = self.baseline_overlay_policy_for(base_sha=base, source_sha=source)

                code, report, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    base,
                    base_ref="main",
                    head_ref="release/production-baseline-alignment-20260812",
                    head_sha=head,
                    repository="Synergie-ITCI/telemedicine-backend",
                    baseline_alignment=True,
                    body_extra=self.baseline_marker(),
                    policy_path=policy,
                )

                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "FAIL")
                self.assertIn(needle, report)

    def test_telemedicine_source_overlay_rejects_governance_content_tamper(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        cases = [
            (".github/CODEOWNERS", "* @attacker\n", "does not match authorized base content"),
            (".github/actionlint.yaml", "config-variables: {}\n", "does not match authorized base content"),
            (
                ".github/workflows/pr-qa.yml",
                "name: PR Quality Assurance\non: [pull_request]\njobs:\n  pr-qa:\n    permissions: write-all\n    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@main\n",
                "must only update PR-QA caller",
            ),
        ]
        for path, content, needle in cases:
            with self.subTest(path=path):
                repo, base, source = self.init_telemedicine_overlay_repo(f"telemedicine-governance-tamper-{len(path)}-{abs(hash(path))}")
                self.write(repo / path, content)
                self.commit(repo, "chore: tamper with governance overlay")
                head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
                policy = self.baseline_overlay_policy_for(base_sha=base, source_sha=source)

                code, report, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    base,
                    base_ref="main",
                    head_ref="release/production-baseline-alignment-20260812",
                    head_sha=head,
                    repository="Synergie-ITCI/telemedicine-backend",
                    baseline_alignment=True,
                    body_extra=self.baseline_marker(),
                    policy_path=policy,
                )

                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "FAIL")
                self.assertIn(needle, report)

    def test_telemedicine_source_overlay_fails_closed_for_wrong_coordinates_marker_and_expiry(self) -> None:
        self.install_fake_composer(audit_exit=0, test_exit=0)
        repo, base, source = self.init_telemedicine_overlay_repo()
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        good_policy = self.baseline_overlay_policy_for(base_sha=base, source_sha=source)
        wrong_source_policy = self.baseline_overlay_policy_for(base_sha=base, source_sha=base)
        expired_policy = self.baseline_overlay_policy_for(base_sha=base, source_sha=source, expires_after="2000-01-01T00:00:00Z")
        cases = [
            {"repository": "Synergie-ITCI/other", "base_ref": "main", "head_ref": "release/production-baseline-alignment-20260812", "body": self.baseline_marker(), "policy": good_policy, "needle": "repository `Synergie-ITCI/other` is not authorized"},
            {"repository": "Synergie-ITCI/telemedicine-backend", "base_ref": "staging", "head_ref": "release/production-baseline-alignment-20260812", "body": self.baseline_marker(), "policy": good_policy, "needle": "target branch `staging` is not authorized"},
            {"repository": "Synergie-ITCI/telemedicine-backend", "base_ref": "main", "head_ref": "release/other", "body": self.baseline_marker(), "policy": good_policy, "needle": "source branch `release/other` is not authorized"},
            {"repository": "Synergie-ITCI/telemedicine-backend", "base_ref": "main", "head_ref": "release/production-baseline-alignment-20260812", "body": "", "policy": good_policy, "needle": "PR body is missing required baseline marker"},
            {"repository": "Synergie-ITCI/telemedicine-backend", "base_ref": "main", "head_ref": "release/production-baseline-alignment-20260812", "body": self.baseline_marker(), "policy": expired_policy, "needle": "baseline authorization expired"},
            {"repository": "Synergie-ITCI/telemedicine-backend", "base_ref": "main", "head_ref": "release/production-baseline-alignment-20260812", "body": self.baseline_marker(), "policy": wrong_source_policy, "needle": "candidate differs from approved application source outside the governance overlay"},
        ]
        for case in cases:
            with self.subTest(needle=case["needle"]):
                code, report, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    base,
                    base_ref=case["base_ref"],
                    head_ref=case["head_ref"],
                    head_sha=head,
                    repository=case["repository"],
                    baseline_alignment=True,
                    body_extra=case["body"],
                    policy_path=case["policy"],
                )
                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "FAIL")
                self.assertIn(case["needle"], report)

    def test_authorized_baseline_with_real_secret_still_fails(self) -> None:
        repo, base = self.init_repo("baseline-real-secret")
        self.write(repo / ".env", "PASSWORD=\"super-secret-value\"\n")
        for index in range(3):
            self.write(repo / "docs" / f"baseline-{index}.md", "baseline docs change\n")
        self.commit(repo, "legacy baseline import")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        policy = self.baseline_policy_for(base_sha=base, head_sha=head, minimum_changed_files=1)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=True,
            body_extra=self.baseline_marker(),
            policy_path=policy,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")
        self.assertIn("environment file committed", report)
        self.assertIn("generic credential assignment", report)

    def test_authorized_baseline_with_composer_advisory_still_fails(self) -> None:
        self.install_fake_composer(audit_exit=1, test_exit=0)
        repo, base = self.init_repo("baseline-composer-advisory")
        self.write(repo / "composer.json", json.dumps({"require": {}, "scripts": {"test": "echo ok"}}))
        self.write(repo / "composer.lock", json.dumps({"packages": [], "packages-dev": []}))
        self.write(repo / "app" / "Demo.php", "<?php\nclass Demo {}\n")
        self.commit(repo, "legacy baseline import")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        policy = self.baseline_policy_for(base_sha=base, head_sha=head)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=True,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Dependencies"], "FAIL")
        self.assertIn("Composer audit found vulnerabilities", report)

    def test_authorized_baseline_with_migration_syntax_failure_still_fails(self) -> None:
        repo, base = self.init_repo("baseline-migration-failure")
        self.write(repo / "composer.json", json.dumps({"require": {}}))
        self.write(repo / "composer.lock", json.dumps({"packages": [], "packages-dev": []}))
        self.write(repo / "database" / "migrations" / "2026_08_12_000001_broken.php", "<?php\nfunction broken( {\n")
        self.commit(repo, "legacy baseline import")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        policy = self.baseline_policy_for(base_sha=base, head_sha=head)

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            head_ref="release/production-baseline-alignment-20260812",
            head_sha=head,
            repository="Synergie-ITCI/telemedicine-backend",
            baseline_alignment=True,
            body_extra=self.baseline_marker(),
            policy_path=policy,
            review_policy={"mergeable": True, "reviews": []},
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "PASS")
        self.assertEqual(report_json["summary"]["gate_statuses"]["Lint"], "FAIL")
        self.assertIn("PHP syntax lint failed", report)

    def test_baseline_mode_fails_closed_for_wrong_repository_target_or_source(self) -> None:
        repo, base = self.init_repo("baseline-authorization-failures")
        self.write(repo / "docs" / "baseline.md", "baseline docs change\n")
        self.commit(repo, "legacy baseline import")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        policy = self.baseline_policy_for(base_sha=base, head_sha=head)

        cases = [
            {"repository": "Synergie-ITCI/saksham-backend", "base_ref": "main", "head_ref": "release/production-baseline-alignment-20260812", "needle": "repository `Synergie-ITCI/saksham-backend` is not authorized"},
            {"repository": "Synergie-ITCI/telemedicine-backend", "base_ref": "staging", "head_ref": "release/production-baseline-alignment-20260812", "needle": "target branch `staging` is not authorized"},
            {"repository": "Synergie-ITCI/telemedicine-backend", "base_ref": "main", "head_ref": "release/other-baseline", "needle": "source branch `release/other-baseline` is not authorized"},
            {"repository": "Synergie-ITCI/telemedicine-backend", "base_ref": "main", "head_ref": "agent/production-baseline", "needle": "source branch `agent/production-baseline` is not authorized"},
        ]
        for case in cases:
            with self.subTest(case=case["needle"]):
                code, report, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    base,
                    base_ref=case["base_ref"],
                    head_ref=case["head_ref"],
                    head_sha=head,
                    repository=case["repository"],
                    baseline_alignment=True,
                    body_extra=self.baseline_marker(),
                    policy_path=policy,
                )
                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "FAIL")
                self.assertIn(case["needle"], report)

    def test_baseline_authorization_removed_or_expired_fails_closed(self) -> None:
        repo, base = self.init_repo("baseline-expired")
        for index in range(3):
            self.write(repo / "docs" / f"baseline-{index}.md", "baseline docs change\n")
        self.commit(repo, "legacy baseline import")
        head = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        expired = self.baseline_policy_for(base_sha=base, head_sha=head, expires_after="2000-01-01T00:00:00Z")
        removed = self.baseline_policy_for(base_sha=base, head_sha=head, enabled=False)

        for policy in [expired, removed]:
            with self.subTest(policy=policy.name):
                code, report, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    base,
                    head_ref="release/production-baseline-alignment-20260812",
                    head_sha=head,
                    repository="Synergie-ITCI/telemedicine-backend",
                    baseline_alignment=True,
                    body_extra=self.baseline_marker(),
                    policy_path=policy,
                )
                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Baseline Alignment"], "FAIL")
                self.assertIn("authorization failed closed", report)

    def test_non_saurabh_authored_pr_blocks_without_independent_review(self) -> None:
        repo, base = self.init_repo("developer-no-review")
        self.write(repo / "README.md", "# regression\n\nDeveloper-authored change.\n")
        self.commit(repo, "docs: update developer fixture")
        for author in ["dev.ravi.ranjan", "dev.raveesh.yadav", "mohit.tiwari"]:
            with self.subTest(author=author):
                code, report, report_json, _ = self.run_engine_with_artifacts(
                    repo,
                    base,
                    base_ref="main",
                    head_ref="staging",
                    pr_author=author,
                    review_policy={"mergeable": True, "reviews": []},
                )
                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "FAIL")
                self.assertIn("Executive Release Authority approval is required", report)

    def test_non_saurabh_authored_pr_allows_green_with_independent_review(self) -> None:
        repo, base = self.init_repo("developer-reviewed-green")
        self.write(repo / "README.md", "# regression\n\nReviewed developer change.\n")
        self.commit(repo, "docs: update reviewed developer fixture")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="staging",
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
        self.assertTrue(any("Executive Release Authority review requirement is satisfied" in result["message"] for result in report_json["results"]))

    def test_gate_c_approval_from_other_reviewer_fails(self) -> None:
        repo, base = self.init_repo("developer-reviewed-by-other")
        self.write(repo / "README.md", "# regression\n\nWrong reviewer.\n")
        self.commit(repo, "docs: update wrong reviewer fixture")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="staging",
            pr_author="dev.raveesh.yadav",
            review_policy={
                "mergeable": True,
                "reviews": [
                    {"user": {"login": "another.reviewer"}, "state": "APPROVED"},
                ],
            },
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "FAIL")
        self.assertIn("required_approver=SaurabhVermaIN", report)

    def test_gate_c_owner_latest_review_must_be_approved(self) -> None:
        repo, base = self.init_repo("owner-review-not-latest-approved")
        self.write(repo / "README.md", "# regression\n\nStale owner approval.\n")
        self.commit(repo, "docs: update stale owner review fixture")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="staging",
            pr_author="dev.raveesh.yadav",
            review_policy={
                "mergeable": True,
                "reviews": [
                    {"user": {"login": "SaurabhVermaIN"}, "state": "APPROVED"},
                    {"user": {"login": "SaurabhVermaIN"}, "state": "CHANGES_REQUESTED"},
                ],
            },
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "FAIL")
        self.assertIn("Executive Release Authority approval is required", report)

    def test_gate_c_review_evidence_unavailable_fails_closed(self) -> None:
        repo, base = self.init_repo("gate-c-review-evidence-unavailable")
        self.write(repo / "README.md", "# regression\n\nUnavailable review evidence.\n")
        self.commit(repo, "docs: update unavailable evidence fixture")
        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            base_ref="main",
            head_ref="staging",
            pr_author="dev.raveesh.yadav",
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Review Policy"], "FAIL")
        self.assertIn("Independent review evidence is unavailable", report)

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

    def test_react_native_uses_node_audit_ci_and_skips_generic_native_builds(self) -> None:
        npm_log = self.tmp / "npm.log"
        fake_npm = self.bin / "npm"
        fake_npm.write_text(
            f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> {npm_log}
exit 0
""",
            encoding="utf-8",
        )
        fake_npm.chmod(0o755)
        fake_swift = self.bin / "swift"
        fake_swift.write_text("#!/usr/bin/env bash\nexit 99\n", encoding="utf-8")
        fake_swift.chmod(0o755)

        repo, base = self.init_repo("react-native-runtime")
        self.write(
            repo / "package.json",
            json.dumps(
                {
                    "dependencies": {"react-native": "0.87.0"},
                    "scripts": {
                        "audit:ci": "node scripts/audit-with-risk-acceptance.mjs",
                        "build": "tsc -p tsconfig.json",
                    },
                    "license": "UNLICENSED",
                }
            ),
        )
        self.write(repo / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {}}))
        self.write(repo / "src" / "app.ts", "export const ready = true;\n")
        self.write(repo / "scripts" / "audit-with-risk-acceptance.mjs", 'console.log("accepted audit remains visible");\n')
        self.write(repo / "android" / "settings.gradle", "pluginManagement {}\n")
        self.write(repo / "ios" / "SynergieGiving.xcodeproj" / "project.pbxproj", "// !$*UTF8*$!\n")
        self.commit(repo, "feat: add react native runtime fixture")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base)
        npm_commands = npm_log.read_text(encoding="utf-8")

        self.assertEqual(code, 0, report)
        self.assertIn("run audit:ci", npm_commands)
        self.assertNotIn("audit --audit-level", npm_commands)
        self.assertNotIn("Gradle assemble failed", report)
        self.assertNotIn("Swift dependency vulnerability audit requires configured tooling", report)
        self.assertTrue(
            any(
                result["gate"] == "Dependencies"
                and result["technology"] == "Node.js"
                and result["status"] == "PASS"
                and "`audit:ci` dependency audit passed" in result["message"]
                for result in report_json["results"]
            )
        )

    def test_codeowners_modification_fails(self) -> None:
        repo, base = self.init_repo("codeowners-change")
        self.write(repo / ".github" / "CODEOWNERS", "* @attacker\n")
        self.commit(repo, "chore: change owners")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("CODEOWNERS changes are not allowed", report)

    def test_codeowners_additive_protected_path_maintenance_passes(self) -> None:
        repo, base = self.init_repo_with_migration_protection("codeowners-maintenance")
        self.write(
            repo / ".github" / "CODEOWNERS",
            ".github/** @Synergie-ITCI/saurabh-pr-review-bypass\n"
            "apps/api/alembic/versions/** @Synergie-ITCI/saurabh-pr-review-bypass\n",
        )
        self.commit(repo, "chore: add migration codeowner")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "WARNING")
        self.assertIn("Controlled CODEOWNERS maintenance added protected-path coverage", report)
        self.assertIn("apps/api/alembic/versions/** @Synergie-ITCI/saurabh-pr-review-bypass", report)

    def test_codeowners_additive_maintenance_rejects_unverified_owner(self) -> None:
        repo, base = self.init_repo_with_migration_protection("codeowners-maintenance-unverified-owner")
        self.write(
            repo / ".github" / "CODEOWNERS",
            ".github/** @Synergie-ITCI/saurabh-pr-review-bypass\n"
            "apps/api/alembic/versions/** @Synergie-ITCI/database-admins\n",
        )
        self.commit(repo, "chore: add migration codeowner")

        code, report = self.run_engine(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertIn("new owners are not already present in base CODEOWNERS", report)

    def test_codeowners_additive_maintenance_rejects_bundled_app_changes(self) -> None:
        repo, base = self.init_repo_with_migration_protection("codeowners-maintenance-bundled")
        self.write(
            repo / ".github" / "CODEOWNERS",
            ".github/** @Synergie-ITCI/saurabh-pr-review-bypass\n"
            "apps/api/alembic/versions/** @Synergie-ITCI/saurabh-pr-review-bypass\n",
        )
        self.write(repo / "apps" / "api" / "alembic" / "versions" / "001_create_table.py", "# migration\n")
        self.commit(repo, "chore: add migration codeowner")

        code, report = self.run_engine(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertIn("CODEOWNERS maintenance PRs may change only one CODEOWNERS file", report)

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

    def init_fresh_onboarding_repo(self, name: str, base_files: dict[str, str] | None = None) -> tuple[Path, str]:
        repo = self.tmp / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "qa@example.invalid")
        self.git(repo, "config", "user.name", "QA Regression")
        self.write(repo / "README.md", "# fresh onboarding\n")
        for rel, text in (base_files or {}).items():
            self.write(repo / rel, text)
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: baseline")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "chore/governance-onboarding")
        return repo, base

    def canonical_caller_template(self) -> str:
        return (ROOT / "examples" / "caller-workflow.yml").read_text(encoding="utf-8")

    def canonical_pr_template(self) -> str:
        return (ROOT / "examples" / "pull_request_template.md").read_text(encoding="utf-8")

    def assert_fresh_onboarding_warning(self, report_json: dict, report: str) -> None:
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "WARNING")
        self.assertIn("Canonical fresh PR-QA onboarding matched the authoritative central templates", report)

    def test_canonical_fresh_onboarding_adds_both_bootstrap_files_warning(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-both")
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template())
        self.write(repo / ".github" / "pull_request_template.md", self.canonical_pr_template())
        self.commit(repo, "chore: onboard central pr qa")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertEqual(code, 0, report)
        self.assert_fresh_onboarding_warning(report_json, report)

    def test_canonical_fresh_onboarding_only_caller_new_template_already_base_warning(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-caller-only", {".github/pull_request_template.md": self.canonical_pr_template()})
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template())
        self.commit(repo, "chore: onboard central pr qa")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertEqual(code, 0, report)
        self.assert_fresh_onboarding_warning(report_json, report)

    def test_template_only_new_with_existing_caller_is_not_fresh_onboarding(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-template-only", {".github/workflows/pr-qa.yml": self.canonical_caller_template()})
        self.write(repo / ".github" / "pull_request_template.md", self.canonical_pr_template())
        self.commit(repo, "chore: add pull request template")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "FAIL")
        self.assertNotIn("Canonical fresh PR-QA onboarding", report)

    def test_fresh_onboarding_with_application_file_still_blocks(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-app-file")
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template())
        self.write(repo / "app" / "Http" / "Controller.php", "<?php\n")
        self.commit(repo, "chore: onboard with app file")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "FAIL")
        self.assertNotIn("Canonical fresh PR-QA onboarding", report)

    def test_fresh_onboarding_with_arbitrary_third_file_still_blocks(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-third-file")
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template())
        self.write(repo / ".github" / "README.md", "extra governance file\n")
        self.commit(repo, "chore: onboard with extra file")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "FAIL")
        self.assertNotIn("Canonical fresh PR-QA onboarding", report)

    def test_fresh_onboarding_with_repo_local_pr_qa_config_still_blocks(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-repo-config")
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template())
        self.write(repo / ".github" / "pr-qa.yml", "version: 1\n")
        self.commit(repo, "chore: onboard with repo config")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "FAIL")
        self.assertNotIn("Canonical fresh PR-QA onboarding", report)

    def test_codeowners_file_is_not_accepted_by_fresh_onboarding_exception(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-codeowners")
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template())
        self.write(repo / ".github" / "CODEOWNERS", ".github/** @Synergie-ITCI/saurabh-pr-review-bypass\n")
        self.commit(repo, "chore: onboard with codeowners")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "WARNING")
        self.assertIn("Base CODEOWNERS bootstrap detected", report)
        self.assertNotIn("Canonical fresh PR-QA onboarding", report)

    def test_fresh_onboarding_modified_caller_still_blocks(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-modified-caller")
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template().replace("issues: write", "issues: read", 1))
        self.write(repo / ".github" / "pull_request_template.md", self.canonical_pr_template())
        self.commit(repo, "chore: onboard modified caller")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "FAIL")
        self.assertNotIn("Canonical fresh PR-QA onboarding", report)

    def test_fresh_onboarding_modified_pr_template_still_blocks(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-modified-template")
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template())
        self.write(repo / ".github" / "pull_request_template.md", self.canonical_pr_template() + "\nExtra local section\n")
        self.commit(repo, "chore: onboard modified template")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "FAIL")
        self.assertNotIn("Canonical fresh PR-QA onboarding", report)

    def test_existing_bootstrap_path_modification_still_blocks(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-existing-path", {".github/workflows/pr-qa.yml": self.canonical_caller_template()})
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template() + "\n")
        self.commit(repo, "chore: modify existing caller")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "FAIL")
        self.assertNotIn("Canonical fresh PR-QA onboarding", report)

    def test_fresh_onboarding_base_evidence_error_fails_closed(self) -> None:
        engine = load_engine_module()
        repo, _ = self.init_fresh_onboarding_repo("fresh-onboarding-base-error")
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", self.canonical_caller_template())
        self.commit(repo, "chore: onboard central pr qa")
        ctx = engine.PRContext(
            repo=repo,
            config={"repository": {"protected_paths": [".github/**"]}},
            policy={},
            changed_files=[".github/workflows/pr-qa.yml"],
            base_ref="development",
            head_ref="chore/governance-onboarding",
        )

        results = engine.gate_protected_resources(ctx, {"base_sha": "0" * 40, "is_git_repo": True})

        self.assertEqual(results[0].status, "FAIL")
        self.assertIn("base-branch CODEOWNERS was not found", results[0].message)

    def test_non_bootstrap_protected_resource_without_codeowners_still_blocks(self) -> None:
        repo, base = self.init_fresh_onboarding_repo("fresh-onboarding-other-protected")
        self.write(repo / ".github" / "workflows" / "maintenance.yml", "name: maintenance\non: workflow_dispatch\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n")
        self.commit(repo, "chore: add protected workflow")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True, base_ref="development", head_ref="chore/governance-onboarding")

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "FAIL")
        self.assertIn("Protected resources changed but base-branch CODEOWNERS was not found", report)

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

    def test_exact_inherited_fallback_secret_noise_warns_without_line_number_binding(self) -> None:
        repo, base = self.init_repo("inherited-fallback-secret-noise")
        self.write(
            repo / "application" / "controllers" / "training.php",
            "<?php\n$URL = base_url().'certificate.php?token='.urlencode($certificate['AccessToken']);\n",
        )
        self.commit(repo, "feat: historical runtime token link")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.write(
            repo / "application" / "controllers" / "training.php",
            "<?php\n// line moved during unrelated edit\n$URL = base_url().'certificate.php?token='.urlencode($certificate['AccessToken']);\n",
        )
        self.commit(repo, "feat: unrelated controller change")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "WARNING")
        self.assertIn("Historical inherited credential-shaped fallback findings", report)

    def test_new_or_modified_fallback_secret_literal_still_fails(self) -> None:
        repo, base = self.init_repo("new-fallback-secret-literal")
        self.write(repo / "application" / "controllers" / "training.php", "<?php\n$password = 'new-secret-value';\n")
        self.commit(repo, "feat: add literal credential")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")
        self.assertIn("High-confidence secret indicators found", report)

    def test_modified_inherited_fallback_value_becomes_new_finding(self) -> None:
        repo, base = self.init_repo("modified-fallback-secret")
        self.write(repo / "application" / "controllers" / "training.php", "<?php\n$password = $runtime['AccessToken'];\n")
        self.commit(repo, "feat: historical runtime token reference")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.write(repo / "application" / "controllers" / "training.php", "<?php\n$password = 'changed-literal-secret';\n")
        self.commit(repo, "feat: modify token handling")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")

    def test_fake_env_looking_literal_secret_still_fails(self) -> None:
        repo, base = self.init_repo("fake-env-looking-secret")
        self.write(repo / "application" / "controllers" / "training.php", "<?php\n$password = \"env(API_KEY_SECRET)\";\n")
        self.commit(repo, "feat: fake env-looking literal")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "FAIL")

    def test_runtime_env_reference_is_not_literal_secret_failure_when_inherited(self) -> None:
        repo, base = self.init_repo("runtime-env-reference")
        self.write(
            repo / "application" / "controllers" / "driver.php",
            "<?php\nCURLOPT_POSTFIELDS => \"userId=\".rawurlencode(env('SMS_GATEWAY_USER', '')).\"&password=\".rawurlencode(env('SMS_GATEWAY_PASSWORD', ''));\n",
        )
        self.commit(repo, "feat: historical runtime env sms gateway")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.write(
            repo / "application" / "controllers" / "driver.php",
            "<?php\n// unrelated edit\nCURLOPT_POSTFIELDS => \"userId=\".rawurlencode(env('SMS_GATEWAY_USER', '')).\"&password=\".rawurlencode(env('SMS_GATEWAY_PASSWORD', ''));\n",
        )
        self.commit(repo, "feat: unrelated driver edit")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Secrets"], "WARNING")

    def test_obfuscated_destructive_migration_fails(self) -> None:
        repo, base = self.init_repo("migration")
        self.write(repo / "database" / "migrations" / "2026_01_01_000001_drop.php", "<?php\nDB::statement('DR' . 'OP TABLE users');\n")
        self.commit(repo, "feat: migration")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("CRITICAL migration risk", report)

    def test_laravel_down_only_destructive_migration_does_not_fail_forward_risk(self) -> None:
        repo, base = self.init_repo("laravel-down-only-migration")
        self.write(
            repo / "database" / "migrations" / "2026_01_01_000001_create_widgets.php",
            "<?php\n"
            "return new class {\n"
            "    public function up() { Schema::create('widgets', function ($table) {}); }\n"
            "    public function down() { Schema::dropIfExists('widgets'); }\n"
            "};\n",
        )
        self.commit(repo, "feat: add widget migration")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Migration Risk"], "WARNING")
        self.assertIn("LOW migration risk", report)
        self.assertNotIn("CRITICAL migration risk", report)

    def test_laravel_up_destructive_migration_still_fails(self) -> None:
        repo, base = self.init_repo("laravel-up-destructive-migration")
        self.write(
            repo / "database" / "migrations" / "2026_01_01_000001_drop_widgets.php",
            "<?php\n"
            "return new class {\n"
            "    public function up() { Schema::dropIfExists('widgets'); }\n"
            "    public function down() { Schema::create('widgets', function ($table) {}); }\n"
            "};\n",
        )
        self.commit(repo, "feat: add destructive migration")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Migration Risk"], "FAIL")
        self.assertIn("CRITICAL migration risk", report)

    def test_unknown_executable_language_fails(self) -> None:
        repo, base = self.init_repo("unknown-exec")
        self.write(repo / "src" / "server.js", "module.exports = () => 1\n")
        self.commit(repo, "feat: unclassified js")
        code, report = self.run_engine(repo, base, static_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("Executable code changed without a supported technology adapter", report)

    def test_bounded_static_browser_assets_do_not_require_node_manifest(self) -> None:
        cases = [
            "assets/js/site.js",
            "public/js/app.js",
            "static/js/site.js",
            "resources/js/browser-only.js",
        ]
        for rel in cases:
            with self.subTest(rel=rel):
                repo, base = self.init_repo("static-browser-" + rel.replace("/", "-"))
                self.write(repo / rel, "window.__asset = true;\n")
                self.commit(repo, "feat: browser asset")

                code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

                self.assertEqual(code, 0, report)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Executable Classification"], "WARNING")

    def test_executable_javascript_outside_bounded_static_roots_still_fails(self) -> None:
        cases = [
            "scripts/deploy.js",
            "tools/migrate.js",
            "bin/task.js",
            "server/index.js",
            "my-assets/js/tool.js",
        ]
        for rel in cases:
            with self.subTest(rel=rel):
                repo, base = self.init_repo("exec-js-" + rel.replace("/", "-"))
                self.write(repo / rel, "require('fs').writeFileSync('/tmp/out', 'x');\n")
                self.commit(repo, "feat: executable js")

                code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

                self.assertNotEqual(code, 0)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Executable Classification"], "FAIL")
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

        self.assertNotEqual(code, 0, report)
        self.assertNotIn("Approved central governance workflow/template changes", report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Deployment Risk"], "FAIL")

    def controlled_gate_d_workflow(
        self,
        *,
        actor: bool = True,
        rollback: bool = True,
        push_main: bool = False,
        static_creds: bool = False,
        arbitrary_ref: bool = False,
        runtime_certifier: bool = True,
        runtime_guard: bool = True,
        runtime_release: str = "runtime-certifier-action-v1",
        certifier_after_deploy: bool = False,
    ) -> str:
        lines = [
            "name: Controlled Production Gate D",
            "on:",
            "  workflow_dispatch:",
            "    inputs:",
            "      operation:",
            "        required: true",
            "        type: string",
            "      deploy_ref:",
            "        required: true",
            "        type: string",
        ]

        if rollback:
            lines.extend([
                "      rollback_ref:",
                "        required: true",
                "        type: string",
            ])

        lines.extend([
            "      approval_reference:",
            "        required: true",
            "        type: string",
        ])

        if push_main:
            lines.extend([
                "  push:",
                "    branches:",
                "      - main",
            ])

        lines.extend([
            "permissions:",
            "  contents: read",
            "  id-token: write",
            "jobs:",
            "  deploy:",
            "    runs-on: ubuntu-latest",
            "    env:",
        ])

        if static_creds:
            lines.append(
                "      AWS_ACCESS_KEY_ID: ${{ secrets.PROD_AWS_ACCESS_KEY_ID }}"
            )

        lines.extend([
            "      APP_PATH: /srv/production-app",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "      - name: Validate request",
            "        env:",
            "          DEPLOY_REF: ${{ inputs.deploy_ref }}",
            "          ROLLBACK_REF: ${{ inputs.rollback_ref }}",
            "          APPROVAL: ${{ inputs.approval_reference }}",
            "        run: |",
            "          set -euo pipefail",
        ])

        if actor:
            lines.append(
                '          test "${GITHUB_ACTOR}" = "ReleaseAuthority"'
            )

        lines.append(
            '          test -n "${APPROVAL}"'
        )

        if not arbitrary_ref:
            lines.extend([
                '          [[ "${DEPLOY_REF}" =~ ^[0-9a-f]{40}$ ]]',
                '          MAIN_SHA="$(git rev-parse HEAD)"',
                '          test "${DEPLOY_REF}" = "${MAIN_SHA}"',
            ])

        if rollback:
            lines.extend([
                '          [[ "${ROLLBACK_REF}" =~ ^[0-9a-f]{40}$ ]]',
                '          CURRENT_SHA="$(git rev-parse HEAD)"',
                '          test "$CURRENT_SHA" = "$ROLLBACK_REF"',
                '          git reset --hard "$ROLLBACK_REF"',
            ])

        lines.extend([
            "      - uses: aws-actions/configure-aws-credentials@v4",
            "        with:",
            "          role-to-assume: arn:aws:iam::123456789012:role/AppProductionDeployRole",
            "          aws-region: ap-south-1",
        ])

        runtime_lines = []
        if runtime_certifier:
            runtime_lines = [
                "      - name: Runtime Certifier",
                "        id: runtime",
                f"        uses: Synergie-ITCI/.github/actions/runtime-certifier@{runtime_release}",
                "        with:",
                "          instance-id: i-0123456789abcdef0",
                "          app-path: /srv/production-app",
                "          app-user: deploy",
                "          validation-url: https://example.invalid/health",
                "          deploy-ref: ${{ inputs.deploy_ref }}",
                "          rollback-ref: ${{ inputs.rollback_ref }}",
                '          runtime-version: "8.2"',
            ]

        if runtime_lines and not certifier_after_deploy:
            lines.extend(runtime_lines)

        lines.append(
            "      - name: Gate D via SSM"
        )

        if runtime_guard:
            lines.append(
                "        if: ${{ steps.runtime.outputs.deployment-required == 'true' }}"
            )

        lines.extend([
            "        run: |",
            "          aws ssm send-command --document-name AWS-RunShellScript --parameters commands='[\"sudo systemctl reload app\"]'",
        ])

        if runtime_lines and certifier_after_deploy:
            lines.extend(runtime_lines)

        return "\n".join(lines) + "\n"

    def test_controlled_manual_gate_d_safe_shape_warns_without_phase1_failure(self) -> None:
        repo, base = self.init_repo("controlled-gate-d")
        self.write(repo / ".github" / "workflows" / "production-deploy.yml", self.controlled_gate_d_workflow())
        self.commit(repo, "ci: add controlled gate d")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Deployment Risk"], "WARNING")
        self.assertIn("CONTROLLED_PRODUCTION_GATE_D", report)

    def test_fallback_parser_preserves_controlled_gate_d_steps(self) -> None:
        engine = load_engine_module()
        parsed = engine.parse_simple_yaml(self.controlled_gate_d_workflow())

        steps = parsed["jobs"]["deploy"]["steps"]

        self.assertEqual(len(steps), 5)
        self.assertEqual(steps[0]["uses"], "actions/checkout@v4")
        self.assertEqual(steps[1]["name"], "Validate request")
        self.assertEqual(steps[2]["uses"], "aws-actions/configure-aws-credentials@v4")
        self.assertEqual(steps[3]["name"], "Runtime Certifier")
        self.assertEqual(steps[3]["id"], "runtime")
        self.assertEqual(
            steps[3]["uses"],
            "Synergie-ITCI/.github/actions/runtime-certifier@runtime-certifier-action-v1",
        )
        self.assertEqual(steps[4]["name"], "Gate D via SSM")
        self.assertEqual(
            steps[4]["if"],
            "${{ steps.runtime.outputs.deployment-required == 'true' }}",
        )

    def test_controlled_gate_d_missing_mandatory_conditions_fails(self) -> None:
        cases = {
            "without-actor": {"actor": False},
            "without-rollback": {"rollback": False},
            "with-push-main": {"push_main": True},
            "with-static-creds": {"static_creds": True},
            "arbitrary-ref": {"arbitrary_ref": True},
            "without-runtime-certifier": {"runtime_certifier": False},
            "without-runtime-guard": {"runtime_guard": False},
            "mutable-runtime-release": {"runtime_release": "main"},
            "certifier-after-deploy": {"certifier_after_deploy": True},
        }
        for name, kwargs in cases.items():
            with self.subTest(name=name):
                repo, base = self.init_repo("unsafe-gate-d-" + name)
                self.write(repo / ".github" / "workflows" / "production-deploy.yml", self.controlled_gate_d_workflow(**kwargs))
                self.commit(repo, "ci: add unsafe gate d")

                code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

                self.assertNotEqual(code, 0, report)
                self.assertEqual(report_json["summary"]["gate_statuses"]["Deployment Risk"], "FAIL")

    def test_staging_only_ssh_workflow_warns_without_production_block(self) -> None:
        repo, base = self.init_repo("staging-only-ssh")
        self.write(
            repo / ".github" / "workflows" / "deploy.yml",
            """name: Deploy Staging
on:
  push:
    branches:
      - staging
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: webfactory/ssh-agent@v0.10.0
        with:
          ssh-private-key: ${{ secrets.STAGING_SSH_PRIVATE_KEY }}
      - run: ssh deployer@staging.example.invalid 'cd /srv/staging-app && git merge --ff-only FETCH_HEAD'
""",
        )
        self.commit(repo, "ci: add staging deploy")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Deployment Risk"], "WARNING")
        self.assertIn("STAGING_ONLY_DEPLOYMENT", report)

    def test_staging_workflow_with_hidden_production_target_fails(self) -> None:
        repo, base = self.init_repo("staging-hidden-production")
        self.write(
            repo / ".github" / "workflows" / "deploy.yml",
            """name: Deploy Staging
on:
  push:
    branches:
      - staging
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ssh deployer@staging.example.invalid 'if [ "$BRANCH" = main ]; then cd /srv/production-app; fi'
""",
        )
        self.commit(repo, "ci: add staging deploy with hidden production")

        code, report, report_json, _ = self.run_engine_with_artifacts(repo, base, static_only=True)

        self.assertNotEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Deployment Risk"], "FAIL")

    def test_canonical_staging_to_main_deployment_risk_uses_final_tree_equivalence(self) -> None:
        repo, base = self.init_repo("canonical-promotion-final-tree-equivalent")
        workflow = "name: Deploy\non: workflow_dispatch\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo production review only\n"

        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.write(repo / ".github" / "workflows" / "deploy.yml", workflow)
        self.commit(repo, "ci: add reviewed deployment workflow")
        main_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.git(repo, "checkout", "-q", "-B", "staging", base)
        self.write(repo / ".github" / "workflows" / "deploy.yml", workflow)
        self.commit(repo, "ci: add staging deployment workflow")
        staging_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            main_sha,
            static_only=True,
            base_ref="main",
            head_ref="staging",
            head_sha=staging_sha,
        )

        self.assertEqual(code, 0, report)
        self.assertTrue(
            any(
                result["gate"] == "Deployment Risk"
                and result["status"] == "PASS"
                and "final-tree changes" in result["message"]
                for result in report_json["results"]
            ),
            report,
        )

    def test_canonical_staging_to_main_uses_current_base_when_event_sha_is_stale(self) -> None:
        repo, base = self.init_repo("canonical-promotion-stale-event-base")
        workflow = (
            "name: Deploy\non: workflow_dispatch\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: ssh deployer@production.example.invalid ./deploy-production.sh\n"
            "      - run: rsync -av build/ prod:/var/www\n"
            "      - run: sudo terraform apply -auto-approve\n"
        )

        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.write(repo / ".github" / "workflows" / "deploy.yml", workflow)
        self.commit(repo, "ci: add reviewed deployment workflow")
        current_main_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "update-ref", "refs/remotes/origin/main", current_main_sha)

        self.git(repo, "checkout", "-q", "-B", "staging", base)
        self.write(repo / ".github" / "workflows" / "deploy.yml", workflow)
        self.write(repo / ".env.example", "APP_ENV=production\nRAZORPAY_MODE=prod\n")
        self.commit(repo, "chore: prepare staging promotion")
        staging_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="main",
            head_ref="staging",
            head_sha=staging_sha,
        )

        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["baseline_alignment"]["destination_sha"], current_main_sha)
        self.assertNotIn(".github/workflows/deploy.yml: +", report)
        self.assertTrue(
            any(
                result["gate"] == "Deployment Risk"
                and result["status"] == "WARNING"
                and result["message"] == "Deployment-sensitive changes detected. Risk: LOW."
                for result in report_json["results"]
            ),
            report,
        )

    def test_canonical_staging_to_main_deployment_risk_blocks_real_final_tree_change(self) -> None:
        repo, base = self.init_repo("canonical-promotion-real-deploy-change")
        main_workflow = "name: Deploy\non: workflow_dispatch\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo reviewed deployment\n"
        staging_workflow = (
            "name: Deploy\non: workflow_dispatch\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: ssh deployer@production.example.invalid ./deploy-production.sh\n"
            "      - run: rsync -av build/ prod:/var/www\n"
            "      - run: sudo kubectl apply -f k8s/production.yml\n"
            "      - run: terraform apply -auto-approve\n"
        )

        self.git(repo, "checkout", "-q", "-B", "main", base)
        self.write(repo / ".github" / "workflows" / "deploy.yml", main_workflow)
        self.commit(repo, "ci: add reviewed deployment workflow")
        main_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        self.git(repo, "checkout", "-q", "-B", "staging", base)
        self.write(repo / ".github" / "workflows" / "deploy.yml", staging_workflow)
        self.commit(repo, "ci: add production deploy command")
        staging_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            main_sha,
            static_only=True,
            base_ref="main",
            head_ref="staging",
            head_sha=staging_sha,
        )

        self.assertNotEqual(code, 0, report)
        self.assertTrue(
            any(
                result["gate"] == "Deployment Risk"
                and result["status"] == "FAIL"
                and "structurally unsafe" in result["message"]
                for result in report_json["results"]
            ),
            report,
        )

    def test_workflow_has_no_framework_override_or_checkout_credentials(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "pr-qa.yml").read_text(encoding="utf-8")
        self_workflow = (ROOT / ".github" / "workflows" / "pr-qa-self.yml").read_text(encoding="utf-8")
        caller = (ROOT / "examples" / "caller-workflow.yml").read_text(encoding="utf-8")
        self.assertNotIn("framework-ref", workflow + caller)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("Fetch current pull request base branch", workflow)
        self.assertIn("refs/remotes/origin/${BASE_REF}", workflow)
        self.assertIn('PR_QA_FRAMEWORK_RELEASE: "pr-qa-v1-rc63"', workflow)
        self.assertIn("issues: write", workflow)
        self.assertIn("issues: write", self_workflow)
        self.assertIn("issues: write", caller)
        self.assertEqual(workflow.count("GH_TOKEN: ${{ github.token }}"), 6)
        # The starter onboarding caller consumes the centrally maintained workflow
        # and initially covers all PR boundaries.
        self.assertIn("@main", caller)
        self.assertNotIn("branches-ignore:", caller)
        self.assertIn("resolve_node_version.py", workflow)
        self.assertIn("resolve_php_version.py", workflow)
        self.assertIn("postgres:16", workflow)
        self.assertIn("POSTGRES_DB: telepathy_test", workflow)
        self.assertIn("CREATE ROLE runner LOGIN", workflow)
        self.assertIn("opentofu/setup-opentofu@v1", workflow)
        self.assertIn("tfsec_${TFSEC_VERSION}_linux_amd64.tar.gz", workflow)
        self.assertIn("name: pr-qa", self_workflow)

    def test_workflow_cli_contract_matches_pinned_framework_release(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "pr-qa.yml").read_text(encoding="utf-8")
        release_match = re.search(r'PR_QA_FRAMEWORK_RELEASE:\s*"([^"]+)"', workflow)
        self.assertIsNotNone(release_match)
        release = release_match.group(1)

        tag_sha = subprocess.run(
            ["git", "rev-parse", f"{release}^{{commit}}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(tag_sha.returncode, 0, tag_sha.stderr)
        self.assertRegex(tag_sha.stdout.strip(), r"^[0-9a-f]{40}$")

        pinned_parser = subprocess.run(
            ["git", "show", f"{release}:pr-qa/pr_qa.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(pinned_parser.returncode, 0, pinned_parser.stderr)

        workflow_options = self.pr_qa_workflow_options(workflow)
        parser_options = set(
            re.findall(r"add_argument\(\s*['\"](--[A-Za-z0-9][A-Za-z0-9_-]*)['\"]", pinned_parser.stdout)
        )
        missing = sorted(workflow_options - parser_options)
        self.assertEqual(missing, [])

        required_reuse_options = {
            "--technical-baseline-key-out",
            "--technical-baseline-in",
            "--technical-baseline-out",
            "--qa-packet-out",
            "--publish-pr-status-comment",
            "--status-json-in",
        }
        self.assertTrue(required_reuse_options <= workflow_options)
        self.assertTrue(required_reuse_options <= parser_options)
        self.assertEqual(sorted((workflow_options | {"--future-unsupported-option"}) - parser_options), ["--future-unsupported-option"])

    def test_release_drift_passes_when_release_sensitive_content_matches(self) -> None:
        engine = load_engine_module()
        repo = self.framework_release_repo("release-drift-match")

        state = engine.framework_release_state(repo)

        self.assertEqual(state["active_pr_qa_release"], "pr-qa-v1-test")
        self.assertEqual(state["framework_main_matches_active_release"], "PASS")
        self.assertEqual(state["release_required"], "NO")

    def test_release_drift_fails_when_pr_qa_engine_changes(self) -> None:
        engine = load_engine_module()
        repo = self.framework_release_repo("release-drift-engine")
        self.write(repo / "pr-qa" / "pr_qa.py", "print('changed')\n")

        state = engine.framework_release_state(repo)

        self.assertEqual(state["framework_main_matches_active_release"], "FAIL")
        self.assertEqual(state["release_required"], "YES")
        self.assertIn("pr-qa/pr_qa.py", "\n".join(state["details"]))

    def test_release_drift_fails_when_policy_or_runtime_dependency_changes(self) -> None:
        engine = load_engine_module()
        repo = self.framework_release_repo("release-drift-policy")
        self.write(repo / "policy" / "pr-qa-policy.json", "{\"version\": 2}\n")
        self.write(repo / "pr-qa" / "adapters" / "php.py", "PHP = 'changed'\n")

        state = engine.framework_release_state(repo)

        self.assertEqual(state["framework_main_matches_active_release"], "FAIL")
        self.assertEqual(state["release_required"], "YES")
        details = "\n".join(state["details"])
        self.assertIn("policy/pr-qa-policy.json", details)
        self.assertIn("pr-qa/adapters/php.py", details)

    def test_release_drift_ignores_docs_only_changes(self) -> None:
        engine = load_engine_module()
        repo = self.framework_release_repo("release-drift-docs")
        self.write(repo / "docs" / "guide.md", "# updated docs\n")

        state = engine.framework_release_state(repo)

        self.assertEqual(state["framework_main_matches_active_release"], "PASS")
        self.assertEqual(state["release_required"], "NO")

    def test_release_drift_fails_closed_when_active_release_cannot_be_resolved(self) -> None:
        engine = load_engine_module()
        repo = self.framework_release_repo("release-drift-missing-tag")
        self.write(
            repo / ".github" / "workflows" / "pr-qa.yml",
            'env:\n  PR_QA_FRAMEWORK_RELEASE: "pr-qa-v1-missing"\n',
        )

        state = engine.framework_release_state(repo)

        self.assertEqual(state["active_pr_qa_release"], "pr-qa-v1-missing")
        self.assertEqual(state["framework_main_matches_active_release"], "FAIL")
        self.assertEqual(state["release_required"], "YES")

    def test_release_drift_report_exposes_requested_fields_without_blocking_merge(self) -> None:
        repo = self.framework_release_repo("release-drift-report")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.git(repo, "checkout", "-q", "-b", "feature/release-drift")
        self.write(repo / "pr-qa" / "pr_qa.py", "print('changed')\n")
        self.commit(repo, "fix: change framework")

        code, report, report_json, _ = self.run_engine_with_artifacts(
            repo,
            base,
            static_only=False,
            repository="Synergie-ITCI/.github",
            extra_args=["--repository-profile", "framework", "--no-command-runs"],
        )

        self.assertEqual(code, 0, report)
        self.assertIn("ACTIVE_PR_QA_RELEASE: pr-qa-v1-test", report)
        self.assertIn("FRAMEWORK_MAIN_MATCHES_ACTIVE_RELEASE: FAIL", report)
        self.assertIn("RELEASE_REQUIRED: YES", report)
        self.assertEqual(report_json["summary"]["active_pr_qa_release"], "pr-qa-v1-test")
        self.assertEqual(report_json["summary"]["framework_main_matches_active_release"], "FAIL")
        self.assertEqual(report_json["summary"]["release_required"], "YES")
        release_result = next(result for result in report_json["results"] if result["gate"] == "Release Drift")
        self.assertFalse(release_result["blocking"])

    def pr_qa_workflow_options(self, workflow: str) -> set[str]:
        lines = workflow.splitlines()
        options: set[str] = set()
        index = 0
        while index < len(lines):
            line = lines[index]
            if "python3 .pr-qa-framework/pr-qa/pr_qa.py" not in line:
                index += 1
                continue
            command = [line]
            index += 1
            while index < len(lines):
                command.append(lines[index])
                if not lines[index].rstrip().endswith("\\"):
                    break
                index += 1
            command_text = "\n".join(command)
            options.update(re.findall(r"(?<![\w-])(--[A-Za-z0-9][A-Za-z0-9_-]*)", command_text))
            if '"${profile_args[@]}"' in command_text:
                options.add("--repository-profile")
            index += 1
        return options

    def framework_release_repo(self, name: str) -> Path:
        repo = self.tmp / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "qa@example.invalid")
        self.git(repo, "config", "user.name", "QA Regression")
        self.write(repo / ".github" / "workflows" / "pr-qa.yml", 'env:\n  PR_QA_FRAMEWORK_RELEASE: "pr-qa-v1-test"\n')
        self.write(repo / ".github" / "pr-qa.yml", self.base_config(profile="framework"))
        self.write(repo / ".github" / "CODEOWNERS", "* @synergie/security\n")
        self.write(repo / "policy" / "pr-qa-policy.json", "{\"version\": 1}\n")
        self.write(repo / "pr-qa" / "pr_qa.py", "print('engine')\n")
        self.write(repo / "pr-qa" / "resolve_node_version.py", "print('node')\n")
        self.write(repo / "pr-qa" / "resolve_php_version.py", "print('php')\n")
        self.write(repo / "pr-qa" / "adapters" / "__init__.py", "")
        self.write(repo / "pr-qa" / "adapters" / "php.py", "PHP = 'runtime'\n")
        self.write(repo / "docs" / "guide.md", "# docs\n")
        self.commit(repo, "chore: baseline")
        self.git(repo, "tag", "pr-qa-v1-test")
        return repo

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

    def test_php_version_resolver_honors_locked_package_runtime_floor(self) -> None:
        repo = self.tmp / "php-version-84"
        repo.mkdir()
        self.write(
            repo / "composer.lock",
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "symfony/yaml",
                            "require": {"php": ">=8.4.1"},
                        }
                    ],
                    "packages-dev": [],
                    "platform": {"php": "^8.2"},
                }
            ),
        )

        completed = subprocess.run(["python3", str(PHP_RESOLVER), str(repo)], text=True, capture_output=True, check=False)

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), "php-version=8.4")

    def test_php_version_resolver_preserves_default_without_higher_floor(self) -> None:
        repo = self.tmp / "php-version-default"
        repo.mkdir()
        self.write(repo / "composer.json", json.dumps({"require": {"php": "^8.2"}}))

        completed = subprocess.run(["python3", str(PHP_RESOLVER), str(repo)], text=True, capture_output=True, check=False)

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), "php-version=8.2")

    def test_php_pint_failure_path_parser_extracts_only_reported_php_files(self) -> None:
        sys.path.insert(0, str(ROOT / "pr-qa"))
        try:
            from adapters.php import pint_failure_paths
        finally:
            sys.path.pop(0)

        output = """
  ──────────────────────────────────────────────────────────────────── Laravel
    FAIL   ......................................... 863 files, 8 style issues
  ⨯ app/Http/Controllers/API/ToBeDeleted/AgoraController.php     phpdoc_indent
  ⨯ app/Http/Controllers/AppointmentController.php phpdoc_indent, fully_quali…
  plain diagnostic line
"""

        self.assertEqual(
            pint_failure_paths(output),
            [
                "app/Http/Controllers/API/ToBeDeleted/AgoraController.php",
                "app/Http/Controllers/AppointmentController.php",
            ],
        )

    def test_php_pint_formats_only_changed_php_files_not_legacy_debt(self) -> None:
        sys.path.insert(0, str(ROOT / "pr-qa"))
        try:
            from adapters.php import PhpAdapter
            from adapters.base import PASS, PRContext
        finally:
            sys.path.pop(0)

        repo = self.tmp / "php-pint-changed-only"
        self.write(repo / "vendor" / "bin" / "pint", "")
        self.write(repo / "app" / "LegacyBad.php", "<?php echo 'legacy';\n")
        self.write(repo / "app" / "ChangedClean.php", "<?php echo 'changed';\n")
        args_file = self.tmp / "pint-args.txt"
        fake_php = self.bin / "php"
        fake_php.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "pathlib.Path(os.environ['PINT_ARGS_FILE']).write_text(' '.join(sys.argv[1:]), encoding='utf-8')\n"
            "sys.exit(1 if any('LegacyBad.php' in arg for arg in sys.argv[1:]) else 0)\n",
            encoding="utf-8",
        )
        fake_php.chmod(0o755)
        ctx = PRContext(
            repo=repo,
            config={"runtime": {"install_dependencies": False}},
            policy={},
            changed_files=["app/ChangedClean.php"],
        )

        with mock.patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""), "PINT_ARGS_FILE": str(args_file)}):
            results = PhpAdapter().format(ctx, [repo])

        self.assertEqual(results[0].status, PASS)
        self.assertIn("app/ChangedClean.php", args_file.read_text(encoding="utf-8"))
        self.assertNotIn("app/LegacyBad.php", args_file.read_text(encoding="utf-8"))

    def test_php_pint_changed_file_formatting_failure_still_blocks(self) -> None:
        sys.path.insert(0, str(ROOT / "pr-qa"))
        try:
            from adapters.php import PhpAdapter
            from adapters.base import FAIL, PRContext
        finally:
            sys.path.pop(0)

        repo = self.tmp / "php-pint-changed-fails"
        self.write(repo / "vendor" / "bin" / "pint", "")
        self.write(repo / "app" / "ChangedBad.php", "<?php echo 'bad';\n")
        fake_php = self.bin / "php"
        fake_php.write_text("#!/usr/bin/env bash\necho 'changed file needs formatting'\nexit 1\n", encoding="utf-8")
        fake_php.chmod(0o755)
        ctx = PRContext(
            repo=repo,
            config={"runtime": {"install_dependencies": False}},
            policy={},
            changed_files=["app/ChangedBad.php"],
        )

        sys.path.insert(0, str(ROOT / "pr-qa"))
        try:
            with mock.patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", "")}):
                results = PhpAdapter().format(ctx, [repo])
        finally:
            sys.path.pop(0)

        self.assertEqual(results[0].status, FAIL)
        self.assertIn("Laravel Pint failed", results[0].message)

    def test_php_pint_no_changed_php_files_does_not_scan_tree(self) -> None:
        sys.path.insert(0, str(ROOT / "pr-qa"))
        try:
            from adapters.php import PhpAdapter
            from adapters.base import PASS, PRContext
        finally:
            sys.path.pop(0)

        repo = self.tmp / "php-pint-no-php-changes"
        self.write(repo / "vendor" / "bin" / "pint", "")
        self.write(repo / "app" / "LegacyBad.php", "<?php echo 'legacy';\n")
        fake_php = self.bin / "php"
        fake_php.write_text("#!/usr/bin/env bash\nexit 99\n", encoding="utf-8")
        fake_php.chmod(0o755)
        ctx = PRContext(
            repo=repo,
            config={"runtime": {"install_dependencies": False}},
            policy={},
            changed_files=["README.md"],
        )

        with mock.patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", "")}):
            results = PhpAdapter().format(ctx, [repo])

        self.assertEqual(results[0].status, PASS)
        self.assertEqual(ctx.command_log, [])
        self.assertIn("No changed PHP files", results[0].message)

    def test_timeout_bytes_are_normalized_before_command_logging(self) -> None:
        sys.path.insert(0, str(ROOT / "pr-qa"))
        try:
            from adapters.base import PRContext
        finally:
            sys.path.pop(0)

        repo = self.tmp / "timeout-bytes"
        repo.mkdir()
        ctx = PRContext(repo=repo, config={}, policy={}, changed_files=[])

        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(["fake"], timeout=1, output=b"stdout bytes", stderr=b"stderr bytes"),
        ):
            outcome = ctx.run(["fake"], cwd=repo, timeout=1)

        self.assertTrue(outcome.timed_out)
        self.assertIsInstance(outcome.stdout, str)
        self.assertIsInstance(outcome.stderr, str)
        self.assertIn("stdout bytes", outcome.concise_output())
        self.assertIn("stderr bytes", outcome.concise_output())
        self.assertTrue(ctx.command_log)

    def test_python_adapter_uses_current_interpreter_without_python_shim(self) -> None:
        fake_bin = self.tmp / "python-path-without-python"
        fake_bin.mkdir()
        fake_gitleaks = fake_bin / "gitleaks"
        fake_gitleaks.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        fake_gitleaks.chmod(0o755)
        fake_python = fake_bin / "python"
        fake_python.write_text("#!/usr/bin/env bash\nexit 127\n", encoding="utf-8")
        fake_python.chmod(0o755)
        fake_pip_audit = fake_bin / "pip-audit"
        fake_pip_audit.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        fake_pip_audit.chmod(0o755)
        repo, base = self.init_repo("python-no-python-shim")
        self.write(repo / ".github" / "pr-qa.yml", self.base_config() + "runtime:\n  install_dependencies: false\n  allow_network_installs: false\n")
        self.git(repo, "add", ".github/pr-qa.yml")
        self.git(repo, "commit", "-q", "-m", "chore: configure python fixture qa")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.write(repo / "app.py", "print('ok')\n")
        self.commit(repo, "feat: add python fixture")
        env = dict(self.env)
        env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
        event = repo / "event.json"
        event.write_text(
            json.dumps(
                {
                    "pull_request": {
                        "number": 123,
                        "user": {"login": "SaurabhVermaIN"},
                        "base": {"sha": base, "ref": "main"},
                        "head": {"sha": "HEAD", "ref": "feature/regression"},
                        "body": "## Business Purpose\nRegression.\n## Testing Performed\nUnit.\n## Rollback Strategy\nRevert.\n## Linked Issue\nhttps://github.com/Synergie-ITCI/.github/issues/123\n",
                    }
                }
            ),
            encoding="utf-8",
        )

        completed = subprocess.run(
            [
                sys.executable,
                str(ENGINE),
                "--repo",
                str(repo),
                "--event-path",
                str(event),
                "--out",
                str(repo / "report.md"),
                "--json-out",
                str(repo / "report.json"),
            ],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

        report = (repo / "report.md").read_text(encoding="utf-8")
        report_json = json.loads((repo / "report.json").read_text(encoding="utf-8"))
        commands = json.loads((repo / "report.json").read_text(encoding="utf-8"))["commands"]
        self.assertNotIn("No such file or directory: 'python'", completed.stderr + report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Build"], "PASS")
        self.assertTrue(any(sys.executable in command["command"] and "compileall" in command["command"] for command in commands))
        self.assertFalse(any(command["command"].startswith("python -m compileall") for command in commands))

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

    def test_pr_status_comment_blocks_developer_failures_with_actionable_guidance(self) -> None:
        engine = load_engine_module()
        body = engine.render_pr_status_comment(
            self.status_report(
                "FAIL",
                "staging",
                "feature/work",
                [
                    {"gate": "Tests", "status": "FAIL", "blocking": True, "message": "Tests failed."},
                    {"gate": "Repository Hygiene", "status": "FAIL", "blocking": True, "message": "Branch is behind."},
                ],
            ),
            self.status_event("developer"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "behind"}, "reviews": []},
        )

        self.assertIn("STATUS: BLOCKED", body)
        self.assertIn("- Automated tests failed", body)
        self.assertIn("- Your branch is behind staging", body)
        self.assertIn("SAURABH APPROVAL REQUIRED: NO", body)
        self.assertIn("align locally with the latest staging branch", body)
        self.assertNotIn("Update branch", body)

    def test_pr_status_comment_explains_secret_failure_actionably(self) -> None:
        engine = load_engine_module()
        body = engine.render_pr_status_comment(
            self.status_report(
                "FAIL",
                "development",
                "feature/work",
                [
                    {
                        "gate": "Secrets",
                        "status": "FAIL",
                        "blocking": True,
                        "message": "Potential generic-api-key found.",
                        "details": ["config/example.php:27"],
                    }
                ],
            ),
            self.status_event("developer"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )

        self.assertIn("WHAT NEEDS FIXING:", body)
        self.assertIn("WHAT FAILED:", body)
        self.assertIn("A possible secret was committed.", body)
        self.assertIn("WHERE: config/example.php:27", body)
        self.assertIn("Remove the credential from Git", body)
        self.assertIn("Push the fix; PR-QA will re-check it.", body)
        self.assertIn("Use WHAT NEEDS FIXING below", body)

    def test_pr_status_comment_explains_test_failure_actionably(self) -> None:
        engine = load_engine_module()
        body = engine.render_pr_status_comment(
            self.status_report(
                "FAIL",
                "development",
                "feature/work",
                [
                    {
                        "gate": "Tests",
                        "status": "FAIL",
                        "blocking": True,
                        "message": "php artisan test failed.",
                        "details": ["tests/Feature/LoginTest.php:18"],
                    }
                ],
            ),
            self.status_event("developer"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )

        self.assertIn("A required automated test or build command failed.", body)
        self.assertIn("WHERE: tests/Feature/LoginTest.php:18", body)
        self.assertIn("Fix the failing command or test shown in the details.", body)
        self.assertIn("Run the same failing command locally when available", body)

    def test_pr_status_comment_explains_deployment_failure_actionably(self) -> None:
        engine = load_engine_module()
        body = engine.render_pr_status_comment(
            self.status_report(
                "FAIL",
                "development",
                "feature/work",
                [
                    {
                        "gate": "Deployment Risk",
                        "status": "FAIL",
                        "blocking": True,
                        "message": "Production workflow allows push deployment.",
                        "details": [".github/workflows/production-deploy.yml"],
                    }
                ],
            ),
            self.status_event("developer"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )

        self.assertIn("deployment workflow or production-sensitive change", body)
        self.assertIn("WHERE: .github/workflows/production-deploy.yml", body)
        self.assertIn("Update only the affected workflow/deployment file", body)
        self.assertIn("PR-QA will re-check deployment safety", body)

    def test_pr_status_comment_explains_migration_failure_actionably(self) -> None:
        engine = load_engine_module()
        body = engine.render_pr_status_comment(
            self.status_report(
                "FAIL",
                "staging",
                "development",
                [
                    {
                        "gate": "Migration Risk",
                        "status": "FAIL",
                        "blocking": True,
                        "message": "DROP COLUMN detected in migration up().",
                        "details": ["database/migrations/2026_01_01_000000_update_users.php"],
                    }
                ],
            ),
            self.status_event("developer", base_ref="staging", head_ref="development"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )

        self.assertIn("DEVELOPER_HANDOFF_READY: NO", body)
        self.assertIn("A database migration may be unsafe for forward deployment.", body)
        self.assertIn("WHERE: database/migrations/2026_01_01_000000_update_users.php", body)
        self.assertIn("Make the migration forward-safe", body)
        self.assertIn("PR-QA will re-check migration safety", body)

    def test_pr_status_comment_explains_protected_resource_failure_actionably(self) -> None:
        engine = load_engine_module()
        body = engine.render_pr_status_comment(
            self.status_report(
                "FAIL",
                "development",
                "feature/work",
                [
                    {
                        "gate": "Protected Resources",
                        "status": "FAIL",
                        "blocking": True,
                        "message": "CODEOWNERS evidence missing.",
                        "details": [".github/workflows/pr-qa.yml"],
                    }
                ],
            ),
            self.status_event("developer"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )

        self.assertIn("A protected file or path changed", body)
        self.assertIn("WHERE: .github/workflows/pr-qa.yml", body)
        self.assertIn("Add the required review/ownership evidence", body)
        self.assertIn("PR-QA will re-check protected-resource rules", body)

    def test_pr_status_comment_explains_generic_failure_actionably(self) -> None:
        engine = load_engine_module()
        body = engine.render_pr_status_comment(
            self.status_report(
                "FAIL",
                "development",
                "feature/work",
                [
                    {
                        "gate": "Custom Gate",
                        "status": "FAIL",
                        "blocking": True,
                        "message": "Custom validation failed.",
                        "details": ["docs/release.md"],
                    }
                ],
            ),
            self.status_event("developer"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )

        self.assertIn("Custom Gate failed.", body)
        self.assertIn("WHERE: docs/release.md", body)
        self.assertIn("Fix the issue shown in the details.", body)
        self.assertIn("Push the fix; PR-QA will re-check it.", body)

    def test_pr_status_comment_ready_without_review_for_non_gate_c_transitions(self) -> None:
        engine = load_engine_module()
        feature_body = engine.render_pr_status_comment(
            self.status_report("PASS", "development", "feature/work", []),
            self.status_event("developer", base_ref="development", head_ref="feature/work"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )
        staging_body = engine.render_pr_status_comment(
            self.status_report("PASS", "staging", "development", []),
            self.status_event("developer", base_ref="staging", head_ref="development"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )

        self.assertIn("STATUS: READY TO MERGE", feature_body)
        self.assertIn("SAURABH APPROVAL REQUIRED: NO", feature_body)
        self.assertIn("STATUS: READY TO MERGE", staging_body)
        self.assertIn("SAURABH APPROVAL REQUIRED: NO", staging_body)

    def test_pr_status_comment_gate_c_uses_owner_login_only(self) -> None:
        engine = load_engine_module()
        report = self.status_report(
            "FAIL",
            "main",
            "staging",
            [{"gate": "Review Policy", "status": "FAIL", "blocking": True, "message": "Owner approval required."}],
        )
        awaiting = engine.render_pr_status_comment(
            report,
            self.status_event("developer", base_ref="main", head_ref="staging"),
            self.status_policy(owner="SaurabhVermaIN"),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )
        other_reviewer = engine.render_pr_status_comment(
            report,
            self.status_event("developer", base_ref="main", head_ref="staging"),
            self.status_policy(owner="SaurabhVermaIN"),
            {
                "pull_request": {"mergeable_state": "clean"},
                "reviews": [{"user": {"login": "other-reviewer"}, "state": "APPROVED"}],
            },
        )
        approved = engine.render_pr_status_comment(
            self.status_report("PASS", "main", "staging", []),
            self.status_event("developer", base_ref="main", head_ref="staging"),
            self.status_policy(owner="SaurabhVermaIN"),
            {
                "pull_request": {"mergeable_state": "clean"},
                "reviews": [{"user": {"login": "SaurabhVermaIN"}, "state": "APPROVED"}],
            },
        )

        self.assertIn("STATUS: TECHNICALLY READY", awaiting)
        self.assertIn("SAURABH GATE C APPROVAL REQUIRED: YES", awaiting)
        self.assertIn("STATUS: TECHNICALLY READY", other_reviewer)
        self.assertNotIn("APPROVED BY:", other_reviewer)
        self.assertIn("STATUS: READY FOR GATE C MERGE", approved)
        self.assertIn("APPROVED BY: SaurabhVermaIN", approved)

    def test_pr_status_comment_uses_current_run_json_and_never_renders_ready_for_failed_qa(self) -> None:
        engine = load_engine_module()
        event = self.status_event("developer")
        evidence = {"pull_request": {"mergeable_state": "clean"}, "reviews": []}
        failed = engine.render_pr_status_comment(
            self.status_report("FAIL", "development", "feature/work", [{"gate": "Tests", "status": "FAIL", "blocking": True}]),
            event,
            self.status_policy(),
            evidence,
        )
        passed = engine.render_pr_status_comment(
            self.status_report("PASS", "development", "feature/work", []),
            event,
            self.status_policy(),
            evidence,
        )

        self.assertIn("STATUS: BLOCKED", failed)
        self.assertNotIn("STATUS: READY TO MERGE", failed)
        self.assertIn("STATUS: READY TO MERGE", passed)
        self.assertNotIn("Automated tests failed", passed)

    def test_pr_status_comment_uses_exact_check_context_matching(self) -> None:
        engine = load_engine_module()
        self.assertEqual(
            engine.exact_missing_required_contexts(["pr-qa / Pull Request Quality Assurance"], ["pr-qa / Pull Request Quality Assurance"]),
            [],
        )
        self.assertEqual(
            engine.exact_missing_required_contexts(["pr-qa / Pull Request Quality Assurance"], ["Pull Request Quality Assurance"]),
            ["pr-qa / Pull Request Quality Assurance"],
        )

    def test_pr_status_comment_updates_one_marker_comment_and_collapses_races(self) -> None:
        engine = load_engine_module()
        old = f"{engine.PR_STATUS_COMMENT_MARKER}\nSYNERGIE PR STATUS\n\nSTATUS: BLOCKED\n"
        new = f"{engine.PR_STATUS_COMMENT_MARKER}\nSYNERGIE PR STATUS\n\nSTATUS: READY TO MERGE\n"
        comments = [
            {"id": 10, "created_at": "2026-01-01T00:00:00Z", "body": old},
            {"id": 11, "created_at": "2026-01-01T00:00:01Z", "body": old},
            {"id": 12, "created_at": "2026-01-01T00:00:02Z", "body": "unrelated"},
        ]

        updated = engine.apply_status_comment_update(comments, new)

        marker_comments = [comment for comment in updated if engine.PR_STATUS_COMMENT_MARKER in comment["body"]]
        self.assertEqual(len(marker_comments), 1)
        self.assertEqual(marker_comments[0]["id"], 10)
        self.assertIn("STATUS: READY TO MERGE", marker_comments[0]["body"])

    def test_pr_status_comment_publish_failure_does_not_change_qa_result(self) -> None:
        engine = load_engine_module()
        code = engine.publish_pr_status_comment_cli(
            argparse.Namespace(repo=str(self.tmp), policy=str(ROOT / "policy" / "pr-qa-policy.json"), event_path="", status_json_in="", json_out=""),
            self.status_policy(),
        )
        self.assertEqual(code, 0)

    def test_pr_status_comment_redacts_secret_like_output(self) -> None:
        engine = load_engine_module()
        body = engine.render_pr_status_comment(
            self.status_report(
                "FAIL",
                "development",
                "feature/work",
                [{"gate": "Secrets", "status": "FAIL", "blocking": True, "message": "ghp_abcdefghijklmnopqrstuvwxyz123456"}],
            ),
            self.status_event("developer"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )
        self.assertIn("Secret scanning failed", body)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", body)

    def test_pr_status_comment_redacts_secret_shaped_values_in_actionable_output(self) -> None:
        engine = load_engine_module()
        fake_token = "ghp_FAKEtokenForRegressionOnly1234567890"
        body = engine.render_pr_status_comment(
            self.status_report(
                "FAIL",
                "development",
                "feature/work",
                [
                    {
                        "gate": "Secrets",
                        "status": "FAIL",
                        "blocking": True,
                        "message": f"Potential token detected: {fake_token}",
                        "details": [
                            "config/example.php:27",
                            f"token = {fake_token}",
                        ],
                    }
                ],
            ),
            self.status_event("developer"),
            self.status_policy(),
            {"pull_request": {"mergeable_state": "clean"}, "reviews": []},
        )

        self.assertIn("A possible secret was committed.", body)
        self.assertIn("Remove the credential from Git", body)
        self.assertIn("Push the fix; PR-QA will re-check it.", body)
        self.assertIn("WHERE: config/example.php:27", body)
        self.assertNotIn(fake_token, body)
        self.assertIn("ghp_[REDACTED]", body)

    def override_digest(self, record: dict) -> str:
        payload = {key: value for key, value in record.items() if key != "record_sha256"}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)

    def attach_origin_with_staging(self, repo: Path, name: str) -> None:
        remote = self.tmp / name
        self.git(repo, "init", "-q", "--bare", str(remote))
        self.git(repo, "remote", "add", "origin", str(remote))
        self.git(repo, "push", "-q", "origin", "staging")
        self.git(repo, "fetch", "-q", "origin", "staging")

    def attach_origin_with_main_and_staging(self, repo: Path, name: str) -> None:
        remote = self.tmp / name
        self.git(repo, "init", "-q", "--bare", str(remote))
        self.git(repo, "remote", "add", "origin", str(remote))
        self.git(repo, "push", "-q", "origin", "main")
        self.git(repo, "push", "-q", "origin", "staging")
        self.git(repo, "fetch", "-q", "origin", "main", "staging")

    def attach_origin_with_development_and_staging(self, repo: Path, name: str) -> None:
        remote = self.tmp / name
        self.git(repo, "init", "-q", "--bare", str(remote))
        self.git(repo, "remote", "add", "origin", str(remote))
        self.git(repo, "push", "-q", "origin", "development")
        self.git(repo, "push", "-q", "origin", "staging")
        self.git(repo, "fetch", "-q", "origin", "development", "staging")

    def development_staging_alignment_repo(self, name: str) -> tuple[Path, str, str, str, str]:
        repo, base = self.init_repo(name, profile="framework")
        self.git(repo, "checkout", "-q", "-b", "development", base)
        self.write(repo / "app" / "ExistingDevelopment.php", "<?php\nreturn 'first';\n")
        self.commit(repo, "feat: add first development content")
        self.git(repo, "checkout", "-q", "-b", "feature/historical-merge", base)
        self.write(repo / "app" / "MergedFeature.php", "<?php\nreturn 'second';\n")
        self.commit(repo, "feat: add historically merged feature")
        self.git(repo, "checkout", "-q", "development")
        self.git(repo, "merge", "--no-ff", "-m", "feat: merge historical feature", "feature/historical-merge")
        historical_merge = self.git(repo, "rev-parse", "development").stdout.strip()
        development_sha = historical_merge

        self.git(repo, "checkout", "-q", "-b", "staging", base)
        self.write(repo / "app" / "ExistingDevelopment.php", "<?php\nreturn 'first';\n")
        self.write(repo / "app" / "MergedFeature.php", "<?php\nreturn 'second';\n")
        self.commit(repo, "feat: add equivalent staged application content")
        staging_sha = self.git(repo, "rev-parse", "staging").stdout.strip()
        self.assertEqual(self.git(repo, "rev-parse", "development^{tree}").stdout.strip(), self.git(repo, "rev-parse", "staging^{tree}").stdout.strip())

        self.attach_origin_with_development_and_staging(repo, f"{name}-origin.git")
        self.git(repo, "checkout", "-q", "-b", "chore/align-development-into-staging", "staging")
        self.git(repo, "merge", "--no-ff", "-m", "chore: align development into staging", "development")
        alignment_sha = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        return repo, staging_sha, development_sha, historical_merge, alignment_sha

    def commit(self, repo: Path, message: str) -> None:
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", message)

    def large_package_lock(self, entries: int = 1200, lockfile_version: object = 3) -> str:
        packages = {"": {"name": "fixture", "version": "1.0.0"}}
        for index in range(entries):
            packages[f"node_modules/pkg-{index:04d}"] = {
                "version": "1.0.0",
                "resolved": f"https://registry.npmjs.org/pkg-{index:04d}/-/pkg-{index:04d}-1.0.0.tgz",
                "integrity": "sha512-test",
            }
        return json.dumps({"lockfileVersion": lockfile_version, "packages": packages}, indent=2) + "\n"

    def write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_bytes(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def status_report(self, result: str, base_ref: str, head_ref: str, results: list[dict]) -> dict:
        return {
            "summary": {
                "overall_result": result,
                "base_ref": base_ref,
                "head_ref": head_ref,
                "gate_statuses": {},
            },
            "results": results,
        }

    def status_event(self, author: str, *, base_ref: str = "development", head_ref: str = "feature/work") -> dict:
        return {
            "pull_request": {
                "number": 123,
                "user": {"login": author},
                "base": {"ref": base_ref},
                "head": {"ref": head_ref},
            }
        }

    def status_policy(self, *, owner: str = "SaurabhVermaIN") -> dict:
        return {
            "version": 1,
            "defaults": {},
            "governance": {
                "review_policy": {
                    "owner_review_exception": {
                        "github_login": owner,
                    }
                }
            },
        }

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
