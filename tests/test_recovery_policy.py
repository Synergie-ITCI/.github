from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "tools" / "recovery_policy.py"


class RecoveryPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="recovery-policy-"))
        self.env = dict(os.environ)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def init_repo(self, name: str) -> Path:
        repo = self.tmp / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "qa@example.invalid")
        self.git(repo, "config", "user.name", "QA Regression")
        return repo

    def git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True)

    def write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_minimal_app(self, repo: Path, *, package_lock: bool = True) -> None:
        self.write(repo / "package.json", '{"scripts":{"build":"echo build"},"dependencies":{"left-pad":"1.3.0"}}\n')
        if package_lock:
            self.write(repo / "package-lock.json", '{"lockfileVersion":3,"packages":{}}\n')
        self.write(repo / "src" / "app.js", "console.log('recoverable');\n")
        self.write(repo / ".env.example", "APP_ENV=production\n")
        self.write(repo / "deploy" / "nginx.conf", "server { listen 80; }\n")

    def write_manifest(self, repo: Path, extra: str = "", required_asset_paths: str = "[]") -> None:
        self.write(
            repo / ".github" / "synergie-recovery.yml",
            f"""
application_name: Example
repository: Synergie-ITCI/example
runtime: node
runtime_version: "20"
framework: express
framework_version: "4"
build_commands:
  - npm ci
  - npm run build
dependency_manifests:
  - package.json
dependency_lockfiles:
  - package-lock.json
required_source_paths:
  - src/
required_asset_paths: {required_asset_paths}
git_lfs_paths: []
external_artifact_locations: []
environment_template: .env.example
secret_references:
  - /synergie/example/production/app
database_engine: postgres
database_backup_strategy: AWS Backup daily encrypted backup, 35-day retention.
database_restore_reference: runbooks/database-restore.md
persistent_upload_locations: []
persistent_storage_backup_strategy: No persistent uploads.
web_server_template: deploy/nginx.conf
scheduled_jobs: []
service_definitions: []
deployment_method: github-actions-release-artifact
production_target_reference: aws-account/ap-south-1/example-production
health_checks:
  - https://example.invalid/health
rollback_method: Restore previous SHA-256 verified artifact.
rto_target: 4h
rpo_target: 24h
recovery_owner_role: Example Platform Owner
{extra}
""",
        )

    def run_policy(self, repo: Path, mode: str = "staging") -> tuple[int, str, dict]:
        json_out = repo / "recovery-policy.json"
        args = [
            "python3",
            str(POLICY),
            "--repo",
            str(repo),
            "--mode",
            mode,
            "--json-out",
            str(json_out),
            "--out",
            str(repo / "recovery-policy.md"),
        ]
        completed = subprocess.run(args, text=True, capture_output=True, env=self.env, check=False)
        parsed = json.loads(json_out.read_text(encoding="utf-8")) if json_out.exists() else {}
        return completed.returncode, completed.stdout + completed.stderr, parsed

    def test_valid_staging_manifest_passes(self) -> None:
        repo = self.init_repo("valid")
        self.write_minimal_app(repo)
        self.write_manifest(repo)

        code, output, parsed = self.run_policy(repo)

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")

    def test_missing_manifest_fails(self) -> None:
        repo = self.init_repo("missing-manifest")
        self.write_minimal_app(repo)

        code, output, parsed = self.run_policy(repo)

        self.assertNotEqual(code, 0)
        self.assertIn("RECOVERY MANIFEST MISSING", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_required_asset_ignored_without_source_of_truth_fails(self) -> None:
        repo = self.init_repo("ignored-asset")
        self.write_minimal_app(repo)
        self.write(repo / ".gitignore", "public/*\n")
        self.write(repo / "public" / "app-assets" / "logo.png", "not really png\n")
        self.write_manifest(repo, required_asset_paths="['public/app-assets/logo.png']")

        code, output, parsed = self.run_policy(repo)

        self.assertNotEqual(code, 0)
        self.assertIn("RECOVERY-CRITICAL FILE EXCLUDED FROM SOURCE OF TRUTH", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_required_asset_ignored_with_versioned_artifact_mapping_passes(self) -> None:
        repo = self.init_repo("ignored-artifact")
        self.write_minimal_app(repo)
        self.write(repo / ".gitignore", "public/model.bin\n")
        self.write(repo / "public" / "model.bin", "model bytes\n")
        self.write_manifest(
            repo,
            extra="""
external_artifact_locations:
  - path: public/model.bin
    uri: s3://synergie-release-artifacts/example/model.bin
    checksum_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    version: "2026-08-09T00:00:00Z"
""",
            required_asset_paths="['public/model.bin']",
        )

        code, output, parsed = self.run_policy(repo)

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")

    def test_missing_node_lockfile_fails(self) -> None:
        repo = self.init_repo("missing-lock")
        self.write_minimal_app(repo, package_lock=False)
        self.write_manifest(repo)

        code, output, parsed = self.run_policy(repo)

        self.assertNotEqual(code, 0)
        self.assertIn("RECOVERY DEPENDENCY LOCKFILE MISSING", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_secret_value_in_manifest_fails_without_printing_value(self) -> None:
        repo = self.init_repo("secret-value")
        self.write_minimal_app(repo)
        self.write_manifest(repo, extra="password: plain-super-secret\n")

        code, output, parsed = self.run_policy(repo)

        self.assertNotEqual(code, 0)
        self.assertIn("RECOVERY MANIFEST CONTAINS SECRET FIELD", output)
        self.assertNotIn("plain-super-secret", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_person_dependent_artifact_fails(self) -> None:
        repo = self.init_repo("developer-laptop")
        self.write_minimal_app(repo)
        self.write_manifest(
            repo,
            extra="""
external_artifact_locations:
  - path: public/model.bin
    uri: /Users/alice/Desktop/model.bin
    checksum_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    version: "local"
""",
        )

        code, output, parsed = self.run_policy(repo)

        self.assertNotEqual(code, 0)
        self.assertIn("PERSON-DEPENDENT RECOVERY ASSET", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_lfs_paths_require_gitattributes(self) -> None:
        repo = self.init_repo("lfs-missing-attributes")
        self.write_minimal_app(repo)
        self.write(repo / "public" / "large.pdf", "large file placeholder\n")
        self.write_manifest(repo, extra="git_lfs_paths:\n  - public/large.pdf\n", required_asset_paths="['public/large.pdf']")

        code, output, parsed = self.run_policy(repo)

        self.assertNotEqual(code, 0)
        self.assertIn("RECOVERY LFS ATTRIBUTES MISSING", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_production_server_only_files_fail(self) -> None:
        repo = self.init_repo("server-only")
        self.write_minimal_app(repo)
        self.write_manifest(
            repo,
            extra="""
server_file_audit:
  last_audit_reference: runbooks/server-file-audit.md
  recovery_critical_server_only_count: 2
deployment_traceability:
  commit_marker: .deployed_commit
  artifact_manifest: release-manifest.json
  artifact_checksum_algorithm: sha256
  release_artifact_retention: keep last 10 releases
""",
        )

        code, output, parsed = self.run_policy(repo, mode="production")

        self.assertNotEqual(code, 0)
        self.assertIn("RECOVERY-CRITICAL SERVER-ONLY FILE", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_valid_production_manifest_passes_with_audit_and_traceability(self) -> None:
        repo = self.init_repo("valid-production")
        self.write_minimal_app(repo)
        self.write_manifest(
            repo,
            extra="""
server_file_audit:
  last_audit_reference: runbooks/server-file-audit.md
  recovery_critical_server_only_count: 0
deployment_traceability:
  commit_marker: .deployed_commit
  artifact_manifest: release-manifest.json
  artifact_checksum_algorithm: sha256
  release_artifact_retention: keep last 10 releases
""",
        )

        code, output, parsed = self.run_policy(repo, mode="production")

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
