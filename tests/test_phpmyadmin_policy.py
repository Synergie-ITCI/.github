from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "tools" / "phpmyadmin_policy.py"


class PhpMyAdminPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="phpmyadmin-policy-"))
        self.env = dict(os.environ)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def init_repo(self, name: str) -> tuple[Path, str]:
        repo = self.tmp / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "qa@example.invalid")
        self.git(repo, "config", "user.name", "QA Regression")
        self.write(repo / "README.md", "# policy regression\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: baseline")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        return repo, base

    def run_policy(self, repo: Path, mode: str, base: str | None = None) -> tuple[int, str, dict]:
        json_out = repo / "policy.json"
        args = ["python3", str(POLICY), "--repo", str(repo), "--mode", mode, "--json-out", str(json_out)]
        if base:
            args.extend(["--base-sha", base, "--head-sha", "HEAD"])
        completed = subprocess.run(args, text=True, capture_output=True, env=self.env, check=False)
        parsed = json.loads(json_out.read_text(encoding="utf-8")) if json_out.exists() else {}
        return completed.returncode, completed.stdout + completed.stderr, parsed

    def test_documentation_only_phpmyadmin_reference_passes(self) -> None:
        repo, base = self.init_repo("docs-only")
        self.write(repo / "README.md", "Operators may use phpMyAdmin in local development only.\n")
        self.commit(repo, "docs: mention phpmyadmin")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")
        self.assertEqual(parsed["failures"], [])

    def test_production_docker_phpmyadmin_service_fails(self) -> None:
        repo, base = self.init_repo("production-compose")
        self.write(
            repo / "docker-compose.production.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin
    ports:
      - "8080:80"
""",
        )
        self.commit(repo, "feat: add production phpmyadmin")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertNotEqual(code, 0)
        self.assertIn("PRODUCTION PHPMYADMIN POLICY VIOLATION", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_only_phpmyadmin_config_passes_production_gate(self) -> None:
        repo, base = self.init_repo("staging-compose")
        self.write(
            repo / "docker-compose.staging.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin
    profiles: ["staging"]
    environment:
      PMA_HOST: ${STAGING_DB_HOST}
      PMA_USER: ${STAGING_DB_USER}
      PMA_PASSWORD: ${STAGING_DB_PASSWORD}
      PMA_AUTH_TYPE: cookie
""",
        )
        self.commit(repo, "feat: add staging phpmyadmin")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")

    def test_staging_phpmyadmin_to_production_database_fails(self) -> None:
        repo, _ = self.init_repo("staging-prod-db")
        self.write(
            repo / "docker-compose.staging.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin
    profiles: ["staging"]
    environment:
      PMA_HOST: production-db.internal
      PMA_AUTH_TYPE: cookie
""",
        )
        self.commit(repo, "feat: add unsafe staging phpmyadmin")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("STAGING PHPMYADMIN POINTS TO PRODUCTION DATABASE", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_phpmyadmin_hardcoded_password_fails_without_printing_value(self) -> None:
        repo, _ = self.init_repo("staging-hardcoded-secret")
        self.write(
            repo / "docker-compose.staging.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin
    profiles: ["staging"]
    environment:
      PMA_HOST: ${STAGING_DB_HOST}
      PMA_PASSWORD: plain-test-password
      PMA_AUTH_TYPE: cookie
""",
        )
        self.commit(repo, "feat: add staging password")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("STAGING PHPMYADMIN SECRET IN GIT", output)
        self.assertNotIn("plain-test-password", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_pre_existing_production_phpmyadmin_reports_without_blocking_unrelated_pr(self) -> None:
        repo, _ = self.init_repo("legacy-production")
        self.write(
            repo / "docker-compose.production.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin
""",
        )
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", "chore: legacy production phpmyadmin")
        base = self.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.write(repo / "app.php", "<?php echo 'unrelated';\n")
        self.commit(repo, "feat: unrelated app change")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertEqual(code, 0, output)
        self.assertIn("PRE-EXISTING PRODUCTION PHPMYADMIN VIOLATION", output)
        self.assertEqual(parsed["status"], "PASS")

    def git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)

    def commit(self, repo: Path, message: str) -> None:
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", message)

    def write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
