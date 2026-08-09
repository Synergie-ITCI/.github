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
        self.write_governance_config(repo)
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
        self.write_governance_config(repo)
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
        self.write_governance_config(repo)
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

    def test_staging_phpmyadmin_requires_environment_mapping(self) -> None:
        repo, _ = self.init_repo("staging-missing-mapping")
        self.write(
            repo / ".github" / "synergie-governance.yml",
            """
application: Example
phpmyadmin:
  staging:
    allowed: true
  production:
    allowed: false
""",
        )
        self.write(
            repo / "docker-compose.staging.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin
    profiles: ["staging"]
    environment:
      PMA_HOST: ${STAGING_DB_HOST}
      PMA_AUTH_TYPE: cookie
""",
        )
        self.commit(repo, "feat: add unmapped staging phpmyadmin")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PHPMYADMIN ENVIRONMENT MAPPING MISSING", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_phpmyadmin_with_environment_mapping_passes(self) -> None:
        repo, _ = self.init_repo("staging-mapped")
        self.write_governance_config(repo)
        self.write(
            repo / "docker-compose.staging.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin
    profiles: ["staging"]
    environment:
      PMA_HOST: ${STAGING_DB_HOST}
      PMA_AUTH_TYPE: cookie
""",
        )
        self.commit(repo, "feat: add mapped staging phpmyadmin")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")

    def test_staging_phpmyadmin_rejects_placeholder_environment_mapping(self) -> None:
        repo, _ = self.init_repo("staging-placeholder-mapping")
        self.write(
            repo / ".github" / "synergie-governance.yml",
            """
application: Example
phpmyadmin:
  access:
    application_scoped: true
    shared_company_admin: false
  environments:
    - branch: staging
      environment: staging
      server: null
      database: null
      status: not_configured
  production:
    allowed: false
""",
        )
        self.write(
            repo / "docker-compose.staging.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin
    profiles: ["staging"]
    environment:
      PMA_HOST: ${STAGING_DB_HOST}
      PMA_AUTH_TYPE: cookie
""",
        )
        self.commit(repo, "feat: add placeholder staging phpmyadmin mapping")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PHPMYADMIN ENVIRONMENT MAPPING MISSING", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_governance_config_cannot_enable_production_phpmyadmin(self) -> None:
        repo, base = self.init_repo("production-config-enabled")
        self.write(
            repo / ".github" / "synergie-governance.yml",
            """
application: Example
phpmyadmin:
  production:
    allowed: true
""",
        )
        self.commit(repo, "feat: enable production phpmyadmin")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertNotEqual(code, 0)
        self.assertIn("PRODUCTION PHPMYADMIN ENABLED IN GOVERNANCE CONFIG", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_governance_config_cannot_use_shared_company_admin(self) -> None:
        repo, base = self.init_repo("shared-company-admin")
        self.write(
            repo / ".github" / "synergie-governance.yml",
            """
application: Example
phpmyadmin:
  access:
    application_scoped: true
    shared_company_admin: true
  production:
    allowed: false
""",
        )
        self.commit(repo, "feat: add shared admin")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertNotEqual(code, 0)
        self.assertIn("SHARED PHPMYADMIN ADMIN ACCOUNT PROHIBITED", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_phpmyadmin_requires_database_user_and_scope_mapping(self) -> None:
        repo, _ = self.init_repo("staging-missing-db-user-scope")
        self.write(
            repo / ".github" / "synergie-governance.yml",
            """
application: Example
phpmyadmin:
  access:
    application_scoped: true
    shared_company_admin: false
    database_scoped: true
    cross_application_access: false
    unrestricted_database_admin: false
  environments:
    - branch: staging
      environment: staging
      server: staging.example.invalid
      database: example_staging
      status: configured
  production:
    allowed: false
""",
        )
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
      PMA_AUTH_TYPE: cookie
""",
        )
        self.commit(repo, "feat: add staging phpmyadmin without db user scope")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PHPMYADMIN ENVIRONMENT MAPPING MISSING", output)
        self.assertIn("database user identity", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_phpmyadmin_rejects_root_database_user(self) -> None:
        repo, _ = self.init_repo("staging-root-db-user")
        self.write_governance_config(repo)
        self.write(
            repo / "docker-compose.staging.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin
    profiles: ["staging"]
    environment:
      PMA_HOST: ${STAGING_DB_HOST}
      PMA_USER: root
      PMA_AUTH_TYPE: cookie
""",
        )
        self.commit(repo, "feat: add staging phpmyadmin with root user")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("STAGING PHPMYADMIN DATABASE USER NOT LEAST PRIVILEGE", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_governance_config_rejects_unscoped_database_access(self) -> None:
        repo, base = self.init_repo("unscoped-db-access")
        self.write(
            repo / ".github" / "synergie-governance.yml",
            """
application: Example
phpmyadmin:
  access:
    application_scoped: true
    shared_company_admin: false
    database_scoped: false
    cross_application_access: true
    unrestricted_database_admin: true
  production:
    allowed: false
""",
        )
        self.commit(repo, "feat: allow unscoped database access")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertNotEqual(code, 0)
        self.assertIn("PHPMYADMIN DATABASE ACCESS NOT SCOPED", output)
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

    def test_documentation_only_pgadmin_reference_passes(self) -> None:
        repo, base = self.init_repo("pgadmin-docs-only")
        self.write(repo / "README.md", "Operators may use pgAdmin in UAT when the role is scoped.\n")
        self.commit(repo, "docs: mention pgadmin")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")

    def test_production_pgadmin_service_fails(self) -> None:
        repo, base = self.init_repo("production-pgadmin")
        self.write(
            repo / "docker-compose.production.yml",
            """
services:
  pgadmin:
    image: dpage/pgadmin4
    ports:
      - "5050:80"
""",
        )
        self.commit(repo, "feat: add production pgadmin")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertNotEqual(code, 0)
        self.assertIn("PRODUCTION PGADMIN POLICY VIOLATION", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_production_mixed_admin_services_flags_both(self) -> None:
        repo, base = self.init_repo("production-mixed-admin")
        self.write(
            repo / "docker-compose.production.yml",
            """
services:
  phpmyadmin:
    image: phpmyadmin/phpmyadmin
  pgadmin:
    image: dpage/pgadmin4
""",
        )
        self.commit(repo, "feat: add production admin tools")

        code, output, parsed = self.run_policy(repo, "production", base)

        self.assertNotEqual(code, 0)
        self.assertIn("PRODUCTION PHPMYADMIN POLICY VIOLATION", output)
        self.assertIn("PRODUCTION PGADMIN POLICY VIOLATION", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_pgadmin_with_environment_mapping_passes(self) -> None:
        repo, _ = self.init_repo("staging-pgadmin-mapped")
        self.write_pgadmin_governance_config(repo, environment="staging")
        self.write_pgadmin_compose(repo, "docker-compose.staging.yml")
        self.commit(repo, "feat: add staging pgadmin")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")

    def test_uat_pgadmin_with_environment_mapping_passes(self) -> None:
        repo, _ = self.init_repo("uat-pgadmin-mapped")
        self.write_pgadmin_governance_config(repo, environment="uat")
        self.write_pgadmin_compose(repo, "docker-compose.uat.yml", profile="uat")
        self.commit(repo, "feat: add uat pgadmin")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")

    def test_staging_pgadmin_to_production_database_fails(self) -> None:
        repo, _ = self.init_repo("staging-pgadmin-prod-db")
        self.write_pgadmin_governance_config(repo, server="postgres-production.internal", database="scholarship_prod")
        self.write_pgadmin_compose(repo, "docker-compose.staging.yml")
        self.commit(repo, "feat: add unsafe pgadmin")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("STAGING PGADMIN POINTS TO PRODUCTION DATABASE", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_pgadmin_rejects_postgres_role(self) -> None:
        repo, _ = self.init_repo("staging-pgadmin-postgres-role")
        self.write_pgadmin_governance_config(repo, role="postgres")
        self.write_pgadmin_compose(repo, "docker-compose.staging.yml")
        self.commit(repo, "feat: add pgadmin with postgres role")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PGADMIN POSTGRES ROLE NOT LEAST PRIVILEGE", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_pgadmin_rejects_superuser_role(self) -> None:
        repo, _ = self.init_repo("staging-pgadmin-superuser")
        self.write_pgadmin_governance_config(repo, extra_role_flags="      superuser: true\n")
        self.write_pgadmin_compose(repo, "docker-compose.staging.yml")
        self.commit(repo, "feat: add pgadmin superuser role")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PGADMIN POSTGRES ROLE NOT LEAST PRIVILEGE", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_pgadmin_rejects_createrole(self) -> None:
        repo, _ = self.init_repo("staging-pgadmin-createrole")
        self.write_pgadmin_governance_config(repo, extra_role_flags="      createrole: true\n")
        self.write_pgadmin_compose(repo, "docker-compose.staging.yml")
        self.commit(repo, "feat: add pgadmin createrole")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PGADMIN POSTGRES ROLE NOT LEAST PRIVILEGE", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_pgadmin_rejects_bypassrls(self) -> None:
        repo, _ = self.init_repo("staging-pgadmin-bypassrls")
        self.write_pgadmin_governance_config(repo, extra_role_flags="      bypassrls: true\n")
        self.write_pgadmin_compose(repo, "docker-compose.staging.yml")
        self.commit(repo, "feat: add pgadmin bypassrls")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PGADMIN POSTGRES ROLE NOT LEAST PRIVILEGE", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_pgadmin_rejects_cross_app_scope(self) -> None:
        repo, _ = self.init_repo("staging-pgadmin-cross-app")
        self.write_pgadmin_governance_config(repo, database_scope="all_databases")
        self.write_pgadmin_compose(repo, "docker-compose.staging.yml")
        self.commit(repo, "feat: add pgadmin cross app scope")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PGADMIN DATABASE ACCESS NOT SCOPED", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_pgadmin_requires_developer_owner(self) -> None:
        repo, _ = self.init_repo("staging-pgadmin-missing-owner")
        self.write_pgadmin_governance_config(repo, developer_owner=None)
        self.write_pgadmin_compose(repo, "docker-compose.staging.yml")
        self.commit(repo, "feat: add pgadmin without owner")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PGADMIN DEVELOPER OWNER NOT VERIFIED", output)
        self.assertEqual(parsed["status"], "FAIL")

    def test_staging_pgadmin_requires_database_scope(self) -> None:
        repo, _ = self.init_repo("staging-pgadmin-missing-db-scope")
        self.write_pgadmin_governance_config(repo, database_scope=None)
        self.write_pgadmin_compose(repo, "docker-compose.staging.yml")
        self.commit(repo, "feat: add pgadmin without db scope")

        code, output, parsed = self.run_policy(repo, "staging")

        self.assertNotEqual(code, 0)
        self.assertIn("PGADMIN ENVIRONMENT MAPPING MISSING", output)
        self.assertEqual(parsed["status"], "FAIL")

    def git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)

    def commit(self, repo: Path, message: str) -> None:
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-q", "-m", message)

    def write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_governance_config(self, repo: Path) -> None:
        self.write(
            repo / ".github" / "synergie-governance.yml",
            """
application: Example
phpmyadmin:
  access:
    application_scoped: true
    shared_company_admin: false
    database_scoped: true
    cross_application_access: false
    unrestricted_database_admin: false
  environments:
    - branch: staging
      environment: staging
      server: staging.example.invalid
      database: example_staging
      database_user_identity: example_staging_phpmyadmin
      database_scope: example_staging
      status: configured
  staging:
    allowed: true
    require_authentication: true
    require_database_isolation: true
    require_environment_secrets: true
  production:
    allowed: false
    block_runtime_exposure: true
""",
        )

    def write_pgadmin_compose(self, repo: Path, path: str, profile: str = "staging") -> None:
        self.write(
            repo / path,
            f"""
services:
  pgadmin:
    image: dpage/pgadmin4
    profiles: ["{profile}"]
    environment:
      PGADMIN_DEFAULT_EMAIL: ${{PGADMIN_DEFAULT_EMAIL}}
      PGADMIN_DEFAULT_PASSWORD: ${{PGADMIN_DEFAULT_PASSWORD}}
    labels:
      caddy: https://uat.example.invalid
      caddy.handle_path: /synergie-pgadmin/*
""",
        )

    def write_pgadmin_governance_config(
        self,
        repo: Path,
        *,
        environment: str = "staging",
        server: str = "uat-postgres.internal",
        database: str = "scholarship_uat",
        role: str = "scholarship_pgadmin",
        database_scope: str | None = "scholarship_uat",
        developer_owner: str | None = "dev.ravi.ranjan",
        extra_role_flags: str = "",
    ) -> None:
        developer_line = (
            f"      developer_owner: {developer_owner}\n" if developer_owner is not None else "      developer_owner: null\n"
        )
        scope_line = f"      database_scope: {database_scope}\n" if database_scope is not None else "      database_scope: null\n"
        self.write(
            repo / ".github" / "synergie-governance.yml",
            f"""
application: Example
pgadmin:
  access:
    application_scoped: true
    shared_company_admin: false
    database_scoped: true
    cross_application_access: false
    unrestricted_database_admin: false
  environments:
    - branch: {environment}
      environment: {environment}
      server: {server}
      database: {database}
      database_user_identity: {role}
{scope_line}{developer_line}{extra_role_flags}      pgadmin_url: https://uat.example.invalid/synergie-pgadmin/
      status: configured
  staging:
    allowed: true
    require_authentication: true
    require_database_isolation: true
    require_environment_secrets: true
  production:
    allowed: false
    block_runtime_exposure: true
""",
        )


if __name__ == "__main__":
    unittest.main()
