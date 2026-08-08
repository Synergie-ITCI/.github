from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "phpmyadmin_nonprod_onboarding.py"


class PhpMyAdminNonProdOnboardingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="phpmyadmin-onboarding-"))
        self.env = dict(os.environ)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def run_tool(self, *extra: str) -> tuple[int, str, dict]:
        json_out = self.tmp / "result.json"
        args = [
            "python3",
            str(TOOL),
            "--application-name",
            "Sankalp",
            "--environment",
            "staging",
            "--hostname",
            "sankalp-staging.synergieinsights.in",
            "--database-name",
            "sankalp_staging_db",
            "--database-user-identity",
            "sankalp_staging_user",
            "--database-scope",
            "sankalp_staging_db",
            "--developer-identity",
            "Raveesh Yadav",
            "--db-classification",
            "staging",
            "--https-available",
            "true",
            "--json-out",
            str(json_out),
            *extra,
        ]
        completed = subprocess.run(args, text=True, capture_output=True, env=self.env, check=False)
        parsed = json.loads(json_out.read_text(encoding="utf-8")) if json_out.exists() else {}
        return completed.returncode, completed.stdout + completed.stderr, parsed

    def assert_refused(self, *extra: str, expected: str) -> None:
        code, output, parsed = self.run_tool(*extra)
        self.assertNotEqual(code, 0)
        self.assertEqual(parsed["status"], "FAIL")
        self.assertIn(expected, output)

    def test_rejects_production_environment(self) -> None:
        self.assert_refused("--environment", "production", expected="production environment is prohibited")

    def test_rejects_production_database_classification(self) -> None:
        self.assert_refused("--db-classification", "production", expected="production database classification is prohibited")

    def test_rejects_root_database_user(self) -> None:
        self.assert_refused("--database-user-identity", "root", expected="root/global database user is prohibited")

    def test_rejects_global_database_user_scope_flag(self) -> None:
        self.assert_refused("--db-user-global-scope", "true", expected="database user must not have global scope")

    def test_rejects_global_database_scope(self) -> None:
        self.assert_refused("--database-scope", "*.*", expected="database scope must be application and environment specific")

    def test_rejects_cross_application_database_scope(self) -> None:
        self.assert_refused("--database-scope", "sankalptraining_db", expected="database scope must match")

    def test_rejects_cross_application_database_name(self) -> None:
        self.assert_refused(
            "--database-name",
            "datamatics_staging_db",
            "--database-scope",
            "datamatics_staging_db",
            expected="database scope must include the application identity",
        )

    def test_rejects_cross_environment_database_name(self) -> None:
        self.assert_refused(
            "--database-name",
            "sankalp_production_db",
            "--database-scope",
            "sankalp_production_db",
            expected="database scope must include the environment identity",
        )

    def test_rejects_missing_developer(self) -> None:
        self.assert_refused("--developer-identity", "", expected="developer owner is required")

    def test_rejects_missing_https(self) -> None:
        self.assert_refused("--https-available", "false", expected="HTTPS must be available")

    def test_valid_staging_configuration_generates_credential_free_artifacts(self) -> None:
        output_dir = self.tmp / "out"
        code, output, parsed = self.run_tool("--output-dir", str(output_dir))

        self.assertEqual(code, 0, output)
        self.assertEqual(parsed["status"], "PASS")
        apache = (output_dir / "apache-include.conf").read_text(encoding="utf-8")
        php = (output_dir / "phpmyadmin-policy.inc.php").read_text(encoding="utf-8")
        readme = (output_dir / "README.md").read_text(encoding="utf-8")
        self.assertIn("Alias /synergie-pma", apache)
        self.assertIn("AuthUserFile /etc/apache2/synergie-pma-sankalp-staging.htpasswd", apache)
        self.assertIn("$cfg['Servers'][1]['auth_type'] = 'cookie';", php)
        self.assertIn("$cfg['Servers'][1]['only_db'] = array('sankalp_staging_db');", php)
        self.assertIn("$cfg['AllowArbitraryServer'] = false;", php)
        self.assertIn("Credential Rotation", readme)
        self.assertNotRegex(apache + php + readme, r"(?i)(password|secret)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{8,}")


if __name__ == "__main__":
    unittest.main()
