import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "tools" / "runtime_certifier.py"

spec = importlib.util.spec_from_file_location(
    "runtime_certifier",
    MODULE,
)

assert spec
assert spec.loader

mod = importlib.util.module_from_spec(spec)

# Required for dataclasses under current Python versions.
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


DEPLOY = "a" * 40
ROLLBACK = "b" * 40


def config(**overrides):
    values = dict(
        instance_id="i-0123456789abcdef0",
        region="ap-south-1",
        app_path="/var/www/example/public_html",
        app_user="synergie-admin",
        validation_url="https://example.org/login",
        deploy_ref=DEPLOY,
        rollback_ref=ROLLBACK,
        runtime_kind="php-fpm",
        runtime_version="8.2",
        web_server="apache",
    )

    values.update(overrides)

    return mod.Config(**values)


class RuntimeCertifierTests(unittest.TestCase):

    def test_remote_script_is_generic_and_read_only(self):
        script = mod.build_remote_script(config())

        self.assertIn(
            'DEPLOY_STATE="ALREADY_DEPLOYED"',
            script,
        )

        self.assertIn(
            'DEPLOY_STATE="READY_FROM_ROLLBACK"',
            script,
        )

        self.assertIn(
            "READY_TO_DEPLOY=YES",
            script,
        )

        self.assertIn(
            "PRODUCTION_MUTATED=NO",
            script,
        )

        self.assertIn(
            "php8.2-fpm.sock",
            script,
        )

        self.assertNotIn(
            "dhansamvaad",
            script.lower(),
        )

        forbidden = [
            "artisan migrate",
            "git reset --hard",
            "systemctl reload",
            "systemctl restart",
            "rm -rf",
            'mv "$APP_PATH"',
        ]

        for value in forbidden:
            self.assertNotIn(
                value,
                script,
            )

    def test_sha_resolution_failure_is_explicit(self):
        script = mod.build_remote_script(config())

        self.assertIn(
            'cert_fail "unable to resolve current production SHA"',
            script,
        )

        self.assertIn(
            'cert_fail "resolved production SHA is not an exact lowercase SHA"',
            script,
        )

    def test_generated_remote_script_has_valid_bash_syntax(self):
        script = mod.build_remote_script(config())

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".sh",
            delete=False,
        ) as handle:
            handle.write(script)
            path = handle.name

        try:
            proc = subprocess.run(
                ["bash", "-n", path],
                text=True,
                capture_output=True,
            )

            self.assertEqual(
                proc.returncode,
                0,
                proc.stderr,
            )

        finally:
            Path(path).unlink(
                missing_ok=True
            )

    def test_detached_head_does_not_require_branch_name(self):
        script = mod.build_remote_script(config())

        self.assertNotIn(
            "branch --show-current",
            script,
        )

    def test_invalid_deploy_sha_fails_closed(self):
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(
                config(deploy_ref="main")
            )

    def test_invalid_rollback_sha_fails_closed(self):
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(
                config(rollback_ref="staging")
            )

    def test_non_https_validation_url_fails_closed(self):
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(
                config(
                    validation_url="http://example.org"
                )
            )

    def test_unsupported_runtime_fails_closed(self):
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(
                config(runtime_kind="node")
            )

    def test_unsupported_web_server_fails_closed(self):
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(
                config(web_server="nginx")
            )

    def test_extract_already_deployed(self):
        state = mod.extract_deploy_state(
            "RUNTIME_CERTIFIER=PASS\n"
            "DEPLOY_STATE=ALREADY_DEPLOYED\n"
        )

        self.assertEqual(
            state,
            "ALREADY_DEPLOYED",
        )

    def test_extract_ready_from_rollback(self):
        state = mod.extract_deploy_state(
            "DEPLOY_STATE=READY_FROM_ROLLBACK\n"
            "RUNTIME_CERTIFIER=PASS\n"
        )

        self.assertEqual(
            state,
            "READY_FROM_ROLLBACK",
        )

    def test_unknown_state_fails_closed(self):
        with self.assertRaises(mod.CertifierError):
            mod.extract_deploy_state(
                "DEPLOY_STATE=SOMETHING_ELSE\n"
            )


if __name__ == "__main__":
    unittest.main()

# LOCAL_SHELL_HARNESS_V1
import os
import shlex
import socket


def run_shell_harness(
    current_sha,
    *,
    git_fail=False,
    release_marker=None,
    http_status="200",
):
    with tempfile.TemporaryDirectory(
        dir="/tmp",
        prefix="runtime-certifier-",
    ) as tmp:
        root = Path(tmp)
        app = root / "app"
        apache = root / "apache"
        fake_bin = root / "bin"
        sock_path = root / "php8.2-fpm.sock"

        app.mkdir()
        apache.mkdir()
        fake_bin.mkdir()

        (app / ".env").write_text(
            "APP_ENV=testing\n",
            encoding="utf-8",
        )

        if release_marker is not None:
            (app / ".release-sha").write_text(
                release_marker,
                encoding="utf-8",
            )

        (apache / "example.conf").write_text(
            "ServerName example.org\n"
            '<FilesMatch "\\.php$">\n'
            f'SetHandler "proxy:unix:{sock_path}|fcgi://localhost/"\n'
            "</FilesMatch>\n",
            encoding="utf-8",
        )

        stubs = {
            "sudo": r"""#!/usr/bin/env bash
set -e
if [ "${1:-}" = "-u" ]; then
  shift 2
fi
if [ "${1:-}" = "-H" ]; then
  shift
fi
exec "$@"
""",
            "git": r"""#!/usr/bin/env bash
set -e
if [ "${1:-}" = "-C" ]; then
  shift 2
fi
if [ "${FAKE_GIT_FAIL:-0}" = "1" ]; then
  exit 17
fi
if [ "${1:-}" = "rev-parse" ] && [ "${2:-}" = "HEAD" ]; then
  printf '%s\n' "$FAKE_CURRENT_SHA"
  exit 0
fi
exit 18
""",
            "php8.2": r"""#!/usr/bin/env bash
set -e
if [ "${1:-}" != "-r" ]; then
  exit 19
fi
case "${2:-}" in
  *"echo PHP_VERSION"*)
    printf '8.2.33'
    exit 0
    ;;
  *"version_compare"*)
    exit 0
    ;;
esac
exit 20
""",
            "systemctl": r"""#!/usr/bin/env bash
set -e
if [ "${1:-}" = "is-active" ] &&
   [ "${2:-}" = "php8.2-fpm" ]; then
  exit 0
fi
exit 21
""",
            "apache2ctl": r"""#!/usr/bin/env bash
set -e
if [ "${1:-}" = "configtest" ]; then
  exit 0
fi
exit 22
""",
            "curl": r"""#!/usr/bin/env bash
set -e
printf '%s' "${FAKE_HTTP_STATUS:-200}"
""",
        }

        for name, content in stubs.items():
            path = fake_bin / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o755)

        cfg = config(
            app_path=str(app),
            validation_url="https://example.org/login",
        )

        script = mod.build_remote_script(cfg)

        script = script.replace(
            "FPM_SOCKET=/run/php/php8.2-fpm.sock",
            "FPM_SOCKET=" + shlex.quote(str(sock_path)),
        )

        script = script.replace(
            "APACHE_SITES_DIR=/etc/apache2/sites-enabled",
            "APACHE_SITES_DIR=" + shlex.quote(str(apache)),
        )

        env = os.environ.copy()
        env["PATH"] = (
            str(fake_bin)
            + os.pathsep
            + env.get("PATH", "")
        )
        env["FAKE_CURRENT_SHA"] = current_sha
        env["FAKE_GIT_FAIL"] = "1" if git_fail else "0"
        env["FAKE_HTTP_STATUS"] = http_status

        sock = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
        sock.bind(str(sock_path))
        sock.listen(1)

        try:
            return subprocess.run(
                ["bash", "-c", script],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        finally:
            sock.close()


class RuntimeCertifierShellHarnessTests(unittest.TestCase):

    def test_shell_already_deployed(self):
        proc = run_shell_harness(DEPLOY)

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "SHA_SOURCE=GIT",
            proc.stdout,
        )
        self.assertIn(
            "DEPLOY_STATE=ALREADY_DEPLOYED",
            proc.stdout,
        )
        self.assertIn(
            "RUNTIME_CERTIFIER=PASS",
            proc.stdout,
        )
        self.assertIn(
            "DEPLOYMENT_REQUIRED=NO",
            proc.stdout,
        )
        self.assertIn(
            "PRODUCTION_MUTATED=NO",
            proc.stdout,
        )

    def test_shell_ready_from_rollback(self):
        proc = run_shell_harness(ROLLBACK)

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "DEPLOY_STATE=READY_FROM_ROLLBACK",
            proc.stdout,
        )
        self.assertIn(
            "READY_TO_DEPLOY=YES",
            proc.stdout,
        )
        self.assertIn(
            "DEPLOYMENT_REQUIRED=YES",
            proc.stdout,
        )
        self.assertIn(
            "PRODUCTION_MUTATED=NO",
            proc.stdout,
        )

    def test_shell_unexpected_sha_fails_closed(self):
        proc = run_shell_harness("c" * 40)

        self.assertEqual(proc.returncode, 41)
        self.assertIn(
            "RUNTIME_CERTIFIER=FAIL",
            proc.stdout,
        )
        self.assertIn(
            "current SHA is neither DEPLOY_REF nor ROLLBACK_REF",
            proc.stdout,
        )
        self.assertIn(
            "READY_TO_DEPLOY=NO",
            proc.stdout,
        )
        self.assertIn(
            "PRODUCTION_MUTATED=NO",
            proc.stdout,
        )

    def test_shell_git_failure_fails_closed(self):
        proc = run_shell_harness(
            "",
            git_fail=True,
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn(
            "unable to resolve current production SHA",
            proc.stdout,
        )
        self.assertIn(
            "PRODUCTION_MUTATED=NO",
            proc.stdout,
        )

    def test_shell_marker_ready_from_rollback(self):
        proc = run_shell_harness(
            "",
            git_fail=True,
            release_marker=ROLLBACK,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "SHA_SOURCE=RELEASE_MARKER",
            proc.stdout,
        )
        self.assertIn(
            "DEPLOY_STATE=READY_FROM_ROLLBACK",
            proc.stdout,
        )
        self.assertIn(
            "DEPLOYMENT_REQUIRED=YES",
            proc.stdout,
        )

    def test_shell_marker_already_deployed(self):
        proc = run_shell_harness(
            "",
            git_fail=True,
            release_marker=DEPLOY,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "SHA_SOURCE=RELEASE_MARKER",
            proc.stdout,
        )
        self.assertIn(
            "DEPLOY_STATE=ALREADY_DEPLOYED",
            proc.stdout,
        )
        self.assertIn(
            "DEPLOYMENT_REQUIRED=NO",
            proc.stdout,
        )

    def test_shell_malformed_marker_fails_closed(self):
        proc = run_shell_harness(
            "",
            git_fail=True,
            release_marker="not-a-sha\n",
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn(
            "resolved production SHA is not an exact lowercase SHA",
            proc.stdout,
        )
        self.assertIn(
            "PRODUCTION_MUTATED=NO",
            proc.stdout,
        )

    def test_shell_marker_trims_outer_whitespace_only(self):
        proc = run_shell_harness(
            "",
            git_fail=True,
            release_marker=f"  {DEPLOY}\n",
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            f"CURRENT_SHA={DEPLOY}",
            proc.stdout,
        )
        self.assertIn(
            "SHA_SOURCE=RELEASE_MARKER",
            proc.stdout,
        )

    def test_shell_marker_keeps_runtime_checks_blocking(self):
        proc = run_shell_harness(
            "",
            git_fail=True,
            release_marker=DEPLOY,
            http_status="500",
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn(
            "pre-deployment endpoint smoke failed HTTP 500",
            proc.stdout,
        )
        self.assertIn(
            "PRODUCTION_MUTATED=NO",
            proc.stdout,
        )
