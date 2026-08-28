import importlib.util
import json
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


def persistent_path(
    application_path="public/inventoryuploads",
    physical_path="shared/public/inventoryuploads",
    persistence_mechanism="symlink",
):
    return mod.PersistentDataPath(
        application_path=application_path,
        physical_path=physical_path,
        persistence_mechanism=persistence_mechanism,
    )


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

    def test_static_vite_apache_runtime_is_supported(self):
        mod.validate_config(
            config(
                runtime_kind="static-vite-apache",
                runtime_version="vite",
            )
        )

    def test_static_vite_apache_rejects_non_vite_runtime_version(self):
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(
                config(
                    runtime_kind="static-vite-apache",
                    runtime_version="8.2",
                )
            )

    def test_django_gunicorn_nginx_runtime_is_supported(self):
        mod.validate_config(
            config(
                runtime_kind="django-gunicorn-nginx",
                runtime_version="django-4.2.17",
                web_server="nginx",
            )
        )

    def test_django_gunicorn_nginx_rejects_non_django_runtime_version(self):
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(
                config(
                    runtime_kind="django-gunicorn-nginx",
                    runtime_version="4.2.17",
                    web_server="nginx",
                )
            )

    def test_django_remote_script_does_not_require_php_fpm_or_apache(self):
        script = mod.build_remote_script(
            config(
                runtime_kind="django-gunicorn-nginx",
                runtime_version="django-4.2.17",
                web_server="nginx",
            )
        )

        self.assertIn(
            "RUNTIME_KIND=django-gunicorn-nginx",
            script,
        )
        self.assertIn(
            "PERSISTENT_STORAGE=PASS",
            script,
        )
        self.assertIn(
            "WEB_SERVER=nginx",
            script,
        )
        self.assertNotIn(
            "php8.2-fpm.sock",
            script,
        )
        self.assertNotIn(
            "apache2ctl",
            script,
        )

    def test_static_remote_script_does_not_require_php_fpm(self):
        script = mod.build_remote_script(
            config(
                runtime_kind="static-vite-apache",
                runtime_version="vite",
            )
        )

        self.assertIn(
            "RUNTIME_KIND=static-vite-apache",
            script,
        )
        self.assertIn(
            "STATIC_ASSETS=PASS",
            script,
        )
        self.assertIn(
            'DEPLOY_STATE="READY_FROM_STATIC_BASELINE"',
            script,
        )
        self.assertNotIn(
            "php8.2-fpm.sock",
            script,
        )
        self.assertNotIn(
            'test -f "$APP_PATH/.env"',
            script,
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
    persistent_data=(),
    persistent_setup=None,
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
        mounts_file = root / "mounts"
        mounts_file.write_text("", encoding="utf-8")

        (app / ".env").write_text(
            "APP_ENV=testing\n",
            encoding="utf-8",
        )

        if persistent_setup:
            persistent_setup(root, app, mounts_file)

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
            persistent_data=tuple(persistent_data),
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

        script = script.replace(
            "PERSISTENCE_MOUNTS_FILE=/proc/mounts",
            "PERSISTENCE_MOUNTS_FILE=" + shlex.quote(str(mounts_file)),
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


def run_static_shell_harness(
    *,
    manifest_sha=None,
    release_marker=None,
    http_status="200",
    document_root_matches=True,
):
    with tempfile.TemporaryDirectory(
        dir="/tmp",
        prefix="runtime-certifier-static-",
    ) as tmp:
        root = Path(tmp)
        app = root / "public_html"
        apache = root / "apache"
        fake_bin = root / "bin"

        app.mkdir()
        (app / "assets").mkdir()
        apache.mkdir()
        fake_bin.mkdir()

        (app / "index.html").write_text(
            "<div id=\"root\"></div>\n",
            encoding="utf-8",
        )
        (app / "assets" / "index.js").write_text(
            "console.log('ok');\n",
            encoding="utf-8",
        )

        if manifest_sha is not None:
            (app / "deployment-manifest.json").write_text(
                json.dumps({"commit_sha": manifest_sha}),
                encoding="utf-8",
            )

        if release_marker is not None:
            (app / ".release-sha").write_text(
                release_marker,
                encoding="utf-8",
            )

        document_root = app if document_root_matches else root / "wrong"
        (apache / "example.conf").write_text(
            "ServerName example.org\n"
            f"DocumentRoot {document_root}\n",
            encoding="utf-8",
        )

        stubs = {
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
            runtime_kind="static-vite-apache",
            runtime_version="vite",
        )

        script = mod.build_remote_script(cfg)

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
        env["FAKE_HTTP_STATUS"] = http_status

        return subprocess.run(
            ["bash", "-c", script],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


def run_django_shell_harness(
    *,
    marker_sha=DEPLOY,
    http_status="302",
    persistent_links=True,
):
    with tempfile.TemporaryDirectory(
        dir="/tmp",
        prefix="runtime-certifier-django-",
    ) as tmp:
        root = Path(tmp)
        app = root / "current"
        shared = root / "shared"
        nginx = root / "nginx"
        fake_bin = root / "bin"
        venv_bin = app / ".venv" / "bin"

        app.mkdir(parents=True)
        shared.mkdir()
        (shared / "media" / "audio").mkdir(parents=True)
        (shared / "media" / "profile_pics").mkdir(parents=True)
        fake_bin.mkdir()
        nginx.mkdir()
        venv_bin.mkdir(parents=True)

        (app / "manage.py").write_text(
            "#!/usr/bin/env python3\n",
            encoding="utf-8",
        )
        (app / ".deployment-sha").write_text(
            marker_sha + "\n",
            encoding="utf-8",
        )
        (shared / "db.sqlite3").write_text(
            "",
            encoding="utf-8",
        )

        if persistent_links:
            (app / "db.sqlite3").symlink_to(shared / "db.sqlite3")
            (app / "media").symlink_to(shared / "media")
        else:
            (app / "db.sqlite3").write_text(
                "",
                encoding="utf-8",
            )
            (app / "media").mkdir()

        (nginx / "example.conf").write_text(
            "server {\n"
            "  server_name example.org;\n"
            "  location / { proxy_pass http://127.0.0.1:8000; }\n"
            "}\n",
            encoding="utf-8",
        )

        stubs = {
            "python": r"""#!/usr/bin/env bash
set -e
cat >/dev/null
printf 'django-4.2.17\n'
""",
            "gunicorn": r"""#!/usr/bin/env bash
exit 0
""",
            "systemctl": r"""#!/usr/bin/env bash
set -e
if [ "${1:-}" = "is-active" ] &&
   [ "${2:-}" = "django-app.service" ]; then
  exit 0
fi
if [ "${1:-}" = "list-units" ]; then
  printf 'django-app.service loaded active running test\n'
  exit 0
fi
if [ "${1:-}" = "cat" ] &&
   [ "${2:-}" = "django-app.service" ]; then
  printf 'ExecStart=%s/.venv/bin/gunicorn loginSingup.wsgi:application\n' "$FAKE_APP_PATH"
  exit 0
fi
exit 21
""",
            "nginx": r"""#!/usr/bin/env bash
set -e
if [ "${1:-}" = "-t" ]; then
  exit 0
fi
exit 22
""",
            "curl": r"""#!/usr/bin/env bash
set -e
printf '%s' "${FAKE_HTTP_STATUS:-302}"
""",
            "git": r"""#!/usr/bin/env bash
exit 18
""",
        }

        for name, content in stubs.items():
            path = (
                venv_bin / name
                if name in {"python", "gunicorn"}
                else fake_bin / name
            )
            path.write_text(content, encoding="utf-8")
            path.chmod(0o755)

        cfg = config(
            app_path=str(app),
            validation_url="https://example.org/login",
            runtime_kind="django-gunicorn-nginx",
            runtime_version="django-4.2.17",
            web_server="nginx",
        )

        script = mod.build_remote_script(cfg)

        script = script.replace(
            "NGINX_SITES_DIR=/etc/nginx/sites-enabled",
            "NGINX_SITES_DIR=" + shlex.quote(str(nginx)),
        )

        env = os.environ.copy()
        env["PATH"] = (
            str(fake_bin)
            + os.pathsep
            + env.get("PATH", "")
        )
        env["FAKE_HTTP_STATUS"] = http_status
        env["FAKE_APP_PATH"] = str(app)

        return subprocess.run(
            ["bash", "-c", script],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


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

    def test_persistent_data_correct_symlink_passes(self):
        def setup(root, app, mounts_file):
            physical = root / "shared" / "public" / "inventoryuploads"
            physical.mkdir(parents=True)
            (app / "public").mkdir()
            (app / "public" / "inventoryuploads").symlink_to(physical)

        proc = run_shell_harness(
            DEPLOY,
            persistent_data=[persistent_path()],
            persistent_setup=setup,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PERSISTENT_DATA_SAFETY=PASS", proc.stdout)
        self.assertIn("PRODUCTION_MUTATED=NO", proc.stdout)

    def test_persistent_data_wrong_symlink_destination_fails(self):
        def setup(root, app, mounts_file):
            declared = root / "shared" / "public" / "inventoryuploads"
            wrong = root / "shared" / "wrong" / "inventoryuploads"
            declared.mkdir(parents=True)
            wrong.mkdir(parents=True)
            (app / "public").mkdir()
            (app / "public" / "inventoryuploads").symlink_to(wrong)

        proc = run_shell_harness(
            DEPLOY,
            persistent_data=[persistent_path()],
            persistent_setup=setup,
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn("resolved target does not match declared physical path", proc.stdout)
        self.assertIn("READY_TO_DEPLOY=NO", proc.stdout)
        self.assertIn("PRODUCTION_MUTATED=NO", proc.stdout)

    def test_persistent_data_plain_release_directory_fails(self):
        def setup(root, app, mounts_file):
            (root / "shared" / "public" / "inventoryuploads").mkdir(parents=True)
            (app / "public" / "inventoryuploads").mkdir(parents=True)

        proc = run_shell_harness(
            DEPLOY,
            persistent_data=[persistent_path()],
            persistent_setup=setup,
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn("plain directory inside the current release", proc.stdout)
        self.assertIn("PRODUCTION_MUTATED=NO", proc.stdout)

    def test_persistent_data_missing_physical_path_fails(self):
        def setup(root, app, mounts_file):
            (app / "public").mkdir()
            (app / "public" / "inventoryuploads").symlink_to(root / "shared" / "public" / "inventoryuploads")

        proc = run_shell_harness(
            DEPLOY,
            persistent_data=[persistent_path()],
            persistent_setup=setup,
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn("declared physical path is missing", proc.stdout)
        self.assertIn("PRODUCTION_MUTATED=NO", proc.stdout)

    def test_persistent_data_correct_bind_mount_passes(self):
        def setup(root, app, mounts_file):
            physical = root / "shared" / "public" / "inventoryuploads"
            target = app / "public" / "inventoryuploads"
            physical.mkdir(parents=True)
            target.mkdir(parents=True)
            mounts_file.write_text(f"{physical} {target} none rw,bind 0 0\n", encoding="utf-8")

        proc = run_shell_harness(
            DEPLOY,
            persistent_data=[persistent_path(persistence_mechanism="bind_mount")],
            persistent_setup=setup,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PERSISTENT_DATA_SAFETY=PASS", proc.stdout)

    def test_persistent_data_incorrect_bind_mount_source_fails(self):
        def setup(root, app, mounts_file):
            physical = root / "shared" / "public" / "inventoryuploads"
            wrong = root / "shared" / "wrong" / "inventoryuploads"
            target = app / "public" / "inventoryuploads"
            physical.mkdir(parents=True)
            wrong.mkdir(parents=True)
            target.mkdir(parents=True)
            mounts_file.write_text(f"{wrong} {target} none rw,bind 0 0\n", encoding="utf-8")

        proc = run_shell_harness(
            DEPLOY,
            persistent_data=[persistent_path(persistence_mechanism="bind_mount")],
            persistent_setup=setup,
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn("bind mount source does not match declared physical path", proc.stdout)
        self.assertIn("PRODUCTION_MUTATED=NO", proc.stdout)

    def test_persistent_data_unsupported_mechanism_fails_closed(self):
        with self.assertRaises(mod.CertifierError):
            mod.build_remote_script(
                config(
                    persistent_data=[
                        persistent_path(persistence_mechanism="object_storage")
                    ]
                )
            )

    def test_disposable_persistent_data_declarations_are_ignored(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            manifest = Path(tmp) / "synergie-governance.yml"
            manifest.write_text(
                """persistent_data:
  - application_path: storage/logs
    classification: DISPOSABLE
""",
                encoding="utf-8",
            )

            self.assertEqual(mod.load_persistent_data_declarations(manifest), ())

    def test_no_persistent_data_declarations_keep_script_unchanged(self):
        script = mod.build_remote_script(config())

        self.assertNotIn("PERSISTENT_DATA_SAFETY", script)
        self.assertNotIn("certify_persistent_data_path", script)

    def test_telemedicine_plain_inventoryuploads_directory_fails(self):
        def setup(root, app, mounts_file):
            (root / "shared" / "public" / "inventoryuploads").mkdir(parents=True)
            (app / "public" / "inventoryuploads").mkdir(parents=True)

        proc = run_shell_harness(
            DEPLOY,
            persistent_data=[persistent_path()],
            persistent_setup=setup,
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn("plain directory inside the current release", proc.stdout)

    def test_telemedicine_inventoryuploads_symlink_passes(self):
        def setup(root, app, mounts_file):
            physical = root / "shared" / "public" / "inventoryuploads"
            physical.mkdir(parents=True)
            (app / "public").mkdir()
            (app / "public" / "inventoryuploads").symlink_to(physical)

        proc = run_shell_harness(
            DEPLOY,
            persistent_data=[persistent_path()],
            persistent_setup=setup,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PERSISTENT_DATA_SAFETY=PASS", proc.stdout)


class StaticViteApacheRuntimeCertifierShellHarnessTests(unittest.TestCase):

    def test_static_shell_accepts_unmarked_baseline_without_php(self):
        proc = run_static_shell_harness()

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "SHA_SOURCE=STATIC_BASELINE",
            proc.stdout,
        )
        self.assertIn(
            "DEPLOY_STATE=READY_FROM_STATIC_BASELINE",
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

    def test_static_shell_manifest_already_deployed(self):
        proc = run_static_shell_harness(
            manifest_sha=DEPLOY,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "SHA_SOURCE=DEPLOYMENT_MANIFEST",
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

    def test_static_shell_manifest_ready_from_rollback(self):
        proc = run_static_shell_harness(
            manifest_sha=ROLLBACK,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "DEPLOY_STATE=READY_FROM_ROLLBACK",
            proc.stdout,
        )
        self.assertIn(
            "DEPLOYMENT_REQUIRED=YES",
            proc.stdout,
        )

    def test_static_shell_wrong_document_root_fails_closed(self):
        proc = run_static_shell_harness(
            document_root_matches=False,
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn(
            "target Apache vhost is not mapped to APP_PATH DocumentRoot",
            proc.stdout,
        )
        self.assertIn(
            "PRODUCTION_MUTATED=NO",
            proc.stdout,
        )


class DjangoGunicornNginxRuntimeCertifierShellHarnessTests(unittest.TestCase):

    def test_django_shell_already_deployed(self):
        proc = run_django_shell_harness()

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "SHA_SOURCE=DEPLOYMENT_MARKER",
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

    def test_django_shell_requires_persistent_links(self):
        proc = run_django_shell_harness(
            persistent_links=False,
        )

        self.assertEqual(proc.returncode, 41)
        self.assertIn(
            "db.sqlite3 is not linked to persistent storage",
            proc.stdout,
        )
        self.assertIn(
            "PRODUCTION_MUTATED=NO",
            proc.stdout,
        )
