#!/usr/bin/env python3
"""
Synergie Runtime Certifier v1.

Read-only certification of the actual target environment immediately before
Gate D deployment.

v1:
- Linux
- AWS SSM
- Apache
- PHP-FPM

This tool does not deploy, migrate, switch releases, restart services,
edit configuration, or otherwise mutate production.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DEPLOY_STATES = {"ALREADY_DEPLOYED", "READY_FROM_ROLLBACK"}


class CertifierError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    instance_id: str
    region: str
    app_path: str
    app_user: str
    validation_url: str
    deploy_ref: str
    rollback_ref: str
    runtime_kind: str
    runtime_version: str
    web_server: str


def validate_config(config: Config) -> None:
    if not SHA_RE.fullmatch(config.deploy_ref):
        raise CertifierError(
            "deploy_ref must be an exact 40-character lowercase SHA"
        )

    if not SHA_RE.fullmatch(config.rollback_ref):
        raise CertifierError(
            "rollback_ref must be an exact 40-character lowercase SHA"
        )

    parsed = urlparse(config.validation_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise CertifierError(
            "validation_url must be an HTTPS URL with a hostname"
        )

    if not config.app_path.startswith("/"):
        raise CertifierError("app_path must be absolute")

    if config.runtime_kind != "php-fpm":
        raise CertifierError(
            f"unsupported runtime_kind={config.runtime_kind!r}; "
            "v1 supports php-fpm"
        )

    if not re.fullmatch(r"[0-9]+\.[0-9]+", config.runtime_version):
        raise CertifierError(
            "runtime_version must be major.minor, for example 8.2"
        )

    if config.web_server != "apache":
        raise CertifierError(
            f"unsupported web_server={config.web_server!r}; "
            "v1 supports apache"
        )


def build_remote_script(config: Config) -> str:
    validate_config(config)

    host = urlparse(config.validation_url).hostname
    assert host is not None

    php_bin = f"php{config.runtime_version}"
    fpm_service = f"php{config.runtime_version}-fpm"
    fpm_socket = f"/run/php/php{config.runtime_version}-fpm.sock"

    assignments = [
        "set -euo pipefail",
        f"APP_PATH={shlex.quote(config.app_path)}",
        f"APP_USER={shlex.quote(config.app_user)}",
        f"VALIDATION_URL={shlex.quote(config.validation_url)}",
        f"TARGET_HOST={shlex.quote(host)}",
        f"DEPLOY_REF={shlex.quote(config.deploy_ref)}",
        f"ROLLBACK_REF={shlex.quote(config.rollback_ref)}",
        f"EXPECTED_RUNTIME_VERSION={shlex.quote(config.runtime_version)}",
        f"PHP_BIN={shlex.quote(php_bin)}",
        f"FPM_SERVICE={shlex.quote(fpm_service)}",
        f"FPM_SOCKET={shlex.quote(fpm_socket)}",
        "APACHE_SITES_DIR=/etc/apache2/sites-enabled",
    ]

    body = r'''
cert_fail() {
  echo "RUNTIME_CERTIFIER=FAIL"
  echo "CERTIFIER_REASON=$1"
  echo "READY_TO_DEPLOY=NO"
  echo "DEPLOYMENT_STARTED=NO"
  echo "PRODUCTION_MUTATED=NO"
  exit 41
}

test -d "$APP_PATH" \
  || cert_fail "APP_PATH missing"

test -f "$APP_PATH/.env" \
  || cert_fail "production .env missing"

if ! CURRENT_SHA="$(
  sudo -u "$APP_USER" -H git -C "$APP_PATH" rev-parse HEAD 2>/dev/null
)"; then
  cert_fail "unable to resolve current production SHA"
fi

test -n "$CURRENT_SHA" \
  || cert_fail "resolved production SHA is empty"

case "$CURRENT_SHA" in
  "$DEPLOY_REF")
    DEPLOY_STATE="ALREADY_DEPLOYED"
    ;;
  "$ROLLBACK_REF")
    DEPLOY_STATE="READY_FROM_ROLLBACK"
    ;;
  *)
    echo "CURRENT_SHA=$CURRENT_SHA"
    echo "DEPLOY_REF=$DEPLOY_REF"
    echo "ROLLBACK_REF=$ROLLBACK_REF"
    cert_fail "current SHA is neither DEPLOY_REF nor ROLLBACK_REF"
    ;;
esac

command -v "$PHP_BIN" >/dev/null \
  || cert_fail "required PHP CLI is not installed"

CLI_RUNTIME_VERSION="$(
  "$PHP_BIN" -r 'echo PHP_VERSION;' 2>/dev/null
)" || cert_fail "unable to determine CLI PHP version"

"$PHP_BIN" -r \
  'exit(version_compare(PHP_VERSION, $argv[1], ">=") ? 0 : 1);' \
  "$EXPECTED_RUNTIME_VERSION" \
  || cert_fail "CLI PHP is below the required runtime version"

systemctl is-active "$FPM_SERVICE" >/dev/null \
  || cert_fail "required PHP-FPM service is not active"

test -S "$FPM_SOCKET" \
  || cert_fail "required PHP-FPM socket is missing"

test -d "$APACHE_SITES_DIR" \
  || cert_fail "Apache sites-enabled directory is missing"

VHOST=""

for candidate in "$APACHE_SITES_DIR"/*; do
  [ -f "$candidate" ] || continue

  if awk -v host="$TARGET_HOST" '
      $1 == "ServerName" && $2 == host { found=1 }
      END { exit !found }
    ' "$candidate"
  then
    VHOST="$candidate"
    break
  fi
done

test -n "$VHOST" \
  || cert_fail "target hostname is not mapped to an enabled Apache vhost"

grep -Fq "$FPM_SOCKET" "$VHOST" \
  || cert_fail "target Apache vhost is not mapped to required PHP-FPM socket"

command -v apache2ctl >/dev/null \
  || cert_fail "apache2ctl is unavailable"

apache2ctl configtest >/dev/null 2>&1 \
  || cert_fail "Apache configuration test failed"

command -v curl >/dev/null \
  || cert_fail "curl is unavailable"

HTTP_STATUS="$(
  curl -k -sS \
    -o /dev/null \
    -w '%{http_code}' \
    --max-time 30 \
    "$VALIDATION_URL" \
    || true
)"

case "$HTTP_STATUS" in
  200|301|302|403)
    ;;
  *)
    cert_fail "pre-deployment endpoint smoke failed HTTP $HTTP_STATUS"
    ;;
esac

echo "=== PRODUCTION RUNTIME CERTIFICATION ==="
echo "TARGET_IDENTITY=PASS"
echo "TARGET_HOST=$TARGET_HOST"
echo "CURRENT_SHA=$CURRENT_SHA"
echo "DEPLOY_REF=$DEPLOY_REF"
echo "ROLLBACK_REF=$ROLLBACK_REF"
echo "DEPLOY_STATE=$DEPLOY_STATE"
echo "CLI_RUNTIME_VERSION=$CLI_RUNTIME_VERSION"
echo "EXPECTED_RUNTIME_VERSION=$EXPECTED_RUNTIME_VERSION"
echo "FPM_SERVICE=$FPM_SERVICE"
echo "FPM_SOCKET=$FPM_SOCKET"
echo "WEB_SERVER=apache"
echo "WEB_RUNTIME_MAPPING=PASS"
echo "VALIDATION_HTTP=$HTTP_STATUS"
echo "RUNTIME_CERTIFIER=PASS"
echo "READY_TO_DEPLOY=YES"
echo "DEPLOYMENT_STARTED=NO"
echo "PRODUCTION_MUTATED=NO"

if [ "$DEPLOY_STATE" = "ALREADY_DEPLOYED" ]; then
  echo "DEPLOYMENT_REQUIRED=NO"
else
  echo "DEPLOYMENT_REQUIRED=YES"
fi
'''

    return "\n".join(assignments) + "\n" + body


def run_command(
    argv: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def extract_deploy_state(output: str) -> str:
    match = re.search(r"(?m)^DEPLOY_STATE=(.+)$", output)

    if not match:
        raise CertifierError(
            "runtime certifier output did not contain DEPLOY_STATE"
        )

    state = match.group(1).strip()

    if state not in DEPLOY_STATES:
        raise CertifierError(
            f"unexpected DEPLOY_STATE={state!r}"
        )

    return state


def write_github_outputs(state: str) -> None:
    output_path = os.getenv("GITHUB_OUTPUT", "").strip()

    if not output_path:
        return

    deployment_required = (
        "false"
        if state == "ALREADY_DEPLOYED"
        else "true"
    )

    with Path(output_path).open("a", encoding="utf-8") as handle:
        handle.write(f"deploy_state={state}\n")
        handle.write(
            f"deployment_required={deployment_required}\n"
        )


def certify(config: Config) -> int:
    remote_script = build_remote_script(config)

    payload = {
        "commands": [
            "bash -lc " + shlex.quote(remote_script),
        ]
    }

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".json",
        delete=False,
    ) as handle:
        json.dump(payload, handle)
        payload_path = handle.name

    try:
        send = run_command(
            [
                "aws",
                "ssm",
                "send-command",
                "--region",
                config.region,
                "--instance-ids",
                config.instance_id,
                "--document-name",
                "AWS-RunShellScript",
                "--comment",
                f"Synergie Runtime Certifier {config.deploy_ref}",
                "--parameters",
                f"file://{payload_path}",
                "--query",
                "Command.CommandId",
                "--output",
                "text",
            ]
        )

        command_id = send.stdout.strip()

        if not command_id:
            raise CertifierError(
                "SSM send-command returned no command ID"
            )

        run_command(
            [
                "aws",
                "ssm",
                "wait",
                "command-executed",
                "--region",
                config.region,
                "--command-id",
                command_id,
                "--instance-id",
                config.instance_id,
            ],
            check=False,
        )

        invocation = run_command(
            [
                "aws",
                "ssm",
                "get-command-invocation",
                "--region",
                config.region,
                "--command-id",
                command_id,
                "--instance-id",
                config.instance_id,
                "--output",
                "json",
            ]
        )

        result = json.loads(invocation.stdout)

        stdout = result.get(
            "StandardOutputContent",
            "",
        )

        stderr = result.get(
            "StandardErrorContent",
            "",
        )

        status = result.get(
            "Status",
            "UNKNOWN",
        )

        if stdout:
            print(
                stdout,
                end="" if stdout.endswith("\n") else "\n",
            )

        if stderr:
            print(
                stderr,
                file=sys.stderr,
                end="" if stderr.endswith("\n") else "\n",
            )

        if status != "Success":
            print(
                f"RUNTIME_CERTIFIER_SSM_STATUS={status}",
                file=sys.stderr,
            )
            return 1

        state = extract_deploy_state(stdout)
        write_github_outputs(state)

        return 0

    finally:
        Path(payload_path).unlink(
            missing_ok=True
        )


def parse_args() -> Config:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--instance-id",
        required=True,
    )

    parser.add_argument(
        "--region",
        default="ap-south-1",
    )

    parser.add_argument(
        "--app-path",
        required=True,
    )

    parser.add_argument(
        "--app-user",
        default="synergie-admin",
    )

    parser.add_argument(
        "--validation-url",
        required=True,
    )

    parser.add_argument(
        "--deploy-ref",
        required=True,
    )

    parser.add_argument(
        "--rollback-ref",
        required=True,
    )

    parser.add_argument(
        "--runtime-kind",
        default="php-fpm",
    )

    parser.add_argument(
        "--runtime-version",
        required=True,
    )

    parser.add_argument(
        "--web-server",
        default="apache",
    )

    args = parser.parse_args()

    return Config(
        instance_id=args.instance_id,
        region=args.region,
        app_path=args.app_path,
        app_user=args.app_user,
        validation_url=args.validation_url,
        deploy_ref=args.deploy_ref,
        rollback_ref=args.rollback_ref,
        runtime_kind=args.runtime_kind,
        runtime_version=args.runtime_version,
        web_server=args.web_server,
    )


def main() -> int:
    try:
        config = parse_args()
        validate_config(config)
        return certify(config)

    except (
        CertifierError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as exc:
        print(
            f"RUNTIME_CERTIFIER=FAIL: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
