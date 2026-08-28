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
- Static Vite/Apache webroot
- Django/Gunicorn/Nginx

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
DEPLOY_STATES = {
    "ALREADY_DEPLOYED",
    "READY_FROM_ROLLBACK",
    "READY_FROM_STATIC_BASELINE",
}
SUPPORTED_RUNTIME_KINDS = {
    "php-fpm",
    "static-vite-apache",
    "django-gunicorn-nginx",
}
SUPPORTED_PERSISTENCE_MECHANISMS = {
    "SYMLINK",
    "BIND_MOUNT",
}


class CertifierError(RuntimeError):
    pass


@dataclass(frozen=True)
class PersistentDataPath:
    application_path: str
    physical_path: str
    persistence_mechanism: str


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
    persistent_data: tuple[PersistentDataPath, ...] = ()


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

    validate_persistent_data(config.persistent_data)

    if config.runtime_kind not in SUPPORTED_RUNTIME_KINDS:
        raise CertifierError(
            f"unsupported runtime_kind={config.runtime_kind!r}; "
            "v1 supports php-fpm and static-vite-apache"
        )

    if (
        config.runtime_kind == "php-fpm"
        and not re.fullmatch(r"[0-9]+\.[0-9]+", config.runtime_version)
    ):
        raise CertifierError(
            "runtime_version must be major.minor, for example 8.2"
        )

    if (
        config.runtime_kind == "static-vite-apache"
        and config.runtime_version != "vite"
    ):
        raise CertifierError(
            "static-vite-apache runtime_version must be vite"
        )

    if (
        config.runtime_kind == "django-gunicorn-nginx"
        and not re.fullmatch(r"django-[0-9]+(?:\.[0-9]+){1,2}", config.runtime_version)
    ):
        raise CertifierError(
            "django-gunicorn-nginx runtime_version must be django-major.minor[.patch]"
        )

    if config.runtime_kind == "django-gunicorn-nginx":
        return

    if config.web_server != "apache":
        raise CertifierError(
            f"unsupported web_server={config.web_server!r}; "
            "v1 supports apache"
        )


def validate_persistent_data(paths: tuple[PersistentDataPath, ...]) -> None:
    for item in paths:
        if not item.application_path.strip():
            raise CertifierError("persistent_data application_path is required")
        if item.application_path.startswith("/"):
            raise CertifierError("persistent_data application_path must be relative to app_path")
        if not item.physical_path.strip():
            raise CertifierError("persistent_data physical_path is required")
        mechanism = normalize_persistence_mechanism(item.persistence_mechanism)
        if mechanism not in SUPPORTED_PERSISTENCE_MECHANISMS:
            raise CertifierError(
                "The declared persistence mechanism is not supported by Runtime Certifier v1."
            )


def normalize_persistence_mechanism(value: str) -> str:
    return value.strip().replace("-", "_").upper()


def build_remote_script(config: Config) -> str:
    validate_config(config)

    if config.runtime_kind == "static-vite-apache":
        return build_static_vite_apache_remote_script(config)

    if config.runtime_kind == "django-gunicorn-nginx":
        return build_django_gunicorn_nginx_remote_script(config)

    host = urlparse(config.validation_url).hostname
    assert host is not None

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
        f"FPM_SERVICE={shlex.quote(fpm_service)}",
        f"FPM_SOCKET={shlex.quote(fpm_socket)}",
        "APACHE_SITES_DIR=/etc/apache2/sites-enabled",
        "PERSISTENCE_MOUNTS_FILE=/proc/mounts",
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

''' + persistent_data_shell_functions(config) + r'''

test -d "$APP_PATH" \
  || cert_fail "APP_PATH missing"

''' + persistent_data_shell_invocations(config) + r'''

test -f "$APP_PATH/.env" \
  || cert_fail "production .env missing"

SHA_SOURCE=""

if CURRENT_SHA="$(
  sudo -u "$APP_USER" -H git -C "$APP_PATH" rev-parse HEAD 2>/dev/null
)"; then
  SHA_SOURCE="GIT"
else
  CURRENT_SHA=""
fi

if [ -z "$SHA_SOURCE" ] && [ -r "$APP_PATH/.release-sha" ]; then
  CURRENT_SHA="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$APP_PATH/.release-sha")"
  SHA_SOURCE="RELEASE_MARKER"
fi

test -n "$CURRENT_SHA" \
  || cert_fail "unable to resolve current production SHA"

case "$CURRENT_SHA" in
  *[!0-9a-f]*|"")
    cert_fail "resolved production SHA is not an exact lowercase SHA"
    ;;
esac

if [ "${#CURRENT_SHA}" -ne 40 ]; then
  cert_fail "resolved production SHA is not an exact lowercase SHA"
fi

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

PHP_BIN=""
CLI_RUNTIME_VERSION=""

select_compatible_php_cli() {
  for candidate in "php$EXPECTED_RUNTIME_VERSION" php; do
    command -v "$candidate" >/dev/null 2>&1 || continue

    candidate_path="$(command -v "$candidate")" \
      || continue

    candidate_version="$(
      "$candidate_path" -r 'echo PHP_VERSION;' 2>/dev/null
    )" || continue

    "$candidate_path" -r \
      'exit(version_compare(PHP_VERSION, $argv[1], ">=") ? 0 : 1);' \
      "$EXPECTED_RUNTIME_VERSION" \
      || continue

    PHP_BIN="$candidate_path"
    CLI_RUNTIME_VERSION="$candidate_version"
    return 0
  done

  return 1
}

select_compatible_php_cli \
  || cert_fail "required compatible PHP CLI is not installed"

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
echo "SHA_SOURCE=$SHA_SOURCE"
echo "DEPLOY_REF=$DEPLOY_REF"
echo "ROLLBACK_REF=$ROLLBACK_REF"
echo "DEPLOY_STATE=$DEPLOY_STATE"
echo "PHP_BIN=$PHP_BIN"
echo "CLI_RUNTIME_VERSION=$CLI_RUNTIME_VERSION"
echo "EXPECTED_RUNTIME_VERSION=$EXPECTED_RUNTIME_VERSION"
echo "FPM_SERVICE=$FPM_SERVICE"
echo "FPM_SOCKET=$FPM_SOCKET"
echo "WEB_SERVER=apache"
echo "WEB_RUNTIME_MAPPING=PASS"
''' + persistent_data_pass_output(config) + r'''
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


def build_django_gunicorn_nginx_remote_script(config: Config) -> str:
    host = urlparse(config.validation_url).hostname
    assert host is not None

    assignments = [
        "set -euo pipefail",
        f"APP_PATH={shlex.quote(config.app_path)}",
        f"VALIDATION_URL={shlex.quote(config.validation_url)}",
        f"TARGET_HOST={shlex.quote(host)}",
        f"DEPLOY_REF={shlex.quote(config.deploy_ref)}",
        f"ROLLBACK_REF={shlex.quote(config.rollback_ref)}",
        f"EXPECTED_RUNTIME_VERSION={shlex.quote(config.runtime_version)}",
        "NGINX_SITES_DIR=/etc/nginx/sites-enabled",
        "PERSISTENCE_MOUNTS_FILE=/proc/mounts",
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

''' + persistent_data_shell_functions(config) + r'''

test -d "$APP_PATH" \
  || cert_fail "APP_PATH missing"

''' + persistent_data_shell_invocations(config) + r'''

test -f "$APP_PATH/manage.py" \
  || cert_fail "Django manage.py missing"

test -x "$APP_PATH/.venv/bin/python" \
  || cert_fail "Django virtualenv python missing"

test -x "$APP_PATH/.venv/bin/gunicorn" \
  || cert_fail "Gunicorn executable missing"

test -L "$APP_PATH/db.sqlite3" \
  || cert_fail "db.sqlite3 is not linked to persistent storage"

test -L "$APP_PATH/media" \
  || cert_fail "media is not linked to persistent storage"

test -d "$APP_PATH/media/audio" \
  || cert_fail "persistent media/audio directory missing"

test -d "$APP_PATH/media/profile_pics" \
  || cert_fail "persistent media/profile_pics directory missing"

SHA_SOURCE=""
CURRENT_SHA=""

if [ -r "$APP_PATH/.deployment-sha" ]; then
  CURRENT_SHA="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$APP_PATH/.deployment-sha")"
  SHA_SOURCE="DEPLOYMENT_MARKER"
elif [ -r "$APP_PATH/.release-sha" ]; then
  CURRENT_SHA="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$APP_PATH/.release-sha")"
  SHA_SOURCE="RELEASE_MARKER"
elif CURRENT_SHA="$(git -C "$APP_PATH" rev-parse HEAD 2>/dev/null)"; then
  SHA_SOURCE="GIT"
else
  CURRENT_SHA=""
fi

test -n "$CURRENT_SHA" \
  || cert_fail "unable to resolve current production SHA"

case "$CURRENT_SHA" in
  *[!0-9a-f]*|"")
    cert_fail "resolved production SHA is not an exact lowercase SHA"
    ;;
esac

if [ "${#CURRENT_SHA}" -ne 40 ]; then
  cert_fail "resolved production SHA is not an exact lowercase SHA"
fi

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

DJANGO_VERSION="$(
  "$APP_PATH/.venv/bin/python" - <<'PY'
import django
print("django-" + django.get_version())
PY
)" || cert_fail "unable to determine Django version"

test "$DJANGO_VERSION" = "$EXPECTED_RUNTIME_VERSION" \
  || cert_fail "Django runtime version mismatch"

command -v systemctl >/dev/null \
  || cert_fail "systemctl is unavailable"

SERVICE=""
while IFS= read -r candidate; do
  [ -n "$candidate" ] || continue

  systemctl is-active "$candidate" >/dev/null 2>&1 \
    || continue

  UNIT_CONFIG="$(systemctl cat "$candidate" 2>/dev/null || true)"

  case "$UNIT_CONFIG" in
    *"$APP_PATH"*|*".venv/bin/gunicorn"*|*" gunicorn "*)
      SERVICE="$candidate"
      break
      ;;
  esac
done < <(
  systemctl list-units \
    --type=service \
    --state=active \
    --no-legend \
    --no-pager 2>/dev/null \
    | awk '{print $1}'
)

test -n "$SERVICE" \
  || cert_fail "Gunicorn/Django service is not active"

test -d "$NGINX_SITES_DIR" \
  || cert_fail "Nginx sites-enabled directory is missing"

VHOST=""

for candidate in "$NGINX_SITES_DIR"/*; do
  [ -f "$candidate" ] || continue

  if awk -v host="$TARGET_HOST" '
      $1 == "server_name" {
        for (i = 2; i <= NF; i++) {
          value = $i
          sub(/;$/, "", value)
          if (value == host) { found=1 }
        }
      }
      END { exit !found }
    ' "$candidate"
  then
    VHOST="$candidate"
    break
  fi
done

test -n "$VHOST" \
  || cert_fail "target hostname is not mapped to an enabled Nginx server block"

grep -Eq 'proxy_pass[[:space:]]+http://127\.0\.0\.1:[0-9]+' "$VHOST" \
  || cert_fail "target Nginx server block is not mapped to local Gunicorn upstream"

command -v nginx >/dev/null \
  || cert_fail "nginx is unavailable"

nginx -t >/dev/null 2>&1 \
  || cert_fail "Nginx configuration test failed"

command -v curl >/dev/null \
  || cert_fail "curl is unavailable"

HTTP_STATUS="$(
  curl -sS \
    -o /dev/null \
    -w '%{http_code}' \
    --max-time 30 \
    "$VALIDATION_URL" \
    || true
)"

case "$HTTP_STATUS" in
  200|301|302|303|403)
    ;;
  *)
    cert_fail "pre-deployment endpoint smoke failed HTTP $HTTP_STATUS"
    ;;
esac

echo "=== PRODUCTION RUNTIME CERTIFICATION ==="
echo "TARGET_IDENTITY=PASS"
echo "TARGET_HOST=$TARGET_HOST"
echo "APP_PATH=$APP_PATH"
echo "CURRENT_SHA=$CURRENT_SHA"
echo "SHA_SOURCE=$SHA_SOURCE"
echo "DEPLOY_REF=$DEPLOY_REF"
echo "ROLLBACK_REF=$ROLLBACK_REF"
echo "DEPLOY_STATE=$DEPLOY_STATE"
echo "RUNTIME_KIND=django-gunicorn-nginx"
echo "DJANGO_RUNTIME_VERSION=$DJANGO_VERSION"
echo "GUNICORN_SERVICE=$SERVICE"
echo "WEB_SERVER=nginx"
echo "WEB_RUNTIME_MAPPING=PASS"
echo "PERSISTENT_STORAGE=PASS"
''' + persistent_data_pass_output(config) + r'''
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


def build_static_vite_apache_remote_script(config: Config) -> str:
    host = urlparse(config.validation_url).hostname
    assert host is not None

    assignments = [
        "set -euo pipefail",
        f"APP_PATH={shlex.quote(config.app_path)}",
        f"VALIDATION_URL={shlex.quote(config.validation_url)}",
        f"TARGET_HOST={shlex.quote(host)}",
        f"DEPLOY_REF={shlex.quote(config.deploy_ref)}",
        f"ROLLBACK_REF={shlex.quote(config.rollback_ref)}",
        "APACHE_SITES_DIR=/etc/apache2/sites-enabled",
        "PERSISTENCE_MOUNTS_FILE=/proc/mounts",
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

''' + persistent_data_shell_functions(config) + r'''

test -d "$APP_PATH" \
  || cert_fail "APP_PATH missing"

''' + persistent_data_shell_invocations(config) + r'''

test -f "$APP_PATH/index.html" \
  || cert_fail "static index.html missing"

test -d "$APP_PATH/assets" \
  || cert_fail "static assets directory missing"

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

if ! awk -v path="$APP_PATH" '
    $1 == "DocumentRoot" && $2 == path { found=1 }
    END { exit !found }
  ' "$VHOST"
then
  cert_fail "target Apache vhost is not mapped to APP_PATH DocumentRoot"
fi

SHA_SOURCE=""
CURRENT_SHA=""

if [ -r "$APP_PATH/deployment-manifest.json" ]; then
  command -v python3 >/dev/null \
    || cert_fail "python3 is unavailable for static manifest validation"

  CURRENT_SHA="$(
    python3 - "$APP_PATH/deployment-manifest.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(str(data.get("commit_sha", "")).strip())
PY
  )" || cert_fail "unable to parse static deployment manifest"
  SHA_SOURCE="DEPLOYMENT_MANIFEST"
fi

if [ -z "$SHA_SOURCE" ] && [ -r "$APP_PATH/.release-sha" ]; then
  CURRENT_SHA="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$APP_PATH/.release-sha")"
  SHA_SOURCE="RELEASE_MARKER"
fi

if [ -n "$SHA_SOURCE" ]; then
  case "$CURRENT_SHA" in
    *[!0-9a-f]*|"")
      cert_fail "resolved production SHA is not an exact lowercase SHA"
      ;;
  esac

  if [ "${#CURRENT_SHA}" -ne 40 ]; then
    cert_fail "resolved production SHA is not an exact lowercase SHA"
  fi

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
else
  CURRENT_SHA="UNMARKED_STATIC_WEBROOT"
  SHA_SOURCE="STATIC_BASELINE"
  DEPLOY_STATE="READY_FROM_STATIC_BASELINE"
fi

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
echo "APP_PATH=$APP_PATH"
echo "CURRENT_SHA=$CURRENT_SHA"
echo "SHA_SOURCE=$SHA_SOURCE"
echo "DEPLOY_REF=$DEPLOY_REF"
echo "ROLLBACK_REF=$ROLLBACK_REF"
echo "DEPLOY_STATE=$DEPLOY_STATE"
echo "RUNTIME_KIND=static-vite-apache"
echo "STATIC_ASSETS=PASS"
echo "WEB_SERVER=apache"
echo "WEB_RUNTIME_MAPPING=PASS"
''' + persistent_data_pass_output(config) + r'''
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


def persistent_data_shell_functions(config: Config) -> str:
    if not config.persistent_data:
        return ""
    return r'''
resolve_declared_path() {
  case "$1" in
    /*)
      printf '%s\n' "$1"
      ;;
    *)
      readlink -f "$(dirname "$APP_PATH")/$1" 2>/dev/null
      ;;
  esac
}

certify_persistent_data_path() {
  application_path="$1"
  physical_path="$2"
  mechanism="$3"
  app_target="$APP_PATH/$application_path"

  { test -e "$app_target" || test -L "$app_target"; } \
    || cert_fail "Persistent Data Safety: declared application path is missing"

  expected_target="$(resolve_declared_path "$physical_path")" \
    || cert_fail "Persistent Data Safety: declared physical path is missing"

  test -e "$expected_target" \
    || cert_fail "Persistent Data Safety: declared physical path is missing"

  case "$mechanism" in
    SYMLINK)
      test -L "$app_target" \
        || cert_fail "Persistent Data Safety: declared persistent path is a plain directory inside the current release"

      resolved_target="$(readlink -f "$app_target" 2>/dev/null)" \
        || cert_fail "Persistent Data Safety: unable to resolve declared persistent symlink"

      test "$resolved_target" = "$expected_target" \
        || cert_fail "Persistent Data Safety: resolved target does not match declared physical path"
      ;;
    BIND_MOUNT)
      test -d "$app_target" \
        || cert_fail "Persistent Data Safety: declared bind mount application path is missing"

      mount_source="$(awk -v target="$app_target" '$2 == target { print $1; found=1; exit } END { exit found ? 0 : 1 }' "$PERSISTENCE_MOUNTS_FILE" 2>/dev/null)" \
        || cert_fail "Persistent Data Safety: declared bind mount is not active"

      resolved_source="$(readlink -f "$mount_source" 2>/dev/null)" \
        || cert_fail "Persistent Data Safety: unable to resolve bind mount source"

      test "$resolved_source" = "$expected_target" \
        || cert_fail "Persistent Data Safety: bind mount source does not match declared physical path"
      ;;
    *)
      cert_fail "Persistent Data Safety: The declared persistence mechanism is not supported by Runtime Certifier v1."
      ;;
  esac
}
'''


def persistent_data_shell_invocations(config: Config) -> str:
    lines = []
    for item in config.persistent_data:
        lines.append(
            "certify_persistent_data_path "
            + shlex.quote(item.application_path)
            + " "
            + shlex.quote(item.physical_path)
            + " "
            + shlex.quote(normalize_persistence_mechanism(item.persistence_mechanism))
        )
    return "\n".join(lines) + ("\n" if lines else "")


def persistent_data_pass_output(config: Config) -> str:
    if not config.persistent_data:
        return ""
    return 'echo "PERSISTENT_DATA_SAFETY=PASS"\n'


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


def parse_scalar(value: str) -> object:
    if value in {"true", "True", "TRUE"}:
        return True
    if value in {"false", "False", "FALSE"}:
        return False
    if value in {"null", "Null", "NULL", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        return value


def strip_inline_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line


def parse_yaml_subset(text: str) -> object:
    tokens: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = strip_inline_comment(raw.rstrip())
        if line.strip():
            tokens.append((len(line) - len(line.lstrip(" ")), line.strip()))

    def parse_block(index: int, indent: int) -> tuple[object, int]:
        if index >= len(tokens):
            return {}, index
        if tokens[index][1].startswith("- "):
            return parse_list(index, indent)
        return parse_dict(index, indent)

    def parse_dict(index: int, indent: int) -> tuple[dict[str, object], int]:
        result: dict[str, object] = {}
        while index < len(tokens):
            current_indent, content = tokens[index]
            if current_indent < indent or current_indent > indent or content.startswith("- "):
                break
            key, sep, raw_value = content.partition(":")
            if not sep:
                index += 1
                continue
            index += 1
            raw_value = raw_value.strip()
            if raw_value:
                result[key.strip()] = parse_scalar(raw_value)
            elif index < len(tokens) and tokens[index][0] > current_indent:
                result[key.strip()], index = parse_block(index, tokens[index][0])
            else:
                result[key.strip()] = None
        return result, index

    def parse_list(index: int, indent: int) -> tuple[list[object], int]:
        result: list[object] = []
        while index < len(tokens):
            current_indent, content = tokens[index]
            if current_indent < indent or current_indent > indent or not content.startswith("- "):
                break
            item = content[2:].strip()
            index += 1
            if ":" in item and not item.startswith(("http://", "https://", "s3://", "arn:")):
                key, raw_value = item.split(":", 1)
                value: dict[str, object] = {key.strip(): parse_scalar(raw_value.strip()) if raw_value.strip() else None}
                if index < len(tokens) and tokens[index][0] > current_indent:
                    nested, index = parse_dict(index, tokens[index][0])
                    value.update(nested)
                result.append(value)
            elif item:
                result.append(parse_scalar(item))
            elif index < len(tokens) and tokens[index][0] > current_indent:
                value, index = parse_block(index, tokens[index][0])
                result.append(value)
            else:
                result.append(None)
        return result, index

    parsed, _ = parse_block(0, tokens[0][0] if tokens else 0)
    return parsed


def load_governance_manifest(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
        except Exception:
            data = parse_yaml_subset(text)
    if not isinstance(data, dict):
        raise CertifierError("governance config must be a mapping/object")
    return data


def load_persistent_data_declarations(path: Path) -> tuple[PersistentDataPath, ...]:
    manifest = load_governance_manifest(path)
    raw_items = manifest.get("persistent_data", [])
    if raw_items is None:
        return ()
    if not isinstance(raw_items, list):
        raise CertifierError("persistent_data must be a list")
    paths: list[PersistentDataPath] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise CertifierError("persistent_data entries must be mappings")
        classification = str(raw.get("classification") or "").strip().upper()
        if classification == "DISPOSABLE":
            continue
        if classification != "PERSISTENT":
            raise CertifierError("persistent_data classification must be PERSISTENT or DISPOSABLE")
        paths.append(
            PersistentDataPath(
                application_path=str(raw.get("application_path") or "").strip().strip("/"),
                physical_path=str(raw.get("physical_path") or "").strip(),
                persistence_mechanism=str(raw.get("persistence_mechanism") or "").strip(),
            )
        )
    return tuple(paths)


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

    parser.add_argument(
        "--governance-config",
        type=Path,
        default=Path(".github/synergie-governance.yml"),
    )

    args = parser.parse_args()
    persistent_data = load_persistent_data_declarations(args.governance_config)

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
        persistent_data=persistent_data,
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
