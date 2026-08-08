#!/usr/bin/env python3
"""Generate a credential-free phpMyAdmin onboarding plan for non-production apps."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


PRODUCTION_ENVIRONMENTS = {"prod", "production", "main", "live"}
NON_PRODUCTION_ENVIRONMENTS = {"local", "dev", "development", "staging", "stage", "uat", "test", "training"}
PRODUCTION_CLASSIFICATIONS = {"prod", "production", "main", "live", "production-db", "prod-db"}
ROOT_USERS = {"root", "mysql.root", "admin", "administrator", "dba", "superuser"}
GLOBAL_SCOPES = {"*", "*.*", "all", "global", "company", "shared", "all_databases", "all-databases"}
GENERIC_APPLICATION_TOKENS = {"app", "application", "project", "system", "service", "portal", "admin", "new"}
ENVIRONMENT_SCOPE_TOKENS = {
    "local": {"local"},
    "dev": {"dev", "development"},
    "development": {"dev", "development"},
    "staging": {"stage", "staging"},
    "stage": {"stage", "staging"},
    "uat": {"uat"},
    "test": {"test"},
    "training": {"train", "training"},
}


@dataclass
class OnboardingInput:
    application_name: str
    environment: str
    hostname: str
    database_name: str
    database_user_identity: str
    database_scope: str
    developer_identity: str
    db_classification: str
    https_available: bool
    db_user_global_scope: bool
    route: str


@dataclass
class OnboardingPlan:
    status: str
    application_name: str
    environment: str
    hostname: str
    route: str
    database_name: str
    database_user_identity: str
    database_scope: str
    developer_identity: str
    generated_files: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a Synergie non-production phpMyAdmin onboarding plan.")
    parser.add_argument("--application-name", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--database-name", required=True)
    parser.add_argument("--database-user-identity", required=True)
    parser.add_argument("--database-scope", required=True)
    parser.add_argument("--developer-identity", required=True)
    parser.add_argument("--db-classification", required=True, help="development, staging, uat, test, or production classification.")
    parser.add_argument("--https-available", choices=["true", "false"], required=True)
    parser.add_argument("--db-user-global-scope", choices=["true", "false"], default="false")
    parser.add_argument("--route", default="/synergie-pma/")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--json-out", default="")
    return parser.parse_args()


def normalize_bool(value: str) -> bool:
    return value.lower() == "true"


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return normalized or "application"


def identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def application_scope_tokens(application_name: str) -> set[str]:
    tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", application_name.lower())
        if len(token) >= 3 and token not in GENERIC_APPLICATION_TOKENS
    }
    compact = identifier(application_name)
    if len(compact) >= 3:
        tokens.add(compact)
    return tokens


def contains_any_scope_token(value: str, tokens: set[str]) -> bool:
    normalized = identifier(value)
    return any(identifier(token) in normalized for token in tokens if identifier(token))


def build_input(args: argparse.Namespace) -> OnboardingInput:
    return OnboardingInput(
        application_name=args.application_name.strip(),
        environment=args.environment.strip().lower(),
        hostname=args.hostname.strip().lower(),
        database_name=args.database_name.strip(),
        database_user_identity=args.database_user_identity.strip(),
        database_scope=args.database_scope.strip(),
        developer_identity=args.developer_identity.strip(),
        db_classification=args.db_classification.strip().lower(),
        https_available=normalize_bool(args.https_available),
        db_user_global_scope=normalize_bool(args.db_user_global_scope),
        route=normalize_route(args.route),
    )


def normalize_route(route: str) -> str:
    cleaned = route.strip() or "/synergie-pma/"
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    if not cleaned.endswith("/"):
        cleaned += "/"
    return cleaned


def validate_input(config: OnboardingInput) -> list[str]:
    errors: list[str] = []
    if config.environment in PRODUCTION_ENVIRONMENTS:
        errors.append("production environment is prohibited")
    if config.environment not in NON_PRODUCTION_ENVIRONMENTS:
        errors.append("environment must be explicit non-production")
    if config.db_classification in PRODUCTION_CLASSIFICATIONS:
        errors.append("production database classification is prohibited")
    if config.database_user_identity.lower() in ROOT_USERS:
        errors.append("root/global database user is prohibited")
    if config.db_user_global_scope:
        errors.append("database user must not have global scope")
    if config.database_scope.lower() in GLOBAL_SCOPES:
        errors.append("database scope must be application and environment specific")
    if config.database_scope != config.database_name:
        errors.append("database scope must match the approved application/environment database")
    app_tokens = application_scope_tokens(config.application_name)
    if app_tokens and not contains_any_scope_token(config.database_name, app_tokens):
        errors.append("database scope must include the application identity")
    environment_tokens = ENVIRONMENT_SCOPE_TOKENS.get(config.environment, {config.environment})
    if not contains_any_scope_token(config.database_name, environment_tokens):
        errors.append("database scope must include the environment identity")
    if not contains_any_scope_token(config.database_user_identity, app_tokens | environment_tokens):
        errors.append("database user identity must include the application or environment scope")
    if not config.developer_identity:
        errors.append("developer owner is required")
    if not config.https_available:
        errors.append("HTTPS must be available before phpMyAdmin is exposed")
    if re.search(r"(?i)(prod|production|live)", config.database_name):
        errors.append("database name appears production-like")
    if re.search(r"(?i)(prod|production|live)", config.hostname) and config.environment not in {"staging", "stage"}:
        errors.append("hostname appears production-like for this environment")
    return errors


def render_apache_include(config: OnboardingInput) -> str:
    name = slug(f"{config.application_name}-{config.environment}")
    auth_file = f"/etc/apache2/synergie-pma-{name}.htpasswd"
    route = config.route.rstrip("/")
    return f"""# Synergie managed phpMyAdmin access for {config.application_name} {config.environment}.
# Include this only inside the approved HTTPS vhost for {config.hostname}.
Alias {route} /usr/share/phpmyadmin

<Directory /usr/share/phpmyadmin>
    Options SymLinksIfOwnerMatch
    DirectoryIndex index.php
    AllowOverride None
    AuthType Basic
    AuthName "Synergie {config.application_name} {config.environment} database administration"
    AuthUserFile {auth_file}
    Require valid-user
</Directory>

<Directory /usr/share/phpmyadmin/templates>
    Require all denied
</Directory>

<Directory /usr/share/phpmyadmin/libraries>
    Require all denied
</Directory>
"""


def render_phpmyadmin_policy(config: OnboardingInput) -> str:
    return f"""<?php
// Synergie managed phpMyAdmin policy for {config.application_name} {config.environment}.
// The blowfish secret must be generated on the target host. Do not commit secrets.
$cfg['Servers'][1]['auth_type'] = 'cookie';
$cfg['Servers'][1]['verbose'] = '{config.application_name} {config.environment} database';
$cfg['Servers'][1]['host'] = '127.0.0.1';
$cfg['Servers'][1]['connect_type'] = 'tcp';
$cfg['Servers'][1]['AllowNoPassword'] = false;
$cfg['Servers'][1]['only_db'] = array('{config.database_name}');
$cfg['Servers'][1]['hide_db'] = '^(information_schema|mysql|performance_schema|sys)$';
$cfg['ForceSSL'] = true;
$cfg['LoginCookieSecure'] = true;
$cfg['LoginCookieHttpOnly'] = true;
$cfg['AllowArbitraryServer'] = false;
"""


def render_runbook(config: OnboardingInput) -> str:
    name = slug(f"{config.application_name}-{config.environment}")
    auth_file = f"/etc/apache2/synergie-pma-{name}.htpasswd"
    include_file = f"/etc/apache2/conf-available/synergie-pma-{name}.conf"
    pma_policy = f"/etc/phpmyadmin/conf.d/synergie-pma-{name}.inc.php"
    return f"""# Synergie Non-Production phpMyAdmin Onboarding

Application: `{config.application_name}`
Environment: `{config.environment}`
Hostname: `{config.hostname}`
Route: `{config.route}`
Database: `{config.database_name}`
Database user: `{config.database_user_identity}`
Developer: `{config.developer_identity}`

## Controls

- Non-production only.
- Include phpMyAdmin only inside the approved application HTTPS vhost.
- Keep the global Apache phpMyAdmin alias disabled.
- Put Basic Auth in `{auth_file}`, outside all document roots.
- Store only Apache-compatible password hashes in Basic Auth files.
- Do not store database passwords in phpMyAdmin config, Git, PR comments, or runbooks.
- Use phpMyAdmin cookie authentication.
- Use the scoped database user `{config.database_user_identity}` for database login.
- Confirm the database user can access only `{config.database_name}`.
- Do not use root, global, shared, or production database users.

## Installation Outline

1. Install phpMyAdmin and Apache utilities on the approved non-production host.
2. Disable `/etc/apache2/conf-enabled/phpmyadmin.conf` if the package enables it.
3. Install the generated Apache include as `{include_file}`.
4. Install the generated phpMyAdmin policy as `{pma_policy}` and generate the blowfish secret on the host.
5. Create or update `{auth_file}` with a hashed Basic Auth credential for `{config.developer_identity}`.
6. Include `{include_file}` only in the approved HTTPS vhost for `{config.hostname}`.
7. Run `apache2ctl configtest` and reload Apache.
8. Validate unauthenticated HTTPS returns `401`, authenticated HTTPS reaches the phpMyAdmin login page, and HTTP redirects to HTTPS.
9. Validate effective MySQL grants by logging in as `{config.database_user_identity}` and confirming only `{config.database_name}` is visible.

## Credential Rotation

1. Generate a strong replacement Basic Auth password on the target host.
2. Update `{auth_file}` with `htpasswd -B` or another Apache-compatible hash.
3. Validate the new credential reaches the phpMyAdmin login page.
4. Confirm the old credential no longer authenticates.
5. Deliver the new credential through the approved secure channel.
6. Remove any temporary plaintext bootstrap material after delivery confirmation.

## Developer Revocation

Disable a developer without uninstalling phpMyAdmin or changing application database credentials:

```bash
sudo cp -a {auth_file} {auth_file}.$(date -u +%Y%m%dT%H%M%SZ).bak
sudo htpasswd -D {auth_file} <basic-auth-username>
sudo apache2ctl configtest
sudo systemctl reload apache2
```

Validate the removed identity receives `401` and any remaining authorized identities still work.

## Rollback

```bash
sudo cp -a /etc/apache2/sites-enabled/<vhost>.conf /etc/apache2/sites-enabled/<vhost>.conf.rollback.$(date -u +%Y%m%dT%H%M%SZ)
sudo sed -i '\\#IncludeOptional {include_file}#d' /etc/apache2/sites-enabled/<vhost>.conf
sudo apache2ctl configtest
sudo systemctl reload apache2
```

Do not modify production, production databases, or unrelated vhosts as part of rollback.
"""


def write_outputs(config: OnboardingInput, output_dir: Path) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "apache-include.conf": render_apache_include(config),
        "phpmyadmin-policy.inc.php": render_phpmyadmin_policy(config),
        "README.md": render_runbook(config),
    }
    written: list[str] = []
    for name, text in files.items():
        path = output_dir / name
        path.write_text(text, encoding="utf-8")
        written.append(str(path))
    return written


def main() -> int:
    args = parse_args()
    config = build_input(args)
    errors = validate_input(config)
    if errors:
        payload = {"status": "FAIL", "errors": errors, "input": asdict(config)}
        write_json(args.json_out, payload)
        print("PHPMYADMIN NON-PRODUCTION ONBOARDING REFUSED")
        for error in errors:
            print(f"- {error}")
        return 1

    generated: list[str] = []
    if args.output_dir:
        generated = write_outputs(config, Path(args.output_dir))
    plan = OnboardingPlan(
        status="PASS",
        application_name=config.application_name,
        environment=config.environment,
        hostname=config.hostname,
        route=config.route,
        database_name=config.database_name,
        database_user_identity=config.database_user_identity,
        database_scope=config.database_scope,
        developer_identity=config.developer_identity,
        generated_files=generated,
    )
    payload = asdict(plan)
    write_json(args.json_out, payload)
    print(json.dumps(payload, indent=2))
    return 0


def write_json(path: str, payload: dict[str, object]) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
