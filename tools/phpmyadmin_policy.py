#!/usr/bin/env python3
"""Synergie phpMyAdmin environment policy scanner.

This tool is intentionally static and read-only. It distinguishes runtime
phpMyAdmin exposure from harmless documentation references and never prints
secret values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


DOC_EXTENSIONS = {".md", ".rst", ".adoc", ".txt"}
DOC_PARTS = {"docs", "doc", "documentation", "changelog"}
FIXTURE_PARTS = {"tests", "test", "__tests__", "fixtures", "fixture", "examples"}
IGNORED_DIRS = {".git", "node_modules", "vendor", ".next", "dist", "build", "coverage"}

RUNTIME_SUFFIXES = {
    ".conf",
    ".cnf",
    ".env",
    ".example",
    ".ini",
    ".json",
    ".php",
    ".sh",
    ".tf",
    ".tfvars",
    ".toml",
    ".yaml",
    ".yml",
}

RUNTIME_NAME_PATTERNS = [
    "apache",
    "caddy",
    "cloudformation",
    "compose",
    "deployment",
    "docker",
    "dockerfile",
    "helm",
    "httpd",
    "ingress",
    "k8s",
    "kubernetes",
    "nginx",
    "package.json",
    "composer.json",
    "serverless",
    "terraform",
    "vhost",
]

PHPMYADMIN_PATTERNS = [
    re.compile(r"(?i)\bphpmyadmin/phpmyadmin\b"),
    re.compile(r"(?i)\bimage\s*:\s*['\"]?phpmyadmin(?:/phpmyadmin)?\b"),
    re.compile(r"(?i)^\s*(phpmyadmin|pma)\s*:\s*$"),
    re.compile(r"(?i)\b(container_name|service)\s*:\s*['\"]?(phpmyadmin|pma)\b"),
    re.compile(r"(?i)\b(apt|apt-get|yum|dnf|apk|brew)\s+.*\binstall\b.*\bphpmyadmin\b"),
    re.compile(r"(?i)\b(alias|location|proxypass|path|route|rewrite)\s+['\"]?/(?:phpmyadmin|phpMyAdmin|pma)\b"),
    re.compile(r"(?i)['\"]/(?:phpmyadmin|phpMyAdmin|pma)['\"]"),
]

PRODUCTION_HINTS = [
    re.compile(r"(?i)\bprod(?:uction)?\b"),
    re.compile(r"(?i)\blive\b"),
    re.compile(r"(?i)\bmain\b"),
]

NON_PRODUCTION_HINTS = [
    re.compile(r"(?i)\bstag(?:ing)?\b"),
    re.compile(r"(?i)\buat\b"),
    re.compile(r"(?i)\bdev(?:elopment)?\b"),
    re.compile(r"(?i)\blocal\b"),
    re.compile(r"(?i)\btest\b"),
]

PRODUCTION_DB_HINTS = [
    re.compile(r"(?i)\b(prod|production|live)[-_]?(db|database|mysql|mariadb)\b"),
    re.compile(r"(?i)\b(db|database|mysql|mariadb)[-_]?(prod|production|live)\b"),
    re.compile(r"(?i)\bPMA_HOST\s*[:=]\s*['\"]?[^'\"\n]*(prod|production|live)"),
    re.compile(r"(?i)\bDB_(HOST|DATABASE|NAME)\s*[:=]\s*['\"]?[^'\"\n]*(prod|production|live)"),
]

DB_USER_KEYS = r"(PMA_USER|MYSQL_USER|DB_USER|database_user|database_user_identity|db_user)"
DB_SCOPE_KEYS = r"(database_scope|database_privilege_scope|privilege_scope)"

PRIVILEGED_DB_USER_PATTERNS = [
    re.compile(rf"(?i)\b{DB_USER_KEYS}\s*[:=]\s*['\"]?(root|mysql\.root|admin|administrator|dba|superuser)\b"),
    re.compile(rf"(?i)\b{DB_USER_KEYS}\s*[:=]\s*['\"]?[^'\"\n]*(global|company|shared|all[_-]?databases|prod|production|live)[^'\"\n]*"),
]

UNSCOPED_DB_PRIVILEGE_PATTERNS = [
    re.compile(r"(?im)^\s*database_scoped\s*:\s*false\s*(?:#.*)?$"),
    re.compile(r"(?im)^\s*cross_application_access\s*:\s*true\s*(?:#.*)?$"),
    re.compile(r"(?im)^\s*unrestricted_database_admin\s*:\s*true\s*(?:#.*)?$"),
    re.compile(rf"(?i)\b{DB_SCOPE_KEYS}\s*[:=]\s*['\"]?(\*|all|global|company|shared|all[_-]?databases)\b"),
]

HARDCODED_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(PMA_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|DB_PASSWORD)\s*[:=]\s*['\"]?([^\s'\"#{}$][^\s'\"#]*)"),
    re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"#{}$][^\s'\"#]{5,})"),
]

INSECURE_STAGING_PATTERNS = [
    re.compile(r"(?i)\ballow_no_password\s*[:=]\s*(1|true|yes|on)\b"),
    re.compile(r"(?i)\bPMA_ALLOW_NO_PASSWORD\s*[:=]\s*(1|true|yes|on)\b"),
    re.compile(r"(?i)\bauth_type\s*[:=]\s*config\b"),
    re.compile(r"(?i)\bPMA_AUTH_TYPE\s*[:=]\s*config\b"),
]

GOVERNANCE_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pwd)\s*:"),
    re.compile(r"(?i)\b(secret|token|credential)\s*:"),
    re.compile(r"(?i)\b(access_key|private_key)\b"),
]

SECTION_HEADER_PATTERN = re.compile(r"^(\s*)([A-Za-z0-9_-]+)\s*:\s*(?:#.*)?$")


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    path: str
    line: int | None = None


def run_git(repo: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)


def path_parts(path: Path) -> set[str]:
    return {part.lower() for part in path.parts}


def is_documentation(path: Path) -> bool:
    parts = path_parts(path)
    if parts & DOC_PARTS:
        return True
    if path.name.lower().startswith(("readme", "changelog", "license")):
        return True
    return path.suffix.lower() in DOC_EXTENSIONS


def is_fixture(path: Path) -> bool:
    return bool(path_parts(path) & FIXTURE_PARTS)


def is_runtime_file(path: Path) -> bool:
    lower = str(path).lower()
    if is_documentation(path) or is_fixture(path):
        return False
    if path.suffix.lower() in RUNTIME_SUFFIXES:
        return True
    return any(token in lower for token in RUNTIME_NAME_PATTERNS)


def iter_files(repo: Path) -> list[Path]:
    files: list[Path] = []
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(repo).parts):
            continue
        files.append(path.relative_to(repo))
    return sorted(files)


def changed_files(repo: Path, base_sha: str | None, head_sha: str | None) -> set[Path] | None:
    if not base_sha:
        return None
    head = head_sha or "HEAD"
    cp = run_git(repo, ["diff", "--name-only", f"{base_sha}..{head}"])
    if cp.returncode != 0:
        return None
    return {Path(line.strip()) for line in cp.stdout.splitlines() if line.strip()}


def read_text(repo: Path, path: Path) -> str:
    try:
        file_path = repo / path
        if file_path.stat().st_size > 2_000_000:
            return ""
        return file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def find_indicator_lines(text: str) -> list[int]:
    lines: list[int] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if any(pattern.search(line) for pattern in PHPMYADMIN_PATTERNS):
            lines.append(number)
    return lines


def contains_phpmyadmin(text: str) -> bool:
    return any(pattern.search(text) for pattern in PHPMYADMIN_PATTERNS)


def is_non_production_context(path: Path, text: str) -> bool:
    haystack = f"{path}\n{text[:5000]}"
    has_non_prod = any(pattern.search(haystack) for pattern in NON_PRODUCTION_HINTS)
    has_prod = any(pattern.search(haystack) for pattern in PRODUCTION_HINTS)
    return has_non_prod and not has_prod


def is_staging_context(path: Path, text: str) -> bool:
    haystack = f"{path}\n{text[:5000]}"
    return any(pattern.search(haystack) for pattern in NON_PRODUCTION_HINTS)


def references_production_db(text: str) -> bool:
    return any(pattern.search(text) for pattern in PRODUCTION_DB_HINTS)


def references_privileged_db_user(text: str) -> bool:
    return any(pattern.search(text) for pattern in PRIVILEGED_DB_USER_PATTERNS)


def references_unscoped_db_privileges(text: str) -> bool:
    return any(pattern.search(text) for pattern in UNSCOPED_DB_PRIVILEGE_PATTERNS)


def has_hardcoded_secret(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for pattern in HARDCODED_SECRET_PATTERNS:
            match = pattern.search(stripped)
            if not match:
                continue
            if "${" in stripped or "secrets." in stripped or "secretKeyRef" in stripped or "env(" in stripped or "process.env" in stripped:
                continue
            return True
    return False


def has_insecure_staging_auth(text: str) -> bool:
    return any(pattern.search(text) for pattern in INSECURE_STAGING_PATTERNS)


def has_auth_signal(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered
        for token in (
            "pma_user",
            "pma_password",
            "pma_auth_type",
            "auth_type",
            "basic_auth",
            "htpasswd",
            "oauth",
            "sso",
            "secretkeyref",
            "cookie",
        )
    )


def config_line_number(text: str, pattern: re.Pattern[str]) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return number
    return 1


def extract_section(text: str, section_name: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = SECTION_HEADER_PATTERN.match(line)
        if not match or match.group(2) != section_name:
            continue
        indent = len(match.group(1))
        section_lines: list[str] = []
        for nested in lines[index + 1 :]:
            nested_match = SECTION_HEADER_PATTERN.match(nested)
            if nested_match and len(nested_match.group(1)) <= indent:
                break
            section_lines.append(nested)
        return "\n".join(section_lines)
    return ""


def has_governance_mapping(phpmyadmin_section: str) -> bool:
    mapping_section = (
        extract_section(phpmyadmin_section, "runtime_inventory")
        or extract_section(phpmyadmin_section, "environment_mappings")
        or extract_section(phpmyadmin_section, "environments")
    )
    lowered = mapping_section.lower()
    has_environment = "environment:" in lowered or "actual_environment:" in lowered
    has_branch = "branch:" in lowered
    has_server = re.search(r"(?im)^\s*server\s*:\s*(?!null\s*$)(?!['\"]?not[_ -]?configured['\"]?\s*$).+", mapping_section)
    has_database = re.search(r"(?im)^\s*database\s*:\s*(?!null\s*$)(?!['\"]?not[_ -]?configured['\"]?\s*$).+", mapping_section)
    has_database_user = re.search(
        r"(?im)^\s*(database_user|database_user_identity|db_user)\s*:\s*(?!null\s*$)(?!['\"]?not[_ -]?configured['\"]?\s*$).+",
        mapping_section,
    )
    has_database_scope = re.search(
        r"(?im)^\s*(database_scope|database_privilege_scope)\s*:\s*(?!null\s*$)(?!['\"]?not[_ -]?configured['\"]?\s*$).+",
        mapping_section,
    )
    has_configured_status = re.search(r"(?im)^\s*status\s*:\s*configured\s*(?:#.*)?$", mapping_section)
    return bool(
        has_branch
        and has_environment
        and has_server
        and has_database
        and has_database_user
        and has_database_scope
        and has_configured_status
    )


def governance_config_scan(
    repo: Path,
    config_path: Path | None,
    mode: str,
    require_environment_mapping: bool,
) -> tuple[list[Finding], list[Finding]]:
    failures: list[Finding] = []
    warnings: list[Finding] = []
    if config_path is None:
        return failures, warnings

    relative_path = config_path
    file_path = repo / relative_path
    if not file_path.exists():
        if require_environment_mapping:
            failures.append(
                Finding(
                    "fail",
                    "PHPMYADMIN ENVIRONMENT MAPPING MISSING",
                    "A non-production phpMyAdmin runtime exists, but the repository has no governance config mapping branch, environment, server, and database.",
                    str(relative_path),
                )
            )
        return failures, warnings

    text = read_text(repo, relative_path)
    phpmyadmin_section = extract_section(text, "phpmyadmin")
    if not phpmyadmin_section:
        if require_environment_mapping:
            failures.append(
                Finding(
                    "fail",
                    "PHPMYADMIN ENVIRONMENT MAPPING MISSING",
                    "A non-production phpMyAdmin runtime exists, but the governance config has no phpmyadmin mapping section.",
                    str(relative_path),
                )
            )
        return failures, warnings

    for pattern in GOVERNANCE_SECRET_PATTERNS:
        if pattern.search(phpmyadmin_section):
            failures.append(
                Finding(
                    "fail",
                    "PHPMYADMIN GOVERNANCE CONFIG CONTAINS SECRET FIELD",
                    "The phpMyAdmin governance config must not contain credential or secret fields.",
                    str(relative_path),
                    config_line_number(text, pattern),
                )
            )
            break

    production_section = extract_section(phpmyadmin_section, "production")
    if re.search(r"(?im)^\s*allowed\s*:\s*true\s*(?:#.*)?$", production_section):
        failures.append(
            Finding(
                "fail",
                "PRODUCTION PHPMYADMIN ENABLED IN GOVERNANCE CONFIG",
                "Production phpMyAdmin is prohibited; production.allowed must be false.",
                str(relative_path),
                config_line_number(text, re.compile(r"(?im)^\s*allowed\s*:\s*true\s*(?:#.*)?$")),
            )
        )

    access_section = extract_section(phpmyadmin_section, "access")
    if re.search(r"(?im)^\s*shared_company_admin\s*:\s*true\s*(?:#.*)?$", access_section):
        failures.append(
            Finding(
                "fail",
                "SHARED PHPMYADMIN ADMIN ACCOUNT PROHIBITED",
                "phpMyAdmin access must be application-scoped; a company-wide shared database administrator account is prohibited.",
                str(relative_path),
                config_line_number(text, re.compile(r"(?im)^\s*shared_company_admin\s*:\s*true\s*(?:#.*)?$")),
            )
        )
    if re.search(r"(?im)^\s*application_scoped\s*:\s*false\s*(?:#.*)?$", access_section):
        failures.append(
            Finding(
                "fail",
                "PHPMYADMIN ACCESS NOT APPLICATION SCOPED",
                "phpMyAdmin access must be scoped to the assigned application and database.",
                str(relative_path),
                config_line_number(text, re.compile(r"(?im)^\s*application_scoped\s*:\s*false\s*(?:#.*)?$")),
            )
        )
    if require_environment_mapping and not has_governance_mapping(phpmyadmin_section):
        failures.append(
            Finding(
                "fail",
                "PHPMYADMIN ENVIRONMENT MAPPING MISSING",
                "A non-production phpMyAdmin runtime exists, but branch, actual environment, server, database, database user identity, and database scope are not all mapped in governance config.",
                str(relative_path),
                config_line_number(text, re.compile(r"(?im)^\s*phpmyadmin\s*:")),
            )
        )
    if mode == "staging" and references_production_db(phpmyadmin_section):
        failures.append(
            Finding(
                "fail",
                "STAGING PHPMYADMIN POINTS TO PRODUCTION DATABASE",
                "The phpMyAdmin governance mapping appears to target a production database host or database name.",
                str(relative_path),
                config_line_number(text, re.compile(r"(?im)^\s*(database|server)\s*:")),
            )
        )
    if references_privileged_db_user(phpmyadmin_section):
        failures.append(
            Finding(
                "fail",
                "PHPMYADMIN DATABASE USER NOT LEAST PRIVILEGE",
                "phpMyAdmin must not use root, global administrator, shared, or production database user identities.",
                str(relative_path),
                config_line_number(text, re.compile(rf"(?im)^\s*{DB_USER_KEYS}\s*:")),
            )
        )
    if references_unscoped_db_privileges(phpmyadmin_section):
        failures.append(
            Finding(
                "fail",
                "PHPMYADMIN DATABASE ACCESS NOT SCOPED",
                "phpMyAdmin database privileges must be limited to the assigned application database, even in development and staging.",
                str(relative_path),
                config_line_number(
                    text,
                    re.compile(
                        r"(?im)^\s*(database_scoped|cross_application_access|unrestricted_database_admin|database_scope|database_privilege_scope)\s*:"
                    ),
                ),
            )
        )

    if mode == "production" and not production_section:
        warnings.append(
            Finding(
                "warn",
                "PHPMYADMIN PRODUCTION POSTURE NOT DECLARED",
                "Governance config has a phpmyadmin section but does not explicitly declare production.allowed: false.",
                str(relative_path),
                config_line_number(text, re.compile(r"(?im)^\s*phpmyadmin\s*:")),
            )
        )

    return failures, warnings


def production_scan(repo: Path, changed: set[Path] | None) -> tuple[list[Finding], list[Finding]]:
    failures: list[Finding] = []
    warnings: list[Finding] = []
    changed_scope = changed if changed is not None else set(iter_files(repo))
    changed_known = changed is not None

    for path in iter_files(repo):
        if not is_runtime_file(path):
            continue
        text = read_text(repo, path)
        if not contains_phpmyadmin(text):
            continue
        if is_non_production_context(path, text):
            continue
        line = find_indicator_lines(text)[0] if find_indicator_lines(text) else 1
        if path in changed_scope:
            failures.append(
                Finding(
                    "fail",
                    "PRODUCTION PHPMYADMIN POLICY VIOLATION",
                    "Runtime/deployment configuration introduces phpMyAdmin exposure for production.",
                    str(path),
                    line,
                )
            )
        elif changed_known:
            warnings.append(
                Finding(
                    "warn",
                    "PRE-EXISTING PRODUCTION PHPMYADMIN VIOLATION",
                    "Existing runtime/deployment configuration references phpMyAdmin outside the current PR diff.",
                    str(path),
                    line,
                )
            )
        else:
            failures.append(
                Finding(
                    "fail",
                    "PRODUCTION PHPMYADMIN POLICY VIOLATION",
                    "Runtime/deployment configuration exposes phpMyAdmin and no PR diff was available to classify it as legacy.",
                    str(path),
                    line,
                )
            )
    return failures, warnings


def staging_scan(repo: Path) -> tuple[list[Finding], list[Finding], bool]:
    failures: list[Finding] = []
    warnings: list[Finding] = []
    found = False

    for path in iter_files(repo):
        if not is_runtime_file(path):
            continue
        text = read_text(repo, path)
        if not contains_phpmyadmin(text) or not is_staging_context(path, text):
            continue
        found = True
        line = find_indicator_lines(text)[0] if find_indicator_lines(text) else 1
        if references_production_db(text):
            failures.append(
                Finding(
                    "fail",
                    "STAGING PHPMYADMIN POINTS TO PRODUCTION DATABASE",
                    "Staging/UAT phpMyAdmin configuration appears to target a production database host or database name.",
                    str(path),
                    line,
                )
            )
        if references_privileged_db_user(text):
            failures.append(
                Finding(
                    "fail",
                    "STAGING PHPMYADMIN DATABASE USER NOT LEAST PRIVILEGE",
                    "Staging/UAT phpMyAdmin must use an application and environment-scoped database user, not root/global/shared/production credentials.",
                    str(path),
                    line,
                )
            )
        if has_hardcoded_secret(text):
            failures.append(
                Finding(
                    "fail",
                    "STAGING PHPMYADMIN SECRET IN GIT",
                    "Staging/UAT phpMyAdmin configuration contains a hardcoded database/admin password-like value.",
                    str(path),
                    line,
                )
            )
        if has_insecure_staging_auth(text):
            failures.append(
                Finding(
                    "fail",
                    "STAGING PHPMYADMIN INSECURE AUTH",
                    "Staging/UAT phpMyAdmin permits config auth or empty-password login.",
                    str(path),
                    line,
                )
            )
        if "http://" in text.lower() and "https://" not in text.lower():
            warnings.append(
                Finding(
                    "warn",
                    "STAGING PHPMYADMIN HTTPS NOT PROVEN",
                    "Staging/UAT phpMyAdmin should use HTTPS; this file contains only an HTTP URL.",
                    str(path),
                    line,
                )
            )
        if not has_auth_signal(text):
            warnings.append(
                Finding(
                    "warn",
                    "STAGING PHPMYADMIN AUTH NOT PROVEN",
                    "Staging/UAT phpMyAdmin is present, but authentication controls were not proven from this file.",
                    str(path),
                    line,
                )
            )
    if not found:
        warnings.append(Finding("info", "NO PHPMYADMIN", "No staging/UAT phpMyAdmin runtime configuration was found.", ""))
    return failures, warnings, found


def write_reports(out: Path | None, json_out: Path | None, mode: str, failures: list[Finding], warnings: list[Finding]) -> None:
    status = "FAIL" if failures else "PASS"
    lines = [
        "# Synergie phpMyAdmin Policy Report",
        "",
        f"Mode: `{mode}`",
        f"Status: `{status}`",
        "",
    ]
    if failures:
        lines.append("## Blocking Findings")
        for finding in failures:
            location = f"{finding.path}:{finding.line}" if finding.path and finding.line else finding.path
            lines.append(f"- `{finding.code}` {location} - {finding.message}")
        lines.append("")
    if warnings:
        lines.append("## Non-Blocking Findings")
        for finding in warnings:
            location = f"{finding.path}:{finding.line}" if finding.path and finding.line else finding.path
            location = f" {location}" if location else ""
            lines.append(f"- `{finding.code}`{location} - {finding.message}")
        lines.append("")
    if not failures and not warnings:
        lines.append("No phpMyAdmin policy findings.")
        lines.append("")

    payload = {
        "mode": mode,
        "status": status,
        "failures": [asdict(finding) for finding in failures],
        "warnings": [asdict(finding) for finding in warnings],
    }

    text = "\n".join(lines)
    print(text)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synergie phpMyAdmin policy scanner.")
    parser.add_argument("--repo", default=".", help="Repository root to scan.")
    parser.add_argument("--mode", choices=["production", "staging"], required=True)
    parser.add_argument("--base-sha", default=os.getenv("GITHUB_BASE_SHA") or os.getenv("PR_QA_BASE_SHA"))
    parser.add_argument("--head-sha", default=os.getenv("GITHUB_HEAD_SHA") or os.getenv("PR_QA_HEAD_SHA") or "HEAD")
    parser.add_argument(
        "--governance-config",
        type=Path,
        default=Path(".github/synergie-governance.yml"),
        help="Repository governance config to validate when present.",
    )
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json-out", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    changed = changed_files(repo, args.base_sha, args.head_sha)

    staging_phpmyadmin_found = False
    if args.mode == "production":
        failures, warnings = production_scan(repo, changed)
    else:
        failures, warnings, staging_phpmyadmin_found = staging_scan(repo)

    config_failures, config_warnings = governance_config_scan(
        repo,
        args.governance_config,
        args.mode,
        require_environment_mapping=args.mode == "staging" and staging_phpmyadmin_found,
    )
    failures.extend(config_failures)
    warnings.extend(config_warnings)

    write_reports(args.out, args.json_out, args.mode, failures, warnings)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
