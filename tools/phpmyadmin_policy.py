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


def staging_scan(repo: Path) -> tuple[list[Finding], list[Finding]]:
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
    return failures, warnings


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
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json-out", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    changed = changed_files(repo, args.base_sha, args.head_sha)

    if args.mode == "production":
        failures, warnings = production_scan(repo, changed)
    else:
        failures, warnings = staging_scan(repo)

    write_reports(args.out, args.json_out, args.mode, failures, warnings)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
