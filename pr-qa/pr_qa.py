#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from adapters import ADAPTERS
from adapters.base import (
    FAIL,
    MANDATORY_GATES,
    PASS,
    SKIP,
    WARNING,
    CheckResult,
    PRContext,
    command_exists,
    failed,
    find_named_files,
    grep_text_files,
    is_binary_file,
    markdown_escape,
    match_any,
    passed,
    read_json,
    read_text,
    redact,
    should_skip_path,
    skipped,
    warning,
)


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = FRAMEWORK_ROOT / "policy" / "pr-qa-policy.json"
CONFIG_PATH = ".github/pr-qa.yml"
CANONICAL_CALLER_TEMPLATE_PATH = FRAMEWORK_ROOT / "examples" / "caller-workflow.yml"
CANONICAL_PR_TEMPLATE_PATH = FRAMEWORK_ROOT / "examples" / "pull_request_template.md"
EMERGENCY_OVERRIDE_REASON_ENV = "PR_QA_EMERGENCY_OVERRIDE_REASON"
CODEOWNERS_PATHS = {"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}
TECHNICAL_BASELINE_SCHEMA_VERSION = 1
TECHNICAL_BASELINE_TYPE = "pr_qa_technical_pass"
TECHNICAL_BASELINE_DIR = ".pr-qa-technical-baseline"
TECHNICAL_BASELINE_FILE = "technical-baseline.json"
TECHNICAL_BASELINE_CACHE_PREFIX = "pr-qa-technical-v1"
PR_STATUS_COMMENT_MARKER = "<!-- synergie-pr-status -->"
PR_STATUS_ACTION_ITEM_LIMIT = 5
PR_STATUS_TECHNICAL_DETAIL_LIMIT = 4
PR_STATUS_TECHNICAL_DETAIL_CHARS = 240
TECHNICAL_GATE_NAMES = {
    "Baseline Alignment",
    "Config Validation",
    "Repository Integrity",
    "Repository Hygiene",
    "Git Validation",
    "Secrets",
    "Executable Classification",
    "Protected Resources",
    "Deployment Risk",
    "Migration Risk",
    "Formatting",
    "Lint",
    "Build",
    "Tests",
    "Dependencies",
    "Licence",
}
REUSABLE_SANDBOXED_GATE_NAMES = {
    "Formatting",
    "Lint",
    "Build",
    "Tests",
    "Dependencies",
    "Licence",
}
RELEASE_SENSITIVE_EXACT_FILES = {
    "policy/pr-qa-policy.json",
}
RELEASE_SENSITIVE_ROOTS = {
    "pr-qa",
}

GATE_ORDER = [
    ("baseline_alignment", "Baseline Alignment"),
    ("config_validation", "Config Validation"),
    ("repository_integrity", "Repository Integrity"),
    ("repository_hygiene", "Repository Hygiene"),
    ("git_validation", "Git Validation"),
    ("secrets", "Secrets"),
    ("executable_classification", "Executable Classification"),
    ("protected_resources", "Protected Resources"),
    ("deployment_safety", "Deployment Risk"),
    ("database_safety", "Migration Risk"),
    ("formatting", "Formatting"),
    ("lint", "Lint"),
    ("build", "Build"),
    ("tests", "Tests"),
    ("dependencies", "Dependencies"),
    ("licence", "Licence"),
    ("documentation", "Documentation"),
    ("advisory_review", "Architecture"),
    ("release_drift", "Release Drift"),
    ("risk", "Risk Engine"),
    ("evidence", "Evidence"),
    ("review_policy", "Review Policy"),
]

BASELINE_NON_RELAXABLE_CHECKS = [
    "Gitleaks execution and true-secret detection",
    "Composer/dependency security audit",
    "language syntax/lint and application tests",
    "migration syntax/executability evidence",
    "CODEOWNERS, human review, and branch protection",
    "deployment and workflow-security review",
    "dangerous credential files and suspicious binaries",
]

NEW_FINDING = "NEW_FINDING"
INHERITED_BASELINE = "INHERITED_BASELINE"
AUTHORIZED_OVERLAY = "AUTHORIZED_OVERLAY"
NON_INHERITABLE_SECURITY_FINDING = "NON_INHERITABLE_SECURITY_FINDING"

BASELINE_STATIC_ASSET_PATTERNS = [
    "public/**",
    "assets/**",
    "static/**",
    "resources/**/*.min.js",
    "resources/**/*.min.css",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
]
STATIC_BROWSER_ASSET_ROOTS = {"assets", "public", "static"}
STATIC_BROWSER_RESOURCE_ROOTS = {"js", "css", "assets"}
STATIC_BROWSER_ASSET_DIRS = {"js", "javascript", "css", "styles", "stylesheets"}
STATIC_BROWSER_ASSET_SUFFIXES = {".js", ".css"}
EXECUTABLE_SCRIPT_ROOTS = {".github", "bin", "ci", "deploy", "scripts", "server", "tools"}

ADAPTER_EXTENSIONS = {
    "php": {".php"},
    "node": {".js", ".jsx", ".ts", ".tsx"},
    "python": {".py"},
    "go": {".go"},
    "gradle": {".kt", ".kts", ".java"},
    "java": {".java"},
    "swift": {".swift"},
    "dotnet": {".cs", ".vb", ".fs"},
    "rust": {".rs"},
    "shell": {".sh", ".bash"},
    "sql": {".sql"},
    "terraform": {".tf"},
}

TECHNOLOGY_CHANGE_PATTERNS = {
    "php": [
        "*.php",
        "artisan",
        "composer.json",
        "composer.lock",
        "phpunit.xml",
        "phpunit.xml.dist",
        ".php-cs-fixer.php",
        "pint.json",
    ],
    "node": [
        "*.cjs",
        "*.cts",
        "*.js",
        "*.jsx",
        "*.mjs",
        "*.mts",
        "*.ts",
        "*.tsx",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
        "vite.config.*",
        "webpack.config.*",
        "rollup.config.*",
        "tsconfig*.json",
    ],
    "python": [
        "*.py",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements*.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
    ],
    "go": ["*.go", "go.mod", "go.sum"],
    "gradle": ["*.gradle", "*.gradle.kts", "*.java", "*.kt", "*.kts", "build.gradle", "settings.gradle", "gradle.properties"],
    "java": ["*.java", "pom.xml"],
    "swift": ["*.swift", "Package.swift", "*.xcodeproj/**", "*.xcworkspace/**"],
    "dotnet": ["*.cs", "*.vb", "*.fs", "*.sln", "*.csproj", "*.vbproj", "*.fsproj"],
    "rust": ["*.rs", "Cargo.toml", "Cargo.lock"],
    "shell": ["*.sh", "*.bash"],
    "sql": ["*.sql", "**/*.sql"],
    "docker": ["Dockerfile", "Dockerfile.*", "docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml"],
    "terraform": ["*.tf", "*.tfvars", "*.tf.json", "*.tfvars.json", ".terraform.lock.hcl"],
    "kubernetes": ["*.yml", "*.yaml"],
    "github_actions": ["*.yml", "*.yaml"],
}


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    policy = load_policy(Path(args.policy))

    if args.publish_pr_status_comment:
        return publish_pr_status_comment_cli(args, policy)

    if args.detect_only:
        write_detection_outputs(detect_technologies(repo), args.github_output)
        return 0

    event = load_event(args.event_path)
    git_context = gather_git_context(repo, event, args.base_ref, args.head_ref)
    config, config_violations = load_effective_config(repo, CONFIG_PATH, policy, git_context)
    config_violations.extend(apply_repository_profile_override(config, args.repository_profile, policy))
    technologies = detect_technologies(repo)
    ctx = PRContext(
        repo=repo,
        config=config,
        policy=policy,
        changed_files=git_context["changed_files"],
        base_ref=git_context.get("base_ref"),
        head_ref=git_context.get("head_ref"),
        pr_body=git_context.get("pr_body", ""),
        event=event,
        additions=git_context.get("additions", 0),
        deletions=git_context.get("deletions", 0),
        no_command_runs=args.no_command_runs,
        command_timeout_seconds=int(args.command_timeout_minutes * 60),
        config_violations=config_violations,
        diff_error=git_context.get("diff_error", ""),
    )
    context_cache(ctx)["numstat"] = dict(git_context.get("numstat") or {})

    if args.technical_baseline_key_out:
        write_technical_baseline_key_output(args.technical_baseline_key_out, technical_baseline_binding(ctx, git_context, technologies, policy, Path(args.policy)))
        return 0

    results: list[CheckResult] = []
    results.extend(run_static_preflight(ctx, git_context, technologies, args.out))
    static_failed = any(result.is_blocking_failure() for result in results)

    if args.static_only or static_failed:
        if static_failed and not args.static_only:
            add_phase_skips(results, "Phase 1 static preflight failed; no repository-controlled commands were executed.")
        summary = summarize(results, technologies, ctx, git_context)
        write_emergency_override_audit(args, summary, results, ctx, git_context)
        write_reports(args, summary, results, ctx)
        return 1 if summary["overall_result"] == FAIL else 0

    reused_baseline, baseline_details = load_reusable_technical_baseline(args.technical_baseline_in, ctx, git_context, technologies, policy, Path(args.policy))
    if reused_baseline:
        results.extend(reused_baseline)
    else:
        if args.technical_baseline_in:
            context_cache(ctx)["technical_baseline_reuse_details"] = baseline_details
        sandboxed_results = run_sandboxed_validation(ctx, technologies)
        results.extend(sandboxed_results)
        write_technical_baseline_if_passed(args.technical_baseline_out, ctx, git_context, technologies, policy, Path(args.policy), results)
    results.extend(run_governance(ctx, results, args))
    summary = summarize(results, technologies, ctx, git_context)
    write_emergency_override_audit(args, summary, results, ctx, git_context)
    write_reports(args, summary, results, ctx)
    return 1 if summary["overall_result"] == FAIL else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synergie hardened PR QA engine.")
    parser.add_argument("--repo", default=".", help="Repository root to inspect.")
    parser.add_argument("--config", default=CONFIG_PATH, help="Ignored for security; repository config path is fixed.")
    parser.add_argument("--policy", default=str(DEFAULT_POLICY_PATH), help="Immutable central policy path.")
    parser.add_argument("--out", default="", help="Markdown report path.")
    parser.add_argument("--json-out", default="", help="JSON report path.")
    parser.add_argument("--event-path", default=os.environ.get("GITHUB_EVENT_PATH", ""), help="GitHub event JSON path.")
    parser.add_argument("--base-ref", default="", help="Base ref or SHA override.")
    parser.add_argument("--head-ref", default="", help="Head ref override.")
    parser.add_argument("--command-timeout-minutes", type=float, default=20)
    parser.add_argument("--detect-only", action="store_true")
    parser.add_argument("--static-only", action="store_true", help="Run only Phase 1 static preflight.")
    parser.add_argument("--repository-profile", default="", help="Operator-selected repository profile for governance-aware self-validation.")
    parser.add_argument("--github-output", default="", help="GITHUB_OUTPUT file for detection mode.")
    parser.add_argument("--no-command-runs", action="store_true", help="Do not execute adapter commands.")
    parser.add_argument("--emergency-override-reason", default=os.environ.get(EMERGENCY_OVERRIDE_REASON_ENV, ""), help="Governance-only emergency override reason.")
    parser.add_argument("--emergency-override-out", default="", help="Emergency override audit record path.")
    parser.add_argument("--review-policy-input", default="", help="Optional JSON file with pull request review and mergeability evidence.")
    parser.add_argument("--technical-baseline-key-out", default="", help="GITHUB_OUTPUT path for exact-content technical baseline cache key.")
    parser.add_argument("--technical-baseline-in", default="", help="Reusable exact-content technical PASS baseline JSON path.")
    parser.add_argument("--technical-baseline-out", default="", help="Write exact-content technical PASS baseline JSON after technical validation succeeds.")
    parser.add_argument("--qa-packet-out", default="", help="Write QA packet assembled from technical baseline state and current PR evidence.")
    parser.add_argument("--publish-pr-status-comment", action="store_true", help="Publish or update the human-friendly PR status comment.")
    parser.add_argument("--status-json-in", default="", help="Current-run PR QA JSON report used to render the status comment.")
    return parser.parse_args()


def load_policy(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"FAIL: immutable central policy is unavailable at {path}")
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"FAIL: immutable central policy is invalid JSON: {exc}") from exc
    if policy.get("version") != 1 or not isinstance(policy.get("defaults"), dict):
        raise SystemExit("FAIL: immutable central policy has unsupported shape.")
    mandatory = set(policy.get("mandatory_gates", []))
    missing = MANDATORY_GATES - mandatory
    if missing:
        raise SystemExit(f"FAIL: immutable central policy does not include mandatory gates: {sorted(missing)}")
    return policy


def load_effective_config(repo: Path, config_path: str, policy: dict[str, Any], git_context: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    config = deepcopy(policy["defaults"])
    violations: list[str] = []
    trusted_text = read_base_file(repo, git_context, config_path)
    if trusted_text:
        parsed = parse_yaml_or_json(trusted_text)
        if not isinstance(parsed, dict):
            violations.append(f"{config_path}: trusted base configuration is not a mapping.")
        else:
            violations.extend(validate_repo_config(parsed, policy))
            config = merge_governed_config(config, parsed, policy, violations)
    elif (repo / config_path).exists() and git_context.get("base_sha"):
        violations.append(f"{config_path}: configuration is new or unavailable on the base branch; PR-head configuration is not trusted.")

    if config_path in git_context.get("changed_files", []):
        violations.append(f"{config_path}: PR modifies QA configuration; mandatory policy changes must be made through the central framework.")
        head_path = repo / config_path
        if head_path.exists():
            head_parsed = parse_yaml_or_json(head_path.read_text(encoding="utf-8"))
            if isinstance(head_parsed, dict):
                violations.extend(validate_repo_config(head_parsed, policy))
    return config, violations


def validate_repo_config(parsed: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    allowed_top = {"version", "repository", "gates", "thresholds", "branch_naming", "commit_messages", "evidence", "runtime", "adapters"}
    for key in parsed:
        if key not in allowed_top:
            violations.append(f"Unknown top-level config key `{key}`.")
    if parsed.get("version") not in {None, 1}:
        violations.append("Unsupported config version.")
    repository = parsed.get("repository", {})
    if repository is not None and not isinstance(repository, dict):
        violations.append("`repository` must be a mapping.")
    elif isinstance(repository, dict):
        profile = repository.get("profile")
        if profile is not None and profile not in set(policy.get("repository_profiles", {})):
            violations.append(f"`repository.profile` uses unknown profile `{profile}`.")
    gates = parsed.get("gates", {})
    if gates is not None and not isinstance(gates, dict):
        violations.append("`gates` must be a mapping.")
    else:
        for gate, enabled in (gates or {}).items():
            if not isinstance(enabled, bool):
                violations.append(f"`gates.{gate}` must be boolean.")
            if gate in set(policy.get("mandatory_gates", [])) and enabled is False:
                violations.append(f"Mandatory gate `{gate}` cannot be disabled by repository configuration.")
    thresholds = parsed.get("thresholds", {})
    if thresholds is not None and not isinstance(thresholds, dict):
        violations.append("`thresholds` must be a mapping.")
    else:
        for key, value in (thresholds or {}).items():
            if not isinstance(value, int):
                violations.append(f"`thresholds.{key}` must be an integer.")
    return violations


def apply_repository_profile_override(config: dict[str, Any], profile: str, policy: dict[str, Any]) -> list[str]:
    repository = dict(config.get("repository", {}) or {})
    repository.setdefault("profile", "application")
    normalized = profile.strip().lower()
    if normalized:
        if normalized not in set(policy.get("repository_profiles", {})):
            return [f"Operator selected unknown repository profile `{profile}`."]
        repository["profile"] = normalized
    config["repository"] = repository
    return []


def merge_governed_config(base: dict[str, Any], override: dict[str, Any], policy: dict[str, Any], violations: list[str]) -> dict[str, Any]:
    merged = deep_merge(base, {k: v for k, v in override.items() if k not in {"gates", "thresholds", "repository"}})
    repo = dict(base.get("repository", {}))
    incoming_repo = override.get("repository", {}) or {}
    if isinstance(incoming_repo, dict):
        repo.update({k: v for k, v in incoming_repo.items() if k != "protected_paths"})
        protected = list(dict.fromkeys(list(base.get("repository", {}).get("protected_paths", [])) + list(incoming_repo.get("protected_paths", []) or [])))
        repo["protected_paths"] = protected
    merged["repository"] = repo

    gates = dict(base.get("gates", {}))
    for gate, enabled in (override.get("gates", {}) or {}).items():
        if gate in set(policy.get("mandatory_gates", [])) and enabled is False:
            gates[gate] = True
        else:
            gates[gate] = enabled
    merged["gates"] = gates

    thresholds = dict(base.get("thresholds", {}))
    minimums = policy.get("minimum_thresholds", {})
    for key, value in (override.get("thresholds", {}) or {}).items():
        if not isinstance(value, int):
            continue
        if key in {"max_file_bytes", "max_changed_files", "max_additions", "risk_fail", "risk_warning"}:
            thresholds[key] = min(value, int(minimums.get(key, value)))
        else:
            thresholds[key] = value
    merged["thresholds"] = thresholds
    return merged


def parse_yaml_or_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except Exception:
        return parse_simple_yaml(text)


def parse_simple_yaml(text: str) -> Any:
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        stripped = strip_comment(raw.rstrip())
        if stripped.strip():
            lines.append((len(stripped) - len(stripped.lstrip(" ")), stripped.strip()))
    parsed, _ = parse_yaml_block(lines, 0, 0)
    return parsed


def parse_yaml_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return {}, index
    if lines[index][1].startswith("- "):
        items: list[Any] = []
        while index < len(lines):
            current_indent, content = lines[index]
            if current_indent < indent or not content.startswith("- "):
                break
            item = content[2:].strip()
            index += 1
            if not item:
                nested, index = parse_yaml_block(lines, index, indent + 2)
                items.append(nested)
            elif re.match(r"^[A-Za-z0-9_.-]+\s*:", item):
                key, value = item.split(":", 1)
                entry: dict[str, Any] = {}
                value = value.strip()
                if value in {"|", ">"}:
                    block_lines: list[str] = []
                    while index < len(lines) and lines[index][0] > current_indent:
                        block_lines.append(lines[index][1])
                        index += 1
                    entry[key.strip()] = "\n".join(block_lines)
                else:
                    entry[key.strip()] = parse_scalar(value) if value else {}
                    if index < len(lines) and lines[index][0] > current_indent:
                        nested, index = parse_yaml_block(lines, index, lines[index][0])
                        if isinstance(nested, dict):
                            if value:
                                entry.update(nested)
                            else:
                                entry[key.strip()] = nested
                items.append(entry)
            else:
                items.append(parse_scalar(item))
        return items, index

    mapping: dict[str, Any] = {}
    while index < len(lines):
        current_indent, content = lines[index]
        if current_indent < indent or content.startswith("- "):
            break
        if current_indent > indent:
            break
        key, sep, value = content.partition(":")
        if not sep:
            index += 1
            continue
        index += 1
        value = value.strip()
        if value in {"|", ">"}:
            block_lines: list[str] = []
            while index < len(lines) and lines[index][0] > current_indent:
                block_lines.append(lines[index][1])
                index += 1
            mapping[key.strip()] = "\n".join(block_lines)
        elif value:
            mapping[key.strip()] = parse_scalar(value)
        elif index < len(lines) and lines[index][0] > current_indent:
            nested, index = parse_yaml_block(lines, index, lines[index][0])
            mapping[key.strip()] = nested
        else:
            mapping[key.strip()] = {}
    return mapping, index


def strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    for i, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double and (i == 0 or line[i - 1].isspace()):
            return line[:i].rstrip()
    return line


def parse_scalar(value: str) -> Any:
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


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_event(event_path: str) -> dict[str, Any]:
    path = Path(event_path) if event_path else None
    if path and path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def detect_technologies(repo: Path) -> dict[str, dict[str, Any]]:
    detected: dict[str, dict[str, Any]] = {}
    for adapter in ADAPTERS:
        roots = adapter.detect(repo)
        if roots:
            detected[adapter.key] = {"adapter": adapter, "roots": roots, "name": adapter.name}
    return detected


def write_detection_outputs(technologies: dict[str, dict[str, Any]], github_output: str) -> None:
    payload = sorted(value["name"] for value in technologies.values())
    lines = [f"technologies={json.dumps(payload)}"]
    for key in ["php", "node", "python", "go", "gradle", "java", "dotnet", "rust", "swift", "shell", "terraform"]:
        lines.append(f"{key}={'true' if key in technologies else 'false'}")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))


def is_bounded_static_browser_asset(rel: str) -> bool:
    path = Path(rel)
    parts = path.parts
    if not parts or path.suffix.lower() not in STATIC_BROWSER_ASSET_SUFFIXES:
        return False
    if parts[0] in EXECUTABLE_SCRIPT_ROOTS:
        return False
    if parts[0] in STATIC_BROWSER_ASSET_ROOTS:
        return any(part.lower() in STATIC_BROWSER_ASSET_DIRS for part in parts[1:-1])
    if parts[0] == "resources" and len(parts) > 2:
        return parts[1].lower() in STATIC_BROWSER_RESOURCE_ROOTS
    return False


def gather_git_context(repo: Path, event: dict[str, Any], base_ref: str, head_ref: str) -> dict[str, Any]:
    pull_request = event.get("pull_request", {}) or {}
    base_sha = pull_request.get("base", {}).get("sha") or base_ref
    head_sha = pull_request.get("head", {}).get("sha") or "HEAD"
    resolved_head_ref = pull_request.get("head", {}).get("ref") or head_ref or os.environ.get("GITHUB_HEAD_REF") or current_branch(repo)
    resolved_base_ref = pull_request.get("base", {}).get("ref") or base_ref or os.environ.get("GITHUB_BASE_REF")
    canonical_base_sha = resolve_current_canonical_promotion_base_sha(repo, resolved_base_ref, resolved_head_ref)
    if canonical_base_sha:
        base_sha = canonical_base_sha
    pr_body = pull_request.get("body") or ""
    context = {
        "base_ref": resolved_base_ref,
        "head_ref": resolved_head_ref,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "pr_body": pr_body,
        "diff_error": "",
        "is_git_repo": is_git_repo(repo),
    }
    if not context["is_git_repo"]:
        context.update({"changed_files": list_repo_files(repo), "commits": [], "additions": 0, "deletions": 0, "diff_range": ""})
        return context

    if base_sha:
        ensure_ref_available(repo, base_sha, resolved_base_ref)
        if not commit_exists(repo, base_sha):
            context["diff_error"] = f"Base commit `{base_sha}` is unavailable; refusing to fall back to an approximate diff."
            context.update({"changed_files": [], "commits": [], "additions": 0, "deletions": 0, "diff_range": ""})
            return context
        diff_range = f"{base_sha}...HEAD"
    else:
        diff_range = "HEAD~1...HEAD"

    changed = git_lines(repo, ["diff", "--name-only", "--diff-filter=ACMRTUXB", diff_range])
    additions, deletions = git_numstat(repo, diff_range)
    numstat = git_numstat_by_path(repo, diff_range)
    if base_sha:
        pr_commit_range = f"{base_sha}..HEAD"
        commits = git_lines(repo, ["log", "--first-parent", "--format=%s", pr_commit_range])
        commit_shas = git_lines(repo, ["rev-list", "--first-parent", pr_commit_range])
    else:
        pr_commit_range = "HEAD~1..HEAD"
        commits = git_lines(repo, ["log", "--format=%s", "-n", "1"])
        commit_shas = git_lines(repo, ["rev-list", "-n", "1", "HEAD"])
    context.update({
        "changed_files": changed,
        "commits": commits,
        "commit_shas": commit_shas,
        "pr_commit_range": pr_commit_range,
        "additions": additions,
        "deletions": deletions,
        "numstat": numstat,
        "diff_range": diff_range,
    })
    return context


def is_git_repo(repo: Path) -> bool:
    return subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo, capture_output=True, text=True).returncode == 0


def current_branch(repo: Path) -> str:
    return run_git(repo, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()


def ensure_ref_available(repo: Path, base_sha: str, base_ref: str) -> None:
    if commit_exists(repo, base_sha) or not base_ref:
        return
    subprocess.run(["git", "fetch", "--no-tags", "origin", f"+refs/heads/{base_ref}:refs/remotes/origin/{base_ref}"], cwd=repo, check=False, capture_output=True)


def resolve_current_canonical_promotion_base_sha(repo: Path, base_ref: str, head_ref: str) -> str:
    if base_ref != "main" or head_ref != "staging" or not is_git_repo(repo):
        return ""
    remote_ref = f"refs/remotes/origin/{base_ref}"
    resolved = run_git(repo, ["rev-parse", "--verify", f"{remote_ref}^{{commit}}"]).strip()
    if resolved and commit_exists(repo, resolved):
        return resolved
    subprocess.run(["git", "fetch", "--no-tags", "origin", f"+refs/heads/{base_ref}:{remote_ref}"], cwd=repo, check=False, capture_output=True)
    resolved = run_git(repo, ["rev-parse", "--verify", f"{remote_ref}^{{commit}}"]).strip()
    return resolved if resolved and commit_exists(repo, resolved) else ""


def commit_exists(repo: Path, sha: str) -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo, capture_output=True).returncode == 0


def tree_entry_exists(repo: Path, ref: str, rel: str) -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{ref}:{rel}"], cwd=repo, capture_output=True).returncode == 0


def tree_path_state(repo: Path, ref: str, rel: str) -> str:
    if not ref or not is_git_repo(repo) or not commit_exists(repo, ref):
        return "ERROR"
    completed = subprocess.run(["git", "ls-tree", "-z", "--name-only", ref, rel], cwd=repo, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        return "ERROR"
    return "PRESENT" if completed.stdout else "ABSENT"


def run_git(repo: Path, args: list[str]) -> str:
    completed = subprocess.run(["git"] + args, cwd=repo, capture_output=True, text=True, check=False)
    return completed.stdout if completed.returncode == 0 else ""


def git_lines(repo: Path, args: list[str]) -> list[str]:
    return [line for line in run_git(repo, args).splitlines() if line.strip()]


def git_numstat(repo: Path, diff_range: str) -> tuple[int, int]:
    additions = 0
    deletions = 0
    for line in git_lines(repo, ["diff", "--numstat", diff_range]):
        parts = line.split("\t")
        if len(parts) >= 3:
            try:
                additions += int(parts[0]) if parts[0] != "-" else 0
                deletions += int(parts[1]) if parts[1] != "-" else 0
            except ValueError:
                pass
    return additions, deletions


def git_numstat_by_path(repo: Path, diff_range: str) -> dict[str, tuple[int, int]]:
    stats: dict[str, tuple[int, int]] = {}
    for line in git_lines(repo, ["diff", "--numstat", diff_range]):
        parts = line.split("\t")
        if len(parts) >= 3:
            try:
                additions = int(parts[0]) if parts[0] != "-" else 0
                deletions = int(parts[1]) if parts[1] != "-" else 0
            except ValueError:
                continue
            stats[parts[-1]] = (additions, deletions)
    return stats


def read_base_file(repo: Path, git_context: dict[str, Any], rel: str) -> str:
    base_sha = git_context.get("base_sha")
    if not base_sha or not git_context.get("is_git_repo") or not commit_exists(repo, base_sha):
        return ""
    completed = subprocess.run(["git", "show", f"{base_sha}:{rel}"], cwd=repo, capture_output=True, text=True, check=False)
    return completed.stdout if completed.returncode == 0 else ""


def read_tree_file(repo: Path, ref: str, rel: str) -> str:
    if not ref or not is_git_repo(repo) or not commit_exists(repo, ref):
        return ""
    completed = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=repo, capture_output=True, text=True, check=False)
    return completed.stdout if completed.returncode == 0 else ""


def tree_file_sha256(repo: Path, ref: str, rel: str) -> str:
    completed = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=repo, capture_output=True, check=False)
    if completed.returncode != 0:
        return ""
    return hashlib.sha256(completed.stdout).hexdigest()


def list_repo_files(repo: Path) -> list[str]:
    files: list[str] = []
    for path in repo.rglob("*"):
        if path.is_file():
            rel = path.relative_to(repo)
            if not should_skip_path(rel):
                files.append(rel.as_posix())
    return sorted(files)


def react_native_roots(ctx: PRContext) -> list[Path]:
    cache = context_cache(ctx)
    if "react_native_roots" in cache:
        return list(cache["react_native_roots"])
    roots: list[Path] = []
    for package_json in find_named_files(ctx.repo, {"package.json"}):
        package = read_json(package_json)
        dependencies: set[str] = set()
        for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            dependencies.update((package.get(key) or {}).keys())
        root = package_json.parent
        if "react-native" in dependencies and (root / "android").is_dir() and (root / "ios").is_dir():
            roots.append(root)
    detected = sorted(set(roots))
    cache["react_native_roots"] = detected
    return detected


def context_cache(ctx: PRContext) -> dict[str, Any]:
    cache = getattr(ctx, "_stack_cache", None)
    if cache is None:
        cache = {}
        setattr(ctx, "_stack_cache", cache)
    return cache


def is_react_native_repository(ctx: PRContext) -> bool:
    return bool(react_native_roots(ctx))


def react_native_exception_settings(ctx: PRContext) -> dict[str, Any]:
    return dict(ctx.policy.get("stack_integrity_exceptions", {}).get("react_native", {}) or {})


def react_native_relative_path(ctx: PRContext, rel: str) -> str:
    for root in react_native_roots(ctx):
        root_rel = ctx.rel(root).rstrip("/")
        if root_rel in {"", "."}:
            return rel
        prefix = root_rel + "/"
        if rel.startswith(prefix):
            return rel[len(prefix) :]
    return rel


def is_react_native_hidden_text_exception(ctx: PRContext, rel: str) -> bool:
    if not is_react_native_repository(ctx):
        return False
    rn_rel = react_native_relative_path(ctx, rel)
    allowed = set(react_native_exception_settings(ctx).get("hidden_text_files", []) or [])
    path = ctx.repo / rel
    if rn_rel not in allowed or not path.is_file() or is_binary_file(path):
        return False
    max_bytes = int(react_native_exception_settings(ctx).get("max_hidden_text_file_bytes", 8192))
    if path.stat().st_size > max_bytes:
        return False
    text = read_text(path)
    if rn_rel == ".watchmanconfig":
        try:
            parsed = json.loads(text or "{}")
        except json.JSONDecodeError:
            return False
        if not isinstance(parsed, dict):
            return False
    return not contains_mobile_credential_indicator(text)


def is_react_native_binary_bootstrap_exception(ctx: PRContext, rel: str) -> bool:
    if not is_react_native_repository(ctx):
        return False
    rn_rel = react_native_relative_path(ctx, rel)
    path = ctx.repo / rel
    settings = react_native_exception_settings(ctx)
    if rn_rel not in set(settings.get("binary_bootstrap_files", []) or []) or not path.is_file():
        return False
    if rn_rel == "android/gradle/wrapper/gradle-wrapper.jar":
        max_bytes = int(settings.get("max_gradle_wrapper_jar_bytes", 262144))
        return path.stat().st_size <= max_bytes and is_zip_archive(path) and uses_official_gradle_distribution(ctx, rel)
    if rn_rel == "android/app/debug.keystore":
        max_bytes = int(settings.get("max_debug_keystore_bytes", 16384))
        return path.stat().st_size <= max_bytes and uses_android_debug_keystore(ctx, rel)
    return False


def is_react_native_line_ending_exception(ctx: PRContext, rel: str) -> bool:
    if not is_react_native_repository(ctx):
        return False
    rn_rel = react_native_relative_path(ctx, rel)
    allowed = set(react_native_exception_settings(ctx).get("line_ending_text_files", []) or [])
    path = ctx.repo / rel
    if rn_rel not in allowed or not path.is_file() or is_binary_file(path):
        return False
    return path.name == "gradlew.bat" and "gradle" in read_text(path).lower()


def uses_official_gradle_distribution(ctx: PRContext, rel: str) -> bool:
    rn_rel = react_native_relative_path(ctx, rel)
    prefix = rel[: -len(rn_rel)] if rel.endswith(rn_rel) else ""
    properties = ctx.repo / prefix / "android/gradle/wrapper/gradle-wrapper.properties"
    text = read_text(properties)
    normalized = text.replace("\\:", ":")
    return bool(re.search(r"(?m)^distributionUrl=https://services\.gradle\.org/distributions/gradle-[0-9][0-9A-Za-z._-]*-(?:bin|all)\.zip$", normalized))


def is_zip_archive(path: Path) -> bool:
    try:
        return path.read_bytes()[:4] == b"PK\x03\x04"
    except OSError:
        return False


def uses_android_debug_keystore(ctx: PRContext, rel: str) -> bool:
    rn_rel = react_native_relative_path(ctx, rel)
    prefix = rel[: -len(rn_rel)] if rel.endswith(rn_rel) else ""
    build_gradle = read_text(ctx.repo / prefix / "android/app/build.gradle") + "\n" + read_text(ctx.repo / prefix / "android/app/build.gradle.kts")
    required_patterns = [
        r"debug\.keystore",
        r"androiddebugkey",
        r"storePassword\s*=?\s*['\"]android['\"]",
        r"keyPassword\s*=?\s*['\"]android['\"]",
    ]
    return all(re.search(pattern, build_gradle) for pattern in required_patterns) and "release.keystore" not in build_gradle.lower()


def contains_mobile_credential_indicator(text: str) -> bool:
    pattern = re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_-]?(?:key|token)|access[_-]?token|client[_-]?secret|certificate|"
        r"provisioning|profile|app[_-]?store|play[_-]?store|signing|keystore|p12|pfx)\b"
    )
    return bool(pattern.search(text))


def filter_diff_check_output(ctx: PRContext, output: str) -> tuple[list[str], list[str]]:
    blocking: list[str] = []
    ignored: list[str] = []
    ignoring_continuation = False
    for line in output.splitlines():
        match = re.match(r"^([^:]+):", line)
        rel = match.group(1) if match else ""
        if rel and is_react_native_line_ending_exception(ctx, rel):
            ignored.append(line)
            ignoring_continuation = True
        elif ignoring_continuation and line.startswith("+"):
            ignored.append(line)
        elif line.strip():
            blocking.append(line)
            ignoring_continuation = False
    return blocking, ignored


def split_path_line(value: str) -> tuple[str, int]:
    parts = value.rsplit(":", 1)
    if len(parts) != 2:
        return value, 0
    try:
        return parts[0], int(parts[1])
    except ValueError:
        return value, 0


def read_line(path: Path, line_number: int) -> str:
    if line_number <= 0 or not path.is_file() or is_binary_file(path):
        return ""
    try:
        return read_text(path).splitlines()[line_number - 1]
    except IndexError:
        return ""


def classify_diff_check_output(ctx: PRContext, output: str) -> tuple[list[str], list[str]]:
    blocking: list[str] = []
    inherited: list[str] = []
    lines = output.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^([^:]+):([0-9]+):", line)
        if not match:
            if line.strip():
                blocking.append(line)
            index += 1
            continue
        rel = match.group(1)
        line_number = int(match.group(2))
        preview = lines[index + 1] if index + 1 < len(lines) and lines[index + 1].startswith("+") else ""
        source_line = read_line(ctx.repo / rel, line_number)
        if baseline_inherited_path(ctx, rel, "whitespace", line=source_line):
            inherited.append(f"{line}: INHERITED_BASELINE whitespace.")
            if preview:
                inherited.append(preview)
        else:
            blocking.append(line)
            if preview:
                blocking.append(preview)
        index += 2 if preview else 1
    return blocking, inherited


def run_static_preflight(ctx: PRContext, git_context: dict[str, Any], technologies: dict[str, dict[str, Any]], report_path: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    results.extend(gate_baseline_alignment(ctx, git_context))
    results.extend(gate_config_validation(ctx))
    results.extend(gate_repository_integrity(ctx, git_context))
    results.extend(gate_repository_hygiene(ctx, git_context))
    results.extend(gate_git_validation(ctx, git_context))
    results.extend(gate_secrets(ctx, git_context, report_path))
    results.extend(gate_executable_classification(ctx, technologies))
    results.extend(gate_protected_resources(ctx, git_context))
    results.extend(gate_deployment_safety(ctx, git_context))
    results.extend(gate_database_safety(ctx))
    return results


def run_sandboxed_validation(ctx: PRContext, technologies: dict[str, dict[str, Any]]) -> list[CheckResult]:
    results: list[CheckResult] = []
    results.extend(run_adapter_gate(ctx, technologies, "formatting", "format"))
    results.extend(run_adapter_gate(ctx, technologies, "lint", "lint"))
    results.extend(run_adapter_gate(ctx, technologies, "build", "build"))
    results.extend(run_adapter_gate(ctx, technologies, "tests", "test"))
    results.extend(run_adapter_gate(ctx, technologies, "dependencies", "dependencies"))
    results.extend(run_adapter_gate(ctx, technologies, "licence", "licences"))
    return results


def run_governance(ctx: PRContext, existing_results: list[CheckResult], args: argparse.Namespace) -> list[CheckResult]:
    results: list[CheckResult] = []
    results.extend(run_if_enabled(ctx, "documentation", lambda: gate_documentation(ctx)))
    results.extend(run_if_enabled(ctx, "advisory_review", lambda: gate_advisory_review(ctx)))
    results.extend(gate_release_drift(ctx))
    results.extend(run_if_enabled(ctx, "risk", lambda: gate_risk(ctx, existing_results + results)))
    results.extend(run_if_enabled(ctx, "evidence", lambda: gate_evidence(ctx)))
    results.extend(run_if_enabled(ctx, "review_policy", lambda: gate_review_policy(ctx, args.review_policy_input)))
    return results


def gate_release_drift(ctx: PRContext) -> list[CheckResult]:
    if repository_profile(ctx) != "framework":
        return []
    state = framework_release_state(ctx.repo)
    context_cache(ctx)["release_drift"] = state
    details = list(state.get("details") or [])
    details.append(f"ACTIVE_PR_QA_RELEASE: {state['active_pr_qa_release'] or 'UNKNOWN'}")
    details.append(f"FRAMEWORK_MAIN_MATCHES_ACTIVE_RELEASE: {state['framework_main_matches_active_release']}")
    details.append(f"RELEASE_REQUIRED: {state['release_required']}")
    if state["framework_main_matches_active_release"] == PASS:
        return [passed("Release Drift", None, "Active PR-QA release matches current release-sensitive framework content.", details)]
    return [
        CheckResult(
            "Release Drift",
            FAIL,
            "Active PR-QA release does not match current release-sensitive framework content.",
            details,
            blocking=False,
        )
    ]


def run_if_enabled(ctx: PRContext, key: str, fn: Callable[[], list[CheckResult]]) -> list[CheckResult]:
    display = dict(GATE_ORDER)[key]
    if not ctx.gate_enabled(key):
        return [skipped(display, None, "Gate disabled by central policy.")]
    return fn()


def run_adapter_gate(ctx: PRContext, technologies: dict[str, dict[str, Any]], key: str, method_name: str) -> list[CheckResult]:
    display = dict(GATE_ORDER)[key]
    if not ctx.gate_enabled(key):
        return [skipped(display, None, "Gate disabled by central policy.")]
    if not technologies:
        return [passed(display, None, "No supported technology markers detected after executable-code classification.")]
    results: list[CheckResult] = []
    for detected in technologies.values():
        roots = relevant_roots_for_adapter(ctx, detected["adapter"].key, detected["roots"])
        if not roots:
            results.append(skipped(display, detected["name"], f"No {detected['name']}-relevant files changed."))
            continue
        method = getattr(detected["adapter"], method_name)
        results.extend(method(ctx, roots))
    return results or [passed(display, None, "No applicable checks for detected technologies.")]


def relevant_roots_for_adapter(ctx: PRContext, adapter_key: str, roots: list[Path]) -> list[Path]:
    roots = roots_after_stack_classification(ctx, adapter_key, roots)
    patterns = TECHNOLOGY_CHANGE_PATTERNS.get(adapter_key)
    if patterns is None:
        return roots
    if adapter_key == "node":
        return relevant_node_project_roots(ctx, roots, patterns)
    relevant = []
    for root in roots:
        if any(match_any(relative_to_root(ctx, root, rel), patterns) for rel in ctx.changed_under(root)):
            relevant.append(root)
    return relevant


def relevant_node_project_roots(ctx: PRContext, roots: list[Path], patterns: list[str]) -> list[Path]:
    roots = deepest_changed_project_roots(ctx, roots)
    relevant: list[Path] = []
    for root in roots:
        own_changes = [
            rel
            for rel in ctx.changed_under(root)
            if not changed_file_belongs_to_nested_root(ctx, root, roots, rel)
            and match_any(relative_to_root(ctx, root, rel), patterns)
        ]
        if not own_changes:
            continue
        if nested_node_roots(ctx, root, roots) and not node_root_has_local_project_markers(root):
            continue
        relevant.append(root)
    return relevant


def deepest_changed_project_roots(ctx: PRContext, roots: list[Path]) -> list[Path]:
    if len(roots) <= 1:
        return roots
    selected: set[Path] = set()
    root_by_resolved = {root.resolve(): root for root in roots}
    resolved_roots = sorted(root_by_resolved, key=lambda item: len(item.relative_to(ctx.repo.resolve()).parts), reverse=True)
    for rel in ctx.changed_files:
        path = (ctx.repo / rel).resolve()
        for resolved in resolved_roots:
            try:
                path.relative_to(resolved)
            except ValueError:
                continue
            selected.add(root_by_resolved[resolved])
            break
    return [root for root in roots if root in selected]


def changed_file_belongs_to_nested_root(ctx: PRContext, root: Path, roots: list[Path], rel: str) -> bool:
    path = (ctx.repo / rel).resolve()
    for nested in nested_node_roots(ctx, root, roots):
        try:
            path.relative_to(nested.resolve())
            return True
        except ValueError:
            continue
    return False


def nested_node_roots(ctx: PRContext, root: Path, roots: list[Path]) -> list[Path]:
    nested: list[Path] = []
    root_resolved = root.resolve()
    for candidate in roots:
        if candidate == root:
            continue
        try:
            candidate.resolve().relative_to(root_resolved)
        except ValueError:
            continue
        nested.append(candidate)
    return nested


def node_root_has_local_project_markers(root: Path) -> bool:
    marker_names = {
        "index.html",
        "vite.config.js",
        "vite.config.mjs",
        "vite.config.ts",
        "webpack.config.js",
        "rollup.config.js",
        "next.config.js",
        "next.config.mjs",
        "eslint.config.js",
        "eslint.config.mjs",
        "tsconfig.json",
    }
    if any((root / name).exists() for name in marker_names):
        return True
    return any((root / name).is_dir() for name in ["src", "public", "pages", "components"])


def roots_after_stack_classification(ctx: PRContext, adapter_key: str, roots: list[Path]) -> list[Path]:
    if adapter_key not in {"gradle", "swift"}:
        return roots
    if not is_react_native_repository(ctx):
        return roots
    return [root for root in roots if not is_react_native_native_project_root(ctx, root)]


def is_react_native_native_project_root(ctx: PRContext, root: Path) -> bool:
    for rn_root in react_native_roots(ctx):
        try:
            relative = root.resolve().relative_to(rn_root.resolve())
        except ValueError:
            continue
        if relative.parts and relative.parts[0] in {"android", "ios"}:
            return True
    return False


def relative_to_root(ctx: PRContext, root: Path, rel: str) -> str:
    root_rel = ctx.rel(root).rstrip("/")
    if root_rel in {"", "."}:
        return rel
    prefix = root_rel + "/"
    return rel[len(prefix) :] if rel.startswith(prefix) else rel


def add_phase_skips(results: list[CheckResult], message: str) -> None:
    existing = {result.gate for result in results}
    for _, display in GATE_ORDER:
        if display not in existing:
            results.append(skipped(display, None, message))


def baseline_policy(ctx: PRContext) -> dict[str, Any]:
    return dict(ctx.policy.get("one_time_baseline_alignment", {}) or {})


def branch_alignment_policy(ctx: PRContext) -> dict[str, Any]:
    return dict(ctx.policy.get("one_time_branch_alignment", {}) or {})


def baseline_requested(ctx: PRContext) -> bool:
    requested = os.environ.get("PR_QA_BASELINE_ALIGNMENT", "").strip().lower()
    if requested in {"1", "true", "yes", "on"}:
        return True
    pull_request = ctx.event.get("pull_request", {}) or {}
    marker = str(baseline_policy(ctx).get("required_pr_body_marker", "") or "")
    if marker and marker in str(pull_request.get("body") or ctx.pr_body or ""):
        return True
    labels = pull_request.get("labels", []) or []
    label_names = {str((label or {}).get("name", "")).lower() for label in labels if isinstance(label, dict)}
    return "one-time-baseline-alignment" in label_names


def branch_alignment_requested(ctx: PRContext) -> bool:
    requested = os.environ.get("PR_QA_BRANCH_ALIGNMENT", "").strip().lower()
    if requested in {"1", "true", "yes", "on"}:
        return True
    pull_request = ctx.event.get("pull_request", {}) or {}
    marker = str(branch_alignment_policy(ctx).get("required_pr_body_marker", "") or "")
    if marker and marker in str(pull_request.get("body") or ctx.pr_body or ""):
        return True
    labels = pull_request.get("labels", []) or []
    label_names = {str((label or {}).get("name", "")).lower() for label in labels if isinstance(label, dict)}
    return "one-time-branch-alignment" in label_names


def baseline_authorization(ctx: PRContext, git_context: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
    policy = baseline_policy(ctx)
    details: list[str] = []
    if not baseline_requested(ctx):
        return False, ["Baseline alignment mode was not requested."], policy
    if not policy.get("enabled", False):
        return False, ["Central policy does not enable baseline alignment mode."], policy

    repository = resolve_repository_name(ctx)
    expected_repository = str(policy.get("repository", ""))
    if repository != expected_repository:
        details.append(f"repository `{repository}` is not authorized; expected `{expected_repository}`.")

    head_ref = ctx.head_ref or ""
    expected_head = str(policy.get("head_ref", ""))
    if head_ref != expected_head:
        details.append(f"source branch `{head_ref}` is not authorized; expected `{expected_head}`.")

    base_ref = ctx.base_ref or ""
    expected_base = str(policy.get("base_ref", ""))
    if base_ref != expected_base:
        details.append(f"target branch `{base_ref}` is not authorized; expected `{expected_base}`.")

    base_sha = str(git_context.get("base_sha") or "")
    expected_base_sha = str(policy.get("expected_base_sha", ""))
    if expected_base_sha and base_sha != expected_base_sha:
        details.append(f"destination SHA `{base_sha}` is not authorized; expected `{expected_base_sha}`.")

    head_sha = resolve_head_sha(ctx.repo, git_context)
    details.extend(baseline_source_overlay_authorization(ctx, git_context, policy, head_sha, base_sha))

    expires_after = str(policy.get("expires_after", ""))
    if expires_after:
        try:
            expires = datetime.fromisoformat(expires_after.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires:
                details.append(f"baseline authorization expired at `{expires_after}`.")
        except ValueError:
            details.append(f"baseline authorization expiry `{expires_after}` is invalid.")

    minimum_changed = int(policy.get("minimum_changed_files", 0) or 0)
    if len(ctx.changed_files) < minimum_changed:
        details.append(f"changed-file count `{len(ctx.changed_files)}` is below baseline minimum `{minimum_changed}`.")

    marker = str(policy.get("required_pr_body_marker", ""))
    if marker and marker not in (ctx.pr_body or ""):
        details.append(f"PR body is missing required baseline marker `{marker}`.")

    return not details, details, policy


def branch_alignment_authorization(ctx: PRContext, git_context: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
    policy = branch_alignment_policy(ctx)
    details: list[str] = []
    if not branch_alignment_requested(ctx):
        return False, ["Branch alignment mode was not requested."], policy
    if not policy.get("enabled", False):
        return False, ["Central policy does not enable branch alignment mode."], policy

    repository = resolve_repository_name(ctx)
    expected_repository = str(policy.get("repository", ""))
    if repository != expected_repository:
        details.append(f"repository `{repository}` is not authorized; expected `{expected_repository}`.")

    head_ref = ctx.head_ref or ""
    expected_head = str(policy.get("head_ref", ""))
    if head_ref != expected_head:
        details.append(f"source branch `{head_ref}` is not authorized; expected `{expected_head}`.")

    base_ref = ctx.base_ref or ""
    expected_base = str(policy.get("base_ref", ""))
    if base_ref != expected_base:
        details.append(f"target branch `{base_ref}` is not authorized; expected `{expected_base}`.")

    base_sha = str(git_context.get("base_sha") or "")
    expected_base_sha = str(policy.get("expected_base_sha", ""))
    if expected_base_sha and base_sha != expected_base_sha:
        details.append(f"destination SHA `{base_sha}` is not authorized; expected `{expected_base_sha}`.")

    head_sha = resolve_head_sha(ctx.repo, git_context)
    expected_head_sha = str(policy.get("expected_head_sha", ""))
    if expected_head_sha and head_sha != expected_head_sha:
        details.append(f"source SHA `{head_sha}` is not authorized; expected `{expected_head_sha}`.")

    if not git_context.get("is_git_repo"):
        details.append("branch alignment authorization requires a Git checkout.")
    else:
        details.extend(branch_alignment_merge_authorization(ctx, head_sha, policy))
        details.extend(baseline_source_overlay_authorization(ctx, git_context, policy, head_sha, base_sha))

    expires_after = str(policy.get("expires_after", ""))
    if expires_after:
        try:
            expires = datetime.fromisoformat(expires_after.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires:
                details.append(f"branch alignment authorization expired at `{expires_after}`.")
        except ValueError:
            details.append(f"branch alignment authorization expiry `{expires_after}` is invalid.")

    minimum_changed = int(policy.get("minimum_changed_files", 0) or 0)
    if len(ctx.changed_files) < minimum_changed:
        details.append(f"changed-file count `{len(ctx.changed_files)}` is below branch alignment minimum `{minimum_changed}`.")

    marker = str(policy.get("required_pr_body_marker", ""))
    if marker and marker not in (ctx.pr_body or ""):
        details.append(f"PR body is missing required branch alignment marker `{marker}`.")

    return not details, details, policy


def branch_alignment_merge_authorization(ctx: PRContext, head_sha: str, policy: dict[str, Any]) -> list[str]:
    details: list[str] = []
    merge_sha = str(policy.get("expected_merge_commit_sha") or "")
    if not merge_sha:
        return ["branch alignment authorization is missing expected merge commit SHA."]
    if not commit_exists(ctx.repo, merge_sha):
        ensure_ref_available(ctx.repo, merge_sha, str(ctx.head_ref or ""))
    if not commit_exists(ctx.repo, merge_sha):
        return [f"expected alignment merge commit `{merge_sha}` is unavailable."]
    if not head_sha or not commit_exists(ctx.repo, head_sha):
        return [f"candidate source SHA `{head_sha}` is unavailable."]

    ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", merge_sha, head_sha], cwd=ctx.repo, text=True, capture_output=True, check=False)
    if ancestor.returncode != 0:
        details.append(f"expected alignment merge commit `{merge_sha}` is not in candidate head ancestry.")

    parents = git_lines(ctx.repo, ["show", "-s", "--format=%P", merge_sha])
    parent_values = parents[0].split() if parents else []
    if len(parent_values) != 2:
        details.append(f"expected alignment merge commit `{merge_sha}` must have exactly two parents.")
    else:
        expected_first = str(policy.get("expected_merge_first_parent_sha") or "")
        expected_second = str(policy.get("expected_merge_second_parent_sha") or "")
        if expected_first and parent_values[0] != expected_first:
            details.append(f"alignment merge first parent `{parent_values[0]}` is not authorized; expected `{expected_first}`.")
        if expected_second and parent_values[1] != expected_second:
            details.append(f"alignment merge second parent `{parent_values[1]}` is not authorized; expected `{expected_second}`.")
        if expected_second and not merge_commit_matches_second_parent_tree(ctx.repo, merge_sha):
            details.append(f"alignment merge commit `{merge_sha}` does not preserve the approved second-parent tree.")
    return details


def baseline_source_overlay_authorization(ctx: PRContext, git_context: dict[str, Any], policy: dict[str, Any], head_sha: str, base_sha: str) -> list[str]:
    source_overlay = policy.get("source_overlay")
    expected_head_sha = str(policy.get("expected_head_sha", ""))
    if not source_overlay:
        if expected_head_sha and head_sha != expected_head_sha:
            return [f"source SHA `{head_sha}` is not authorized; expected `{expected_head_sha}`."]
        return []
    return validate_baseline_source_overlay(ctx, git_context, source_overlay, expected_head_sha, head_sha, base_sha)


def validate_baseline_source_overlay(
    ctx: PRContext,
    git_context: dict[str, Any],
    overlay: dict[str, Any],
    expected_head_sha: str,
    head_sha: str,
    base_sha: str,
) -> list[str]:
    details: list[str] = []
    if not git_context.get("is_git_repo"):
        return ["source-plus-overlay authorization requires a Git checkout."]

    source_sha = str(overlay.get("approved_application_source_sha") or expected_head_sha)
    if not source_sha:
        return ["source-plus-overlay authorization is missing approved application source SHA."]
    if not commit_exists(ctx.repo, source_sha):
        ensure_ref_available(ctx.repo, source_sha, str(ctx.head_ref or ""))
    if not commit_exists(ctx.repo, source_sha):
        return [f"approved application source SHA `{source_sha}` is unavailable."]
    if not head_sha or head_sha == "HEAD":
        head_sha = run_git(ctx.repo, ["rev-parse", "HEAD"]).strip()
    if not commit_exists(ctx.repo, head_sha):
        return [f"candidate source SHA `{head_sha}` is unavailable."]
    if base_sha and not commit_exists(ctx.repo, base_sha):
        return [f"authorized base SHA `{base_sha}` is unavailable."]

    allowed_paths = {str(path) for path in overlay.get("allowed_paths", []) or []}
    if not allowed_paths:
        return ["source-plus-overlay authorization has no allowed overlay paths."]

    unexpected = baseline_source_tree_differences(ctx, source_sha, head_sha, allowed_paths)
    if unexpected:
        details.append("candidate differs from approved application source outside the governance overlay: " + ", ".join(unexpected[:30]))

    overlay_entries = overlay.get("paths", {}) or {}
    for path in sorted(allowed_paths):
        spec = overlay_entries.get(path) or {}
        details.extend(validate_baseline_overlay_path(ctx, source_sha, head_sha, base_sha, path, spec))

    return details


def baseline_source_tree_differences(ctx: PRContext, source_sha: str, head_sha: str, allowed_paths: set[str]) -> list[str]:
    source_blobs = {
        path: blob
        for path, blob in baseline_tree_blob_ids(ctx, source_sha).items()
        if path not in allowed_paths
    }
    head_blobs = {
        path: blob
        for path, blob in baseline_tree_blob_ids(ctx, head_sha).items()
        if path not in allowed_paths
    }
    return sorted(set(source_blobs).symmetric_difference(head_blobs) | {path for path in set(source_blobs) & set(head_blobs) if source_blobs[path] != head_blobs[path]})


def validate_baseline_overlay_path(ctx: PRContext, source_sha: str, head_sha: str, base_sha: str, path: str, spec: dict[str, Any]) -> list[str]:
    details: list[str] = []
    source_exists = tree_entry_exists(ctx.repo, source_sha, path)
    head_exists = tree_entry_exists(ctx.repo, head_sha, path)
    base_exists = tree_entry_exists(ctx.repo, base_sha, path) if base_sha else False
    if not head_exists:
        return [f"governance overlay path `{path}` is missing from candidate head."]

    expected_source = str(spec.get("source") or "")
    if expected_source == "absent" and source_exists:
        details.append(f"governance overlay path `{path}` must be absent in approved application source.")
    elif expected_source == "present" and not source_exists:
        details.append(f"governance overlay path `{path}` must exist in approved application source.")

    expected_candidate = str(spec.get("candidate") or "")
    if expected_candidate == "base" and base_sha:
        if not base_exists:
            details.append(f"governance overlay path `{path}` must match base but is absent from authorized base.")
        elif tree_file_sha256(ctx.repo, head_sha, path) != tree_file_sha256(ctx.repo, base_sha, path):
            details.append(f"governance overlay path `{path}` does not match authorized base content.")
    elif expected_candidate == "source" and source_exists:
        if tree_file_sha256(ctx.repo, head_sha, path) != tree_file_sha256(ctx.repo, source_sha, path):
            details.append(f"governance overlay path `{path}` does not match approved application source content.")

    if path == ".github/workflows/pr-qa.yml":
        details.extend(validate_baseline_pr_qa_caller_update(ctx, source_sha, head_sha, base_sha, path, spec))
    return details


def validate_baseline_pr_qa_caller_update(ctx: PRContext, source_sha: str, head_sha: str, base_sha: str, path: str, spec: dict[str, Any]) -> list[str]:
    details: list[str] = []
    old_ref = str(spec.get("old_ref") or "")
    new_ref = str(spec.get("new_ref") or "")
    expected_uses = str(spec.get("uses") or "Synergie-ITCI/.github/.github/workflows/pr-qa.yml")
    if not old_ref or not new_ref:
        return [f"governance overlay path `{path}` is missing exact PR-QA caller ref transition."]
    source_text = read_tree_file(ctx.repo, source_sha, path)
    base_text = read_tree_file(ctx.repo, base_sha, path) if base_sha else ""
    head_text = read_tree_file(ctx.repo, head_sha, path)
    expected_old_line = f"uses: {expected_uses}@{old_ref}"
    expected_new_line = f"uses: {expected_uses}@{new_ref}"

    if source_text:
        starting_text = source_text
        starting_label = "approved application source"
    else:
        starting_text = base_text
        starting_label = "authorized base"
    if expected_old_line not in starting_text:
        details.append(f"governance overlay path `{path}` does not start from `{expected_old_line}` in {starting_label}.")
        return details
    expected_text = starting_text.replace(expected_old_line, expected_new_line, 1)
    if expected_old_line in expected_text:
        details.append(f"governance overlay path `{path}` contains multiple old PR-QA caller refs.")
    if head_text != expected_text:
        details.append(f"governance overlay path `{path}` must only update PR-QA caller `{old_ref}` to `{new_ref}`.")
    return details


def baseline_active(ctx: PRContext) -> bool:
    cache = context_cache(ctx)
    return bool(cache.get("baseline_authorized"))


def baseline_policy_settings(ctx: PRContext) -> dict[str, Any]:
    return dict(context_cache(ctx).get("baseline_policy") or baseline_policy(ctx))


def baseline_relaxations(ctx: PRContext) -> set[str]:
    return set(baseline_policy_settings(ctx).get("relaxations", []) or [])


def baseline_allows(ctx: PRContext, relaxation: str) -> bool:
    return baseline_active(ctx) and relaxation in baseline_relaxations(ctx)


def baseline_source_sha(ctx: PRContext) -> str:
    if not baseline_active(ctx):
        return ""
    policy = baseline_policy_settings(ctx)
    overlay = policy.get("source_overlay", {}) or {}
    return str(overlay.get("approved_application_source_sha") or policy.get("approved_target_tree_sha") or policy.get("expected_head_sha") or "")


def baseline_base_sha(ctx: PRContext) -> str:
    if not baseline_active(ctx):
        return ""
    return str(baseline_policy_settings(ctx).get("expected_base_sha") or "")


def baseline_candidate_head_sha(ctx: PRContext) -> str:
    cache = context_cache(ctx)
    key = "baseline_candidate_head_sha"
    if key not in cache:
        cache[key] = run_git(ctx.repo, ["rev-parse", "HEAD"]).strip()
    return str(cache.get(key) or "")


def baseline_tree_blob_ids(ctx: PRContext, ref: str) -> dict[str, str]:
    cache = context_cache(ctx)
    key = ("baseline_tree_blob_ids", ref)
    if key in cache:
        return dict(cache[key])
    entries: dict[str, str] = {}
    if ref and commit_exists(ctx.repo, ref):
        completed = subprocess.run(["git", "ls-tree", "-r", "-z", ref], cwd=ctx.repo, capture_output=True, text=False, check=False)
        if completed.returncode == 0:
            for raw in completed.stdout.split(b"\0"):
                if not raw:
                    continue
                meta, _, path = raw.partition(b"\t")
                parts = meta.decode("utf-8", errors="replace").split()
                if len(parts) >= 3 and parts[1] == "blob":
                    entries[path.decode("utf-8", errors="replace")] = parts[2]
    cache[key] = dict(entries)
    return entries


def baseline_read_tree_file(ctx: PRContext, ref: str, rel: str) -> str:
    cache = context_cache(ctx)
    key = ("baseline_read_tree_file", ref, rel)
    if key not in cache:
        cache[key] = read_tree_file(ctx.repo, ref, rel)
    return str(cache.get(key) or "")


def baseline_overlay_allowed_paths(ctx: PRContext) -> set[str]:
    if not baseline_active(ctx):
        return set()
    overlay = baseline_policy_settings(ctx).get("source_overlay", {}) or {}
    return {str(path) for path in overlay.get("allowed_paths", []) or []}


def baseline_finding_classification(ctx: PRContext, rel: str, category: str, *, line: str = "") -> dict[str, str]:
    cache_key = ("baseline_finding_classification", rel, category, hashlib.sha256(line.encode("utf-8")).hexdigest() if line else "")
    cache = context_cache(ctx)
    if cache_key in cache:
        return dict(cache[cache_key])

    def remember(result: dict[str, str]) -> dict[str, str]:
        cache[cache_key] = dict(result)
        return result

    if not baseline_active(ctx):
        return remember({"classification": NEW_FINDING, "reason": "baseline inactive"})
    if category in {"confirmed_secret", "unsafe_binary", "path_traversal", "symlink", "submodule", "lfs"}:
        return remember({"classification": NON_INHERITABLE_SECURITY_FINDING, "reason": f"{category} is non-inheritable"})
    if rel in baseline_overlay_allowed_paths(ctx):
        return remember(baseline_overlay_classification(ctx, rel))
    source_sha = baseline_source_sha(ctx)
    head_sha = baseline_candidate_head_sha(ctx)
    if not source_sha or not head_sha or not commit_exists(ctx.repo, source_sha):
        return remember({"classification": NEW_FINDING, "reason": "approved source unavailable"})
    source_blobs = baseline_tree_blob_ids(ctx, source_sha)
    head_blobs = baseline_tree_blob_ids(ctx, head_sha)
    source_blob = source_blobs.get(rel, "")
    head_blob = head_blobs.get(rel, "")
    if not source_blob:
        return remember({"classification": NEW_FINDING, "reason": "path absent from approved source"})
    if not head_blob:
        return remember({"classification": NEW_FINDING, "reason": "path absent from candidate"})
    if source_blob != head_blob:
        return remember({"classification": NEW_FINDING, "reason": "candidate blob differs from approved source"})
    if line and line not in baseline_read_tree_file(ctx, source_sha, rel):
        return remember({"classification": NEW_FINDING, "reason": "finding line is not present in approved source blob"})
    return remember({
        "classification": INHERITED_BASELINE,
        "reason": f"path/blob matches approved source {source_sha}",
        "candidate_blob": head_blob,
        "approved_source_blob": source_blob,
        "category": category,
    })


def baseline_overlay_classification(ctx: PRContext, rel: str) -> dict[str, str]:
    policy = baseline_policy_settings(ctx)
    overlay = policy.get("source_overlay", {}) or {}
    details = validate_baseline_overlay_path(
        ctx,
        baseline_source_sha(ctx),
        baseline_candidate_head_sha(ctx),
        baseline_base_sha(ctx),
        rel,
        (overlay.get("paths", {}) or {}).get(rel) or {},
    )
    if details:
        return {"classification": NEW_FINDING, "reason": "; ".join(details)}
    return {"classification": AUTHORIZED_OVERLAY, "reason": "matches exact source+overlay authorization"}


def baseline_classified_detail(ctx: PRContext, rel: str, category: str, message: str, *, line: str = "") -> tuple[bool, str]:
    classification = baseline_finding_classification(ctx, rel, category, line=line)
    state = classification["classification"]
    if state in {INHERITED_BASELINE, AUTHORIZED_OVERLAY}:
        return True, f"{rel}: {state} {category}; {message}"
    return False, f"{rel}: {message}"


def append_or_relax_baseline_finding(
    ctx: PRContext,
    findings: list[str],
    relaxed: list[str],
    rel: str,
    category: str,
    message: str,
    *,
    line: str = "",
) -> None:
    can_relax, detail = baseline_classified_detail(ctx, rel, category, message, line=line)
    if can_relax:
        relaxed.append(detail)
    else:
        findings.append(detail)


def baseline_inherited_path(ctx: PRContext, rel: str, category: str = "historical_content", *, line: str = "") -> bool:
    return baseline_finding_classification(ctx, rel, category, line=line)["classification"] == INHERITED_BASELINE


def baseline_authorized_overlay_path(ctx: PRContext, rel: str) -> bool:
    return baseline_finding_classification(ctx, rel, "governance_overlay")["classification"] == AUTHORIZED_OVERLAY


def baseline_inherited_or_overlay_path(ctx: PRContext, rel: str, category: str = "historical_content", *, line: str = "") -> bool:
    return baseline_finding_classification(ctx, rel, category, line=line)["classification"] in {INHERITED_BASELINE, AUTHORIZED_OVERLAY}


def gate_baseline_alignment(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    mode = "baseline"
    requested = baseline_requested(ctx)
    if requested:
        authorized, details, policy = baseline_authorization(ctx, git_context)
    elif branch_alignment_requested(ctx):
        mode = "branch_alignment"
        requested = True
        authorized, details, policy = branch_alignment_authorization(ctx, git_context)
    else:
        authorized, details, policy = False, ["Baseline alignment mode was not requested."], baseline_policy(ctx)
    cache = context_cache(ctx)
    cache["baseline_authorized"] = authorized
    cache["baseline_policy"] = policy
    cache["baseline_authorization_details"] = details
    cache["baseline_mode"] = mode
    if not requested:
        return [passed("Baseline Alignment", None, "One-time baseline alignment mode was not requested.")]
    if not authorized:
        label = "branch alignment" if mode == "branch_alignment" else "baseline alignment"
        return [failed("Baseline Alignment", None, f"One-time {label} authorization failed closed.", details, score=30)]
    mode_label = "BRANCH ANCESTRY ALIGNMENT PREFLIGHT" if mode == "branch_alignment" else "BASELINE ALIGNMENT PREFLIGHT"
    evidence = [
        f"repository={resolve_repository_name(ctx)}",
        f"source_branch={ctx.head_ref or 'unknown'}",
        f"target_branch={ctx.base_ref or 'unknown'}",
        f"source_sha={resolve_head_sha(ctx.repo, git_context)}",
        f"destination_sha={git_context.get('base_sha') or 'unknown'}",
        f"changed_files={len(ctx.changed_files)}",
        f"additions={ctx.additions}",
        f"deletions={ctx.deletions}",
        f"mode={mode_label}",
    ]
    evidence.extend(f"relaxed={item}" for item in sorted(baseline_relaxations(ctx)))
    return [passed("Baseline Alignment", None, f"{mode_label} authorized by central one-time policy.", evidence)]


def gate_config_validation(ctx: PRContext) -> list[CheckResult]:
    if ctx.config_violations:
        return [failed("Config Validation", None, "Repository QA configuration failed immutable policy validation.", ctx.config_violations, score=25)]
    return [passed("Config Validation", None, "Immutable central policy loaded and repository config is trusted from base branch.")]


def gate_repository_integrity(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    findings: list[str] = []
    relaxed: list[str] = []
    if ctx.diff_error:
        findings.append(ctx.diff_error)
    allowed_hidden = set(ctx.policy.get("allowed_hidden_files", []))
    generated_components = set(ctx.policy.get("generated_path_components", []))
    generated_patterns = ctx.policy.get("generated_artifact_patterns", [])
    allowed_binary = set(ctx.policy.get("allowed_binary_extensions", []))
    max_bytes = ctx.threshold("max_file_bytes", 5 * 1024 * 1024)
    for rel in ctx.changed_files:
        path = ctx.repo / rel
        parts = Path(rel).parts
        if ".." in parts or rel.startswith("/"):
            findings.append(f"{rel}: path traversal or absolute path marker.")
        if any(ord(char) > 127 for char in rel):
            findings.append(f"{rel}: non-ASCII/Unicode filename is not allowed in protected PR QA.")
        if not is_approved_governance_asset(ctx, rel):
            hidden_parts = [part for part in parts if part.startswith(".") and part not in {".github"}]
            for hidden in hidden_parts:
                if is_baseline_safe_environment_file(ctx, rel):
                    relaxed.append(f"{rel}: baseline-approved environment template/test fixture classification.")
                elif hidden not in allowed_hidden and not is_react_native_hidden_text_exception(ctx, rel):
                    append_or_relax_baseline_finding(
                        ctx,
                        findings,
                        relaxed,
                        rel,
                        "hidden_file",
                        f"unexpected hidden file or directory `{hidden}`.",
                    )
        if any(part in generated_components for part in parts) or match_any(rel, generated_patterns):
            append_or_relax_baseline_finding(
                ctx,
                findings,
                relaxed,
                rel,
                "generated_static_baseline_content",
                "generated artifact path changed.",
            )
        if path.is_symlink():
            target = os.readlink(path)
            append_or_relax_baseline_finding(
                ctx,
                findings,
                relaxed,
                rel,
                "symlink",
                f"symlink changed; target `{target}` requires manual security review.",
            )
        if path.is_file():
            size = path.stat().st_size
            if size > max_bytes:
                append_or_relax_baseline_finding(
                    ctx,
                    findings,
                    relaxed,
                    rel,
                    "oversized_file",
                    f"oversized file ({size} bytes).",
                )
            if is_binary_file(path) and path.suffix.lower() not in allowed_binary and not is_react_native_binary_bootstrap_exception(ctx, rel):
                if is_baseline_allowed_binary(ctx, rel):
                    relaxed.append(f"{rel}: baseline-approved binary asset classification.")
                else:
                    append_or_relax_baseline_finding(
                        ctx,
                        findings,
                        relaxed,
                        rel,
                        "binary_file",
                        "binary file type is not allowed.",
                    )
            if is_lfs_pointer(path):
                append_or_relax_baseline_finding(
                    ctx,
                    findings,
                    relaxed,
                    rel,
                    "lfs",
                    "Git LFS pointer changed; actual object is not available for local scanning.",
                )
    if git_context.get("is_git_repo"):
        for rel in ctx.changed_files:
            mode = git_lines(ctx.repo, ["ls-files", "-s", "--", rel])
            if mode and mode[0].startswith("160000 "):
                append_or_relax_baseline_finding(
                    ctx,
                    findings,
                    relaxed,
                    rel,
                    "submodule",
                    "submodule/gitlink changed.",
                )
    if findings:
        return [failed("Repository Integrity", None, "Repository integrity checks failed.", findings[:60], score=25)]
    if relaxed:
        return [warning("Repository Integrity", None, "Baseline-only repository integrity relaxations applied; secret, binary safety, and path traversal checks remain active.", relaxed[:60])]
    return [passed("Repository Integrity", None, "No symlink, submodule, LFS, Unicode, hidden-file, generated-artifact, binary, or path traversal issues detected.")]


def is_lfs_pointer(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size > 1024:
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    return text.startswith("version https://git-lfs.github.com/spec/v1")


def is_baseline_safe_environment_file(ctx: PRContext, rel: str) -> bool:
    if not baseline_allows(ctx, "environment_fixture_classification"):
        return False
    settings = baseline_policy_settings(ctx).get("environment_files", {}) or {}
    allowed = set(settings.get("safe_paths", []) or [])
    if rel not in allowed:
        return False
    if not baseline_inherited_path(ctx, rel, "environment_fixture"):
        return False
    path = ctx.repo / rel
    if not path.is_file() or is_binary_file(path):
        return False
    text = read_text(path)
    required_by_path = settings.get("required_markers_by_path", {}) or {}
    required_markers = list(required_by_path.get(rel, []) or settings.get("required_markers", []) or [])
    if required_markers and not all(str(marker) in text for marker in required_markers):
        return False
    forbidden_patterns = settings.get("forbidden_patterns", []) or []
    return not any(re.search(str(pattern), text, flags=re.IGNORECASE) for pattern in forbidden_patterns)


def is_baseline_allowed_binary(ctx: PRContext, rel: str) -> bool:
    if not baseline_allows(ctx, "baseline_binary_assets"):
        return False
    settings = baseline_policy_settings(ctx).get("binary_assets", {}) or {}
    allowed = set(settings.get("safe_paths", []) or [])
    if rel not in allowed:
        return False
    if not baseline_inherited_path(ctx, rel, "binary_asset"):
        return False
    max_bytes = int(settings.get("max_file_bytes", 0) or 0)
    path = ctx.repo / rel
    return path.is_file() and (not max_bytes or path.stat().st_size <= max_bytes)


def gate_repository_hygiene(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    results: list[CheckResult] = []
    branch = ctx.head_ref or ""
    branch_patterns = ctx.config.get("branch_naming", {}).get("allowed_patterns", [])
    if branch and any(re.match(pattern, branch) for pattern in branch_patterns):
        results.append(passed("Repository Hygiene", None, f"Branch name `{branch}` matches allowed convention."))
    elif branch and canonical_branch_promotion(ctx):
        results.append(passed("Repository Hygiene", None, f"Branch name `{branch}` is accepted for governed branch promotion."))
    elif branch and baseline_allows(ctx, "historical_branch_name"):
        results.append(warning("Repository Hygiene", None, f"Historical baseline source branch `{branch}` predates current branch naming convention; future PRs remain governed."))
    elif branch:
        results.append(warning("Repository Hygiene", None, f"Branch name `{branch}` does not match allowed convention; future branch names should follow the central convention."))
    else:
        results.append(warning("Repository Hygiene", None, "Branch name could not be determined."))

    commits = git_context.get("commits", [])
    commit_patterns = ctx.config.get("commit_messages", {}).get("allowed_patterns", [])
    invalid_commits = [message for message in commits if not any(re.match(pattern, message) for pattern in commit_patterns)]
    if invalid_commits:
        if baseline_allows(ctx, "historical_commit_volume"):
            results.append(warning("Repository Hygiene", None, "Historical baseline commit messages predate current convention; future commits remain governed.", invalid_commits[:20]))
        elif long_lived_staging_to_main_promotion(ctx):
            results.append(warning("Repository Hygiene", None, "Inherited branch-promotion commit messages predate current convention; future direct PR commits remain governed.", invalid_commits[:20]))
        else:
            results.append(warning("Repository Hygiene", None, "Commit messages do not match convention; future commit messages should follow the central convention.", invalid_commits[:20]))
    elif commits:
        results.append(passed("Repository Hygiene", None, "Commit messages match convention."))
    else:
        results.append(warning("Repository Hygiene", None, "Commit messages were not available for validation."))

    merge_marker_hits = grep_text_files(ctx.repo, ctx.changed_files, r"^(<<<<<<<|=======|>>>>>>>)")
    if merge_marker_hits:
        blocking_markers: list[str] = []
        inherited_markers: list[str] = []
        for hit in merge_marker_hits:
            rel, line_no = split_path_line(hit)
            line_text = read_line(ctx.repo / rel, line_no)
            if match_any(rel, BASELINE_STATIC_ASSET_PATTERNS) and baseline_inherited_path(ctx, rel, "static_asset_marker", line=line_text):
                inherited_markers.append(f"{hit}: INHERITED_BASELINE static asset marker-like content.")
            else:
                blocking_markers.append(hit)
        if blocking_markers:
            results.append(failed("Repository Hygiene", None, "Merge conflict markers found in changed files.", blocking_markers[:60], score=20))
        if inherited_markers:
            results.append(warning("Repository Hygiene", None, "Inherited baseline static assets contain marker-like text; future changes remain blocking.", inherited_markers[:60]))
    else:
        results.append(passed("Repository Hygiene", None, "No merge conflict markers found in changed files."))

    if git_context.get("is_git_repo") and git_context.get("base_sha"):
        merge_commits = git_lines(ctx.repo, ["rev-list", "--first-parent", "--merges", git_context.get("pr_commit_range") or f"{git_context['base_sha']}..HEAD"])
        main_to_development_source = main_to_development_current_alignment_source_tip(ctx) if merge_commits else ""
        unexpected_merge_commits = merge_commits
        if merge_commits and canonical_branch_promotion(ctx):
            unexpected_merge_commits = [
                sha for sha in merge_commits if not merge_commit_matches_second_parent_tree(ctx.repo, sha)
            ]
        elif merge_commits:
            unexpected_merge_commits = [
                sha for sha in merge_commits
                if not (
                    tree_neutral_ancestry_reconciliation_merge_commit(ctx, sha)
                    or main_to_staging_gate_c_alignment_merge_commit(ctx, sha)
                    or development_to_staging_current_alignment_merge_commit(ctx, sha)
                    or main_to_development_current_alignment_merge_commit(ctx, sha)
                    or (
                        main_to_development_source
                        and commit_is_ancestor(ctx.repo, sha, main_to_development_source)
                    )
                    or governed_ancestry_alignment_merge_commit(ctx, sha)
                )
            ]
        if unexpected_merge_commits and baseline_allows(ctx, "historical_commit_volume"):
            results.append(warning("Repository Hygiene", None, "Historical baseline merge commits predate current promotion policy; future PRs remain governed.", unexpected_merge_commits[:20]))
        elif unexpected_merge_commits and long_lived_staging_to_main_promotion(ctx):
            results.append(warning("Repository Hygiene", None, "Inherited branch-promotion merge commits predate current promotion policy; future direct PR merges remain governed.", unexpected_merge_commits[:20]))
        elif unexpected_merge_commits and not ctx.config.get("repository", {}).get("allow_merge_commits", False):
            results.append(failed("Repository Hygiene", None, "Accidental merge commits detected.", unexpected_merge_commits[:20], score=8))
        elif merge_commits and canonical_branch_promotion(ctx):
            results.append(passed("Repository Hygiene", None, "Only governed branch-promotion merge commits detected."))
        elif merge_commits and all(tree_neutral_ancestry_reconciliation_merge_commit(ctx, sha) for sha in merge_commits):
            results.append(passed("Repository Hygiene", None, "Only intentional tree-neutral ancestry reconciliation merge commits detected."))
        elif merge_commits and all(main_to_staging_gate_c_alignment_merge_commit(ctx, sha) for sha in merge_commits):
            results.append(passed("Repository Hygiene", None, "Only expected Gate C main-to-staging alignment merge commits detected."))
        elif merge_commits and all(development_to_staging_current_alignment_merge_commit(ctx, sha) for sha in merge_commits):
            results.append(passed("Repository Hygiene", None, "Only current development-to-staging tree-neutral alignment merge commits detected."))
        elif merge_commits and main_to_development_source:
            results.append(passed("Repository Hygiene", None, "Only current main-to-development tree-neutral alignment merge commits detected."))
        elif merge_commits:
            results.append(passed("Repository Hygiene", None, "Only governed ancestry-alignment merge commits detected."))
        else:
            results.append(passed("Repository Hygiene", None, "No accidental merge commits detected."))
    return results


def canonical_branch_promotion(ctx: PRContext) -> bool:
    pair = ((ctx.head_ref or "").lower(), (ctx.base_ref or "").lower())
    return pair in {
        ("develop", "staging"),
        ("development", "staging"),
        ("staging", "main"),
        ("staging", "master"),
    }


def long_lived_staging_to_main_promotion(ctx: PRContext) -> bool:
    pair = ((ctx.head_ref or "").lower(), (ctx.base_ref or "").lower())
    return pair in {
        ("staging", "main"),
        ("staging", "master"),
    }


def merge_commit_matches_second_parent_tree(repo: Path, sha: str) -> bool:
    parents = git_lines(repo, ["show", "-s", "--format=%P", sha])
    if not parents:
        return False
    if len(parents[0].split()) != 2:
        return False
    completed = subprocess.run(["git", "diff", "--quiet", sha, f"{sha}^2"], cwd=repo, text=True, capture_output=True, check=False)
    return completed.returncode == 0


def commit_is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(["git", "merge-base", "--is-ancestor", ancestor, descendant], cwd=repo, text=True, capture_output=True, check=False)
    return completed.returncode == 0


def tree_neutral_ancestry_reconciliation_merge_commit(ctx: PRContext, sha: str) -> bool:
    if (ctx.base_ref or "").lower() != "development":
        return False
    parents = git_lines(ctx.repo, ["show", "-s", "--format=%P", sha])
    if not parents:
        return False
    parent_values = parents[0].split()
    if len(parent_values) != 2:
        return False
    completed = subprocess.run(["git", "diff", "--quiet", f"{sha}^1", sha], cwd=ctx.repo, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        return False
    staging_tip = resolve_fresh_origin_staging_tip(ctx.repo)
    return bool(staging_tip) and parent_values[1] == staging_tip


def resolve_fresh_origin_staging_tip(repo: Path) -> str:
    return resolve_fresh_origin_branch_tip(repo, "staging")


def resolve_fresh_origin_development_tip(repo: Path) -> str:
    return resolve_fresh_origin_branch_tip(repo, "development")


def resolve_fresh_origin_branch_tip(repo: Path, branch: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch or ""):
        return ""
    remote_ref = f"refs/remotes/origin/{branch}"
    fetch_args = ["git", "fetch", "--no-tags", "origin", f"+refs/heads/{branch}:{remote_ref}"]
    if origin_is_github_https(repo):
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            return ""
        encoded = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
        fetch_args = ["git", "-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {encoded}", "fetch", "--no-tags", "origin", f"+refs/heads/{branch}:{remote_ref}"]
    fetched = subprocess.run(fetch_args, cwd=repo, text=True, capture_output=True, check=False)
    if fetched.returncode != 0:
        return ""
    resolved = run_git(repo, ["rev-parse", "--verify", f"{remote_ref}^{{commit}}"]).strip()
    return resolved if resolved and commit_exists(repo, resolved) else ""


def origin_is_github_https(repo: Path) -> bool:
    origin_url = run_git(repo, ["remote", "get-url", "origin"]).strip().lower()
    return origin_url.startswith("https://github.com/") or origin_url.startswith("https://www.github.com/")


def main_to_staging_gate_c_alignment_merge_commit(ctx: PRContext, sha: str) -> bool:
    if (ctx.base_ref or "").lower() != "staging":
        return False
    current_main_tip = resolve_fresh_origin_main_tip(ctx.repo)
    staging_tip = resolve_fresh_origin_staging_tip(ctx.repo)
    if not current_main_tip or not staging_tip:
        return False
    if not current_main_tip_is_gate_c_merge_for_staging(ctx.repo, current_main_tip, staging_tip):
        return False
    parents = git_lines(ctx.repo, ["show", "-s", "--format=%P", sha])
    if not parents:
        return False
    parent_values = parents[0].split()
    if len(parent_values) != 2:
        return False
    if sha == current_main_tip:
        return merge_commit_matches_second_parent_tree(ctx.repo, sha)
    if parent_values[0] == staging_tip and parent_values[1] == current_main_tip:
        tree_neutral = subprocess.run(["git", "diff", "--quiet", f"{sha}^1", sha], cwd=ctx.repo, text=True, capture_output=True, check=False)
        return tree_neutral.returncode == 0
    return False


def development_to_staging_current_alignment_merge_commit(ctx: PRContext, sha: str) -> bool:
    if (ctx.base_ref or "").lower() != "staging":
        return False
    head_sha = run_git(ctx.repo, ["rev-parse", "--verify", "HEAD^{commit}"]).strip()
    if not head_sha or sha != head_sha:
        return False
    staging_tip = resolve_fresh_origin_staging_tip(ctx.repo)
    development_tip = resolve_fresh_origin_development_tip(ctx.repo)
    if not staging_tip or not development_tip:
        return False
    parents = git_lines(ctx.repo, ["show", "-s", "--format=%P", sha])
    if not parents:
        return False
    parent_values = parents[0].split()
    if len(parent_values) != 2:
        return False
    if parent_values[0] != staging_tip or parent_values[1] != development_tip:
        return False
    tree_neutral = subprocess.run(["git", "diff", "--quiet", f"{head_sha}^1", head_sha], cwd=ctx.repo, text=True, capture_output=True, check=False)
    return tree_neutral.returncode == 0


def main_to_development_current_alignment_merge_commit(ctx: PRContext, sha: str) -> bool:
    if (ctx.base_ref or "").lower() != "development":
        return False
    head_sha = run_git(ctx.repo, ["rev-parse", "--verify", "HEAD^{commit}"]).strip()
    if not head_sha or sha != head_sha:
        return False
    if not main_to_development_current_alignment_source_tip(ctx):
        return False
    parents = git_lines(ctx.repo, ["show", "-s", "--format=%P", sha])
    if not parents:
        return False
    parent_values = parents[0].split()
    if len(parent_values) != 2:
        return False
    development_tip = resolve_fresh_origin_development_tip(ctx.repo)
    main_tip = resolve_fresh_origin_main_tip(ctx.repo)
    if parent_values[0] != development_tip or parent_values[1] != main_tip:
        return False
    return True


def main_to_development_current_alignment_source_tip(ctx: PRContext) -> str:
    if (ctx.base_ref or "").lower() != "development":
        return ""
    head_sha = run_git(ctx.repo, ["rev-parse", "--verify", "HEAD^{commit}"]).strip()
    if not head_sha:
        return ""
    development_tip = resolve_fresh_origin_development_tip(ctx.repo)
    main_tip = resolve_fresh_origin_main_tip(ctx.repo)
    if not development_tip or not main_tip:
        return ""
    if head_sha == main_tip:
        tree_neutral = subprocess.run(["git", "diff", "--quiet", development_tip, head_sha], cwd=ctx.repo, text=True, capture_output=True, check=False)
        return main_tip if tree_neutral.returncode == 0 else ""
    parents = git_lines(ctx.repo, ["show", "-s", "--format=%P", head_sha])
    if not parents:
        return ""
    parent_values = parents[0].split()
    if len(parent_values) != 2:
        return ""
    if parent_values[0] != development_tip or parent_values[1] != main_tip:
        return ""
    tree_neutral = subprocess.run(["git", "diff", "--quiet", f"{head_sha}^1", head_sha], cwd=ctx.repo, text=True, capture_output=True, check=False)
    return main_tip if tree_neutral.returncode == 0 else ""


def current_main_tip_is_gate_c_merge_for_staging(repo: Path, current_main_tip: str, staging_tip: str) -> bool:
    parents = git_lines(repo, ["show", "-s", "--format=%P", current_main_tip])
    if not parents:
        return False
    parent_values = parents[0].split()
    if len(parent_values) != 2:
        return False
    staging_lineage = subprocess.run(["git", "merge-base", "--is-ancestor", parent_values[1], staging_tip], cwd=repo, text=True, capture_output=True, check=False)
    if staging_lineage.returncode != 0:
        return False
    return merge_commit_matches_second_parent_tree(repo, current_main_tip)


def resolve_fresh_origin_main_tip(repo: Path) -> str:
    return resolve_fresh_origin_branch_tip(repo, "main")


def governed_ancestry_alignment_merge_commit(ctx: PRContext, sha: str) -> bool:
    allowed_paths = {".github/CODEOWNERS", ".github/workflows/pr-qa.yml"}
    base = (ctx.base_ref or "").lower()
    head = (ctx.head_ref or "").lower()
    if base not in {"development", "staging", "main", "master"}:
        return False
    if "align" not in head and "promote" not in head:
        return False
    if not set(ctx.changed_files).issubset(allowed_paths):
        return False
    parents = git_lines(ctx.repo, ["show", "-s", "--format=%P", sha])
    parent_values = parents[0].split() if parents else []
    if len(parent_values) != 2:
        return False
    first_parent_delta = set(git_lines(ctx.repo, ["diff", "--name-only", f"{sha}^1..{sha}"]))
    return bool(first_parent_delta) and first_parent_delta.issubset(allowed_paths)


def gate_git_validation(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    results: list[CheckResult] = []
    if ctx.diff_error:
        return [failed("Git Validation", None, "Base diff validation failed closed.", [ctx.diff_error], score=20)]
    if git_context.get("is_git_repo") and git_context.get("diff_range"):
        outcome = ctx.run(["git", "diff", "--check", git_context["diff_range"]], cwd=ctx.repo)
        if outcome.ok:
            results.append(passed("Git Validation", None, "`git diff --check` passed."))
        else:
            full_output = redact("\n".join(part for part in [outcome.stdout, outcome.stderr] if part).strip())
            blocking, ignored = filter_diff_check_output(ctx, full_output)
            inherited_blocking: list[str] = []
            if blocking and baseline_active(ctx):
                blocking, inherited_blocking = classify_diff_check_output(ctx, "\n".join(blocking))
            if blocking:
                results.append(failed("Git Validation", None, "`git diff --check` found whitespace or marker issues.", blocking[:30], score=10))
            if inherited_blocking:
                results.append(warning("Git Validation", None, "Inherited baseline whitespace detected; future whitespace changes remain blocking.", inherited_blocking[:60]))
            else:
                if not blocking:
                    results.append(passed("Git Validation", None, "`git diff --check` passed with only approved React Native Gradle wrapper batch line-ending findings.", ignored[:30]))
    else:
        results.append(failed("Git Validation", None, "Git diff range was not available; failing closed.", score=20))
    crlf = []
    for rel in ctx.changed_files:
        path = ctx.repo / rel
        if path.is_file() and not is_binary_file(path):
            try:
                if b"\r\n" in path.read_bytes() and not is_react_native_line_ending_exception(ctx, rel):
                    crlf.append(rel)
            except OSError:
                pass
    if crlf:
        results.append(warning("Git Validation", None, "CRLF line endings detected in changed text files.", crlf[:30]))
    else:
        results.append(passed("Git Validation", None, "No CRLF line endings detected in changed text files."))
    return results


def gate_secrets(ctx: PRContext, git_context: dict[str, Any], report_path: str) -> list[CheckResult]:
    results: list[CheckResult] = [run_gitleaks(ctx, git_context, report_path)]
    findings, fixture_findings, inherited_findings = fallback_secret_scan(ctx, git_context)
    if findings:
        results.append(failed("Secrets", None, "High-confidence secret indicators found in changed files.", findings[:60], score=40))
    elif results[0].status == PASS:
        results.append(passed("Secrets", None, "Fallback and encoded secret scans found no high-confidence issues."))
    if inherited_findings and not findings and results[0].status == PASS:
        results.append(warning("Secrets", None, "Historical inherited credential-shaped fallback findings remain visible; cleanup remains required.", inherited_findings[:60]))
    if fixture_findings and not findings and results[0].status == PASS:
        if baseline_active(ctx):
            results.append(warning("Secrets", None, "Inherited baseline secret-like false positives were classified; future findings remain blocking.", fixture_findings[:60]))
        else:
            results.append(passed("Secrets", None, "Approved framework regression fixtures remain detectable and isolated.", fixture_findings[:60]))
    return results


def run_gitleaks(ctx: PRContext, git_context: dict[str, Any], report_path: str) -> CheckResult:
    if not command_exists("gitleaks"):
        return failed("Secrets", None, "Gitleaks is mandatory and is not available on the runner.", score=40)
    out_dir = Path(report_path).parent if report_path else ctx.repo / "pr-qa-results"
    out_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "gitleaks",
        "detect",
        "--source",
        str(ctx.repo),
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        str(out_dir / "gitleaks.json"),
        "--exit-code",
        "1",
    ]
    if long_lived_staging_to_main_promotion(ctx) and not baseline_active(ctx):
        with tempfile.TemporaryDirectory(prefix="pr-qa-gitleaks-content-") as scan_root:
            scan_source = Path(scan_root)
            populate_changed_file_scan_source(ctx, scan_source)
            command[command.index(str(ctx.repo))] = str(scan_source)
            command.append("--no-git")
            outcome = ctx.run(command, cwd=ctx.repo)
        success_message = "Gitleaks content-delta scan passed for canonical branch promotion."
    else:
        if git_context.get("pr_commit_range"):
            command.extend(["--log-opts", f"--first-parent {git_context['pr_commit_range']}"])
        elif git_context.get("base_sha"):
            command.extend(["--log-opts", f"{git_context['base_sha']}..HEAD"])
        outcome = ctx.run(command, cwd=ctx.repo)
        success_message = "Gitleaks scan passed."
    if outcome.ok:
        return passed("Secrets", None, success_message)
    report = out_dir / "gitleaks.json"
    allowed, unexpected, allowance_details = classify_gitleaks_findings(ctx, report)
    if allowed and not unexpected:
        return warning(
            "Secrets",
            None,
            "Gitleaks executed and returned only centrally allowlisted baseline fixture fingerprints; future findings remain blocking.",
            allowance_details[:60],
        )
    details = [outcome.concise_output()]
    if unexpected:
        details.extend(unexpected[:60])
    return failed("Secrets", None, "Gitleaks detected secrets.", details, score=40)


def populate_changed_file_scan_source(ctx: PRContext, scan_source: Path) -> None:
    scan_source.mkdir(parents=True, exist_ok=True)
    for rel in ctx.changed_files:
        src = ctx.repo / rel
        if not src.is_file():
            continue
        dst = scan_source / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)


def classify_gitleaks_findings(ctx: PRContext, report: Path) -> tuple[bool, list[str], list[str]]:
    if not report.exists():
        return False, ["Gitleaks report was not generated."], []
    try:
        findings = json.loads(report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, [f"Gitleaks report is invalid JSON: {exc}"], []
    if not isinstance(findings, list):
        return False, ["Gitleaks report is not a list."], []
    if not findings:
        return False, [], []
    if not baseline_allows(ctx, "exact_gitleaks_fingerprint_allowlist"):
        return False, [gitleaks_finding_summary(item) for item in findings if isinstance(item, dict)], []
    allowed = baseline_policy_settings(ctx).get("gitleaks_allowlist", []) or []
    unexpected: list[str] = []
    allowed_details: list[str] = []
    for raw in findings:
        item = raw if isinstance(raw, dict) else {}
        match = matching_gitleaks_allowance(ctx, item, allowed)
        if not match:
            unexpected.append(gitleaks_finding_summary(item))
            continue
        allowed_details.append(
            f"{item.get('File', 'unknown')}:{item.get('StartLine', '?')} {item.get('RuleID', 'unknown')} "
            f"fingerprint={item.get('Fingerprint', 'unknown')} justification={match.get('justification', 'baseline fixture')}"
        )
    return bool(allowed_details), unexpected, allowed_details


def matching_gitleaks_allowance(ctx: PRContext, item: dict[str, Any], allowlist: list[Any]) -> dict[str, Any] | None:
    inherited_match: dict[str, Any] | None = None
    for candidate in allowlist:
        if not isinstance(candidate, dict):
            continue
        fingerprint = str(candidate.get("fingerprint", ""))
        rule = str(candidate.get("rule_id", ""))
        if rule and rule != str(item.get("RuleID", "")):
            continue
        path = str(candidate.get("path", ""))
        if path and path != str(item.get("File", "")):
            continue
        line = candidate.get("line")
        expires_after = str(candidate.get("expires_after", ""))
        if expires_after and baseline_allowance_expired(expires_after):
            continue
        item_line = int(item.get("StartLine") or 0)
        if line is not None and int(line) != item_line:
            if baseline_inherited_gitleaks_false_positive(ctx, item):
                inherited_match = candidate
            continue
        if fingerprint and fingerprint != str(item.get("Fingerprint", "")):
            if not baseline_inherited_gitleaks_false_positive(ctx, item):
                continue
            allowed_parts = fingerprint.split(":")
            item_parts = str(item.get("Fingerprint", "")).split(":")
            if len(allowed_parts) < 4 or len(item_parts) < 4 or allowed_parts[2] != item_parts[2]:
                continue
        return candidate
    return inherited_match


def baseline_inherited_gitleaks_false_positive(ctx: PRContext, item: dict[str, Any]) -> bool:
    rel = str(item.get("File", ""))
    if not rel or not baseline_inherited_path(ctx, rel, "gitleaks_fingerprint"):
        return False
    line = source_line(ctx.repo, rel, int(item.get("StartLine") or 0))
    return baseline_inherited_gitleaks_fixture_line(rel, line)


def baseline_inherited_gitleaks_fixture_line(rel: str, line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", stripped):
        return False
    if re.search(r"\b(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+)\b", stripped):
        return False
    if re.search(r"\b(idempotency_key|jwt\.secret|PROVIDER_SECRET|api_surface)\b", stripped):
        return True
    if rel.startswith("tests/") and re.search(r"\b(test|fixture|secret|key|token|provider|idempotent|jwt|razorpay)\b", stripped, re.IGNORECASE):
        return True
    return baseline_inherited_config_reference_false_positive(stripped)


def source_line(repo: Path, rel: str, line_number: int) -> str:
    if line_number <= 0:
        return ""
    path = repo / rel
    if not path.is_file():
        return ""
    for text in decoded_text_variants(path):
        lines = text.splitlines()
        if line_number <= len(lines):
            return lines[line_number - 1]
    return ""


def baseline_allowance_expired(expires_after: str) -> bool:
    try:
        expires = datetime.fromisoformat(expires_after.replace("Z", "+00:00"))
    except ValueError:
        return True
    return datetime.now(timezone.utc) > expires


def gitleaks_finding_summary(item: dict[str, Any]) -> str:
    return (
        f"{item.get('File', 'unknown')}:{item.get('StartLine', '?')} "
        f"{item.get('RuleID', 'unknown')} fingerprint={item.get('Fingerprint', 'unknown')}"
    )


def fallback_secret_scan(ctx: PRContext, git_context: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    findings: list[str] = []
    fixture_findings: list[str] = []
    inherited_findings: list[str] = []
    env_patterns = [".env", ".env.*"]
    allowed_env = {".env.example", ".env.sample", ".env.template", ".env.local.example"}
    regexes = {
        "AWS access key": r"AKIA[0-9A-Z]{16}",
        "private key": r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        "GitHub token": r"(ghp|github_pat)_[A-Za-z0-9_]{20,}",
        "generic credential assignment": r"(?i)\b(password|passwd|secret|token|api[_-]?(?:key|token)|access[_-]?token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
    }
    for rel in ctx.changed_files:
        rel_findings: list[str] = []
        path = ctx.repo / rel
        name = Path(rel).name
        if any(fnmatch.fnmatch(name, pattern) for pattern in env_patterns) and name not in allowed_env and not is_baseline_safe_environment_file(ctx, rel):
            rel_findings.append(f"{rel}: environment file committed.")
        if name.endswith((".pem", ".key", ".p12", ".pfx")):
            rel_findings.append(f"{rel}: key or certificate container committed.")
        if not path.is_file():
            findings.extend(rel_findings)
            continue
        texts = decoded_text_variants(path)
        for text in texts:
            line_labels_found: set[str] = set()
            for line in text.splitlines():
                normalized = normalize_secret_text(line)
                for label, pattern in regexes.items():
                    if re.search(pattern, normalized):
                        rel_findings.append(fallback_secret_finding(rel, label, line))
                        line_labels_found.add(label)
                for decoded in decode_base64_candidates(line, ctx.policy):
                    for label, pattern in regexes.items():
                        if re.search(pattern, decoded):
                            decoded_label = f"base64-encoded {label}"
                            rel_findings.append(fallback_secret_finding(rel, decoded_label, line))
                            line_labels_found.add(decoded_label)
            normalized = normalize_secret_text(text)
            for label, pattern in regexes.items():
                if label not in line_labels_found and re.search(pattern, normalized):
                    rel_findings.append(f"{rel}: {label}.")
            for decoded in decode_base64_candidates(text, ctx.policy):
                for label, pattern in regexes.items():
                    decoded_label = f"base64-encoded {label}"
                    if decoded_label not in line_labels_found and re.search(pattern, decoded):
                        rel_findings.append(f"{rel}: {decoded_label}.")
        inherited, remaining = classify_inherited_fallback_secret_findings(ctx, git_context, rel, rel_findings)
        inherited_findings.extend(inherited)
        rel_findings = remaining
        if baseline_allowed_fallback_secret_findings(ctx, rel, rel_findings, texts):
            fixture_findings.extend(rel_findings)
        elif is_approved_regression_fixture(ctx, rel):
            fixture_findings.extend(rel_findings)
        else:
            findings.extend(rel_findings)
    return sorted(set(findings)), sorted(set(fixture_findings)), sorted(set(inherited_findings))


def classify_inherited_fallback_secret_findings(
    ctx: PRContext,
    git_context: dict[str, Any],
    rel: str,
    rel_findings: list[str],
) -> tuple[list[str], list[str]]:
    inherited: list[str] = []
    remaining: list[str] = []
    for finding in rel_findings:
        if inherited_fallback_finding_is_exact_low_confidence_noise(ctx, git_context, rel, finding):
            inherited.append(f"{finding} inherited_exact=true")
        else:
            remaining.append(finding)
    return inherited, remaining


def inherited_fallback_finding_is_exact_low_confidence_noise(
    ctx: PRContext,
    git_context: dict[str, Any],
    rel: str,
    finding: str,
) -> bool:
    if not git_context.get("is_git_repo"):
        return False
    if not finding.startswith(f"{rel}: generic credential assignment. "):
        return False
    head_line = fallback_finding_line_from_texts(decoded_text_variants(ctx.repo / rel), finding)
    if not head_line or not fallback_line_is_low_confidence_noise(head_line):
        return False
    base_text = read_base_file(ctx.repo, git_context, rel)
    if not base_text:
        return False
    base_line = fallback_finding_line_from_texts([base_text], finding)
    return bool(base_line) and base_line.strip() == head_line.strip()


def fallback_finding_line_from_texts(texts: list[str], finding: str) -> str:
    match = re.search(r"line_sha256=([0-9a-f]{64})", finding)
    if not match:
        return ""
    target_hash = match.group(1)
    for text in texts:
        for line in text.splitlines():
            if hashlib.sha256(line.strip().encode("utf-8")).hexdigest() == target_hash:
                return line
    return ""


def fallback_line_is_low_confidence_noise(line: str) -> bool:
    normalized = normalize_secret_text(line)
    if re.search(r"\b(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+)\b", normalized):
        return False
    if re.search(r"-----BEGIN [A-Z ]+PRIVATE KEY-----", normalized):
        return False
    if structural_runtime_env_lookup_present(line):
        return True
    if re.search(r"\$[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])+", line) and re.search(r"\b(password|secret|token|api[_-]?(?:key|token)|access[_-]?token)\b", normalized, re.IGNORECASE):
        return True
    if re.search(r"\$result\s*\[", normalized):
        return True
    if re.search(r"['\"][A-Za-z0-9_.-]+['\"]\s*=>\s*['\"][A-Za-z0-9_.-]+['\"]", normalized):
        return True
    return False


def structural_runtime_env_lookup_present(line: str) -> bool:
    for match in re.finditer(r"(?<!['\"A-Za-z0-9_])(?:env|config)\s*\(\s*(['\"])([A-Z0-9_.-]+)\1(?:\s*,\s*([^)]+))?\)", line):
        default = (match.group(3) or "").strip()
        if not default:
            return True
        if runtime_lookup_default_is_safe(default):
            return True
    return False


def runtime_lookup_default_is_safe(default: str) -> bool:
    if default in {"''", '""', "null", "NULL", "false", "FALSE", "true", "TRUE", "0", "1"}:
        return True
    quoted = re.fullmatch(r"(['\"])(.*)\1", default)
    if not quoted:
        return True
    value = quoted.group(2)
    if value == "":
        return True
    if re.match(r"^https?://", value):
        return True
    if re.fullmatch(r"[A-Za-z0-9_.:/ -]{1,32}", value) and not re.search(r"(secret|token|password|passwd|api[_-]?key|access[_-]?token)", value, re.IGNORECASE):
        return True
    return False


def fallback_secret_finding(rel: str, label: str, line: str) -> str:
    line_sha256 = hashlib.sha256(line.strip().encode("utf-8")).hexdigest()
    return f"{rel}: {label}. line_sha256={line_sha256}"


def baseline_allowed_fallback_secret_findings(ctx: PRContext, rel: str, rel_findings: list[str], texts: list[str]) -> bool:
    if not rel_findings or not baseline_allows(ctx, "exact_secret_fallback_allowlist"):
        return False
    allowlist = baseline_policy_settings(ctx).get("fallback_secret_allowlist", []) or []
    for finding in rel_findings:
        exact_match = any(fallback_secret_allowance_matches(rel, finding, texts, item) for item in allowlist if isinstance(item, dict))
        inherited_false_positive = baseline_inherited_fallback_secret_false_positive(ctx, rel, finding)
        if not exact_match and not inherited_false_positive:
            return False
    return True


def baseline_inherited_fallback_secret_false_positive(ctx: PRContext, rel: str, finding: str) -> bool:
    settings = baseline_policy_settings(ctx)
    patterns = settings.get("fallback_secret_inherited_false_positive_paths", []) or []
    labels = settings.get("fallback_secret_inherited_false_positive_labels", []) or ["generic credential assignment"]
    if patterns and match_any(rel, [str(pattern) for pattern in patterns]):
        path_allowed = True
    else:
        line = baseline_finding_line_from_sha(ctx, rel, finding)
        path_allowed = bool(
            line
            and "generic credential assignment" in finding
            and baseline_inherited_config_reference_false_positive(line)
        )
    if not path_allowed:
        return False
    if labels and not any(str(label) in finding for label in labels):
        return False
    return baseline_inherited_path(ctx, rel, "secret_false_positive")


def baseline_finding_line_from_sha(ctx: PRContext, rel: str, finding: str) -> str:
    match = re.search(r"line_sha256=([0-9a-f]{64})", finding)
    if not match:
        return ""
    target_hash = match.group(1)
    path = ctx.repo / rel
    if not path.is_file():
        return ""
    for text in decoded_text_variants(path):
        for line in text.splitlines():
            if hashlib.sha256(line.strip().encode("utf-8")).hexdigest() == target_hash:
                return line
    return ""


def baseline_inherited_config_reference_false_positive(line: str) -> bool:
    normalized = normalize_secret_text(line)
    return bool(
        re.search(r"\b(config|env)\s*\(", normalized)
        or re.search(r"\$result\s*\[", normalized)
        or re.search(r"['\"][A-Za-z0-9_.-]+['\"]\s*=>\s*['\"][A-Za-z0-9_.-]+['\"]", normalized)
    )


def fallback_secret_allowance_matches(rel: str, finding: str, texts: list[str], allowance: dict[str, Any]) -> bool:
    if str(allowance.get("path", "")) != rel:
        return False
    label = str(allowance.get("label", ""))
    if label and label not in finding:
        return False
    line_sha256 = str(allowance.get("line_sha256", ""))
    if not line_sha256:
        return False
    expires_after = str(allowance.get("expires_after", ""))
    if expires_after and baseline_allowance_expired(expires_after):
        return False
    finding_hash = re.search(r"line_sha256=([0-9a-f]{64})", finding)
    if not finding_hash or finding_hash.group(1) != line_sha256:
        return False
    return any(
        hashlib.sha256(line.strip().encode("utf-8")).hexdigest() == line_sha256
        for text in texts
        for line in text.splitlines()
    )


def repository_profile(ctx: PRContext) -> str:
    return str(ctx.config.get("repository", {}).get("profile", "application")).lower()


def repository_profile_settings(ctx: PRContext) -> dict[str, Any]:
    return dict(ctx.policy.get("repository_profiles", {}).get(repository_profile(ctx), {}) or {})


def is_approved_governance_asset(ctx: PRContext, rel: str) -> bool:
    patterns = list(ctx.policy.get("approved_governance_assets", []) or [])
    patterns.extend(repository_profile_settings(ctx).get("approved_governance_assets", []) or [])
    return match_any(rel, patterns)


def is_approved_regression_fixture(ctx: PRContext, rel: str) -> bool:
    if repository_profile(ctx) != "framework":
        return False
    patterns = repository_profile_settings(ctx).get("approved_regression_fixtures", []) or []
    return match_any(rel, patterns)


def is_approved_deployment_sensitive_asset(ctx: PRContext, rel: str) -> bool:
    if repository_profile(ctx) != "framework":
        return False
    patterns = repository_profile_settings(ctx).get("approved_deployment_sensitive_assets", []) or []
    return match_any(rel, patterns)


def decoded_text_variants(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    variants = []
    for encoding in ["utf-8", "utf-16", "utf-16-le", "utf-16-be", "latin-1"]:
        try:
            variants.append(raw.decode(encoding))
        except UnicodeDecodeError:
            pass
    return variants


def normalize_secret_text(text: str) -> str:
    return re.sub(r"['\"\s+._-]+", "", text) + "\n" + text


def decode_base64_candidates(text: str, policy: dict[str, Any]) -> list[str]:
    minimum = int(policy.get("secret_scan", {}).get("minimum_base64_length", 24))
    decoded: list[str] = []
    for token in re.findall(r"[A-Za-z0-9+/=]{%d,}" % minimum, text):
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
            value = raw.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if value:
            decoded.append(value)
    return decoded


def gate_executable_classification(ctx: PRContext, technologies: dict[str, dict[str, Any]]) -> list[CheckResult]:
    executable_extensions = set(ctx.policy.get("executable_extensions", []))
    covered: set[str] = set()
    for key in technologies:
        covered.update(ADAPTER_EXTENSIONS.get(key, set()))
    unknown = []
    inherited = []
    static_assets = []
    for rel in ctx.changed_files:
        suffix = Path(rel).suffix
        if suffix in executable_extensions and suffix not in covered:
            if baseline_inherited_path(ctx, rel, "executable_static_asset") and match_any(rel, BASELINE_STATIC_ASSET_PATTERNS):
                inherited.append(f"{rel}: INHERITED_BASELINE static executable asset.")
            elif is_bounded_static_browser_asset(rel):
                static_assets.append(f"{rel}: STATIC_BROWSER_ASSET.")
            else:
                unknown.append(rel)
    if unknown:
        return [failed("Executable Classification", None, "Executable code changed without a supported technology adapter.", unknown[:50], score=18)]
    if inherited:
        return [warning("Executable Classification", None, "Inherited baseline static executable assets are classified; future modifications remain blocking.", inherited[:50])]
    if static_assets:
        return [warning("Executable Classification", None, "Bounded static browser assets changed without requiring a Node project manifest.", static_assets[:50])]
    return [passed("Executable Classification", None, "All changed executable code is covered by detected technology adapters.")]


def gate_protected_resources(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    protected_patterns = ctx.config.get("repository", {}).get("protected_paths", [])
    changed = [path for path in ctx.changed_files if match_any(path, protected_patterns)]
    authorized_overlay = [path for path in changed if baseline_authorized_overlay_path(ctx, path)]
    inherited_protected = [
        path
        for path in changed
        if baseline_allows(ctx, "historical_protected_resources")
        and path not in set(authorized_overlay)
        and baseline_inherited_path(ctx, path, "protected_resource")
    ]
    inherited_codeowners = [
        path
        for path in changed
        if path in CODEOWNERS_PATHS
        and path not in set(inherited_protected)
        and baseline_inherited_path(ctx, path, "codeowners")
    ]
    changed_for_standard_policy = [
        path
        for path in changed
        if path not in set(authorized_overlay + inherited_protected + inherited_codeowners)
    ]
    codeowners_changed = any(path in CODEOWNERS_PATHS for path in ctx.changed_files)
    codeowners_changed_for_standard_policy = any(path in CODEOWNERS_PATHS for path in changed_for_standard_policy)
    codeowners = load_base_codeowners(ctx.repo, git_context)
    if codeowners_changed and authorized_overlay and not codeowners_changed_for_standard_policy:
        return [warning("Protected Resources", None, "Authorized governance overlay passed exact source+overlay validation; required status checks and Review Policy gate remain mandatory.", authorized_overlay[:30])]
    if codeowners_changed_for_standard_policy and not codeowners and is_codeowners_bootstrap_pr(ctx):
        return [warning("Protected Resources", None, "Base CODEOWNERS bootstrap detected; required status checks and Review Policy gate must enforce governance.", sorted(ctx.changed_files))]
    if codeowners_changed_for_standard_policy:
        maintenance = evaluate_codeowners_maintenance(ctx, git_context, protected_patterns)
        if maintenance.allowed:
            return [warning("Protected Resources", None, "Controlled CODEOWNERS maintenance added protected-path coverage; required status checks and Review Policy gate remain mandatory.", maintenance.details[:30])]
        return [failed("Protected Resources", None, "CODEOWNERS changes are not allowed in PR QA guarded changes except controlled additive protected-path coverage.", maintenance.details[:30], score=20)]
    if not changed_for_standard_policy:
        if authorized_overlay:
            return [warning("Protected Resources", None, "Authorized governance overlay passed exact source+overlay validation; required status checks and Review Policy gate remain mandatory.", authorized_overlay[:30])]
        if inherited_protected:
            return [warning("Protected Resources", None, "Inherited baseline protected resources match the exact approved source; future changes require normal CODEOWNERS coverage.", inherited_protected[:30])]
        return [passed("Protected Resources", None, "No protected resources changed.")]
    if not codeowners:
        if is_canonical_fresh_pr_qa_onboarding(ctx, git_context, changed_for_standard_policy):
            return [warning("Protected Resources", None, "Canonical fresh PR-QA onboarding matched the authoritative central templates while base CODEOWNERS is absent. Required status checks and Review Policy remain mandatory. Future protected-resource modifications remain subject to normal CODEOWNERS enforcement.", sorted(ctx.changed_files))]
        return [failed("Protected Resources", None, "Protected resources changed but base-branch CODEOWNERS was not found.", changed_for_standard_policy[:30], score=14)]
    uncovered = [path for path in changed_for_standard_policy if not codeowners_covers(path, codeowners)]
    if uncovered:
        return [failed("Protected Resources", None, "Protected resources changed without base-branch CODEOWNERS coverage.", uncovered[:30], score=14)]
    details = (
        changed_for_standard_policy[:30]
        + [f"{path}: INHERITED_BASELINE protected_resource" for path in inherited_protected[:30]]
        + [f"{path}: INHERITED_BASELINE codeowners" for path in inherited_codeowners[:30]]
        + [f"{path}: AUTHORIZED_OVERLAY" for path in authorized_overlay[:30]]
    )
    return [warning("Protected Resources", None, "Protected resources changed; required status checks and Review Policy gate must enforce governance.", details)]


def is_codeowners_bootstrap_pr(ctx: PRContext) -> bool:
    allowed = {"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS", ".github/workflows/pr-qa.yml"}
    changed = set(ctx.changed_files)
    return bool(changed) and changed <= allowed and any(path in changed for path in CODEOWNERS_PATHS)


def is_canonical_fresh_pr_qa_onboarding(ctx: PRContext, git_context: dict[str, Any], protected_changed: list[str]) -> bool:
    allowed = {".github/workflows/pr-qa.yml", ".github/pull_request_template.md"}
    changed = set(ctx.changed_files)
    if not changed or not changed <= allowed or ".github/workflows/pr-qa.yml" not in changed:
        return False
    if set(protected_changed) != changed:
        return False
    base_sha = str(git_context.get("base_sha") or "")
    if not base_sha or not commit_exists(ctx.repo, base_sha):
        return False
    for rel in CODEOWNERS_PATHS:
        if tree_path_state(ctx.repo, base_sha, rel) != "ABSENT":
            return False
    expected = {
        ".github/workflows/pr-qa.yml": CANONICAL_CALLER_TEMPLATE_PATH,
        ".github/pull_request_template.md": CANONICAL_PR_TEMPLATE_PATH,
    }
    for rel in changed:
        if tree_path_state(ctx.repo, base_sha, rel) != "ABSENT":
            return False
        if tree_path_state(ctx.repo, "HEAD", rel) != "PRESENT":
            return False
        template_path = expected[rel]
        if not template_path.is_file():
            return False
        if read_tree_file(ctx.repo, "HEAD", rel) != read_text(template_path):
            return False
    return True


@dataclass(frozen=True)
class CodeownersEntry:
    line_number: int
    pattern: str
    owners: tuple[str, ...]

    def display(self) -> str:
        return f"{self.pattern} {' '.join(self.owners)}"


@dataclass(frozen=True)
class CodeownersMaintenanceResult:
    allowed: bool
    details: list[str]


def evaluate_codeowners_maintenance(
    ctx: PRContext,
    git_context: dict[str, Any],
    protected_patterns: list[str],
) -> CodeownersMaintenanceResult:
    changed_codeowners = [path for path in ctx.changed_files if path in CODEOWNERS_PATHS]
    if len(ctx.changed_files) != 1 or len(changed_codeowners) != 1:
        return CodeownersMaintenanceResult(False, ["CODEOWNERS maintenance PRs may change only one CODEOWNERS file."])
    rel = changed_codeowners[0]
    base_text = read_base_file(ctx.repo, git_context, rel)
    if not base_text:
        return CodeownersMaintenanceResult(False, [f"{rel}: base CODEOWNERS file is absent; use the bootstrap path only before CODEOWNERS exists."])
    head_path = ctx.repo / rel
    if not head_path.is_file():
        return CodeownersMaintenanceResult(False, [f"{rel}: CODEOWNERS deletion is not controlled maintenance."])
    head_text = read_text(head_path)
    base_entries, base_errors = parse_codeowners_entries(base_text)
    head_entries, head_errors = parse_codeowners_entries(head_text)
    if base_errors or head_errors:
        return CodeownersMaintenanceResult(False, [f"{rel}: {error}" for error in (base_errors + head_errors)])
    if len(head_entries) <= len(base_entries):
        return CodeownersMaintenanceResult(False, [f"{rel}: controlled maintenance must append protected-path coverage without removing existing rules."])
    for index, base_entry in enumerate(base_entries):
        if index >= len(head_entries) or head_entries[index] != base_entry:
            return CodeownersMaintenanceResult(False, [f"{rel}: existing CODEOWNERS rules must remain unchanged and in their original order."])
    base_owners = {owner for entry in base_entries for owner in entry.owners}
    if not base_owners:
        return CodeownersMaintenanceResult(False, [f"{rel}: base CODEOWNERS has no verified owners to reuse."])
    added = head_entries[len(base_entries) :]
    details: list[str] = []
    for entry in added:
        owner_set = set(entry.owners)
        if not owner_set <= base_owners:
            unknown = sorted(owner_set - base_owners)
            return CodeownersMaintenanceResult(False, [f"{rel}:{entry.line_number}: new owners are not already present in base CODEOWNERS: {', '.join(unknown)}"])
        if not codeowners_pattern_targets_protected_path(entry.pattern, protected_patterns):
            return CodeownersMaintenanceResult(False, [f"{rel}:{entry.line_number}: added rule does not target a configured protected path: {entry.pattern}"])
        details.append(f"{rel}:{entry.line_number}: ADDED {entry.display()}")
    return CodeownersMaintenanceResult(True, details)


def parse_codeowners_entries(text: str) -> tuple[list[CodeownersEntry], list[str]]:
    entries: list[CodeownersEntry] = []
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            errors.append(f"line {line_number} has a CODEOWNERS pattern without an owner.")
            continue
        entries.append(CodeownersEntry(line_number=line_number, pattern=parts[0], owners=tuple(parts[1:])))
    return entries, errors


def normalize_codeowners_pattern(pattern: str) -> str:
    normalized = pattern.lstrip("/")
    if normalized.endswith("/"):
        normalized += "**"
    return normalized


def pattern_probe_path(pattern: str) -> str:
    normalized = normalize_codeowners_pattern(pattern)
    wildcard = re.search(r"[*?\[]", normalized)
    if not wildcard:
        return normalized
    prefix = normalized[: wildcard.start()]
    if prefix.endswith("/"):
        return prefix + "__pr_qa_probe__"
    return prefix + "__pr_qa_probe__"


def codeowners_pattern_targets_protected_path(pattern: str, protected_patterns: list[str]) -> bool:
    normalized_protected = [normalize_codeowners_pattern(item) for item in protected_patterns]
    for protected_pattern in normalized_protected:
        if fnmatch.fnmatch(pattern_probe_path(pattern), protected_pattern):
            return True
        if codeowners_covers(pattern_probe_path(protected_pattern), [pattern]):
            return True
    return False


def load_base_codeowners(repo: Path, git_context: dict[str, Any]) -> list[str]:
    for rel in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]:
        text = read_base_file(repo, git_context, rel)
        if text:
            patterns = []
            for line in text.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    patterns.append(stripped.split()[0])
            return patterns
    return []


def codeowners_covers(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        normalized = pattern.lstrip("/")
        if normalized.endswith("/"):
            normalized += "**"
        candidates = [normalized, f"**/{normalized}"] if "/" not in normalized else [normalized]
        if any(fnmatch.fnmatch(path, candidate) for candidate in candidates):
            return True
    return False


def gate_deployment_safety(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    deployment_patterns = [
        ".github/workflows/**",
        "deploy/**",
        "deployment/**",
        "scripts/deploy*",
        "Dockerfile",
        "Dockerfile.*",
        "docker-compose*.yml",
        "docker-compose*.yaml",
        "terraform/**",
        "infra/**",
        "k8s/**",
        "kubernetes/**",
        "nginx/**",
        "apache/**",
        "**/*.service",
        "**/*.env",
        ".env.example",
    ]
    changed = [path for path in ctx.changed_files if match_any(path, deployment_patterns)]
    if is_canonical_staging_to_main_promotion(ctx):
        changed, equivalent = final_tree_deployment_changes(ctx, changed)
        if equivalent and not changed:
            return [
                passed(
                    "Deployment Risk",
                    None,
                    "Canonical staging-to-main promotion has no deployment-sensitive final-tree changes.",
                    equivalent[:40],
                )
            ]
    if not changed:
        return [passed("Deployment Risk", None, "No deployment-sensitive files changed.")]
    if baseline_active(ctx):
        blocking: list[str] = []
        inherited: list[str] = []
        overlay: list[str] = []
        for path in changed:
            text = read_text(ctx.repo / path)
            lower = (path + "\n" + text).lower()
            risky_tokens = [token for token in ["production", "prod", "ssh", "rsync", "sudo", "kubectl apply", "terraform apply", "tofu apply"] if token in lower]
            if baseline_authorized_overlay_path(ctx, path):
                overlay.append(f"{path}: AUTHORIZED_OVERLAY")
            elif baseline_inherited_path(ctx, path, "deployment_sensitive"):
                workflow_note = " inherited workflow introduction" if path.startswith(".github/workflows/") and path != ".github/workflows/pr-qa.yml" else ""
                inherited.append(f"{path}: INHERITED_BASELINE deployment-sensitive content{workflow_note}" + (f" tokens={','.join(risky_tokens[:8])}" if risky_tokens else ""))
            elif path.startswith(".github/workflows/") and path != ".github/workflows/pr-qa.yml":
                blocking.append(f"{path}: workflow introduction is not part of the authorized governance overlay or approved source.")
                blocking.extend(f"{path}: `{token}`" for token in risky_tokens[:8])
            else:
                blocking.append(f"{path}: new or modified deployment-sensitive content.")
                blocking.extend(f"{path}: `{token}`" for token in risky_tokens[:8])
        if blocking:
            return [failed("Deployment Risk", None, "High-risk deployment change detected. Risk: CRITICAL.", blocking[:60], score=20)]
        return [
            warning(
                "Deployment Risk",
                None,
                "Inherited baseline deployment-sensitive content requires human review; no production deployment is authorized by this QA result.",
                (inherited + overlay)[:60],
            )
        ]
    safe_workflow_details, safe_workflow_paths = classify_safe_deployment_workflows(ctx, changed)
    if safe_workflow_paths:
        changed = [path for path in changed if path not in safe_workflow_paths]
        if not changed:
            return [
                warning(
                    "Deployment Risk",
                    None,
                    "Controlled deployment-sensitive workflow shape detected; human review remains required.",
                    safe_workflow_details[:60],
                )
            ]
    framework_approved = [path for path in changed if is_approved_deployment_sensitive_asset(ctx, path)]
    if framework_approved and len(framework_approved) == len(changed):
        dangerous_tokens = []
        for path in framework_approved:
            text = read_text(ctx.repo / path)
            lower = (path + "\n" + text).lower()
            for token in ["ssh", "rsync", "sudo", "kubectl apply", "terraform apply", "tofu apply"]:
                if token in lower:
                    dangerous_tokens.append(f"{path}: `{token}`")
        if not dangerous_tokens:
            return [
                warning(
                    "Deployment Risk",
                    None,
                    "Approved central governance workflow/template changes detected; required status checks and Review Policy gate remain mandatory.",
                    framework_approved[:40],
                )
            ]
    unsafe_workflows = unsafe_deployment_workflow_details(ctx, changed)
    if unsafe_workflows:
        return [
            failed(
                "Deployment Risk",
                None,
                "Deployment workflow is structurally unsafe or missing required controlled-release safeguards.",
                safe_workflow_details[:20] + unsafe_workflows[:60],
                score=20,
            )
        ]
    details = []
    score = 0
    risky_tokens = []
    for path in changed:
        text = read_text(ctx.repo / path)
        lower = (path + "\n" + text).lower()
        item_score = 5
        for token, value in {"production": 10, "prod": 8, "ssh": 12, "rsync": 12, "sudo": 12, "kubectl apply": 10, "terraform apply": 15, "tofu apply": 15}.items():
            if token in lower:
                item_score += value
                risky_tokens.append(f"{path}: `{token}`")
        if path.startswith(".github/workflows"):
            item_score += 8
        score += item_score
        details.append(f"{path}: +{item_score}")
    level = risk_class(min(score, 100))
    if risky_tokens and level in {"HIGH", "CRITICAL"}:
        return [failed("Deployment Risk", None, f"High-risk deployment change detected. Risk: {level}.", safe_workflow_details[:20] + details[:30] + risky_tokens[:20], score=20)]
    return [warning("Deployment Risk", None, f"Deployment-sensitive changes detected. Risk: {level}.", safe_workflow_details[:20] + details[:40])]


def classify_safe_deployment_workflows(ctx: PRContext, changed: list[str]) -> tuple[list[str], set[str]]:
    details: list[str] = []
    safe_paths: set[str] = set()
    for path in changed:
        if not path.startswith(".github/workflows/"):
            continue
        if is_approved_deployment_sensitive_asset(ctx, path):
            continue
        workflow_path = ctx.repo / path
        if not workflow_path.is_file():
            continue
        text = read_text(workflow_path)
        gate_d = controlled_gate_d_workflow_details(path, text)
        if gate_d:
            details.extend(gate_d)
            safe_paths.add(path)
            continue
        staging = staging_only_workflow_details(path, text)
        if staging:
            details.extend(staging)
            safe_paths.add(path)
    return details, safe_paths


APPROVED_RUNTIME_CERTIFIER_ACTIONS = {
    "Synergie-ITCI/.github/actions/runtime-certifier@runtime-certifier-action-v1",
    "Synergie-ITCI/.github/actions/runtime-certifier@runtime-certifier-action-v1.1",
}
RUNTIME_CERTIFIER_REQUIRED_INPUTS = {
    "instance-id",
    "app-path",
    "app-user",
    "validation-url",
    "deploy-ref",
    "rollback-ref",
    "runtime-version",
}


def workflow_has_runtime_certifier_guard(parsed: dict[str, Any], text: str) -> bool:
    jobs = parsed.get("jobs", {})
    if not isinstance(jobs, dict):
        return False

    saw_valid_certifier = False
    saw_remote_deploy = False

    for job in jobs.values():
        if not isinstance(job, dict):
            continue

        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        available_certifiers: list[tuple[int, str]] = []

        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            uses = str(step.get("uses", "") or "").strip()

            if uses in APPROVED_RUNTIME_CERTIFIER_ACTIONS:
                step_id = str(step.get("id", "") or "").strip()
                with_values = step.get("with", {})
                supplied_inputs = (
                    {str(key) for key in with_values}
                    if isinstance(with_values, dict)
                    else set()
                )

                if (
                    step_id
                    and RUNTIME_CERTIFIER_REQUIRED_INPUTS <= supplied_inputs
                ):
                    available_certifiers.append((index, step_id))
                    saw_valid_certifier = True

            run_text = str(step.get("run", "") or "")
            if not workflow_contains_remote_deploy(run_text):
                continue

            saw_remote_deploy = True
            condition = str(step.get("if", "") or "")

            guarded = False
            for cert_index, cert_id in available_certifiers:
                if cert_index >= index:
                    continue

                pattern = (
                    rf"steps\.{re.escape(cert_id)}\.outputs\."
                    rf"deployment-required\s*==\s*['\"]true['\"]"
                )
                if re.search(pattern, condition):
                    guarded = True
                    break

            if not guarded:
                return False

    return saw_valid_certifier and saw_remote_deploy


def controlled_gate_d_workflow_details(path: str, text: str) -> list[str]:
    parsed = parse_workflow_yaml(text)
    checks = {
        "manual_only": workflow_dispatch_only(parsed, text),
        "actor_restricted": workflow_has_actor_restriction(text),
        "deploy_ref_validated": workflow_has_exact_deploy_ref_validation(parsed, text),
        "rollback_ref_validated": workflow_has_rollback_ref_validation(parsed, text),
        "approval_evidence": workflow_has_approval_evidence(parsed, text),
        "oidc": workflow_uses_oidc(parsed, text),
        "controlled_remote": workflow_uses_controlled_remote_execution(text),
        "runtime_certifier": workflow_has_runtime_certifier_guard(parsed, text),
        "no_static_credentials": not workflow_has_embedded_or_static_deployment_credentials(text),
        "no_main_push": not workflow_pushes_to_main_or_master(parsed, text),
    }
    if not all(checks.values()):
        return []
    return [
        f"{path}: CONTROLLED_PRODUCTION_GATE_D manual workflow_dispatch, exact deploy_ref, rollback_ref, actor restriction, OIDC, immutable Runtime Certifier, guarded deployment, and controlled remote execution verified."
    ]


def staging_only_workflow_details(path: str, text: str) -> list[str]:
    parsed = parse_workflow_yaml(text)
    lower = text.lower()
    checks = {
        "push_staging_only": workflow_pushes_only_to_staging(parsed, text),
        "staging_scoped": "staging" in lower or "uat" in lower,
        "no_production_target": not re.search(r"\bprod(?:uction)?\b|PROD_|production", text),
        "no_main_push": not workflow_pushes_to_main_or_master(parsed, text),
        "no_production_branch_logic": not re.search(r"refs/heads/(main|master)|BRANCH=main|branch:\s*main", text),
        "no_static_production_key": not re.search(r"PROD_[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|HOST|USER)", text),
    }
    if not all(checks.values()):
        return []
    return [f"{path}: STAGING_ONLY_DEPLOYMENT trigger and destination are staging-scoped; legacy SSH staging transport remains review-visible."]


def unsafe_deployment_workflow_details(ctx: PRContext, changed: list[str]) -> list[str]:
    details: list[str] = []
    for path in changed:
        if not path.startswith(".github/workflows/"):
            continue
        workflow_path = ctx.repo / path
        if not workflow_path.is_file():
            continue
        text = read_text(workflow_path)
        parsed = parse_workflow_yaml(text)
        if workflow_has_production_intent(parsed, text):
            details.append(f"{path}: production/live deployment-sensitive workflow does not match the controlled Gate D safe shape.")
        elif workflow_pushes_to_main_or_master(parsed, text) and workflow_contains_remote_deploy(text):
            details.append(f"{path}: push to main/master can execute remote deployment commands.")
        elif workflow_has_embedded_or_static_deployment_credentials(text):
            details.append(f"{path}: static deployment credential reference detected.")
    return details


def workflow_has_production_intent(parsed: dict[str, Any], text: str) -> bool:
    lower = text.lower()
    return bool(
        re.search(r"\bprod(?:uction)?\b", lower)
        or re.search(r"PROD_[A-Z0-9_]+", text)
        or workflow_pushes_to_main_or_master(parsed, text)
        or "refs/heads/main" in text
        or "refs/heads/master" in text
    )


def workflow_contains_remote_deploy(text: str) -> bool:
    return bool(re.search(r"\bssh\b|\brsync\b|\baws\s+ssm\s+send-command\b|kubectl apply|terraform apply|tofu apply", text, re.IGNORECASE))


def parse_workflow_yaml(text: str) -> dict[str, Any]:
    parsed = parse_yaml_or_json(text)
    return parsed if isinstance(parsed, dict) else {}


def workflow_on_section(parsed: dict[str, Any]) -> Any:
    return parsed.get("on", parsed.get(True, {}))


def workflow_dispatch_only(parsed: dict[str, Any], text: str) -> bool:
    on_section = workflow_on_section(parsed)
    if isinstance(on_section, dict):
        keys = {str(key) for key in on_section}
        if keys != {"workflow_dispatch"}:
            return False
    elif isinstance(on_section, list):
        if {str(item) for item in on_section} != {"workflow_dispatch"}:
            return False
    elif str(on_section) != "workflow_dispatch":
        return False
    return "push:" not in text and not workflow_pushes_to_main_or_master(parsed, text)


def workflow_push_branches(parsed: dict[str, Any], text: str) -> set[str]:
    branches: set[str] = set()
    on_section = workflow_on_section(parsed)
    push = on_section.get("push") if isinstance(on_section, dict) else None
    if isinstance(push, dict):
        raw = push.get("branches", [])
        if isinstance(raw, str):
            branches.add(raw)
        elif isinstance(raw, list):
            branches.update(str(item) for item in raw)
    if re.search(r"(?m)^\s*push\s*:", text):
        push_block = re.search(r"(?ms)^\s*push\s*:(.*?)(?:^\S|\Z)", text)
        block = push_block.group(1) if push_block else text
        branches.update(match.group(1) for match in re.finditer(r"(?m)^\s*-\s*([A-Za-z0-9_./-]+)\s*$", block))
        inline = re.search(r"branches\s*:\s*\[([^\]]+)\]", block)
        if inline:
            branches.update(item.strip().strip("'\"") for item in inline.group(1).split(",") if item.strip())
    return {branch for branch in branches if branch}


def workflow_pushes_to_main_or_master(parsed: dict[str, Any], text: str) -> bool:
    branches = workflow_push_branches(parsed, text)
    return bool({"main", "master", "refs/heads/main", "refs/heads/master"} & branches)


def workflow_pushes_only_to_staging(parsed: dict[str, Any], text: str) -> bool:
    on_section = workflow_on_section(parsed)
    has_push = (isinstance(on_section, dict) and "push" in {str(key) for key in on_section}) or bool(re.search(r"(?m)^\s*push\s*:", text))
    if not has_push:
        return False
    branches = workflow_push_branches(parsed, text)
    return branches == {"staging"}


def workflow_has_actor_restriction(text: str) -> bool:
    actor_reference = r"(?:GITHUB_ACTOR|github\.actor)"
    return bool(
        re.search(actor_reference + r".{0,120}(?:==|=|!=|contains|test)", text, re.DOTALL)
        or re.search(r"(?:==|=|!=|contains|test).{0,120}" + actor_reference, text, re.DOTALL)
    )


def workflow_inputs(parsed: dict[str, Any]) -> dict[str, Any]:
    on_section = workflow_on_section(parsed)
    dispatch = on_section.get("workflow_dispatch") if isinstance(on_section, dict) else {}
    if isinstance(dispatch, dict) and isinstance(dispatch.get("inputs"), dict):
        return dispatch.get("inputs", {})
    return {}


def workflow_has_exact_deploy_ref_validation(parsed: dict[str, Any], text: str) -> bool:
    inputs = workflow_inputs(parsed)
    return (
        "deploy_ref" in inputs
        and "DEPLOY_REF" in text
        and workflow_contains_sha40_validation(text)
        and "git rev-parse HEAD" in text
        and bool(re.search(r"DEPLOY_REF.{0,80}(MAIN_SHA|HEAD)|(?:MAIN_SHA|HEAD).{0,80}DEPLOY_REF", text, re.DOTALL))
    )


def workflow_has_rollback_ref_validation(parsed: dict[str, Any], text: str) -> bool:
    inputs = workflow_inputs(parsed)
    return (
        "rollback_ref" in inputs
        and "ROLLBACK_REF" in text
        and workflow_contains_sha40_validation(text)
        and bool(re.search(r"ROLLBACK_REF.{0,120}(CURRENT_SHA|reset --hard)|(?:CURRENT_SHA|reset --hard).{0,120}ROLLBACK_REF", text, re.DOTALL))
    )


def workflow_contains_sha40_validation(text: str) -> bool:
    return bool(re.search(r"\[0-9a-f\]\{40\}", text) or re.search(r"\[0-9a-f\]\{40\}", text.replace("\\{", "{").replace("\\}", "}")))


def workflow_has_approval_evidence(parsed: dict[str, Any], text: str) -> bool:
    inputs = workflow_inputs(parsed)
    return "approval_reference" in inputs and bool(re.search(r"APPROVAL|approval_reference", text)) and re.search(r"test\s+-n\s+.*APPROVAL", text) is not None


def workflow_uses_oidc(parsed: dict[str, Any], text: str) -> bool:
    permissions = parsed.get("permissions", {}) if isinstance(parsed.get("permissions"), dict) else {}
    id_token = str(permissions.get("id-token", permissions.get("id_token", ""))).lower()
    return id_token == "write" and "aws-actions/configure-aws-credentials" in text and "role-to-assume" in text


def workflow_uses_controlled_remote_execution(text: str) -> bool:
    return bool(re.search(r"\baws\s+ssm\s+send-command\b|AWS-RunShellScript|ssm:SendCommand", text))


def workflow_has_embedded_or_static_deployment_credentials(text: str) -> bool:
    patterns = [
        r"AWS_ACCESS_KEY_ID",
        r"AWS_SECRET_ACCESS_KEY",
        r"AWS_SESSION_TOKEN",
        r"PROD_[A-Z0-9_]*(PRIVATE_KEY|TOKEN|SECRET|PASSWORD)",
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        r"gh[pousr]_[A-Za-z0-9_]{20,}",
        r"github_pat_[A-Za-z0-9_]+",
        r"AKIA[0-9A-Z]{16}",
    ]
    return any(re.search(pattern, text) for pattern in patterns)


def is_canonical_staging_to_main_promotion(ctx: PRContext) -> bool:
    return (ctx.base_ref or "") == "main" and (ctx.head_ref or "") == "staging"


def final_tree_deployment_changes(ctx: PRContext, paths: list[str]) -> tuple[list[str], list[str]]:
    pull_request = ctx.event.get("pull_request", {}) or {}
    base_sha = resolve_current_canonical_promotion_base_sha(ctx.repo, ctx.base_ref or "", ctx.head_ref or "")
    if not base_sha:
        base_sha = pull_request.get("base", {}).get("sha") or ""
    if not base_sha or not is_git_repo(ctx.repo) or not commit_exists(ctx.repo, base_sha):
        return paths, []

    changed: list[str] = []
    equivalent: list[str] = []
    for path in paths:
        base_exists = tree_entry_exists(ctx.repo, base_sha, path)
        head_exists = tree_entry_exists(ctx.repo, "HEAD", path)
        if base_exists and head_exists and tree_file_sha256(ctx.repo, base_sha, path) == tree_file_sha256(ctx.repo, "HEAD", path):
            equivalent.append(f"{path}: FINAL_TREE_EQUIVALENT")
        else:
            changed.append(path)
    return changed, equivalent


def gate_database_safety(ctx: PRContext) -> list[CheckResult]:
    migration_patterns = ["**/migrations/**", "**/migration/**", "database/**", "db/migrate/**", "**/*.sql"]
    migrations = [path for path in ctx.changed_files if match_any(path, migration_patterns)]
    if not migrations:
        return [passed("Migration Risk", None, "No database migration files changed.")]
    if baseline_allows(ctx, "historical_migration_count"):
        critical, high, medium = classify_migration_risk(ctx, migrations)
        if critical:
            return [failed("Migration Risk", None, "CRITICAL migration risk: destructive database operations detected.", critical[:30], score=30)]
        rollback_destructive = baseline_rollback_destructive_migrations(ctx, migrations)
        details = [
            f"migration_count={len(migrations)}",
            "baseline classification only; fresh migration execution remains required in application QA.",
            "forward-path destructive migration detection ran; rollback/down-method drops remain production DB review evidence.",
        ]
        if rollback_destructive:
            details.append(f"rollback_destructive_count={len(rollback_destructive)}")
        details.extend((high or medium or migrations)[:30])
        return [warning("Migration Risk", None, "Historical baseline migration volume classified for one-time review; migration execution remains mandatory.", details)]
    critical, high, medium = classify_migration_risk(ctx, migrations)
    if critical:
        return [failed("Migration Risk", None, "CRITICAL migration risk: destructive database operations detected.", critical[:30], score=30)]
    if high:
        return [warning("Migration Risk", None, "HIGH migration risk: schema changes may be destructive or irreversible.", high[:30])]
    if medium:
        return [warning("Migration Risk", None, "MEDIUM migration risk: additive schema changes detected.", medium[:30])]
    return [warning("Migration Risk", None, "LOW migration risk: migration files changed without obvious destructive operations.", migrations[:30])]


def classify_migration_risk(ctx: PRContext, migrations: list[str]) -> tuple[list[str], list[str], list[str]]:
    critical = []
    high = []
    medium = []
    for rel in migrations:
        text = read_text(ctx.repo / rel)
        risk_text = migration_risk_text(ctx, text)
        upper = risk_text.upper()
        collapsed = re.sub(r"[^A-Z]+", "", upper)
        if any(token in collapsed for token in ["DROPTABLE", "DROPDATABASE", "DROPSCHEMA", "TRUNCATE", "DELETEFROM"]) or re.search(r"drop(Column|IfExists|Table|Database|Schema)", risk_text):
            critical.append(rel)
        elif re.search(r"\bDROP\s+COLUMN\b|\bRENAME\s+COLUMN\b|\bALTER\s+TABLE\b|dropColumn|renameColumn", risk_text, re.IGNORECASE):
            high.append(rel)
        elif re.search(r"\bCREATE\s+TABLE\b|\bADD\s+COLUMN\b|\bCREATE\s+INDEX\b|createTable|addColumn", risk_text, re.IGNORECASE):
            medium.append(rel)
    return critical, high, medium


def migration_risk_text(ctx: PRContext, text: str) -> str:
    if baseline_allows(ctx, "historical_migration_count"):
        parts = re.split(r"(?i)\bfunction\s+down\s*\(", text, maxsplit=1)
        return parts[0]
    up_match = re.search(r"(?i)\bfunction\s+up\s*\(", text)
    if not up_match:
        return text
    down_match = re.search(r"(?i)\bfunction\s+down\s*\(", text[up_match.start():])
    if down_match:
        return text[up_match.start():up_match.start() + down_match.start()]
    return text[up_match.start():]


def baseline_rollback_destructive_migrations(ctx: PRContext, migrations: list[str]) -> list[str]:
    risky: list[str] = []
    for rel in migrations:
        text = read_text(ctx.repo / rel)
        parts = re.split(r"(?i)\bfunction\s+down\s*\(", text, maxsplit=1)
        if len(parts) < 2:
            continue
        down_text = parts[1]
        collapsed = re.sub(r"[^A-Z]+", "", down_text.upper())
        if any(token in collapsed for token in ["DROPTABLE", "DROPDATABASE", "DROPSCHEMA", "TRUNCATE", "DELETEFROM"]) or re.search(r"drop(Column|IfExists|Table|Database|Schema)", down_text):
            risky.append(rel)
    return risky


def gate_documentation(ctx: PRContext) -> list[CheckResult]:
    docs_changed = any(path.lower().endswith((".md", ".rst")) or path.startswith("docs/") for path in ctx.changed_files)
    api_patterns = ["routes/**", "**/controllers/**", "**/api/**", "openapi.*", "swagger.*", "**/*.proto"]
    config_patterns = [".env.example", "config/**", "**/config/**", "*.env.example", "docker-compose*.yml", "Dockerfile"]
    api_changed = [path for path in ctx.changed_files if match_any(path, api_patterns)]
    config_changed = [path for path in ctx.changed_files if match_any(path, config_patterns)]
    env_added = grep_text_files(ctx.repo, ctx.changed_files, r"^[A-Z][A-Z0-9_]{2,}\s*=")
    if (api_changed or config_changed or env_added) and not docs_changed:
        details = api_changed[:10] + config_changed[:10] + env_added[:10]
        return [warning("Documentation", None, "API, configuration, or environment-variable changes were made without documentation updates.", details)]
    return [passed("Documentation", None, "Documentation evidence is present or no documentation-sensitive changes were detected.")]


def gate_advisory_review(ctx: PRContext) -> list[CheckResult]:
    observations: list[str] = []
    changed_code = [path for path in ctx.changed_files if Path(path).suffix in set(ctx.policy.get("executable_extensions", []))]
    if ctx.additions > 800:
        observations.append("Large PR: consider splitting follow-up refactors or tests for easier human review.")
    observations.extend(detect_duplicate_lines(ctx, changed_code)[:5])
    debug_hits = grep_text_files(ctx.repo, changed_code, r"\b(console\.log|var_dump|dd\(|print_r\(|debugger;)\b")
    if debug_hits:
        observations.append("Debugging statements detected: " + ", ".join(debug_hits[:10]))
    if observations:
        return [warning("Architecture", None, f"{len(observations)} advisory observation(s).", observations)]
    return [passed("Architecture", None, "No advisory maintainability observations detected.")]


def detect_duplicate_lines(ctx: PRContext, paths: list[str]) -> list[str]:
    counts: dict[str, int] = {}
    for rel in paths:
        path = ctx.repo / rel
        if not path.is_file() or is_binary_file(path):
            continue
        for line in read_text(path).splitlines():
            normalized = line.strip()
            if len(normalized) >= 40 and not normalized.startswith(("//", "#", "*")):
                counts[normalized] = counts.get(normalized, 0) + 1
    return sorted(f"Repeated logic-like line appears {count} times: `{redact(line[:120])}`" for line, count in counts.items() if count >= 4)[:10]


def is_generated_npm_lockfile(ctx: PRContext, rel: str) -> bool:
    path = Path(rel)
    if path.name not in {"package-lock.json", "npm-shrinkwrap.json"}:
        return False
    lockfile = ctx.repo / rel
    package_json = lockfile.parent / "package.json"
    if not lockfile.is_file() or not package_json.is_file():
        return False
    try:
        payload = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    version = payload.get("lockfileVersion")
    return isinstance(version, int) and not isinstance(version, bool) and version in {1, 2, 3}


def risk_size_accounting(ctx: PRContext) -> dict[str, int]:
    cache = context_cache(ctx)
    if "risk_size_accounting" in cache:
        return dict(cache["risk_size_accounting"])
    numstat = dict(cache.get("numstat") or {})
    excluded_additions = 0
    excluded_deletions = 0
    for rel in ctx.changed_files:
        if not is_generated_npm_lockfile(ctx, rel):
            continue
        additions, deletions = numstat.get(rel, (0, 0))
        excluded_additions += additions
        excluded_deletions += deletions
    accounting = {
        "raw_additions": ctx.additions,
        "raw_deletions": ctx.deletions,
        "generated_lockfile_additions_excluded": excluded_additions,
        "generated_lockfile_deletions_excluded": excluded_deletions,
        "effective_additions": max(ctx.additions - excluded_additions, 0),
        "effective_deletions": max(ctx.deletions - excluded_deletions, 0),
    }
    cache["risk_size_accounting"] = accounting
    return dict(accounting)


def promotion_direct_size_accounting(ctx: PRContext) -> dict[str, int] | None:
    if not long_lived_staging_to_main_promotion(ctx) or not is_git_repo(ctx.repo):
        return None
    cache = context_cache(ctx)
    if "promotion_direct_size_accounting" in cache:
        return dict(cache["promotion_direct_size_accounting"])
    pull_request = ctx.event.get("pull_request", {}) or {}
    base_sha = resolve_current_canonical_promotion_base_sha(ctx.repo, ctx.base_ref or "", ctx.head_ref or "")
    if not base_sha:
        base_sha = pull_request.get("base", {}).get("sha") or ""
    if not base_sha or not commit_exists(ctx.repo, base_sha):
        return None
    direct_commits = git_lines(ctx.repo, ["rev-list", "--first-parent", "--no-merges", f"{base_sha}..HEAD"])
    changed: set[str] = set()
    additions = 0
    deletions = 0
    direct_numstat: dict[str, tuple[int, int]] = {}
    for sha in direct_commits:
        parent = f"{sha}^"
        for line in git_lines(ctx.repo, ["diff", "--numstat", f"{parent}..{sha}"]):
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            rel = parts[2]
            try:
                add = int(parts[0]) if parts[0] != "-" else 0
                delete = int(parts[1]) if parts[1] != "-" else 0
            except ValueError:
                continue
            changed.add(rel)
            additions += add
            deletions += delete
            old_add, old_delete = direct_numstat.get(rel, (0, 0))
            direct_numstat[rel] = (old_add + add, old_delete + delete)
    excluded_additions = 0
    excluded_deletions = 0
    for rel, (add, delete) in direct_numstat.items():
        if is_generated_npm_lockfile(ctx, rel):
            excluded_additions += add
            excluded_deletions += delete
    accounting = {
        "changed_files": len(changed),
        "raw_additions": additions,
        "raw_deletions": deletions,
        "generated_lockfile_additions_excluded": excluded_additions,
        "generated_lockfile_deletions_excluded": excluded_deletions,
        "effective_additions": max(additions - excluded_additions, 0),
        "effective_deletions": max(deletions - excluded_deletions, 0),
    }
    cache["promotion_direct_size_accounting"] = accounting
    return dict(accounting)


def gate_risk(ctx: PRContext, existing_results: list[CheckResult]) -> list[CheckResult]:
    score = calculate_risk_score(ctx, existing_results)
    level = risk_class(score)
    size = risk_size_accounting(ctx)
    promotion_size = promotion_direct_size_accounting(ctx)
    details = [
        f"Changed files: {len(ctx.changed_files)}",
        f"RAW_ADDITIONS: {size['raw_additions']}",
        f"RAW_DELETIONS: {size['raw_deletions']}",
        f"GENERATED_LOCKFILE_ADDITIONS_EXCLUDED: {size['generated_lockfile_additions_excluded']}",
        f"GENERATED_LOCKFILE_DELETIONS_EXCLUDED: {size['generated_lockfile_deletions_excluded']}",
        f"EFFECTIVE_ADDITIONS: {size['effective_additions']}",
        f"EFFECTIVE_DELETIONS: {size['effective_deletions']}",
        f"Repository criticality: {ctx.config.get('repository', {}).get('criticality', 'medium')}",
    ]
    if promotion_size is not None:
        details.extend(
            [
                f"PROMOTION_DIRECT_CHANGED_FILES: {promotion_size['changed_files']}",
                f"PROMOTION_DIRECT_EFFECTIVE_ADDITIONS: {promotion_size['effective_additions']}",
            ]
        )
    threshold_findings = risk_threshold_findings(ctx)
    if threshold_findings:
        return [failed("Risk Engine", None, "PR exceeds central size thresholds.", details + threshold_findings, score=max(score, 85))]
    if baseline_active(ctx) and score >= ctx.threshold("risk_fail", 85):
        details.append("Baseline mode active: size/history risk remains visible for human review but is not a standalone blocker.")
        return [warning("Risk Engine", None, f"Overall baseline PR risk is {level}: {score} / 100.", details)]
    if score >= ctx.threshold("risk_fail", 85):
        return [failed("Risk Engine", None, f"Overall PR risk is {level}: {score} / 100.", details, score=score)]
    if score >= ctx.threshold("risk_warning", 40):
        return [warning("Risk Engine", None, f"Overall PR risk is {level}: {score} / 100.", details)]
    return [passed("Risk Engine", None, f"Overall PR risk is {level}: {score} / 100.", details)]


def risk_threshold_findings(ctx: PRContext) -> list[str]:
    findings: list[str] = []
    size = risk_size_accounting(ctx)
    promotion_size = promotion_direct_size_accounting(ctx)
    changed_file_count = len(ctx.changed_files)
    if promotion_size is not None:
        size = promotion_size
        changed_file_count = promotion_size["changed_files"]
    max_changed = ctx.threshold("max_changed_files", 200)
    if not baseline_allows(ctx, "changed_file_count") and changed_file_count > max_changed:
        findings.append(f"changed_files={changed_file_count} exceeds max_changed_files={max_changed}")
    max_additions = ctx.threshold("max_additions", 5000)
    if not baseline_allows(ctx, "diff_size") and size["effective_additions"] > max_additions:
        findings.append(f"effective_additions={size['effective_additions']} exceeds max_additions={max_additions}")
    return findings


def calculate_risk_score(ctx: PRContext, results: list[CheckResult]) -> int:
    score = {"low": 0, "medium": 5, "high": 12, "critical": 20}.get(str(ctx.config.get("repository", {}).get("criticality", "medium")).lower(), 5)
    size = risk_size_accounting(ctx)
    promotion_size = promotion_direct_size_accounting(ctx)
    changed_file_count = len(ctx.changed_files)
    if promotion_size is not None:
        size = promotion_size
        changed_file_count = promotion_size["changed_files"]
    if not baseline_allows(ctx, "changed_file_count") and changed_file_count > ctx.threshold("max_changed_files", 200):
        score += 15
    elif not baseline_allows(ctx, "changed_file_count") and changed_file_count > 50:
        score += 8
    if not baseline_allows(ctx, "diff_size") and size["effective_additions"] > ctx.threshold("max_additions", 5000):
        score += 15
    elif not baseline_allows(ctx, "diff_size") and size["effective_additions"] > 1000:
        score += 8
    if any(match_any(path, ctx.config.get("repository", {}).get("protected_paths", [])) for path in ctx.changed_files):
        score += 12
    for result in results:
        if result.status == FAIL:
            score += result.score or 8
        elif result.status == WARNING and result.gate in {"Deployment Risk", "Migration Risk", "Protected Resources", "Secrets"}:
            score += 5
    return min(score, 100)


def risk_class(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def gate_evidence(ctx: PRContext) -> list[CheckResult]:
    if "pull_request" not in ctx.event:
        return [skipped("Evidence", None, "Evidence validation runs only for pull_request events.")]
    missing = []
    for field in ctx.config.get("evidence", {}).get("required_fields", []):
        if not field_has_value(ctx.pr_body or "", field):
            missing.append(field)
    if ctx.config.get("evidence", {}).get("screenshots_required_for_ui_changes", True) and ui_changes_present(ctx):
        if not field_has_value(ctx.pr_body or "", "screenshots"):
            missing.append("screenshots")
    if missing:
        return [warning("Evidence", None, "Administrative PR template evidence is missing or still placeholder text; safety-critical evidence remains enforced by the relevant security, migration, production, rollback, and review gates.", missing)]
    return [passed("Evidence", None, "Mandatory PR template evidence is complete.")]


def gate_review_policy(ctx: PRContext, input_path: str = "") -> list[CheckResult]:
    if "pull_request" not in ctx.event:
        return [skipped("Review Policy", None, "Review policy validation runs only for pull_request events.")]

    policy = review_policy_config(ctx)
    owner_login = str(policy.get("owner_review_exception", {}).get("github_login", "SaurabhVermaIN"))
    pr_author = extract_pr_author(ctx.event)
    evidence = load_review_policy_evidence(ctx, input_path)
    gate_c = is_gate_c_staging_to_main(ctx)

    mergeable = evidence.get("mergeable")
    merge_conflict = evidence.get("merge_conflict")
    if merge_conflict is True or mergeable is False:
        return [failed("Review Policy", None, "Pull request has merge conflicts or is not mergeable.", [f"author={pr_author or 'unknown'}"], score=12)]

    if not gate_c:
        return [
            passed(
                "Review Policy",
                None,
                "Human review is not required for this branch transition; automated gates remain mandatory.",
                [f"source={ctx.head_ref or 'unknown'}", f"target={ctx.base_ref or 'unknown'}"],
            )
        ]

    if pr_author == owner_login:
        return [
            passed(
                "Review Policy",
                None,
                f"Verified GitHub identity {owner_login} is exempt from independent human review for Gate C; automated gates remain mandatory.",
            )
        ]

    if owner_latest_review_approved(evidence.get("reviews", []), owner_login):
        return [
            passed(
                "Review Policy",
                None,
                "Executive Release Authority review requirement is satisfied for Gate C.",
                [f"approver={owner_login}"],
            )
        ]

    if evidence.get("source") == "unavailable":
        return [
            failed(
                "Review Policy",
                None,
                "Independent review evidence is unavailable; protected-branch review policy cannot be verified.",
                evidence.get("errors", []),
                score=12,
            )
        ]

    return [
        failed(
            "Review Policy",
            None,
            "Executive Release Authority approval is required for Gate C staging to main.",
            [f"author={pr_author or 'unknown'}", f"required_approver={owner_login}"],
            score=12,
        )
    ]


def is_gate_c_staging_to_main(ctx: PRContext) -> bool:
    return (ctx.head_ref or "").lower() == "staging" and (ctx.base_ref or "").lower() == "main"


def review_policy_config(ctx: PRContext) -> dict[str, Any]:
    governance = ctx.policy.get("governance", {}) or {}
    return dict(governance.get("review_policy", {}) or {})


def load_review_policy_evidence(ctx: PRContext, input_path: str) -> dict[str, Any]:
    if input_path:
        path = Path(input_path)
        try:
            evidence = json.loads(path.read_text(encoding="utf-8"))
            return evidence if isinstance(evidence, dict) else {"source": "unavailable", "errors": [f"{path}: review policy input is not a JSON object."]}
        except (OSError, json.JSONDecodeError) as exc:
            return {"source": "unavailable", "errors": [f"{path}: {exc}"]}

    if "review_policy" in ctx.event and isinstance(ctx.event["review_policy"], dict):
        return dict(ctx.event["review_policy"])

    live = fetch_github_review_policy_evidence(ctx)
    if live:
        return live

    return {"source": "unavailable", "reviews": [], "errors": ["No review policy input file, event review_policy payload, or GitHub token-backed API evidence was available."]}


def fetch_github_review_policy_evidence(ctx: PRContext) -> dict[str, Any] | None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    pr_number = extract_pr_number(ctx.event)
    if not token or not repository or not pr_number:
        return None

    base_url = f"https://api.github.com/repos/{repository}/pulls/{pr_number}"
    errors: list[str] = []
    pr_payload = github_api_get(base_url, token, errors)
    reviews_payload = github_api_get(f"{base_url}/reviews", token, errors)
    if errors:
        return {"source": "unavailable", "reviews": [], "errors": errors}
    reviews = reviews_payload if isinstance(reviews_payload, list) else []
    mergeable = pr_payload.get("mergeable") if isinstance(pr_payload, dict) else None
    mergeable_state = pr_payload.get("mergeable_state") if isinstance(pr_payload, dict) else ""
    return {
        "source": "github_api",
        "mergeable": mergeable,
        "merge_conflict": mergeable is False or mergeable_state == "dirty",
        "reviews": reviews,
    }


def github_api_get(url: str, token: str, errors: list[str]) -> Any:
    return github_api_request("GET", url, token, errors)


def github_api_request(method: str, url: str, token: str, errors: list[str], payload: Any | None = None) -> Any:
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "synergie-pr-qa",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        errors.append(f"{url}: {exc}")
        return None


def emit_pr_failure_summary_cli(args: argparse.Namespace, policy: dict[str, Any], event: dict[str, Any] | None = None, report: dict[str, Any] | None = None) -> int:
    try:
        loaded_event = event if event is not None else load_event(args.event_path)
        loaded_report = report
        if loaded_report is None:
            report_path = Path(args.status_json_in or args.json_out)
            loaded_report = json.loads(report_path.read_text(encoding="utf-8"))
        summary = render_pr_failure_summary(loaded_report, loaded_event, policy)
        if summary:
            print(summary.rstrip())
            print(actions_error_annotation(summary))
            step_summary = os.environ.get("GITHUB_STEP_SUMMARY", "")
            if step_summary:
                with open(step_summary, "a", encoding="utf-8") as handle:
                    handle.write("\n" + summary.rstrip() + "\n")
    except Exception as exc:
        print(f"WARNING: PR failure summary was not emitted: {redact(str(exc))}", file=sys.stderr)
    return 0


def render_pr_failure_summary(report: dict[str, Any], event: dict[str, Any], policy: dict[str, Any]) -> str:
    status = build_pr_status_model(report, event, policy, {})
    if status["status"] != "BLOCKED" or not status.get("action_items"):
        return ""
    lines = ["PR QA BLOCKED"]
    for index, item in enumerate(status["action_items"], start=1):
        if len(status["action_items"]) > 1:
            lines.extend(["", f"Blocker {index}:"])
        lines.extend(["", "What failed:", item["what_failed"], "", "Why:", item["why"], "", "What to do:", item["what_to_do"]])
        if item.get("technical_details"):
            lines.extend(["", "Technical details:"])
            lines.extend(f"- {detail}" for detail in item["technical_details"])
    if status.get("additional_blockers"):
        lines.extend(["", f"Additional blockers: {status['additional_blockers']} more. Review the PR-QA technical details for the remaining blockers."])
    return "\n".join(lines).rstrip() + "\n"


def actions_error_annotation(summary: str) -> str:
    reason = ""
    lines = summary.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "Why:" and index + 1 < len(lines):
            reason = lines[index + 1].strip()
            break
    message = reason or "PR-QA reported a blocking failure."
    return f"::error title=PR QA BLOCKED::{escape_actions_command_value(message)}"


def escape_actions_command_value(value: str) -> str:
    return redact(str(value)).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def publish_pr_status_comment_cli(args: argparse.Namespace, policy: dict[str, Any]) -> int:
    try:
        event = load_event(args.event_path)
        report_path = Path(args.status_json_in or args.json_out)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if should_emit_actions_failure_summary():
            emit_pr_failure_summary_cli(args, policy, event, report)
        publish_pr_status_comment(event, policy, report)
    except Exception as exc:
        print(f"WARNING: PR status comment was not published: {redact(str(exc))}", file=sys.stderr)
    return 0


def should_emit_actions_failure_summary() -> bool:
    return os.environ.get("PR_QA_EMIT_FAILURE_SUMMARY", "").strip().lower() in {"1", "true", "yes"}


def publish_pr_status_comment(event: dict[str, Any], policy: dict[str, Any], report: dict[str, Any]) -> bool:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    pr_number = extract_pr_number(event)
    if not token or not repository or not pr_number:
        return False
    base_url = f"https://api.github.com/repos/{repository}"
    errors: list[str] = []
    pr_payload = github_api_get(f"{base_url}/pulls/{pr_number}", token, errors)
    reviews_payload = github_api_get(f"{base_url}/pulls/{pr_number}/reviews", token, errors)
    comments_payload = github_api_get(f"{base_url}/issues/{pr_number}/comments", token, errors)
    if errors:
        return False
    evidence = {
        "pull_request": pr_payload if isinstance(pr_payload, dict) else {},
        "reviews": reviews_payload if isinstance(reviews_payload, list) else [],
    }
    body = render_pr_status_comment(report, event, policy, evidence)
    comments = comments_payload if isinstance(comments_payload, list) else []
    canonical, duplicates = select_status_comment(comments)
    if canonical:
        github_api_request("PATCH", str(canonical.get("url", "")), token, errors, {"body": body})
        for duplicate in duplicates:
            github_api_request("DELETE", str(duplicate.get("url", "")), token, errors)
    else:
        github_api_request("POST", f"{base_url}/issues/{pr_number}/comments", token, errors, {"body": body})
    if errors:
        refreshed = github_api_get(f"{base_url}/issues/{pr_number}/comments", token, [])
        if isinstance(refreshed, list):
            canonical, duplicates = select_status_comment(refreshed)
            retry_errors: list[str] = []
            if canonical:
                github_api_request("PATCH", str(canonical.get("url", "")), token, retry_errors, {"body": body})
                for duplicate in duplicates:
                    github_api_request("DELETE", str(duplicate.get("url", "")), token, retry_errors)
            return not retry_errors
        return False
    return True


def select_status_comment(comments: list[Any]) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    marker_comments = [comment for comment in comments if isinstance(comment, dict) and PR_STATUS_COMMENT_MARKER in str(comment.get("body", ""))]
    marker_comments.sort(key=lambda item: (str(item.get("created_at", "")), int(item.get("id") or 0)))
    if not marker_comments:
        return None, []
    return marker_comments[0], marker_comments[1:]


def apply_status_comment_update(comments: list[dict[str, Any]], body: str) -> list[dict[str, Any]]:
    canonical, duplicates = select_status_comment(comments)
    remaining_ids = {int(item.get("id") or 0) for item in duplicates}
    if canonical:
        canonical_id = int(canonical.get("id") or 0)
        return [
            {**comment, "body": body} if int(comment.get("id") or 0) == canonical_id else comment
            for comment in comments
            if int(comment.get("id") or 0) not in remaining_ids
        ]
    next_id = max([int(comment.get("id") or 0) for comment in comments] + [0]) + 1
    return comments + [{"id": next_id, "body": body, "created_at": "9999-12-31T23:59:59Z"}]


def render_pr_status_comment(report: dict[str, Any], event: dict[str, Any], policy: dict[str, Any], evidence: dict[str, Any] | None = None) -> str:
    status = build_pr_status_model(report, event, policy, evidence or {})
    lines = [
        PR_STATUS_COMMENT_MARKER,
        "SYNERGIE PR STATUS",
        "",
        f"STATUS: {status['status']}",
    ]
    if status["why"]:
        lines.extend(["", "WHY:"])
        lines.extend(f"- {reason}" for reason in status["why"])
    if status.get("developer_handoff_ready"):
        lines.extend(["", f"DEVELOPER_HANDOFF_READY: {status['developer_handoff_ready']}"])
    if status.get("action_items"):
        lines.extend(["", "PR QA BLOCKED"])
        for index, item in enumerate(status["action_items"], start=1):
            if len(status["action_items"]) > 1:
                lines.extend(["", f"Blocker {index}:"])
            lines.extend(["", "What failed:", item["what_failed"], "", "Why:", item["why"], "", "What to do:", item["what_to_do"]])
            if item.get("technical_details"):
                lines.extend(["", "Technical details:"])
                lines.extend(f"- {detail}" for detail in item["technical_details"])
        if status.get("additional_blockers"):
            lines.extend(["", f"Additional blockers: {status['additional_blockers']} more. Review the PR-QA technical details for the remaining blockers."])
    if status["approved_by"]:
        lines.extend(["", f"APPROVED BY: {status['approved_by']}"])
    else:
        label = "SAURABH GATE C APPROVAL REQUIRED" if status["gate_c"] else "SAURABH APPROVAL REQUIRED"
        lines.extend(["", f"{label}: {'YES' if status['saurabh_required'] else 'NO'}"])
    lines.extend(["", "DEVELOPER ACTION:", status["developer_action"]])
    return "\n".join(lines).rstrip() + "\n"


def build_pr_status_model(report: dict[str, Any], event: dict[str, Any], policy: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {}) or {}
    results = report.get("results", []) or []
    base_ref = str(summary.get("base_ref") or ((event.get("pull_request", {}) or {}).get("base", {}) or {}).get("ref", ""))
    head_ref = str(summary.get("head_ref") or ((event.get("pull_request", {}) or {}).get("head", {}) or {}).get("ref", ""))
    owner_login = status_owner_login(policy)
    pr_author = extract_pr_author(event)
    gate_c = head_ref.lower() == "staging" and base_ref.lower() == "main"
    owner_approved = pr_author == owner_login or owner_latest_review_approved(evidence.get("reviews", []), owner_login)
    blocking_failures = [result for result in results if result_failed(result)]
    review_only_blocked = gate_c and blocking_failures and all(str(result.get("gate", "")) == "Review Policy" for result in blocking_failures)
    behind = pr_is_behind(evidence, base_ref)
    missing_contexts = exact_missing_required_contexts(evidence.get("required_contexts", []), evidence.get("live_contexts", []))

    if summary.get("overall_result") == PASS and not behind and not missing_contexts:
        if gate_c:
            if owner_approved:
                return status_model("READY FOR GATE C MERGE", [], False, "No action required.", gate_c=True, approved_by=owner_login)
            return status_model("TECHNICALLY READY", [], True, "No code action required. Await Saurabh release approval.", gate_c=True)
        handoff = "YES" if base_ref.lower() == "staging" else ""
        return status_model("READY TO MERGE", [], False, "No action required.", gate_c=False, developer_handoff_ready=handoff)

    if review_only_blocked and not behind and not missing_contexts and not owner_approved:
        return status_model("TECHNICALLY READY", [], True, "No code action required. Await Saurabh release approval.", gate_c=True)

    why = pr_status_failure_reasons(results, behind, base_ref, missing_contexts)
    handoff = "NO" if base_ref.lower() == "staging" else ""
    action_items, additional_blockers = developer_action_items(results, behind, base_ref, head_ref, missing_contexts)
    return status_model("BLOCKED", why, False, developer_action_for(why, base_ref), gate_c=gate_c, action_items=action_items, additional_blockers=additional_blockers, developer_handoff_ready=handoff)


def status_model(
    status: str,
    why: list[str],
    saurabh_required: bool,
    developer_action: str,
    *,
    gate_c: bool,
    approved_by: str = "",
    action_items: list[dict[str, Any]] | None = None,
    additional_blockers: int = 0,
    developer_handoff_ready: str = "",
) -> dict[str, Any]:
    return {
        "status": status,
        "why": why,
        "saurabh_required": saurabh_required,
        "developer_action": developer_action,
        "gate_c": gate_c,
        "approved_by": approved_by,
        "action_items": action_items or [],
        "additional_blockers": additional_blockers,
        "developer_handoff_ready": developer_handoff_ready,
    }


def status_owner_login(policy: dict[str, Any]) -> str:
    governance = policy.get("governance", {}) or {}
    review_policy = governance.get("review_policy", {}) or {}
    return str((review_policy.get("owner_review_exception", {}) or {}).get("github_login", "SaurabhVermaIN"))


def result_failed(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    return result.get("status") == FAIL and bool(result.get("blocking", True))


def pr_is_behind(evidence: dict[str, Any], base_ref: str) -> bool:
    pull_request = evidence.get("pull_request", {}) if isinstance(evidence.get("pull_request", {}), dict) else {}
    return pull_request.get("mergeable_state") == "behind" or int(pull_request.get("behind_by") or 0) > 0


def exact_missing_required_contexts(required: Any, live: Any) -> list[str]:
    if not isinstance(required, list) or not isinstance(live, list):
        return []
    live_set = {str(item) for item in live}
    return [str(item) for item in required if str(item) not in live_set]


def pr_status_failure_reasons(results: list[Any], behind: bool, base_ref: str, missing_contexts: list[str]) -> list[str]:
    reasons: list[str] = []
    failed_gates = {str(result.get("gate", "")) for result in results if result_failed(result)}
    if {"Build", "Tests"} & failed_gates:
        reasons.append("Automated tests failed")
    if "Formatting" in failed_gates or "Lint" in failed_gates:
        reasons.append("Code quality checks failed")
    if "Secrets" in failed_gates:
        reasons.append("Secret scanning failed")
    if "Repository Hygiene" in failed_gates:
        reasons.append("Repository hygiene failed")
    if "Deployment Risk" in failed_gates:
        reasons.append("Deployment risk review failed")
    if "Migration Risk" in failed_gates:
        reasons.append("Migration safety review failed")
    if "Review Policy" in failed_gates:
        reasons.append("Required review policy is not satisfied")
    if behind:
        reasons.append(f"Your branch is behind {base_ref or 'the base branch'}")
    reasons.extend(f"Required check is missing or stale: {context}" for context in missing_contexts)
    if not reasons and failed_gates:
        reasons.append("PR-QA failed")
    return list(dict.fromkeys(reasons))


def developer_action_for(why: list[str], base_ref: str) -> str:
    tests = "Automated tests failed" in why
    behind = any(reason.startswith("Your branch is behind ") for reason in why)
    if tests and behind:
        return f"Fix the failed tests, align locally with the latest {base_ref or 'base'} branch, and push again."
    if behind:
        return f"Align your branch locally with the latest {base_ref or 'base'} branch, then push again."
    return "Use PR QA BLOCKED below, then push again."


def developer_action_items(results: list[Any], behind: bool, base_ref: str, head_ref: str, missing_contexts: list[str]) -> tuple[list[dict[str, Any]], int]:
    items = [developer_action_item_for_result(result) for result in results if result_failed(result)]
    if behind:
        source = head_ref or "this"
        target = base_ref or "the base"
        items.append(
            developer_action_item(
                "Branch history",
                f"Your {source} branch is behind {target}.",
                f"Bring {source} up to date with {target}, resolve any conflicts locally, and push again.",
                [],
            )
        )
    for context in missing_contexts:
        items.append(
            developer_action_item(
                "A required GitHub check is missing or stale.",
                f"The required check `{context}` is missing or stale.",
                "Restore the required workflow/check context or rerun checks so the exact required context reports.",
                [context],
            )
        )
    return compact_developer_action_items(items)


def developer_action_item_for_result(result: dict[str, Any]) -> dict[str, Any]:
    gate = str(result.get("gate", ""))
    message = redact(str(result.get("message") or "")).strip()
    details = [redact(str(detail)) for detail in result.get("details", []) if str(detail).strip()]
    what = developer_failure_label(gate, str(result.get("technology") or ""))
    why = developer_failure_reason_for_gate(gate, message)
    action = developer_next_action_for_gate(gate, message)
    technical_details = developer_technical_details_for_result(gate, message, details)
    return developer_action_item(what, why, action, technical_details)


def developer_action_item(what_failed: str, why: str, what_to_do: str, technical_details: list[str]) -> dict[str, Any]:
    return {
        "what_failed": what_failed,
        "why": why or "PR-QA reported a blocking failure.",
        "what_to_do": what_to_do,
        "technical_details": list(dict.fromkeys(technical_details)),
    }


def compact_developer_action_items(items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    compact: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        key = (item["what_failed"], item["why"], item["what_to_do"])
        existing = by_key.get(key)
        if existing:
            existing["technical_details"] = list(
                dict.fromkeys(existing.get("technical_details", []) + item.get("technical_details", []))
            )[:PR_STATUS_TECHNICAL_DETAIL_LIMIT]
            continue
        by_key[key] = item
        compact.append(item)
    return compact[:PR_STATUS_ACTION_ITEM_LIMIT], max(0, len(compact) - PR_STATUS_ACTION_ITEM_LIMIT)


def developer_failure_label(gate: str, technology: str) -> str:
    label = gate or "PR-QA"
    if technology:
        return f"{label} ({technology})"
    return label


def developer_failure_reason_for_gate(gate: str, message: str) -> str:
    if gate == "Repository Hygiene" and "Accidental merge commits detected" in message:
        return "This branch contains merge history that is not permitted for this PR."
    if gate == "Secrets":
        return "PR-QA detected a possible committed secret."
    if message:
        return message
    return "PR-QA reported a blocking failure without a specific reason."


def developer_next_action_for_gate(gate: str, message: str) -> str:
    if gate in {"Tests", "Build"}:
        return "Fix the failing test or build command shown in the technical details, run it locally if available, then push again."
    if gate in {"Formatting", "Lint"}:
        return "Fix the reported formatting or lint issue, run the formatter/linter locally if available, then push again."
    if gate == "Secrets":
        return "Remove the committed secret or unsafe secret-bearing file. If a real credential was exposed, rotate or revoke it, then push a cleaned commit."
    if gate == "Repository Hygiene":
        if "Accidental merge commits detected" in message:
            return "Update/rebase the branch using the normal development workflow, then push again."
        if "Merge conflict markers" in message:
            return "Resolve the conflict markers in the changed files, then push again."
        return "Clean up the branch history or changed files identified in the technical details, then push again."
    if gate == "Deployment Risk":
        return "Update the affected workflow or deployment change to satisfy the safety control named in the technical details, then push again."
    if gate == "Migration Risk":
        return "Make the migration forward-safe or use the governed migration path identified by the maintainer, then push again."
    if gate == "Protected Resources":
        return "Add the required ownership/review evidence or split the protected-resource change into the governed workflow, then push again."
    if gate == "Review Policy":
        return "Request the required reviewer or approval shown in the technical details; no code change is needed for this blocker."
    if gate in {
        "Baseline Alignment",
        "Config Validation",
        "Repository Integrity",
        "Git Validation",
        "Executable Classification",
        "Dependencies",
        "Licence",
        "Documentation",
        "Architecture",
        "Release Drift",
        "Risk Engine",
        "Evidence",
    }:
        return "Fix the issue described in the technical details, then push again."
    return "Next action: review the technical details or contact the repository maintainer."


def developer_technical_details_for_result(gate: str, message: str, details: list[str]) -> list[str]:
    technical: list[str] = []
    if gate == "Repository Hygiene" and "Accidental merge commits detected" in message and details:
        suffix = "commit" if len(details) == 1 else "commits"
        technical.append(f"{len(details)} unexpected merge {suffix} detected.")
    for detail in details:
        cleaned = compact_status_detail(detail)
        if cleaned:
            technical.append(cleaned)
        if len(technical) >= PR_STATUS_TECHNICAL_DETAIL_LIMIT:
            break
    return list(dict.fromkeys(technical))[:PR_STATUS_TECHNICAL_DETAIL_LIMIT]


def compact_status_detail(value: str) -> str:
    text = redact(str(value)).strip()
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text)
    if len(text) <= PR_STATUS_TECHNICAL_DETAIL_CHARS:
        return text
    return text[: PR_STATUS_TECHNICAL_DETAIL_CHARS - 3].rstrip() + "..."


def independent_approved_reviewers(reviews: Any, pr_author: str) -> list[str]:
    latest_by_user: dict[str, str] = {}
    if not isinstance(reviews, list):
        return []
    for review in reviews:
        if not isinstance(review, dict):
            continue
        login = str((review.get("user", {}) or {}).get("login", "") or review.get("login", ""))
        state = str(review.get("state", "")).upper()
        if not login:
            continue
        latest_by_user[login] = state
    return sorted(login for login, state in latest_by_user.items() if login != pr_author and state == "APPROVED")


def owner_latest_review_approved(reviews: Any, owner_login: str) -> bool:
    latest_state = ""
    if not isinstance(reviews, list):
        return False
    for review in reviews:
        if not isinstance(review, dict):
            continue
        login = str((review.get("user", {}) or {}).get("login", "") or review.get("login", ""))
        if login != owner_login:
            continue
        latest_state = str(review.get("state", "")).upper()
    return latest_state == "APPROVED"


def field_has_value(body: str, field: str) -> bool:
    if not body.strip():
        return False
    match = re.search(rf"(?im)^\s*(?:#+\s*)?{re.escape(field)}\s*$|^\s*\*\*{re.escape(field)}\*\*\s*$", body)
    if not match:
        index = body.lower().find(field.lower())
        if index == -1:
            return False
        start = index + len(field)
    else:
        start = match.end()
    after = re.sub(r"^[\s:#*\-_]+", "", body[start:])
    next_heading = re.search(r"\n\s*#{1,6}\s+|\n\s*\*\*[^*]+\*\*", after)
    value = (after[: next_heading.start()] if next_heading else after).strip()
    if not value:
        return False
    placeholders = ["describe the user", "list the local", "explain how", "link the ticket", "add screenshots", "todo", "tbd"]
    if field.lower() != "screenshots" and value.lower() in {"n/a", "none"}:
        return False
    if field.lower() != "screenshots" and any(item in value.lower() for item in placeholders):
        return False
    if field.lower() == "linked issue" and not re.search(r"(https?://|#[0-9]+|[A-Z][A-Z0-9]+-[0-9]+)", value):
        return False
    return True


def ui_changes_present(ctx: PRContext) -> bool:
    ui_patterns = ["**/*.tsx", "**/*.jsx", "**/*.css", "**/*.scss", "**/*.sass", "**/*.vue", "**/*.html", "resources/views/**", "assets/**", "public/**", "frontend/**", "mobile/**"]
    return any(match_any(path, ui_patterns) for path in ctx.changed_files)


def technical_baseline_binding(
    ctx: PRContext,
    git_context: dict[str, Any],
    technologies: dict[str, dict[str, Any]],
    policy: dict[str, Any],
    policy_path: Path,
) -> dict[str, Any]:
    repository = resolve_repository_name(ctx)
    head_sha = resolve_head_sha(ctx.repo, git_context)
    head_tree = run_git(ctx.repo, ["rev-parse", "HEAD^{tree}"]).strip() if git_context.get("is_git_repo") else ""
    base_sha = str(git_context.get("base_sha") or "")
    changed_digest = hashlib.sha256("\n".join(sorted(ctx.changed_files)).encode("utf-8")).hexdigest()
    policy_digest = file_sha256(policy_path)
    framework_digest = framework_technical_digest(policy_path)
    payload = {
        "repository": repository,
        "head_sha": head_sha,
        "head_tree_sha": head_tree,
        "base_sha": base_sha,
        "changed_files_digest": changed_digest,
        "detected_technologies": sorted(value["name"] for value in technologies.values()),
        "policy_id": policy.get("policy_id", "unknown"),
        "policy_digest": policy_digest,
        "framework_release": os.environ.get("PR_QA_FRAMEWORK_RELEASE", ""),
        "framework_digest": framework_digest,
    }
    payload["technical_input_digest"] = stable_json_digest(payload)
    payload["cache_key"] = technical_baseline_cache_key(repository, payload["technical_input_digest"])
    return payload


def technical_baseline_cache_key(repository: str, digest: str) -> str:
    safe_repo = re.sub(r"[^A-Za-z0-9_.-]+", "-", repository).strip("-") or "repository"
    return f"{TECHNICAL_BASELINE_CACHE_PREFIX}-{safe_repo}-{digest}"


def stable_json_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def framework_technical_digest(policy_path: Path) -> str:
    paths: list[Path] = [policy_path]
    for rel in [
        "pr-qa/pr_qa.py",
        ".github/workflows/pr-qa.yml",
    ]:
        candidate = FRAMEWORK_ROOT / rel
        if candidate.exists():
            paths.append(candidate)
    adapters = FRAMEWORK_ROOT / "pr-qa" / "adapters"
    if adapters.exists():
        paths.extend(sorted(adapters.glob("*.py")))
    hasher = hashlib.sha256()
    for path in sorted(set(paths), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        try:
            rel = path.resolve().relative_to(FRAMEWORK_ROOT.resolve()).as_posix()
        except ValueError:
            rel = path.as_posix()
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


def framework_release_state(repo: Path) -> dict[str, Any]:
    release = active_pr_qa_release(repo)
    if not release:
        return release_state("", False, [], ["active PR-QA release pin could not be found in `.github/workflows/pr-qa.yml`."])
    tag = subprocess.run(
        ["git", "rev-parse", f"{release}^{{commit}}"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if tag.returncode != 0:
        return release_state(release, False, [], [f"active PR-QA release `{release}` could not be resolved."])
    files, details = release_sensitive_files(repo, release)
    if details:
        return release_state(release, False, files, details)
    mismatches: list[str] = []
    for rel in files:
        current = read_release_sensitive_worktree_file(repo, rel)
        pinned = read_release_sensitive_tag_file(repo, release, rel)
        if current is None or pinned is None:
            mismatches.append(f"{rel}: content could not be inspected in current checkout or active release.")
        elif current != pinned:
            mismatches.append(f"{rel}: current content differs from active release `{release}`.")
    return release_state(release, not mismatches, files, mismatches[:20])


def release_state(release: str, matches: bool, files: list[str], details: list[str]) -> dict[str, Any]:
    return {
        "active_pr_qa_release": release,
        "framework_main_matches_active_release": PASS if matches else FAIL,
        "release_required": "NO" if matches else "YES",
        "release_sensitive_files": files,
        "details": details,
    }


def active_pr_qa_release(repo: Path) -> str:
    workflow = repo / ".github" / "workflows" / "pr-qa.yml"
    try:
        text = workflow.read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r'(?m)^\s*PR_QA_FRAMEWORK_RELEASE:\s*["\']?([^"\'\s]+)["\']?\s*$', text)
    return match.group(1) if match else ""


def release_sensitive_files(repo: Path, release: str) -> tuple[list[str], list[str]]:
    current = {
        path.relative_to(repo).as_posix()
        for root in RELEASE_SENSITIVE_ROOTS
        for path in (repo / root).rglob("*.py")
        if path.is_file()
    }
    current.update(rel for rel in RELEASE_SENSITIVE_EXACT_FILES if (repo / rel).is_file())
    tagged = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", release, "--", "pr-qa", *sorted(RELEASE_SENSITIVE_EXACT_FILES)],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if tagged.returncode != 0:
        return sorted(current), [f"release-sensitive file list for `{release}` could not be inspected."]
    for rel in tagged.stdout.splitlines():
        if is_release_sensitive_file(rel):
            current.add(rel)
    return sorted(current), []


def is_release_sensitive_file(rel: str) -> bool:
    path = rel.strip("/")
    if path in RELEASE_SENSITIVE_EXACT_FILES:
        return True
    return path.startswith("pr-qa/") and path.endswith(".py")


def read_release_sensitive_worktree_file(repo: Path, rel: str) -> bytes | None:
    if not is_release_sensitive_file(rel):
        return None
    try:
        return (repo / rel).read_bytes()
    except OSError:
        return None


def read_release_sensitive_tag_file(repo: Path, release: str, rel: str) -> bytes | None:
    if not is_release_sensitive_file(rel):
        return None
    result = subprocess.run(
        ["git", "show", f"{release}:{rel}"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def write_technical_baseline_key_output(output_path: str, binding: dict[str, Any]) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"cache_key={binding['cache_key']}\n")
        handle.write(f"technical_input_digest={binding['technical_input_digest']}\n")
        handle.write(f"baseline_path={TECHNICAL_BASELINE_DIR}/{TECHNICAL_BASELINE_FILE}\n")


def write_technical_baseline_if_passed(
    output_path: str,
    ctx: PRContext,
    git_context: dict[str, Any],
    technologies: dict[str, dict[str, Any]],
    policy: dict[str, Any],
    policy_path: Path,
    results: list[CheckResult],
) -> None:
    if not output_path:
        return
    technical_results = [result for result in results if result.gate in TECHNICAL_GATE_NAMES]
    if not technical_results or any(result.is_blocking_failure() for result in technical_results):
        return
    binding = technical_baseline_binding(ctx, git_context, technologies, policy, policy_path)
    record = {
        "schema_version": TECHNICAL_BASELINE_SCHEMA_VERSION,
        "type": TECHNICAL_BASELINE_TYPE,
        "status": PASS,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "binding": binding,
        "results": [serialize_check_result(result) for result in technical_results if result.gate in REUSABLE_SANDBOXED_GATE_NAMES],
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    context_cache(ctx)["technical_baseline"] = {
        "status": "CREATED",
        "cache_key": binding["cache_key"],
        "technical_input_digest": binding["technical_input_digest"],
    }


def load_reusable_technical_baseline(
    input_path: str,
    ctx: PRContext,
    git_context: dict[str, Any],
    technologies: dict[str, dict[str, Any]],
    policy: dict[str, Any],
    policy_path: Path,
) -> tuple[list[CheckResult], list[str]]:
    if not input_path:
        return [], []
    path = Path(input_path)
    if not path.exists():
        return [], [f"technical baseline `{input_path}` was not found."]
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"technical baseline `{input_path}` is unreadable or invalid JSON: {exc}"]
    expected = technical_baseline_binding(ctx, git_context, technologies, policy, policy_path)
    details = validate_technical_baseline_record(record, expected)
    if details:
        return [], details
    results = [deserialize_check_result(item) for item in record.get("results", [])]
    if not results:
        return [], ["technical baseline has no reusable validation results."]
    if any(result.is_blocking_failure() for result in results):
        return [], ["technical baseline contains a blocking failure and cannot be reused."]
    context_cache(ctx)["technical_baseline"] = {
        "status": "REUSED",
        "cache_key": expected["cache_key"],
        "technical_input_digest": expected["technical_input_digest"],
    }
    return results, []


def validate_technical_baseline_record(record: dict[str, Any], expected_binding: dict[str, Any]) -> list[str]:
    details: list[str] = []
    if record.get("schema_version") != TECHNICAL_BASELINE_SCHEMA_VERSION:
        details.append("technical baseline schema version is unsupported.")
    if record.get("type") != TECHNICAL_BASELINE_TYPE:
        details.append("technical baseline type is unsupported.")
    if record.get("status") != PASS:
        details.append("technical baseline did not record a PASS status.")
    binding = record.get("binding")
    if not isinstance(binding, dict):
        details.append("technical baseline binding is missing.")
        return details
    for key in [
        "repository",
        "head_sha",
        "head_tree_sha",
        "base_sha",
        "changed_files_digest",
        "detected_technologies",
        "policy_id",
        "policy_digest",
        "framework_release",
        "framework_digest",
        "technical_input_digest",
        "cache_key",
    ]:
        if binding.get(key) != expected_binding.get(key):
            details.append(f"technical baseline `{key}` mismatch.")
    return details


def serialize_check_result(result: CheckResult) -> dict[str, Any]:
    return {
        "gate": result.gate,
        "status": result.status,
        "message": result.message,
        "details": list(result.details),
        "technology": result.technology,
        "score": result.score,
        "blocking": result.blocking,
    }


def deserialize_check_result(payload: dict[str, Any]) -> CheckResult:
    return CheckResult(
        gate=str(payload.get("gate") or ""),
        status=str(payload.get("status") or SKIP),
        message=str(payload.get("message") or "Reused exact-content technical validation baseline."),
        details=[str(item) for item in payload.get("details", []) or []],
        technology=str(payload.get("technology")) if payload.get("technology") is not None else None,
        score=int(payload.get("score") or 0),
        blocking=bool(payload.get("blocking", True)),
    )


def summarize(results: list[CheckResult], technologies: dict[str, dict[str, Any]], ctx: PRContext, git_context: dict[str, Any]) -> dict[str, Any]:
    gate_statuses = {}
    for _, display in GATE_ORDER:
        gate_statuses[display] = aggregate_status([result for result in results if result.gate == display])
    overall = FAIL if any(result.is_blocking_failure() for result in results) else PASS
    developer_handoff_ready = ""
    if (git_context.get("base_ref") or "").lower() == "staging":
        developer_handoff_ready = "YES" if overall == PASS else "NO"
    risk_result = next((result for result in results if result.gate == "Risk Engine"), None)
    size = risk_size_accounting(ctx)
    release_drift = build_release_drift_summary(ctx)
    return {
        "repository": resolve_repository_name(ctx),
        "base_ref": git_context.get("base_ref") or "",
        "head_ref": git_context.get("head_ref") or "",
        "detected_technologies": sorted(value["name"] for value in technologies.values()),
        "changed_files": len(ctx.changed_files),
        "additions": ctx.additions,
        "deletions": ctx.deletions,
        "raw_additions": size["raw_additions"],
        "raw_deletions": size["raw_deletions"],
        "generated_lockfile_additions_excluded": size["generated_lockfile_additions_excluded"],
        "generated_lockfile_deletions_excluded": size["generated_lockfile_deletions_excluded"],
        "effective_additions": size["effective_additions"],
        "effective_deletions": size["effective_deletions"],
        "gate_statuses": gate_statuses,
        "overall_result": overall,
        "merge_readiness": "READY FOR HUMAN REVIEW" if overall == PASS else "NOT READY FOR HUMAN REVIEW",
        "developer_handoff_ready": developer_handoff_ready,
        "risk_score": extract_risk_score(risk_result.message if risk_result else ""),
        "policy_id": ctx.policy.get("policy_id", "unknown"),
        "baseline_alignment": build_baseline_summary(ctx, git_context, results),
        "technical_baseline": build_technical_baseline_summary(ctx),
        "release_drift": release_drift,
        "active_pr_qa_release": release_drift.get("active_pr_qa_release", ""),
        "framework_main_matches_active_release": release_drift.get("framework_main_matches_active_release", SKIP),
        "release_required": release_drift.get("release_required", "NO"),
    }


def build_release_drift_summary(ctx: PRContext) -> dict[str, Any]:
    state = dict(context_cache(ctx).get("release_drift") or {})
    return {
        "active_pr_qa_release": state.get("active_pr_qa_release", ""),
        "framework_main_matches_active_release": state.get("framework_main_matches_active_release", SKIP),
        "release_required": state.get("release_required", "NO"),
        "release_sensitive_files": list(state.get("release_sensitive_files") or []),
        "details": list(state.get("details") or []),
    }


def build_technical_baseline_summary(ctx: PRContext) -> dict[str, Any]:
    baseline = dict(context_cache(ctx).get("technical_baseline") or {})
    details = list(context_cache(ctx).get("technical_baseline_reuse_details") or [])
    return {
        "status": baseline.get("status", "NONE"),
        "cache_key": baseline.get("cache_key", ""),
        "technical_input_digest": baseline.get("technical_input_digest", ""),
        "reuse_details": details,
    }


def build_baseline_summary(ctx: PRContext, git_context: dict[str, Any], results: list[CheckResult]) -> dict[str, Any]:
    migration_patterns = ["**/migrations/**", "**/migration/**", "database/**", "db/migrate/**", "**/*.sql"]
    env_files = [
        rel
        for rel in ctx.changed_files
        if fnmatch.fnmatch(Path(rel).name, ".env") or fnmatch.fnmatch(Path(rel).name, ".env.*")
    ]
    safe_env = [rel for rel in env_files if is_baseline_safe_environment_file(ctx, rel)]
    unsafe_env = sorted(set(env_files) - set(safe_env))
    workflow_changes = [rel for rel in ctx.changed_files if rel.startswith(".github/workflows/")]
    governance_files = [
        rel
        for rel in ctx.changed_files
        if rel in {"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS", ".gitleaks.toml"}
        or rel.startswith(("policy/", "schemas/", ".github/"))
    ]
    binary_files = [
        rel
        for rel in ctx.changed_files
        if (ctx.repo / rel).is_file() and is_binary_file(ctx.repo / rel)
    ]
    return {
        "requested": baseline_requested(ctx),
        "authorized": baseline_active(ctx),
        "authorization_details": context_cache(ctx).get("baseline_authorization_details", []),
        "repository": resolve_repository_name(ctx),
        "source_branch": ctx.head_ref or "",
        "target_branch": ctx.base_ref or "",
        "source_sha": resolve_head_sha(ctx.repo, git_context),
        "destination_sha": git_context.get("base_sha") or "",
        "changed_files": len(ctx.changed_files),
        "additions": ctx.additions,
        "deletions": ctx.deletions,
        "migration_count": len([rel for rel in ctx.changed_files if match_any(rel, migration_patterns)]),
        "binary_count": len(binary_files),
        "binary_files": binary_files[:50],
        "environment_files": env_files[:50],
        "safe_environment_files": safe_env[:50],
        "unsafe_environment_files": unsafe_env[:50],
        "workflow_changes": workflow_changes[:50],
        "governance_files": governance_files[:50],
        "relaxed_checks": sorted(baseline_relaxations(ctx)) if baseline_active(ctx) else [],
        "non_relaxed_checks": BASELINE_NON_RELAXABLE_CHECKS,
        "secret_scan_status": aggregate_status([result for result in results if result.gate == "Secrets"]),
        "dependency_audit_status": aggregate_status([result for result in results if result.gate == "Dependencies"]),
        "test_status": aggregate_status([result for result in results if result.gate == "Tests"]),
        "migration_status": aggregate_status([result for result in results if result.gate == "Migration Risk"]),
    }


def resolve_repository_name(ctx: PRContext) -> str:
    event_repository = ctx.event.get("repository", {}) or {}
    event_full_name = str(event_repository.get("full_name") or "")
    if event_full_name:
        return event_full_name
    github_repository = os.environ.get("GITHUB_REPOSITORY")
    if github_repository and is_github_workspace_repo(ctx):
        return github_repository
    return ctx.repo.name


def is_github_workspace_repo(ctx: PRContext) -> bool:
    github_workspace = os.environ.get("GITHUB_WORKSPACE")
    if not github_workspace:
        return False
    try:
        return Path(github_workspace).resolve() == ctx.repo.resolve()
    except OSError:
        return False


def aggregate_status(results: list[CheckResult]) -> str:
    if not results:
        return SKIP
    statuses = [result.status for result in results]
    if FAIL in statuses:
        return FAIL
    if WARNING in statuses:
        return WARNING
    if PASS in statuses:
        return PASS
    return SKIP


def extract_risk_score(message: str) -> int:
    match = re.search(r"(\d+)\s*/\s*100", message)
    return int(match.group(1)) if match else 0


def write_reports(args: argparse.Namespace, summary: dict[str, Any], results: list[CheckResult], ctx: PRContext) -> None:
    report = render_markdown_report(summary, results)
    json_report = render_json_report(summary, results, ctx)
    qa_packet = build_pr_qa_packet(summary, results, ctx)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(report, encoding="utf-8")
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(json_report, indent=2), encoding="utf-8")
    if args.qa_packet_out:
        Path(args.qa_packet_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.qa_packet_out).write_text(json.dumps(qa_packet, indent=2, sort_keys=True), encoding="utf-8")
    print(report)


def build_pr_qa_packet(summary: dict[str, Any], results: list[CheckResult], ctx: PRContext) -> dict[str, Any]:
    technical_baseline = summary.get("technical_baseline") or {}
    evidence_results = [result for result in results if result.gate in {"Evidence", "Review Policy", "Architecture", "Risk Engine", "Documentation"}]
    return redact_secrets(
        {
            "schema_version": 1,
            "type": "pr_qa_packet",
            "repository": summary.get("repository", ""),
            "base_ref": summary.get("base_ref", ""),
            "head_ref": summary.get("head_ref", ""),
            "technical_validation": {
                "status": technical_baseline.get("status", "NONE"),
                "cache_key": technical_baseline.get("cache_key", ""),
                "technical_input_digest": technical_baseline.get("technical_input_digest", ""),
                "reused": technical_baseline.get("status") == "REUSED",
            },
            "current_evidence": {
                "overall_result": summary.get("overall_result", ""),
                "gate_statuses": {
                    result.gate: result.status
                    for result in evidence_results
                },
                "findings": [
                    {
                        "gate": result.gate,
                        "status": result.status,
                        "message": result.message,
                        "details": list(result.details),
                    }
                    for result in evidence_results
                    if result.status in {FAIL, WARNING}
                ],
            },
            "changed_files": summary.get("changed_files", 0),
            "commands": ctx.command_log,
        }
    )


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): redact_secrets(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        return redact(value)
    return value


def write_emergency_override_audit(
    args: argparse.Namespace,
    summary: dict[str, Any],
    results: list[CheckResult],
    ctx: PRContext,
    git_context: dict[str, Any],
) -> None:
    reason = str(args.emergency_override_reason or "").strip()
    if not reason:
        return

    policy_override = ctx.policy.get("emergency_override", {}) or {}
    authorized_actors = set(policy_override.get("authorized_actors", []))
    actor = resolve_override_actor(ctx, ctx.event)
    pr_author = extract_pr_author(ctx.event)
    owner_login = str(review_policy_config(ctx).get("owner_review_exception", {}).get("github_login", "SaurabhVermaIN"))
    actor_authorized = actor in authorized_actors
    saurabh_author_exception = actor_authorized and actor == pr_author and pr_author == owner_login
    administrator_bypass_required = False
    record = {
        "schema_version": 1,
        "type": "emergency_administrative_override",
        "decision": emergency_override_decision(actor_authorized, administrator_bypass_required, saurabh_author_exception),
        "authorized": actor_authorized,
        "actor_authorized": actor_authorized,
        "administrator_bypass_required": administrator_bypass_required,
        "saurabh_author_exception": saurabh_author_exception,
        "self_approval_allowed": False,
        "self_merge_authorized": saurabh_author_exception,
        "actor": actor,
        "pr_author": pr_author,
        "authorized_actors": sorted(authorized_actors),
        "repository": summary["repository"],
        "branch": summary["head_ref"] or "",
        "commit_sha": resolve_head_sha(ctx.repo, git_context),
        "pr_number": extract_pr_number(ctx.event),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "reason": redact(reason),
        "qa_summary": build_override_qa_summary(summary, results),
        "invariants": [
            "QA executed before this audit record was generated.",
            "QA findings, gate statuses, overall result, merge readiness, and process exit code are not changed by emergency override.",
            "Pull requests authored by SaurabhVermaIN are exempt only from independent human review.",
            "Other developers still require independent human approval.",
            "This record is governance evidence only and does not bypass GitHub Branch Protection automatically.",
        ],
    }
    record["record_sha256"] = emergency_override_digest(record)
    out_path = emergency_override_path(args, ctx, policy_override)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def resolve_head_sha(repo: Path, git_context: dict[str, Any]) -> str:
    head_sha = str(git_context.get("head_sha") or "")
    if head_sha and head_sha != "HEAD":
        return head_sha
    if is_git_repo(repo):
        return run_git(repo, ["rev-parse", "HEAD"]).strip()
    return head_sha


def extract_pr_number(event: dict[str, Any]) -> int | str:
    pull_request = event.get("pull_request", {}) or {}
    return pull_request.get("number") or event.get("number") or ""


def extract_pr_author(event: dict[str, Any]) -> str:
    pull_request = event.get("pull_request", {}) or {}
    return (pull_request.get("user", {}) or {}).get("login", "")


def resolve_override_actor(ctx: PRContext, event: dict[str, Any]) -> str:
    sender = (event.get("sender", {}) or {}).get("login", "")
    if not is_github_workspace_repo(ctx):
        return os.environ.get("GITHUB_ACTOR") or sender
    return os.environ.get("GITHUB_ACTOR") or os.environ.get("GITHUB_TRIGGERING_ACTOR") or sender


def emergency_override_decision(actor_authorized: bool, administrator_bypass_required: bool, saurabh_author_exception: bool = False) -> str:
    if not actor_authorized:
        return "REJECTED_UNAUTHORIZED_ACTOR"
    if saurabh_author_exception:
        return "SAURABH_AUTHOR_EXCEPTION_RECORDED"
    if administrator_bypass_required:
        return "ADMINISTRATOR_BYPASS_REQUIRED"
    if actor_authorized:
        return "EXECUTIVE_RELEASE_AUTHORITY_REVIEW_RECORDED"
    return "REJECTED_UNAUTHORIZED_ACTOR"


def build_override_qa_summary(summary: dict[str, Any], results: list[CheckResult]) -> dict[str, Any]:
    return {
        "overall_result": summary["overall_result"],
        "merge_readiness": summary["merge_readiness"],
        "risk_score": summary["risk_score"],
        "gate_statuses": summary["gate_statuses"],
        "failed_findings": [
            {
                "gate": result.gate,
                "message": redact(result.message),
                "technology": result.technology,
                "details": [redact(str(detail)) for detail in result.details],
            }
            for result in results
            if result.status == FAIL
        ],
        "warning_findings": [
            {
                "gate": result.gate,
                "message": redact(result.message),
                "technology": result.technology,
                "details": [redact(str(detail)) for detail in result.details],
            }
            for result in results
            if result.status == WARNING
        ],
    }


def emergency_override_path(args: argparse.Namespace, ctx: PRContext, policy_override: dict[str, Any]) -> Path:
    if args.emergency_override_out:
        return Path(args.emergency_override_out)
    default_name = str(policy_override.get("audit_artifact", "emergency-override-audit.json"))
    base = Path(args.json_out).parent if args.json_out else Path(args.out).parent if args.out else ctx.repo / "pr-qa-results"
    return base / default_name


def emergency_override_digest(record: dict[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "record_sha256"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def render_markdown_report(summary: dict[str, Any], results: list[CheckResult]) -> str:
    techs = ", ".join(summary["detected_technologies"]) or "None detected"
    lines = [
        "# PR QUALITY REPORT",
        "",
        f"Repository: `{markdown_escape(summary['repository'])}`",
        f"Policy: `{markdown_escape(summary['policy_id'])}`",
        f"Base Ref: `{markdown_escape(summary['base_ref'] or 'unknown')}`",
        f"Head Ref: `{markdown_escape(summary['head_ref'] or 'unknown')}`",
        f"Detected Technologies: {markdown_escape(techs)}",
        f"PR Size: {summary['changed_files']} files, +{summary['additions']} / -{summary['deletions']}",
        f"ACTIVE_PR_QA_RELEASE: {markdown_escape(summary.get('active_pr_qa_release') or 'UNKNOWN')}",
        f"FRAMEWORK_MAIN_MATCHES_ACTIVE_RELEASE: {markdown_escape(summary.get('framework_main_matches_active_release') or SKIP)}",
        f"RELEASE_REQUIRED: {markdown_escape(summary.get('release_required') or 'NO')}",
        "",
        "| Gate | Result |",
        "| --- | --- |",
    ]
    for _, display in GATE_ORDER:
        lines.append(f"| {markdown_escape(display)} | {summary['gate_statuses'].get(display, SKIP)} |")
    lines.extend(["", f"Risk Score: {summary['risk_score']} / 100", "", f"Overall Result: {summary['overall_result']}", "", f"Merge Readiness: {summary['merge_readiness']}", ""])
    if summary.get("developer_handoff_ready"):
        lines.extend([f"DEVELOPER_HANDOFF_READY: {markdown_escape(summary['developer_handoff_ready'])}", ""])
    baseline = summary.get("baseline_alignment") or {}
    if baseline.get("requested"):
        lines.extend(
            [
                "## BASELINE ALIGNMENT PREFLIGHT",
                f"- Authorization: {'AUTHORIZED' if baseline.get('authorized') else 'FAILED CLOSED'}",
                f"- Repository: `{markdown_escape(baseline.get('repository', ''))}`",
                f"- Source: `{markdown_escape(baseline.get('source_branch', '') or 'unknown')}` @ `{markdown_escape(baseline.get('source_sha', '') or 'unknown')}`",
                f"- Target: `{markdown_escape(baseline.get('target_branch', '') or 'unknown')}` @ `{markdown_escape(baseline.get('destination_sha', '') or 'unknown')}`",
                f"- Size: {baseline.get('changed_files', 0)} files, +{baseline.get('additions', 0)} / -{baseline.get('deletions', 0)}",
                f"- Migrations: {baseline.get('migration_count', 0)}",
                f"- Binary files: {baseline.get('binary_count', 0)}",
                f"- Environment files: {len(baseline.get('environment_files', []))} total, {len(baseline.get('safe_environment_files', []))} classified as safe templates/fixtures, {len(baseline.get('unsafe_environment_files', []))} unsafe/unclassified",
                f"- Workflow changes: {len(baseline.get('workflow_changes', []))}",
                f"- Governance files: {len(baseline.get('governance_files', []))}",
                f"- Secret scan: {baseline.get('secret_scan_status', SKIP)}",
                f"- Dependency audit: {baseline.get('dependency_audit_status', SKIP)}",
                f"- Tests: {baseline.get('test_status', SKIP)}",
                f"- Migration validation gate: {baseline.get('migration_status', SKIP)}",
                f"- Relaxed checks: {markdown_escape(', '.join(baseline.get('relaxed_checks', [])) or 'none')}",
                f"- Non-relaxed checks: {markdown_escape(', '.join(baseline.get('non_relaxed_checks', [])))}",
            ]
        )
        for detail in baseline.get("authorization_details", [])[:8]:
            lines.append(f"- Authorization detail: {markdown_escape(str(detail))}")
        for rel in baseline.get("workflow_changes", [])[:8]:
            lines.append(f"- Workflow change: `{markdown_escape(rel)}`")
        for rel in baseline.get("unsafe_environment_files", [])[:8]:
            lines.append(f"- Unsafe/unclassified environment file: `{markdown_escape(rel)}`")
        lines.append("")
    findings = [result for result in results if result.status in {FAIL, WARNING}]
    if findings:
        lines.append("## Findings")
        for result in findings:
            technology = f" [{markdown_escape(result.technology)}]" if result.technology else ""
            lines.append(f"- {result.status} {markdown_escape(result.gate)}{technology}: {markdown_escape(result.message)}")
            for detail in result.details[:6]:
                lines.append(f"  - {markdown_escape(str(detail))}")
    lines.append("")
    lines.append("## Audit Note")
    lines.append("This workflow validates technical gates and review policy. GitHub Branch Protection and repository rulesets remain the authority for required status checks, merge permissions, merge conflicts, and merge decisions.")
    return "\n".join(lines) + "\n"


def render_json_report(summary: dict[str, Any], results: list[CheckResult], ctx: PRContext) -> dict[str, Any]:
    return {
        "summary": summary,
        "results": [
            {
                "gate": result.gate,
                "status": result.status,
                "message": redact(result.message),
                "details": [redact(str(detail)) for detail in result.details],
                "technology": result.technology,
                "score": result.score,
                "blocking": result.blocking,
            }
            for result in results
        ],
        "commands": ctx.command_log,
    }


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
