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
import subprocess
from copy import deepcopy
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
    grep_text_files,
    is_binary_file,
    markdown_escape,
    match_any,
    passed,
    read_text,
    redact,
    should_skip_path,
    skipped,
    warning,
)


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = FRAMEWORK_ROOT / "policy" / "pr-qa-policy.json"
CONFIG_PATH = ".github/pr-qa.yml"
EMERGENCY_OVERRIDE_REASON_ENV = "PR_QA_EMERGENCY_OVERRIDE_REASON"

GATE_ORDER = [
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
    ("risk", "Risk Engine"),
    ("evidence", "Evidence"),
]

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
    "terraform": {".tf"},
}


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    policy = load_policy(Path(args.policy))

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

    results.extend(run_sandboxed_validation(ctx, technologies))
    results.extend(run_governance(ctx, results))
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
                items.append({key.strip(): parse_scalar(value.strip())} if value.strip() else {key.strip(): {}})
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
        if value.strip():
            mapping[key.strip()] = parse_scalar(value.strip())
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
    for key in ["php", "node", "python", "go", "gradle", "java", "dotnet", "rust", "swift"]:
        lines.append(f"{key}={'true' if key in technologies else 'false'}")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))


def gather_git_context(repo: Path, event: dict[str, Any], base_ref: str, head_ref: str) -> dict[str, Any]:
    pull_request = event.get("pull_request", {}) or {}
    base_sha = pull_request.get("base", {}).get("sha") or base_ref
    head_sha = pull_request.get("head", {}).get("sha") or "HEAD"
    resolved_head_ref = pull_request.get("head", {}).get("ref") or head_ref or os.environ.get("GITHUB_HEAD_REF") or current_branch(repo)
    resolved_base_ref = pull_request.get("base", {}).get("ref") or base_ref or os.environ.get("GITHUB_BASE_REF")
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
    commits = git_lines(repo, ["log", "--format=%s", f"{base_sha}..HEAD"]) if base_sha else git_lines(repo, ["log", "--format=%s", "-n", "1"])
    context.update({"changed_files": changed, "commits": commits, "additions": additions, "deletions": deletions, "diff_range": diff_range})
    return context


def is_git_repo(repo: Path) -> bool:
    return subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo, capture_output=True, text=True).returncode == 0


def current_branch(repo: Path) -> str:
    return run_git(repo, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()


def ensure_ref_available(repo: Path, base_sha: str, base_ref: str) -> None:
    if commit_exists(repo, base_sha) or not base_ref:
        return
    subprocess.run(["git", "fetch", "--no-tags", "origin", f"+refs/heads/{base_ref}:refs/remotes/origin/{base_ref}"], cwd=repo, check=False, capture_output=True)


def commit_exists(repo: Path, sha: str) -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo, capture_output=True).returncode == 0


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


def read_base_file(repo: Path, git_context: dict[str, Any], rel: str) -> str:
    base_sha = git_context.get("base_sha")
    if not base_sha or not git_context.get("is_git_repo") or not commit_exists(repo, base_sha):
        return ""
    completed = subprocess.run(["git", "show", f"{base_sha}:{rel}"], cwd=repo, capture_output=True, text=True, check=False)
    return completed.stdout if completed.returncode == 0 else ""


def list_repo_files(repo: Path) -> list[str]:
    files: list[str] = []
    for path in repo.rglob("*"):
        if path.is_file():
            rel = path.relative_to(repo)
            if not should_skip_path(rel):
                files.append(rel.as_posix())
    return sorted(files)


def run_static_preflight(ctx: PRContext, git_context: dict[str, Any], technologies: dict[str, dict[str, Any]], report_path: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    results.extend(gate_config_validation(ctx))
    results.extend(gate_repository_integrity(ctx, git_context))
    results.extend(gate_repository_hygiene(ctx, git_context))
    results.extend(gate_git_validation(ctx, git_context))
    results.extend(gate_secrets(ctx, git_context, report_path))
    results.extend(gate_executable_classification(ctx, technologies))
    results.extend(gate_protected_resources(ctx, git_context))
    results.extend(gate_deployment_safety(ctx))
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


def run_governance(ctx: PRContext, existing_results: list[CheckResult]) -> list[CheckResult]:
    results: list[CheckResult] = []
    results.extend(run_if_enabled(ctx, "documentation", lambda: gate_documentation(ctx)))
    results.extend(run_if_enabled(ctx, "advisory_review", lambda: gate_advisory_review(ctx)))
    results.extend(run_if_enabled(ctx, "risk", lambda: gate_risk(ctx, existing_results + results)))
    results.extend(run_if_enabled(ctx, "evidence", lambda: gate_evidence(ctx)))
    return results


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
        method = getattr(detected["adapter"], method_name)
        results.extend(method(ctx, detected["roots"]))
    return results or [passed(display, None, "No applicable checks for detected technologies.")]


def add_phase_skips(results: list[CheckResult], message: str) -> None:
    existing = {result.gate for result in results}
    for _, display in GATE_ORDER:
        if display not in existing:
            results.append(skipped(display, None, message))


def gate_config_validation(ctx: PRContext) -> list[CheckResult]:
    if ctx.config_violations:
        return [failed("Config Validation", None, "Repository QA configuration failed immutable policy validation.", ctx.config_violations, score=25)]
    return [passed("Config Validation", None, "Immutable central policy loaded and repository config is trusted from base branch.")]


def gate_repository_integrity(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    findings: list[str] = []
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
                if hidden not in allowed_hidden:
                    findings.append(f"{rel}: unexpected hidden file or directory `{hidden}`.")
        if any(part in generated_components for part in parts) or match_any(rel, generated_patterns):
            findings.append(f"{rel}: generated artifact path changed.")
        if path.is_symlink():
            target = os.readlink(path)
            findings.append(f"{rel}: symlink changed; target `{target}` requires manual security review.")
        if path.is_file():
            size = path.stat().st_size
            if size > max_bytes:
                findings.append(f"{rel}: oversized file ({size} bytes).")
            if is_binary_file(path) and path.suffix.lower() not in allowed_binary:
                findings.append(f"{rel}: binary file type is not allowed.")
            if is_lfs_pointer(path):
                findings.append(f"{rel}: Git LFS pointer changed; actual object is not available for local scanning.")
    if git_context.get("is_git_repo"):
        for rel in ctx.changed_files:
            mode = git_lines(ctx.repo, ["ls-files", "-s", "--", rel])
            if mode and mode[0].startswith("160000 "):
                findings.append(f"{rel}: submodule/gitlink changed.")
    if findings:
        return [failed("Repository Integrity", None, "Repository integrity checks failed.", findings[:60], score=25)]
    return [passed("Repository Integrity", None, "No symlink, submodule, LFS, Unicode, hidden-file, generated-artifact, binary, or path traversal issues detected.")]


def is_lfs_pointer(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size > 1024:
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    return text.startswith("version https://git-lfs.github.com/spec/v1")


def gate_repository_hygiene(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    results: list[CheckResult] = []
    branch = ctx.head_ref or ""
    branch_patterns = ctx.config.get("branch_naming", {}).get("allowed_patterns", [])
    if branch and any(re.match(pattern, branch) for pattern in branch_patterns):
        results.append(passed("Repository Hygiene", None, f"Branch name `{branch}` matches allowed convention."))
    elif branch:
        results.append(failed("Repository Hygiene", None, f"Branch name `{branch}` does not match allowed convention.", score=5))
    else:
        results.append(warning("Repository Hygiene", None, "Branch name could not be determined."))

    commits = git_context.get("commits", [])
    commit_patterns = ctx.config.get("commit_messages", {}).get("allowed_patterns", [])
    invalid_commits = [message for message in commits if not any(re.match(pattern, message) for pattern in commit_patterns)]
    if invalid_commits:
        results.append(failed("Repository Hygiene", None, "Commit messages do not match convention.", invalid_commits[:20], score=8))
    elif commits:
        results.append(passed("Repository Hygiene", None, "Commit messages match convention."))
    else:
        results.append(warning("Repository Hygiene", None, "Commit messages were not available for validation."))

    merge_marker_hits = grep_text_files(ctx.repo, ctx.changed_files, r"^(<<<<<<<|=======|>>>>>>>)")
    if merge_marker_hits:
        results.append(failed("Repository Hygiene", None, "Merge conflict markers found in changed files.", merge_marker_hits, score=20))
    else:
        results.append(passed("Repository Hygiene", None, "No merge conflict markers found in changed files."))

    if git_context.get("is_git_repo") and git_context.get("base_sha"):
        merge_base = git_lines(ctx.repo, ["merge-base", git_context["base_sha"], "HEAD"])
        merge_base_sha = merge_base[0] if merge_base else git_context["base_sha"]
        merge_commits = git_lines(ctx.repo, ["rev-list", "--merges", f"{merge_base_sha}..HEAD"])
        if merge_commits and not ctx.config.get("repository", {}).get("allow_merge_commits", False):
            results.append(failed("Repository Hygiene", None, "Accidental merge commits detected.", merge_commits[:20], score=8))
        else:
            results.append(passed("Repository Hygiene", None, "No accidental merge commits detected."))
    return results


def gate_git_validation(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    results: list[CheckResult] = []
    if ctx.diff_error:
        return [failed("Git Validation", None, "Base diff validation failed closed.", [ctx.diff_error], score=20)]
    if git_context.get("is_git_repo") and git_context.get("diff_range"):
        outcome = ctx.run(["git", "diff", "--check", git_context["diff_range"]], cwd=ctx.repo)
        if outcome.ok:
            results.append(passed("Git Validation", None, "`git diff --check` passed."))
        else:
            results.append(failed("Git Validation", None, "`git diff --check` found whitespace or marker issues.", [outcome.concise_output()], score=10))
    else:
        results.append(failed("Git Validation", None, "Git diff range was not available; failing closed.", score=20))
    crlf = []
    for rel in ctx.changed_files:
        path = ctx.repo / rel
        if path.is_file() and not is_binary_file(path):
            try:
                if b"\r\n" in path.read_bytes():
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
    findings, fixture_findings = fallback_secret_scan(ctx)
    if findings:
        results.append(failed("Secrets", None, "High-confidence secret indicators found in changed files.", findings[:60], score=40))
    elif results[0].status == PASS:
        results.append(passed("Secrets", None, "Fallback and encoded secret scans found no high-confidence issues."))
    if fixture_findings and not findings and results[0].status == PASS:
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
    if git_context.get("base_sha"):
        command.extend(["--log-opts", f"{git_context['base_sha']}..HEAD"])
    outcome = ctx.run(command, cwd=ctx.repo)
    if outcome.ok:
        return passed("Secrets", None, "Gitleaks scan passed.")
    return failed("Secrets", None, "Gitleaks detected secrets.", [outcome.concise_output()], score=40)


def fallback_secret_scan(ctx: PRContext) -> tuple[list[str], list[str]]:
    findings: list[str] = []
    fixture_findings: list[str] = []
    env_patterns = [".env", ".env.*"]
    allowed_env = {".env.example", ".env.sample", ".env.template", ".env.local.example"}
    regexes = {
        "AWS access key": r"AKIA[0-9A-Z]{16}",
        "private key": r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        "GitHub token": r"(ghp|github_pat)_[A-Za-z0-9_]{20,}",
        "generic credential assignment": r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
    }
    for rel in ctx.changed_files:
        rel_findings: list[str] = []
        path = ctx.repo / rel
        name = Path(rel).name
        if any(fnmatch.fnmatch(name, pattern) for pattern in env_patterns) and name not in allowed_env:
            rel_findings.append(f"{rel}: environment file committed.")
        if name.endswith((".pem", ".key", ".p12", ".pfx")):
            rel_findings.append(f"{rel}: key or certificate container committed.")
        if not path.is_file():
            findings.extend(rel_findings)
            continue
        texts = decoded_text_variants(path)
        for text in texts:
            normalized = normalize_secret_text(text)
            for label, pattern in regexes.items():
                if re.search(pattern, normalized):
                    rel_findings.append(f"{rel}: {label}.")
            for decoded in decode_base64_candidates(text, ctx.policy):
                for label, pattern in regexes.items():
                    if re.search(pattern, decoded):
                        rel_findings.append(f"{rel}: base64-encoded {label}.")
        if is_approved_regression_fixture(ctx, rel):
            fixture_findings.extend(rel_findings)
        else:
            findings.extend(rel_findings)
    return sorted(set(findings)), sorted(set(fixture_findings))


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
    for rel in ctx.changed_files:
        suffix = Path(rel).suffix
        if suffix in executable_extensions and suffix not in covered:
            unknown.append(rel)
    if unknown:
        return [failed("Executable Classification", None, "Executable code changed without a supported technology adapter.", unknown[:50], score=18)]
    return [passed("Executable Classification", None, "All changed executable code is covered by detected technology adapters.")]


def gate_protected_resources(ctx: PRContext, git_context: dict[str, Any]) -> list[CheckResult]:
    protected_patterns = ctx.config.get("repository", {}).get("protected_paths", [])
    changed = [path for path in ctx.changed_files if match_any(path, protected_patterns)]
    if any(path in {"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"} for path in ctx.changed_files):
        return [failed("Protected Resources", None, "CODEOWNERS changes are not allowed in PR QA guarded changes.", score=20)]
    if not changed:
        return [passed("Protected Resources", None, "No protected resources changed.")]
    codeowners = load_base_codeowners(ctx.repo, git_context)
    if not codeowners:
        return [failed("Protected Resources", None, "Protected resources changed but base-branch CODEOWNERS was not found.", changed[:30], score=14)]
    uncovered = [path for path in changed if not codeowners_covers(path, codeowners)]
    if uncovered:
        return [failed("Protected Resources", None, "Protected resources changed without base-branch CODEOWNERS coverage.", uncovered[:30], score=14)]
    return [warning("Protected Resources", None, "Protected resources changed; Branch Protection must enforce CODEOWNERS review.", changed[:30])]


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


def gate_deployment_safety(ctx: PRContext) -> list[CheckResult]:
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
    if not changed:
        return [passed("Deployment Risk", None, "No deployment-sensitive files changed.")]
    details = []
    score = 0
    risky_tokens = []
    for path in changed:
        text = read_text(ctx.repo / path)
        lower = (path + "\n" + text).lower()
        item_score = 5
        for token, value in {"production": 10, "prod": 8, "ssh": 12, "rsync": 12, "sudo": 12, "kubectl apply": 10, "terraform apply": 15}.items():
            if token in lower:
                item_score += value
                risky_tokens.append(f"{path}: `{token}`")
        if path.startswith(".github/workflows"):
            item_score += 8
        score += item_score
        details.append(f"{path}: +{item_score}")
    level = risk_class(min(score, 100))
    if risky_tokens and level in {"HIGH", "CRITICAL"}:
        return [failed("Deployment Risk", None, f"High-risk deployment change detected. Risk: {level}.", details[:30] + risky_tokens[:20], score=20)]
    return [warning("Deployment Risk", None, f"Deployment-sensitive changes detected. Risk: {level}.", details[:40])]


def gate_database_safety(ctx: PRContext) -> list[CheckResult]:
    migration_patterns = ["**/migrations/**", "**/migration/**", "database/**", "db/migrate/**", "**/*.sql"]
    migrations = [path for path in ctx.changed_files if match_any(path, migration_patterns)]
    if not migrations:
        return [passed("Migration Risk", None, "No database migration files changed.")]
    critical = []
    high = []
    medium = []
    for rel in migrations:
        text = read_text(ctx.repo / rel)
        upper = text.upper()
        collapsed = re.sub(r"[^A-Z]+", "", upper)
        if any(token in collapsed for token in ["DROPTABLE", "DROPDATABASE", "DROPSCHEMA", "TRUNCATE", "DELETEFROM"]) or re.search(r"drop(Column|IfExists|Table|Database|Schema)", text):
            critical.append(rel)
        elif re.search(r"\bDROP\s+COLUMN\b|\bRENAME\s+COLUMN\b|\bALTER\s+TABLE\b|dropColumn|renameColumn", text, re.IGNORECASE):
            high.append(rel)
        elif re.search(r"\bCREATE\s+TABLE\b|\bADD\s+COLUMN\b|\bCREATE\s+INDEX\b|createTable|addColumn", text, re.IGNORECASE):
            medium.append(rel)
    if critical:
        return [failed("Migration Risk", None, "CRITICAL migration risk: destructive database operations detected.", critical[:30], score=30)]
    if high:
        return [warning("Migration Risk", None, "HIGH migration risk: schema changes may be destructive or irreversible.", high[:30])]
    if medium:
        return [warning("Migration Risk", None, "MEDIUM migration risk: additive schema changes detected.", medium[:30])]
    return [warning("Migration Risk", None, "LOW migration risk: migration files changed without obvious destructive operations.", migrations[:30])]


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


def gate_risk(ctx: PRContext, existing_results: list[CheckResult]) -> list[CheckResult]:
    score = calculate_risk_score(ctx, existing_results)
    level = risk_class(score)
    details = [
        f"Changed files: {len(ctx.changed_files)}",
        f"Additions: {ctx.additions}",
        f"Deletions: {ctx.deletions}",
        f"Repository criticality: {ctx.config.get('repository', {}).get('criticality', 'medium')}",
    ]
    if score >= ctx.threshold("risk_fail", 85):
        return [failed("Risk Engine", None, f"Overall PR risk is {level}: {score} / 100.", details, score=score)]
    if score >= ctx.threshold("risk_warning", 40):
        return [warning("Risk Engine", None, f"Overall PR risk is {level}: {score} / 100.", details)]
    return [passed("Risk Engine", None, f"Overall PR risk is {level}: {score} / 100.", details)]


def calculate_risk_score(ctx: PRContext, results: list[CheckResult]) -> int:
    score = {"low": 0, "medium": 5, "high": 12, "critical": 20}.get(str(ctx.config.get("repository", {}).get("criticality", "medium")).lower(), 5)
    if len(ctx.changed_files) > ctx.threshold("max_changed_files", 200):
        score += 15
    elif len(ctx.changed_files) > 50:
        score += 8
    if ctx.additions > ctx.threshold("max_additions", 5000):
        score += 15
    elif ctx.additions > 1000:
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
        return [failed("Evidence", None, "Mandatory PR template evidence is missing or still placeholder text.", missing, score=10)]
    return [passed("Evidence", None, "Mandatory PR template evidence is complete.")]


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


def summarize(results: list[CheckResult], technologies: dict[str, dict[str, Any]], ctx: PRContext, git_context: dict[str, Any]) -> dict[str, Any]:
    gate_statuses = {}
    for _, display in GATE_ORDER:
        gate_statuses[display] = aggregate_status([result for result in results if result.gate == display])
    overall = FAIL if any(result.is_blocking_failure() for result in results) else PASS
    risk_result = next((result for result in results if result.gate == "Risk Engine"), None)
    return {
        "repository": resolve_repository_name(ctx),
        "base_ref": git_context.get("base_ref") or "",
        "head_ref": git_context.get("head_ref") or "",
        "detected_technologies": sorted(value["name"] for value in technologies.values()),
        "changed_files": len(ctx.changed_files),
        "additions": ctx.additions,
        "deletions": ctx.deletions,
        "gate_statuses": gate_statuses,
        "overall_result": overall,
        "merge_readiness": "READY FOR HUMAN REVIEW" if overall == PASS else "NOT READY FOR HUMAN REVIEW",
        "risk_score": extract_risk_score(risk_result.message if risk_result else ""),
        "policy_id": ctx.policy.get("policy_id", "unknown"),
    }


def resolve_repository_name(ctx: PRContext) -> str:
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
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(report, encoding="utf-8")
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(json_report, indent=2), encoding="utf-8")
    print(report)


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
    actor_authorized = actor in authorized_actors
    administrator_bypass_required = actor_authorized and actor == pr_author
    record = {
        "schema_version": 1,
        "type": "emergency_administrative_override",
        "decision": emergency_override_decision(actor_authorized, administrator_bypass_required),
        "authorized": actor_authorized,
        "actor_authorized": actor_authorized,
        "administrator_bypass_required": administrator_bypass_required,
        "self_approval_allowed": False,
        "self_merge_authorized": False,
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
            "No developer or Executive Release Authority may approve their own pull request.",
            "Executive-authored pull requests require GitHub Administrator Bypass after QA, with a mandatory reason and preserved QA evidence.",
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


def emergency_override_decision(actor_authorized: bool, administrator_bypass_required: bool) -> str:
    if not actor_authorized:
        return "REJECTED_UNAUTHORIZED_ACTOR"
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
        "",
        "| Gate | Result |",
        "| --- | --- |",
    ]
    for _, display in GATE_ORDER:
        lines.append(f"| {markdown_escape(display)} | {summary['gate_statuses'].get(display, SKIP)} |")
    lines.extend(["", f"Risk Score: {summary['risk_score']} / 100", "", f"Overall Result: {summary['overall_result']}", "", f"Merge Readiness: {summary['merge_readiness']}", ""])
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
    lines.append("This workflow validates and reports only. GitHub Branch Protection remains the authority for approvals, CODEOWNERS review, required checks, merge permissions, and merge decisions.")
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
