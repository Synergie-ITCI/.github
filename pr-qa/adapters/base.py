from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


PASS = "PASS"
WARNING = "WARNING"
FAIL = "FAIL"
SKIP = "SKIP"

BLOCKING_STATUSES = {FAIL}
MANDATORY_GATES = {
    "baseline_alignment",
    "repository_hygiene",
    "formatting",
    "lint",
    "build",
    "tests",
    "git_validation",
    "secrets",
    "dependencies",
    "licence",
    "deployment_safety",
    "database_safety",
    "documentation",
    "protected_resources",
    "review_policy",
    "risk",
    "evidence",
}
EXCLUDED_DIRS = {
    ".git",
    ".pr-qa-framework",
    ".pr-qa-technical-baseline",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "Pods",
    ".terraform",
    "target",
    "build",
    "dist",
    ".next",
    ".gradle",
    "pr-qa-results",
}


@dataclass
class CommandOutcome:
    command: str
    cwd: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    skipped: bool = False
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def concise_output(self, limit: int = 1600) -> str:
        output = "\n".join(part for part in [self.stdout, self.stderr] if part)
        output = redact(output.strip())
        if len(output) <= limit:
            return output
        return output[-limit:]

    def sanitized_dict(self) -> dict[str, Any]:
        return {
            "command": redact(self.command),
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "skipped": self.skipped,
            "duration_seconds": self.duration_seconds,
            "output_excerpt": self.concise_output(limit=600),
        }


@dataclass
class CheckResult:
    gate: str
    status: str
    message: str
    details: list[str] = field(default_factory=list)
    technology: str | None = None
    score: int = 0
    blocking: bool = True

    def is_blocking_failure(self) -> bool:
        return self.blocking and self.status in BLOCKING_STATUSES


@dataclass
class PRContext:
    repo: Path
    config: dict[str, Any]
    policy: dict[str, Any]
    changed_files: list[str]
    base_ref: str | None = None
    head_ref: str | None = None
    pr_body: str = ""
    event: dict[str, Any] = field(default_factory=dict)
    additions: int = 0
    deletions: int = 0
    no_command_runs: bool = False
    command_timeout_seconds: int = 1200
    config_violations: list[str] = field(default_factory=list)
    diff_error: str = ""
    prepared: set[str] = field(default_factory=set)
    command_log: list[dict[str, Any]] = field(default_factory=list)

    def adapter_config(self, key: str) -> dict[str, Any]:
        return dict(self.config.get("adapters", {}).get(key, {}) or {})

    def gate_enabled(self, gate: str) -> bool:
        if gate in set(self.policy.get("mandatory_gates", MANDATORY_GATES)):
            return True
        return bool(self.config.get("gates", {}).get(gate, True))

    def runtime_enabled(self, key: str, default: bool = True) -> bool:
        return bool(self.config.get("runtime", {}).get(key, default))

    def threshold(self, key: str, default: int) -> int:
        try:
            return int(self.config.get("thresholds", {}).get(key, default))
        except (TypeError, ValueError):
            return default

    def rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.repo.resolve()).as_posix()
        except ValueError:
            return path.as_posix()

    def changed_under(self, root: Path) -> list[str]:
        root_rel = self.rel(root)
        if root_rel == ".":
            return list(self.changed_files)
        prefix = root_rel.rstrip("/") + "/"
        return [path for path in self.changed_files if path == root_rel or path.startswith(prefix)]

    def run(
        self,
        args: list[str] | str,
        cwd: Path | None = None,
        timeout: int | None = None,
        shell: bool = False,
    ) -> CommandOutcome:
        working_dir = cwd or self.repo
        command_text = args if isinstance(args, str) else " ".join(args)
        if self.no_command_runs:
            outcome = CommandOutcome(command_text, str(working_dir), 0, skipped=True)
            self.command_log.append(outcome.sanitized_dict())
            return outcome
        started = time.time()
        try:
            completed = subprocess.run(
                args,
                cwd=str(working_dir),
                text=True,
                capture_output=True,
                timeout=timeout or self.command_timeout_seconds,
                shell=shell,
                check=False,
            )
            outcome = CommandOutcome(
                command=command_text,
                cwd=str(working_dir),
                exit_code=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                duration_seconds=round(time.time() - started, 3),
            )
        except subprocess.TimeoutExpired as exc:
            outcome = CommandOutcome(
                command=command_text,
                cwd=str(working_dir),
                exit_code=124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                timed_out=True,
                duration_seconds=round(time.time() - started, 3),
            )
        self.command_log.append(outcome.sanitized_dict())
        return outcome


class TechnologyAdapter:
    key = "base"
    name = "Base"

    def detect(self, repo: Path) -> list[Path]:
        raise NotImplementedError

    def format(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return []

    def lint(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return []

    def build(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return []

    def test(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return []

    def dependencies(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return []

    def licences(self, ctx: PRContext, roots: list[Path]) -> list[CheckResult]:
        return []


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def should_skip_path(path: Path) -> bool:
    return any(part in EXCLUDED_DIRS for part in path.parts)


def find_named_files(repo: Path, names: set[str]) -> list[Path]:
    matches: list[Path] = []
    for path in repo.rglob("*"):
        if path.is_file() and path.name in names and not should_skip_path(path.relative_to(repo)):
            matches.append(path)
    return sorted(matches)


def find_files(repo: Path, patterns: list[str]) -> list[Path]:
    matches: list[Path] = []
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo)
        if should_skip_path(rel):
            continue
        rel_text = rel.as_posix()
        if any(fnmatch.fnmatch(rel_text, pattern) for pattern in patterns):
            matches.append(path)
    return sorted(matches)


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def script_command(package_manager: str, script: str) -> list[str]:
    if package_manager == "yarn":
        return ["yarn", "run", script]
    if package_manager == "pnpm":
        return ["pnpm", "run", script]
    if package_manager == "bun":
        return ["bun", "run", script]
    return ["npm", "run", script]


def detect_package_manager(root: Path) -> str:
    if (root / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (root / "yarn.lock").exists():
        return "yarn"
    if (root / "bun.lockb").exists() or (root / "bun.lock").exists():
        return "bun"
    return "npm"


def first_existing_script(scripts: dict[str, Any], names: list[str]) -> str | None:
    for name in names:
        if name in scripts:
            return name
    return None


def command_result(
    gate: str,
    technology: str,
    outcome: CommandOutcome,
    pass_message: str,
    fail_message: str,
    warning_when_skipped: str | None = None,
    score: int = 0,
) -> CheckResult:
    if outcome.skipped and warning_when_skipped:
        return CheckResult(gate, WARNING, warning_when_skipped, technology=technology, blocking=False)
    if outcome.ok:
        return CheckResult(gate, PASS, pass_message, technology=technology)
    details = [f"`{outcome.command}` exited {outcome.exit_code}."]
    output = outcome.concise_output()
    if output:
        details.append(output)
    return CheckResult(gate, FAIL, fail_message, details, technology=technology, score=score)


def warning(gate: str, technology: str | None, message: str, details: list[str] | None = None) -> CheckResult:
    return CheckResult(gate, WARNING, message, details or [], technology=technology, blocking=False)


def passed(gate: str, technology: str | None, message: str, details: list[str] | None = None) -> CheckResult:
    return CheckResult(gate, PASS, message, details or [], technology=technology)


def failed(
    gate: str,
    technology: str | None,
    message: str,
    details: list[str] | None = None,
    score: int = 0,
) -> CheckResult:
    return CheckResult(gate, FAIL, message, details or [], technology=technology, score=score)


def skipped(gate: str, technology: str | None, message: str) -> CheckResult:
    return CheckResult(gate, SKIP, message, technology=technology, blocking=False)


def match_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def grep_text_files(repo: Path, paths: list[str], pattern: str, flags: int = 0) -> list[str]:
    regex = re.compile(pattern, flags)
    hits: list[str] = []
    for rel in paths:
        path = repo / rel
        if not path.is_file() or is_binary_file(path):
            continue
        text = read_text(path)
        for line_number, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                hits.append(f"{rel}:{line_number}")
    return hits


def is_binary_file(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\0" in chunk


def redact(text: str) -> str:
    replacements = [
        (r"AKIA[0-9A-Z]{16}", "AKIA[REDACTED]"),
        (r"(?i)(password|passwd|secret|token|api[_-]?key)(\s*[:=]\s*)(['\"]?)[^'\"\s]+", r"\1\2\3[REDACTED]"),
        (r"-----BEGIN [A-Z ]+PRIVATE KEY-----", "-----BEGIN [REDACTED] PRIVATE KEY-----"),
        (r"github_pat_[A-Za-z0-9_]+", "github_pat_[REDACTED]"),
        (r"ghp_[A-Za-z0-9_]+", "ghp_[REDACTED]"),
    ]
    redacted = text
    for pattern, replacement in replacements:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def markdown_escape(text: str) -> str:
    escaped = redact(str(text))
    return (
        escaped.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def restricted_license_hit(value: str) -> bool:
    normalized = str(value or "").upper()
    normalized = normalized.replace("(", " ").replace(")", " ").replace(",", " ")
    tokens = {token.strip() for token in re.split(r"\s+|/|\|", normalized) if token.strip()}
    if "AGPL" in normalized:
        return True
    if "UNKNOWN" in tokens or "UNLICENSED" in tokens:
        return True
    if "LGPL" in normalized:
        return False
    return bool(re.search(r"(^|[^A-Z])GPL($|[^A-Z])", normalized))
