#!/usr/bin/env python3
"""Synergie organisation PR quality gate.

The script runs inside the caller repository checked out by GitHub Actions.
It writes:
  - pr-qa-report.md
  - pr-qa-result.json

It intentionally does not approve, merge, modify source files, or change
repository settings.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path.cwd()
REPORT_MD = ROOT / "pr-qa-report.md"
REPORT_JSON = ROOT / "pr-qa-result.json"

DEFAULT_CHECKS = {
    "repository_hygiene": True,
    "formatting": True,
    "lint": True,
    "build": True,
    "tests": True,
    "git_validation": True,
    "secrets": True,
    "dependency_security": True,
    "licence_compliance": True,
    "deployment_risk": True,
    "migration_risk": True,
    "large_files": True,
    "documentation": True,
    "protected_resources": True,
    "ai_advisory": True,
    "risk_engine": True,
    "evidence_validation": True,
}

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |)PRIVATE KEY-----")),
    ("JWT secret assignment", re.compile(r"(?i)\b(jwt[_-]?secret|app[_-]?key|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}")),
    ("Password assignment", re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}")),
    ("Bearer token literal", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
]

SENSITIVE_FILE_PATTERNS = [
    re.compile(r"(^|/)\.env($|\.)"),
    re.compile(r"(?i)\.(pem|key|p12|pfx|jks|keystore)$"),
    re.compile(r"(?i)(keystorecred|credentials?|secrets?)$"),
]

DEPLOYMENT_PATH_PATTERNS = [
    ".github/workflows/",
    "deploy",
    "deployment",
    "Dockerfile",
    "docker-compose",
    "nginx",
    "apache",
    "terraform",
    ".tf",
    "k8s",
    "kubernetes",
    "systemd",
]

MIGRATION_PATTERNS = [
    re.compile(r"database/migrations/", re.I),
    re.compile(r"migrations?/.*\.(php|sql|py|js|ts)$", re.I),
]

PROTECTED_PATH_PATTERNS = [
    re.compile(r"^\.github/"),
    re.compile(r"^(deploy|deployment|infra|infrastructure|terraform|k8s|kubernetes)/", re.I),
    re.compile(r"(^|/)(Dockerfile|docker-compose\.ya?ml)$", re.I),
]

GENERATED_PATH_PATTERNS = [
    re.compile(r"(^|/)(dist|build|coverage|target|DerivedData|Pods)/"),
    re.compile(r"(?i)\.(min\.js|map|generated\.(js|ts|php|py|kt|swift))$"),
]

EVIDENCE_FIELDS = {
    "business purpose": ["business purpose", "purpose"],
    "testing performed": ["testing performed", "testing", "qa evidence"],
    "rollback strategy": ["rollback strategy", "rollback"],
    "linked issue": ["linked issue", "issue", "ticket", "jira"],
    "screenshots": ["screenshots", "screenshots / evidence", "evidence"],
}


@dataclass
class AdapterCommand:
    label: str
    args: list[str]
    timeout: int = 900
    env: dict[str, str] = field(default_factory=dict)
    cwd: Path | None = None


class TechnologyAdapter:
    name = "Unknown"

    def detect(self, root: Path) -> bool:
        return False

    def labels(self, root: Path) -> list[str]:
        return [self.name]

    def setup(self, gate: "Gate") -> None:
        return

    def formatting(self, gate: "Gate") -> list[AdapterCommand]:
        return []

    def lint(self, gate: "Gate") -> list[AdapterCommand]:
        return []

    def build(self, gate: "Gate") -> list[AdapterCommand]:
        return []

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        return []

    def dependency_audit(self, gate: "Gate") -> list[AdapterCommand]:
        return []


class NodeAdapter(TechnologyAdapter):
    name = "Node"

    def detect(self, root: Path) -> bool:
        return (root / "package.json").exists()

    def labels(self, root: Path) -> list[str]:
        labels = ["Node"]
        text = (root / "package.json").read_text(encoding="utf-8", errors="replace")
        if "typescript" in text:
            labels.append("TypeScript")
        if "react-native" in text:
            labels.append("React Native")
        elif "react" in text:
            labels.append("React")
        return labels

    def setup(self, gate: "Gate") -> None:
        gate.ensure_node_dependencies()

    def formatting(self, gate: "Gate") -> list[AdapterCommand]:
        scripts = gate.package_scripts()
        for script in ("format:check", "prettier:check"):
            if script in scripts and shutil.which("npm"):
                return [AdapterCommand(f"npm run {script}", ["npm", "run", script], env={"CI": "true"})]
        return []

    def lint(self, gate: "Gate") -> list[AdapterCommand]:
        scripts = gate.package_scripts()
        if "lint" in scripts and shutil.which("npm"):
            return [AdapterCommand("npm run lint", ["npm", "run", "lint"], env={"CI": "true"})]
        return []

    def build(self, gate: "Gate") -> list[AdapterCommand]:
        scripts = gate.package_scripts()
        if "build" in scripts and shutil.which("npm"):
            return [AdapterCommand("npm run build", ["npm", "run", "build"], timeout=1200, env={"CI": "true"})]
        return []

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        scripts = gate.package_scripts()
        if "test" in scripts and shutil.which("npm"):
            return [AdapterCommand("npm test", ["npm", "test"], timeout=1200, env={"CI": "true", "WATCHMAN_DISABLE": "1"})]
        return []

    def dependency_audit(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("npm"):
            return [AdapterCommand("npm audit --audit-level=high", ["npm", "audit", "--audit-level=high"], timeout=600)]
        return []


class PHPAdapter(TechnologyAdapter):
    name = "PHP"

    def detect(self, root: Path) -> bool:
        return (root / "composer.json").exists() or any(root.glob("**/*.php"))

    def labels(self, root: Path) -> list[str]:
        labels = ["PHP"]
        if (root / "artisan").exists():
            labels.append("Laravel")
        return labels

    def setup(self, gate: "Gate") -> None:
        gate.ensure_php_dependencies()

    def lint(self, gate: "Gate") -> list[AdapterCommand]:
        commands = []
        for path in gate.changed_files:
            if path.endswith(".php") and (ROOT / path).exists() and shutil.which("php"):
                commands.append(AdapterCommand(f"php -l {path}", ["php", "-l", path], timeout=120))
        return commands

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        phpunit = ROOT / "vendor/bin/phpunit"
        if phpunit.exists():
            return [AdapterCommand("vendor/bin/phpunit", [str(phpunit)], timeout=1200)]
        return []

    def dependency_audit(self, gate: "Gate") -> list[AdapterCommand]:
        if (ROOT / "composer.json").exists() and shutil.which("composer"):
            return [AdapterCommand("composer audit", ["composer", "audit", "--no-interaction"], timeout=600)]
        return []


class GradleAdapter(TechnologyAdapter):
    name = "Kotlin/Gradle"

    def detect(self, root: Path) -> bool:
        return (root / "gradlew").exists() or (root / "build.gradle").exists() or (root / "build.gradle.kts").exists()

    def build(self, gate: "Gate") -> list[AdapterCommand]:
        if (ROOT / "gradlew").exists():
            return [AdapterCommand("./gradlew assemble", ["./gradlew", "assemble"], timeout=1800)]
        return []

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        if (ROOT / "gradlew").exists():
            return [AdapterCommand("./gradlew test", ["./gradlew", "test"], timeout=1800)]
        return []


class SwiftAdapter(TechnologyAdapter):
    name = "Swift"

    def detect(self, root: Path) -> bool:
        return any(root.glob("**/Package.swift"))

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        commands = []
        for package_swift in sorted(ROOT.glob("**/Package.swift")):
            if shutil.which("swift"):
                commands.append(AdapterCommand(f"swift test ({package_swift.parent})", ["swift", "test"], timeout=1200, cwd=package_swift.parent))
        return commands


class PythonAdapter(TechnologyAdapter):
    name = "Python"

    def detect(self, root: Path) -> bool:
        return (root / "pyproject.toml").exists() or (root / "requirements.txt").exists()

    def lint(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("ruff") and (ROOT / "pyproject.toml").exists():
            return [AdapterCommand("ruff check .", ["ruff", "check", "."], timeout=600)]
        return []

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("pytest"):
            return [AdapterCommand("pytest", ["pytest"], timeout=1200)]
        return []

    def dependency_audit(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("pip-audit"):
            return [AdapterCommand("pip-audit", ["pip-audit"], timeout=600)]
        return []


class GoAdapter(TechnologyAdapter):
    name = "Go"

    def detect(self, root: Path) -> bool:
        return (root / "go.mod").exists()

    def build(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("go"):
            return [AdapterCommand("go test ./...", ["go", "test", "./..."], timeout=900)]
        return []

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        return []


class RustAdapter(TechnologyAdapter):
    name = "Rust"

    def detect(self, root: Path) -> bool:
        return (root / "Cargo.toml").exists()

    def formatting(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("cargo"):
            return [AdapterCommand("cargo fmt --check", ["cargo", "fmt", "--check"], timeout=600)]
        return []

    def lint(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("cargo"):
            return [AdapterCommand("cargo clippy -- -D warnings", ["cargo", "clippy", "--", "-D", "warnings"], timeout=1200)]
        return []

    def build(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("cargo"):
            return [AdapterCommand("cargo build", ["cargo", "build"], timeout=1200)]
        return []

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("cargo"):
            return [AdapterCommand("cargo test", ["cargo", "test"], timeout=1200)]
        return []


class DotNetAdapter(TechnologyAdapter):
    name = ".NET"

    def detect(self, root: Path) -> bool:
        return any(root.glob("*.sln")) or any(root.glob("**/*.csproj"))

    def build(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("dotnet"):
            return [AdapterCommand("dotnet build", ["dotnet", "build", "--no-restore"], timeout=1200)]
        return []

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("dotnet"):
            return [AdapterCommand("dotnet test", ["dotnet", "test", "--no-build"], timeout=1200)]
        return []


class MavenAdapter(TechnologyAdapter):
    name = "Java/Maven"

    def detect(self, root: Path) -> bool:
        return (root / "pom.xml").exists()

    def build(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("mvn"):
            return [AdapterCommand("mvn -DskipTests package", ["mvn", "-DskipTests", "package"], timeout=1800)]
        return []

    def tests(self, gate: "Gate") -> list[AdapterCommand]:
        if shutil.which("mvn"):
            return [AdapterCommand("mvn test", ["mvn", "test"], timeout=1800)]
        return []


ALL_ADAPTERS: list[TechnologyAdapter] = [
    NodeAdapter(),
    PHPAdapter(),
    GradleAdapter(),
    SwiftAdapter(),
    PythonAdapter(),
    GoAdapter(),
    RustAdapter(),
    DotNetAdapter(),
    MavenAdapter(),
]


@dataclass
class Finding:
    severity: str
    check: str
    message: str
    path: str = ""
    line: int | None = None


@dataclass
class CheckResult:
    name: str
    status: str = "SKIPPED"
    detail: str = ""
    findings: list[Finding] = field(default_factory=list)


class Gate:
    def __init__(self) -> None:
        self.config = self.load_config()
        self.results: dict[str, CheckResult] = {}
        self.changed_files = self.get_changed_files()
        self.adapters = self.detect_adapters()
        self.technologies = self.detect_technologies()
        self.failures: list[Finding] = []
        self.warnings: list[Finding] = []
        self.risk_score = 0
        self.risk_level = "LOW"

    def enabled(self, check: str) -> bool:
        return bool(self.config["checks"].get(check, True))

    def load_config(self) -> dict[str, Any]:
        config: dict[str, Any] = {
            "checks": dict(DEFAULT_CHECKS),
            "large_file_threshold_mb": int(os.getenv("PR_QA_LARGE_FILE_THRESHOLD_MB", "10")),
            "fail_on_dependency_vulnerabilities": os.getenv("PR_QA_FAIL_ON_DEPENDENCY_VULNERABILITIES", "false").lower() == "true",
            "evidence_enforcement": os.getenv("PR_QA_EVIDENCE_ENFORCEMENT", "fail"),
            "repository_criticality": os.getenv("PR_QA_REPOSITORY_CRITICALITY", "medium"),
            "max_changed_files_for_low_risk": int(os.getenv("PR_QA_MAX_CHANGED_FILES_FOR_LOW_RISK", "20")),
        }
        config_path = ROOT / os.getenv("PR_QA_CONFIG_PATH", ".github/pr-qa.yml")
        if not config_path.exists():
            return config

        current_section = ""
        for raw in config_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if not line.startswith(" ") and line.endswith(":"):
                current_section = line[:-1].strip()
                continue
            if ":" not in line:
                continue
            key, value = [part.strip() for part in line.split(":", 1)]
            value_bool = value.lower() in {"true", "yes", "on", "1"}
            if current_section == "checks" and key in config["checks"]:
                config["checks"][key] = value_bool
            elif key == "large_file_threshold_mb":
                try:
                    config["large_file_threshold_mb"] = int(value)
                except ValueError:
                    pass
            elif key == "fail_on_dependency_vulnerabilities":
                config["fail_on_dependency_vulnerabilities"] = value_bool
            elif key == "evidence_enforcement" and value.lower() in {"fail", "warn"}:
                config["evidence_enforcement"] = value.lower()
            elif key == "repository_criticality":
                config["repository_criticality"] = value.lower()
            elif key == "max_changed_files_for_low_risk":
                try:
                    config["max_changed_files_for_low_risk"] = int(value)
                except ValueError:
                    pass
        return config

    def run(self) -> int:
        self.check_repository_hygiene()
        self.check_git_validation()
        self.check_secrets()
        self.check_large_files()
        self.check_deployment_risk()
        self.check_migration_risk()
        self.check_licence_compliance()
        self.check_documentation()
        self.check_protected_resources()
        self.check_formatting()
        self.check_lint()
        self.check_build()
        self.check_tests()
        self.check_dependency_security()
        self.check_evidence_validation()
        self.check_ai_advisory()
        self.check_risk_engine()
        self.write_outputs()
        return 0

    def command(
        self,
        args: list[str],
        timeout: int = 900,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        merged_env = os.environ.copy()
        merged_env.update(env or {})
        return subprocess.run(args, cwd=cwd or ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=merged_env)

    def shell(self, cmd: str, timeout: int = 900, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged_env = os.environ.copy()
        merged_env.update(env or {})
        return subprocess.run(cmd, cwd=ROOT, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=merged_env)

    def record(self, result: CheckResult) -> None:
        self.results[result.name] = result
        for finding in result.findings:
            if finding.severity == "fail":
                self.failures.append(finding)
            elif finding.severity == "warn":
                self.warnings.append(finding)
            self.annotate(finding)

    def annotate(self, finding: Finding) -> None:
        level = "error" if finding.severity == "fail" else "warning"
        msg = finding.message.replace("\n", " ").replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        if finding.path:
            line = f",line={finding.line}" if finding.line else ""
            print(f"::{level} file={finding.path}{line}::{msg}")
        else:
            print(f"::{level}::{msg}")

    def get_changed_files(self) -> list[str]:
        base = os.getenv("PR_QA_BASE_SHA") or os.getenv("GITHUB_BASE_REF") or "origin/main"
        head = os.getenv("PR_QA_HEAD_SHA") or "HEAD"
        cp = self.command(["git", "diff", "--name-only", f"{base}..{head}"], timeout=120)
        if cp.returncode != 0:
            cp = self.command(["git", "diff", "--name-only", "HEAD~1..HEAD"], timeout=120)
        return [line.strip() for line in cp.stdout.splitlines() if line.strip()]

    def detect_technologies(self) -> list[str]:
        tech: list[str] = []
        for adapter in self.adapters:
            for label in adapter.labels(ROOT):
                if label not in tech:
                    tech.append(label)
        if any((ROOT / path).exists() for path in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml")):
            tech.append("Docker")
        if any(ROOT.glob("**/*.tf")):
            tech.append("Terraform")
        if any(ROOT.glob(".github/workflows/*.y*ml")):
            tech.append("GitHub Actions")
        if any("kind:" in p.read_text(encoding="utf-8", errors="ignore")[:2000] for p in ROOT.glob("**/*.y*ml") if p.is_file() and p.stat().st_size < 200_000):
            tech.append("Kubernetes")
        return tech or ["Unknown"]

    def detect_adapters(self) -> list[TechnologyAdapter]:
        return [adapter for adapter in ALL_ADAPTERS if adapter.detect(ROOT)]

    def read_package_json(self) -> dict[str, Any]:
        try:
            return json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        except Exception:
            return {}

    def package_scripts(self) -> dict[str, Any]:
        package = self.read_package_json()
        scripts = package.get("scripts", {})
        return scripts if isinstance(scripts, dict) else {}

    def run_adapter_commands(self, check: str, commands: list[AdapterCommand], fail_message: str) -> CheckResult:
        findings: list[Finding] = []
        ran: list[str] = []
        for command in commands:
            ran.append(command.label)
            cp = self.command(command.args, timeout=command.timeout, env=command.env, cwd=command.cwd)
            if cp.returncode != 0:
                findings.append(Finding("fail", check, fail_message.format(label=command.label)))
        status = "FAIL" if findings else "PASS"
        return CheckResult(check, status, ", ".join(ran), findings)

    def ensure_node_dependencies(self) -> None:
        if not (ROOT / "package.json").exists() or (ROOT / "node_modules").exists():
            return
        if shutil.which("npm") is None:
            return
        if (ROOT / "package-lock.json").exists():
            self.command(["npm", "ci", "--ignore-scripts"], timeout=1200)
        else:
            self.command(["npm", "install", "--ignore-scripts"], timeout=1200)

    def ensure_php_dependencies(self) -> None:
        if not (ROOT / "composer.json").exists() or (ROOT / "vendor").exists() or shutil.which("composer") is None:
            return
        self.command(["composer", "install", "--no-interaction", "--prefer-dist", "--no-progress"], timeout=1200)

    def check_git_validation(self) -> None:
        name = "Git Validation"
        if not self.enabled("git_validation"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        base = os.getenv("PR_QA_BASE_SHA") or "HEAD~1"
        head = os.getenv("PR_QA_HEAD_SHA") or "HEAD"
        cp = self.command(["git", "diff", "--check", f"{base}..{head}"], timeout=120)
        findings = []
        if cp.returncode != 0:
            for line in cp.stdout.splitlines():
                match = re.match(r"([^:]+):(\d+):\s*(.*)", line)
                if match:
                    findings.append(Finding("fail", name, match.group(3), match.group(1), int(match.group(2))))
                elif line.strip():
                    findings.append(Finding("fail", name, line.strip()))
        self.record(CheckResult(name, "FAIL" if findings else "PASS", "git diff --check completed.", findings))

    def check_repository_hygiene(self) -> None:
        name = "Repository Hygiene"
        if not self.enabled("repository_hygiene"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings: list[Finding] = []
        branch = os.getenv("GITHUB_HEAD_REF") or self.command(["git", "rev-parse", "--abbrev-ref", "HEAD"], timeout=120).stdout.strip()
        if branch and branch != "HEAD" and not re.match(r"^(feature|fix|bugfix|hotfix|chore|ci|docs|refactor|test|release|codex)/[A-Za-z0-9._/-]+$", branch):
            findings.append(Finding("warn", name, f"Branch name `{branch}` does not follow the expected prefix/name convention."))

        base = os.getenv("PR_QA_BASE_SHA") or "HEAD~1"
        head = os.getenv("PR_QA_HEAD_SHA") or "HEAD"
        merges = self.command(["git", "rev-list", "--merges", f"{base}..{head}"], timeout=120)
        if merges.returncode == 0 and merges.stdout.strip():
            findings.append(Finding("warn", name, "PR contains merge commits. Prefer rebasing or a clean feature branch unless intentionally preserving history."))

        subjects = self.command(["git", "log", "--format=%s", f"{base}..{head}"], timeout=120)
        nonconforming = []
        if subjects.returncode == 0:
            for subject in subjects.stdout.splitlines():
                if subject and not re.match(r"^(feat|fix|docs|style|refactor|test|chore|ci|build|perf|revert)(\([^)]+\))?: .+", subject):
                    nonconforming.append(subject)
        if nonconforming:
            findings.append(Finding("warn", name, f"{len(nonconforming)} commit message(s) do not follow Conventional Commits."))

        for path in self.changed_files:
            if any(pattern.search(path) for pattern in GENERATED_PATH_PATTERNS):
                findings.append(Finding("warn", name, "Generated/build artifact changed; confirm this belongs in source control.", path, 1))
            file_path = ROOT / path
            if file_path.exists() and file_path.is_file() and file_path.stat().st_size < 2_000_000:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
                if re.search(r"^<<<<<<< |^=======|^>>>>>>> ", text, re.M):
                    findings.append(Finding("fail", name, "Merge conflict marker detected in changed file.", path, 1))
        self.record(CheckResult(name, "FAIL" if any(f.severity == "fail" for f in findings) else ("WARN" if findings else "PASS"), "Repository hygiene checks completed.", findings))

    def check_secrets(self) -> None:
        name = "Secrets"
        if not self.enabled("secrets"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings: list[Finding] = []
        for path in self.changed_files:
            if not Path(path).exists():
                continue
            if any(pattern.search(path) for pattern in SENSITIVE_FILE_PATTERNS):
                findings.append(Finding("fail", name, "Sensitive credential-like file is part of this PR.", path, 1))
                continue
            file_path = ROOT / path
            if file_path.is_dir() or file_path.stat().st_size > 2_000_000:
                continue
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue
            for idx, line in enumerate(lines, start=1):
                for label, pattern in SECRET_PATTERNS:
                    if pattern.search(line):
                        findings.append(Finding("fail", name, f"Possible confirmed secret detected: {label}.", path, idx))
                        break
        if shutil.which("gitleaks"):
            cp = self.command(["gitleaks", "detect", "--no-banner", "--redact", "--source", str(ROOT)], timeout=600)
            if cp.returncode != 0:
                findings.append(Finding("fail", name, "Gitleaks reported one or more secret findings. See workflow logs."))
        detail = "Heuristic secret scan completed."
        if not shutil.which("gitleaks"):
            detail += " Gitleaks was not available on this runner."
        self.record(CheckResult(name, "FAIL" if findings else "PASS", detail, findings))

    def check_large_files(self) -> None:
        name = "Large Files"
        if not self.enabled("large_files"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        threshold = int(self.config["large_file_threshold_mb"]) * 1024 * 1024
        findings = []
        for path in self.changed_files:
            file_path = ROOT / path
            if file_path.exists() and file_path.is_file() and file_path.stat().st_size > threshold:
                findings.append(Finding("warn", name, f"Large file added or changed: {file_path.stat().st_size} bytes.", path, 1))
            if re.search(r"(?i)\.(zip|tar|tgz|gz|7z|mp4|mov|avi|dmg|iso|sqlite|db|csv)$", path):
                findings.append(Finding("warn", name, "Archive, binary, dataset, or generated asset changed; confirm this belongs in Git.", path, 1))
        self.record(CheckResult(name, "WARN" if findings else "PASS", f"Threshold: {self.config['large_file_threshold_mb']} MB.", findings))

    def check_deployment_risk(self) -> None:
        name = "Deployment Risk"
        if not self.enabled("deployment_risk"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings = []
        risky_files = [p for p in self.changed_files if any(token.lower() in p.lower() for token in DEPLOYMENT_PATH_PATTERNS)]
        for path in risky_files:
            findings.append(Finding("warn", name, "Deployment/infrastructure-related file changed; reviewer should inspect manually.", path, 1))
        diff = self.command(["git", "diff", "--unified=0", os.getenv("PR_QA_BASE_SHA", "HEAD~1") + ".." + os.getenv("PR_QA_HEAD_SHA", "HEAD")], timeout=120).stdout
        for idx, line in enumerate(diff.splitlines(), start=1):
            if line.startswith("+") and re.search(r"(?i)(ssh|rsync|PROD_|production|aws_access_key|secret|deploy|kubectl|terraform)", line):
                findings.append(Finding("warn", name, "Production/deployment-sensitive command or credential handling changed."))
                break
        self.record(CheckResult(name, "WARN" if findings else "LOW", "Deployment risk analysis completed.", findings))

    def check_migration_risk(self) -> None:
        name = "Migration Risk"
        if not self.enabled("migration_risk"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings = []
        status = "LOW"
        for path in self.changed_files:
            if not any(pattern.search(path) for pattern in MIGRATION_PATTERNS):
                continue
            text = (ROOT / path).read_text(encoding="utf-8", errors="ignore") if (ROOT / path).exists() else ""
            if re.search(r"(?i)\b(drop\s+table|drop\s+column|alter\s+primary\s+key|rename\s+column|truncate)\b", text):
                status = "CRITICAL"
                findings.append(Finding("warn", name, "Destructive or irreversible migration detected. Manual release review and rollback evidence required.", path, 1))
            elif re.search(r"(?is)\b(delete\s+from|update\s+\w+\s+set)\b(?![^;]*\bwhere\b)", text):
                status = "HIGH" if status != "CRITICAL" else status
                findings.append(Finding("warn", name, "Potentially destructive data update without an obvious WHERE clause detected.", path, 1))
            elif re.search(r"(?i)\b(alter\s+table|modify\s+column|change\s+column)\b", text):
                status = "MEDIUM" if status not in {"HIGH", "CRITICAL"} else status
                findings.append(Finding("warn", name, "Schema-altering migration detected. Confirm manual migration/runbook plan.", path, 1))
            else:
                findings.append(Finding("warn", name, "Migration file changed. Confirm rollout and rollback plan.", path, 1))
        self.record(CheckResult(name, status, "Migration risk analysis completed.", findings))

    def check_licence_compliance(self) -> None:
        name = "Licence Compliance"
        if not self.enabled("licence_compliance"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings: list[Finding] = []
        paths = [p for p in self.changed_files if re.search(r"(?i)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|composer\.lock|go\.sum|Cargo\.lock|LICENSE|NOTICE)", p)]
        for path in paths:
            file_path = ROOT / path
            if not file_path.exists() or file_path.stat().st_size > 5_000_000:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"(?i)\b(AGPL|GPL-?3|GPL-?2|GNU GENERAL PUBLIC LICENSE)\b", text):
                findings.append(Finding("warn", name, "GPL/AGPL-family licence reference detected; confirm licence compatibility before merge.", path, 1))
            if re.search(r"(?i)\"license\"\s*:\s*\"(UNKNOWN|UNLICENSED)\"", text):
                findings.append(Finding("warn", name, "Unknown or unlicensed dependency metadata detected.", path, 1))
        self.record(CheckResult(name, "WARN" if findings else "PASS", "Licence compliance scan completed.", findings))

    def check_documentation(self) -> None:
        name = "Documentation"
        if not self.enabled("documentation"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        config_like = [p for p in self.changed_files if re.search(r"(?i)(\.env\.example|config|settings|routes|api|openapi|swagger|deployment|docker|workflow)", p)]
        docs = [p for p in self.changed_files if re.search(r"(?i)(README|DEPLOYMENT|docs/|CHANGELOG|\.env\.example)", p)]
        findings = []
        if config_like and not docs:
            findings.append(Finding("warn", name, "Configuration/API/deployment-related changes detected without accompanying docs or example config update."))
        self.record(CheckResult(name, "WARN" if findings else "PASS", "Documentation impact check completed.", findings))

    def check_protected_resources(self) -> None:
        name = "Protected Resource Validation"
        if not self.enabled("protected_resources"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings: list[Finding] = []
        protected_files = [p for p in self.changed_files if any(pattern.search(p) for pattern in PROTECTED_PATH_PATTERNS)]
        if protected_files:
            codeowners_exists = any((ROOT / p).exists() for p in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"))
            for path in protected_files:
                findings.append(Finding("warn", name, "Protected path changed; ensure CODEOWNERS review and explicit operational approval before merge.", path, 1))
            if not codeowners_exists:
                findings.append(Finding("warn", name, "Protected paths changed but no CODEOWNERS file was found in a recognised location."))
        self.record(CheckResult(name, "WARN" if findings else "PASS", "Protected resource validation completed.", findings))

    def check_formatting(self) -> None:
        name = "Formatting"
        if not self.enabled("formatting"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        commands: list[AdapterCommand] = []
        for adapter in self.adapters:
            adapter.setup(self)
            commands.extend(adapter.formatting(self))
        if not commands:
            self.record(CheckResult(name, "PASS", "No formatter check configured."))
        else:
            self.record(self.run_adapter_commands(name, commands, "`{label}` failed."))

    def check_lint(self) -> None:
        name = "Lint"
        if not self.enabled("lint"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        commands: list[AdapterCommand] = []
        for adapter in self.adapters:
            adapter.setup(self)
            commands.extend(adapter.lint(self))
        if not commands:
            self.record(CheckResult(name, "PASS", "No lint configuration detected."))
        else:
            self.record(self.run_adapter_commands(name, commands, "`{label}` failed."))

    def check_build(self) -> None:
        name = "Build"
        if not self.enabled("build"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        commands: list[AdapterCommand] = []
        for adapter in self.adapters:
            adapter.setup(self)
            commands.extend(adapter.build(self))
        if not commands:
            self.record(CheckResult(name, "PASS", "No build step configured."))
        else:
            self.record(self.run_adapter_commands(name, commands, "`{label}` failed."))

    def check_tests(self) -> None:
        name = "Tests"
        if not self.enabled("tests"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        commands: list[AdapterCommand] = []
        for adapter in self.adapters:
            adapter.setup(self)
            commands.extend(adapter.tests(self))
        if not commands:
            self.record(CheckResult(name, "PASS", "No automated test suite configured."))
        else:
            self.record(self.run_adapter_commands(name, commands, "`{label}` failed."))

    def check_dependency_security(self) -> None:
        name = "Dependency Security"
        if not self.enabled("dependency_security"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings = []
        ran = []
        fail_on_vuln = bool(self.config["fail_on_dependency_vulnerabilities"])
        commands: list[AdapterCommand] = []
        for adapter in self.adapters:
            adapter.setup(self)
            commands.extend(adapter.dependency_audit(self))
        for command in commands:
            ran.append(command.label)
            cp = self.command(command.args, timeout=command.timeout, env=command.env, cwd=command.cwd)
            if cp.returncode != 0:
                findings.append(Finding("fail" if fail_on_vuln else "warn", name, f"`{command.label}` reported vulnerabilities."))
        self.record(CheckResult(name, "FAIL" if any(f.severity == "fail" for f in findings) else ("WARN" if findings else "PASS"), ", ".join(ran) if ran else "No supported dependency audit configured.", findings))

    def check_ai_advisory(self) -> None:
        name = "AI Advisory"
        if not self.enabled("ai_advisory"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings = []
        if len(self.changed_files) > 100:
            findings.append(Finding("warn", name, "Large PR footprint; consider splitting or adding focused reviewer notes."))
        for path in self.changed_files:
            if path.endswith((".js", ".ts", ".tsx", ".php", ".py", ".kt", ".swift")) and (ROOT / path).exists():
                text = (ROOT / path).read_text(encoding="utf-8", errors="ignore")
                if "console.log(" in text or "var_dump(" in text or "print_r(" in text:
                    findings.append(Finding("warn", name, "Debug logging statement detected; confirm no sensitive data is logged.", path, 1))
                    break
        self.record(CheckResult(name, "INFO", "Advisory-only heuristic review. This check never blocks merges.", findings))

    def check_evidence_validation(self) -> None:
        name = "Evidence Validation"
        if not self.enabled("evidence_validation"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        body = self.pr_body()
        severity = "fail" if self.config.get("evidence_enforcement") == "fail" else "warn"
        findings: list[Finding] = []
        if not body.strip():
            findings.append(Finding(severity, name, "PR body is empty. Complete the standard PR template before merge."))
        else:
            lower = body.lower()
            for field, aliases in EVIDENCE_FIELDS.items():
                if not any(alias in lower for alias in aliases):
                    findings.append(Finding(severity, name, f"PR evidence is missing mandatory field: {field}."))
                elif field != "screenshots" and not self.section_has_content(body, aliases):
                    findings.append(Finding(severity, name, f"PR evidence field appears incomplete: {field}."))
        status = "FAIL" if any(f.severity == "fail" for f in findings) else ("WARN" if findings else "PASS")
        self.record(CheckResult(name, status, f"Evidence enforcement mode: {self.config.get('evidence_enforcement')}.", findings))

    def pr_body(self) -> str:
        event_path = os.getenv("GITHUB_EVENT_PATH")
        if event_path and Path(event_path).exists():
            try:
                event = json.loads(Path(event_path).read_text(encoding="utf-8"))
                return (event.get("pull_request") or {}).get("body") or ""
            except Exception:
                return ""
        return os.getenv("PR_QA_PR_BODY", "")

    def section_has_content(self, body: str, aliases: list[str]) -> bool:
        lines = body.splitlines()
        start = None
        for idx, line in enumerate(lines):
            normalized = re.sub(r"[*_#:\[\]\-]", "", line.lower()).strip()
            if any(alias in normalized for alias in aliases):
                start = idx + 1
                break
        if start is None:
            return False
        collected: list[str] = []
        for line in lines[start:]:
            stripped = line.strip()
            if stripped.startswith("#") or re.match(r"^\*\*.+\*\*\s*:?\s*$", stripped):
                break
            if stripped and not re.match(r"(?i)^(-|\[ \]|n/?a|none|todo|tbd|not done)$", stripped):
                collected.append(stripped)
        return bool(collected)

    def check_risk_engine(self) -> None:
        name = "Risk Engine"
        if not self.enabled("risk_engine"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        score = 0
        score += min(20, max(0, len(self.changed_files) - int(self.config["max_changed_files_for_low_risk"])) // 5 * 2)
        criticality = str(self.config.get("repository_criticality", "medium")).lower()
        score += {"low": 0, "medium": 5, "high": 10, "critical": 15}.get(criticality, 5)
        for finding in self.failures:
            if finding.check == "Secrets":
                score += 50
            elif finding.check in {"Build", "Tests", "Lint", "Git Validation", "Evidence Validation"}:
                score += 20
            else:
                score += 10
        for finding in self.warnings:
            if finding.check == "Migration Risk" and "Destructive" in finding.message:
                score += 25
            elif finding.check == "Migration Risk":
                score += 15
            elif finding.check == "Deployment Risk":
                score += 15
            elif finding.check == "Protected Resource Validation":
                score += 10
            elif finding.check in {"Dependency Security", "Licence Compliance"}:
                score += 8
            else:
                score += 3
        score = min(score, 100)
        if score >= 80:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"
        self.risk_score = score
        self.risk_level = level
        findings = []
        if level in {"HIGH", "CRITICAL"}:
            findings.append(Finding("warn", name, f"Overall PR risk is {level}. Human reviewer should inspect operational/security evidence before merge."))
        self.record(CheckResult(name, level, f"Risk Score: {score} / 100. Repository criticality: {criticality}.", findings))

    def write_outputs(self) -> None:
        overall = "FAIL" if self.failures else "PASS"
        readiness = "NOT READY" if self.failures else "READY FOR REVIEW"
        lines = [
            "<!-- synergie-pr-qa-report -->",
            "========================================",
            "",
            "PR QUALITY REPORT",
            "",
            f"Repository: {os.getenv('GITHUB_REPOSITORY', ROOT.name)}",
            f"Detected Technologies: {', '.join(self.technologies)}",
            "",
        ]
        for result in self.results.values():
            lines.extend([result.name, result.status, result.detail, ""])
        if self.failures:
            lines.append("Blocking Findings")
            for finding in self.failures:
                location = f" ({finding.path}:{finding.line})" if finding.path else ""
                lines.append(f"- {finding.check}{location}: {finding.message}")
            lines.append("")
        if self.warnings:
            lines.append("Warnings")
            for finding in self.warnings[:30]:
                location = f" ({finding.path}:{finding.line})" if finding.path else ""
                lines.append(f"- {finding.check}{location}: {finding.message}")
            if len(self.warnings) > 30:
                lines.append(f"- {len(self.warnings) - 30} additional warnings omitted from summary.")
            lines.append("")
        lines.extend(["Risk Score", f"{self.risk_score} / 100 ({self.risk_level})", "", "Overall Result", overall, "", "Merge Readiness", readiness, "", "========================================", ""])
        REPORT_MD.write_text("\n".join(lines), encoding="utf-8")
        REPORT_JSON.write_text(json.dumps({
            "overall": overall,
            "merge_readiness": readiness,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "technologies": self.technologies,
            "checks": {name: result.__dict__ | {"findings": [f.__dict__ for f in result.findings]} for name, result in self.results.items()},
            "blocking_findings": [f.__dict__ for f in self.failures],
            "warnings": [f.__dict__ for f in self.warnings],
        }, indent=2), encoding="utf-8")
        print(REPORT_MD.read_text(encoding="utf-8"))


if __name__ == "__main__":
    sys.exit(Gate().run())
