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
    "formatting": True,
    "lint": True,
    "build": True,
    "tests": True,
    "git_validation": True,
    "secrets": True,
    "dependency_security": True,
    "deployment_risk": True,
    "migration_risk": True,
    "large_files": True,
    "documentation": True,
    "ai_advisory": True,
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
        self.technologies = self.detect_technologies()
        self.failures: list[Finding] = []
        self.warnings: list[Finding] = []

    def enabled(self, check: str) -> bool:
        return bool(self.config["checks"].get(check, True))

    def load_config(self) -> dict[str, Any]:
        config: dict[str, Any] = {
            "checks": dict(DEFAULT_CHECKS),
            "large_file_threshold_mb": int(os.getenv("PR_QA_LARGE_FILE_THRESHOLD_MB", "10")),
            "fail_on_dependency_vulnerabilities": os.getenv("PR_QA_FAIL_ON_DEPENDENCY_VULNERABILITIES", "false").lower() == "true",
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
        return config

    def run(self) -> int:
        self.check_git_validation()
        self.check_secrets()
        self.check_large_files()
        self.check_deployment_risk()
        self.check_migration_risk()
        self.check_documentation()
        self.check_formatting()
        self.check_lint()
        self.check_build()
        self.check_tests()
        self.check_dependency_security()
        self.check_ai_advisory()
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
        if (ROOT / "composer.json").exists():
            tech.append("PHP")
        if (ROOT / "artisan").exists():
            tech.append("Laravel")
        if (ROOT / "package.json").exists():
            tech.append("Node")
            text = (ROOT / "package.json").read_text(encoding="utf-8", errors="replace")
            if "react-native" in text:
                tech.append("React Native")
            elif "react" in text:
                tech.append("React")
        if any(ROOT.glob("**/Package.swift")):
            tech.append("Swift")
        if (ROOT / "gradlew").exists() or (ROOT / "build.gradle").exists() or (ROOT / "build.gradle.kts").exists():
            tech.append("Kotlin/Gradle")
        if (ROOT / "pyproject.toml").exists() or (ROOT / "requirements.txt").exists():
            tech.append("Python")
        if (ROOT / "go.mod").exists():
            tech.append("Go")
        return tech or ["Unknown"]

    def read_package_json(self) -> dict[str, Any]:
        try:
            return json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        except Exception:
            return {}

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
                status = "HIGH"
                findings.append(Finding("warn", name, "Potentially destructive migration detected. Manual release review required.", path, 1))
            elif re.search(r"(?i)\b(alter\s+table|modify\s+column|change\s+column)\b", text):
                status = "MEDIUM" if status != "HIGH" else status
                findings.append(Finding("warn", name, "Schema-altering migration detected. Confirm manual migration/runbook plan.", path, 1))
            else:
                findings.append(Finding("warn", name, "Migration file changed. Confirm rollout and rollback plan.", path, 1))
        self.record(CheckResult(name, status, "Migration risk analysis completed.", findings))

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

    def check_formatting(self) -> None:
        name = "Formatting"
        if not self.enabled("formatting"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings = []
        ran = []
        package = self.read_package_json()
        scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
        self.ensure_node_dependencies()
        for script in ("format:check", "prettier:check"):
            if script in scripts and shutil.which("npm"):
                cp = self.command(["npm", "run", script], timeout=900, env={"CI": "true"})
                ran.append(f"npm run {script}")
                if cp.returncode != 0:
                    findings.append(Finding("fail", name, f"`npm run {script}` failed."))
                break
        if not ran:
            self.record(CheckResult(name, "PASS", "No formatter check configured."))
        else:
            self.record(CheckResult(name, "FAIL" if findings else "PASS", ", ".join(ran), findings))

    def check_lint(self) -> None:
        name = "Lint"
        if not self.enabled("lint"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings = []
        ran = []
        package = self.read_package_json()
        scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
        self.ensure_node_dependencies()
        if "lint" in scripts and shutil.which("npm"):
            cp = self.command(["npm", "run", "lint"], timeout=900, env={"CI": "true"})
            ran.append("npm run lint")
            if cp.returncode != 0:
                findings.append(Finding("fail", name, "`npm run lint` failed."))
        if "Python" in self.technologies and shutil.which("ruff") and (ROOT / "pyproject.toml").exists():
            cp = self.command(["ruff", "check", "."], timeout=600)
            ran.append("ruff check .")
            if cp.returncode != 0:
                findings.append(Finding("fail", name, "`ruff check .` failed."))
        self.record(CheckResult(name, "FAIL" if findings else "PASS", ", ".join(ran) if ran else "No lint configuration detected.", findings))

    def check_build(self) -> None:
        name = "Build"
        if not self.enabled("build"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings = []
        ran = []
        package = self.read_package_json()
        scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
        self.ensure_node_dependencies()
        if "build" in scripts and shutil.which("npm"):
            cp = self.command(["npm", "run", "build"], timeout=1200, env={"CI": "true"})
            ran.append("npm run build")
            if cp.returncode != 0:
                findings.append(Finding("fail", name, "`npm run build` failed."))
        if "Go" in self.technologies and shutil.which("go"):
            cp = self.command(["go", "test", "./..."], timeout=900)
            ran.append("go test ./...")
            if cp.returncode != 0:
                findings.append(Finding("fail", name, "`go test ./...` failed."))
        self.record(CheckResult(name, "FAIL" if findings else "PASS", ", ".join(ran) if ran else "No build step configured.", findings))

    def check_tests(self) -> None:
        name = "Tests"
        if not self.enabled("tests"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings = []
        ran = []
        package = self.read_package_json()
        scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
        self.ensure_node_dependencies()
        self.ensure_php_dependencies()
        if "test" in scripts and shutil.which("npm"):
            cp = self.command(["npm", "test"], timeout=1200, env={"CI": "true", "WATCHMAN_DISABLE": "1"})
            ran.append("npm test")
            if cp.returncode != 0:
                findings.append(Finding("fail", name, "`npm test` failed."))
        changed_php = [p for p in self.changed_files if p.endswith(".php") and (ROOT / p).exists()]
        if changed_php and shutil.which("php"):
            for path in changed_php:
                cp = self.command(["php", "-l", path], timeout=120)
                ran.append(f"php -l {path}")
                if cp.returncode != 0:
                    findings.append(Finding("fail", name, f"PHP syntax check failed for {path}.", path, 1))
        phpunit = ROOT / "vendor/bin/phpunit"
        if phpunit.exists():
            cp = self.command([str(phpunit)], timeout=1200)
            ran.append("vendor/bin/phpunit")
            if cp.returncode != 0:
                findings.append(Finding("fail", name, "`vendor/bin/phpunit` failed."))
        if "Kotlin/Gradle" in self.technologies and (ROOT / "gradlew").exists():
            cp = self.command(["./gradlew", "test"], timeout=1800)
            ran.append("./gradlew test")
            if cp.returncode != 0:
                findings.append(Finding("fail", name, "`./gradlew test` failed."))
        for package_swift in sorted(ROOT.glob("**/Package.swift")):
            if shutil.which("swift"):
                cp = self.command(["swift", "test"], timeout=1200, env={}, cwd=package_swift.parent)
                ran.append(f"swift test ({package_swift.parent})")
                if cp.returncode != 0:
                    findings.append(Finding("fail", name, f"`swift test` failed in {package_swift.parent}."))
                break
        if "Python" in self.technologies and shutil.which("pytest"):
            cp = self.command(["pytest"], timeout=1200)
            ran.append("pytest")
            if cp.returncode != 0:
                findings.append(Finding("fail", name, "`pytest` failed."))
        self.record(CheckResult(name, "FAIL" if findings else "PASS", ", ".join(ran) if ran else "No automated tests configured.", findings))

    def check_dependency_security(self) -> None:
        name = "Dependency Security"
        if not self.enabled("dependency_security"):
            self.record(CheckResult(name, "SKIPPED", "Disabled by repository configuration."))
            return
        findings = []
        ran = []
        fail_on_vuln = bool(self.config["fail_on_dependency_vulnerabilities"])
        if (ROOT / "composer.json").exists() and shutil.which("composer"):
            cp = self.command(["composer", "audit", "--no-interaction"], timeout=600)
            ran.append("composer audit")
            if cp.returncode != 0:
                findings.append(Finding("fail" if fail_on_vuln else "warn", name, "`composer audit` reported vulnerabilities."))
        if (ROOT / "package.json").exists() and shutil.which("npm"):
            self.ensure_node_dependencies()
            cp = self.command(["npm", "audit", "--audit-level=high"], timeout=600)
            ran.append("npm audit --audit-level=high")
            if cp.returncode != 0:
                findings.append(Finding("fail" if fail_on_vuln else "warn", name, "`npm audit` reported high or critical vulnerabilities."))
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
            f"Technology: {', '.join(self.technologies)}",
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
        lines.extend(["Overall Result", overall, "", "Merge Readiness", readiness, "", "========================================", ""])
        REPORT_MD.write_text("\n".join(lines), encoding="utf-8")
        REPORT_JSON.write_text(json.dumps({
            "overall": overall,
            "merge_readiness": readiness,
            "technologies": self.technologies,
            "checks": {name: result.__dict__ | {"findings": [f.__dict__ for f in result.findings]} for name, result in self.results.items()},
            "blocking_findings": [f.__dict__ for f in self.failures],
            "warnings": [f.__dict__ for f in self.warnings],
        }, indent=2), encoding="utf-8")
        print(REPORT_MD.read_text(encoding="utf-8"))


if __name__ == "__main__":
    sys.exit(Gate().run())
