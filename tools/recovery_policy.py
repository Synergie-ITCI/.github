#!/usr/bin/env python3
"""Synergie application recoverability policy scanner.

The scanner is static, read-only, and secret-redacting. It validates the
machine-readable recovery manifest and catches the class of failures where a
recovery-critical file is ignored from Git without another company-controlled
source of truth.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = [
    "application_name",
    "repository",
    "runtime",
    "runtime_version",
    "framework",
    "framework_version",
    "build_commands",
    "dependency_manifests",
    "dependency_lockfiles",
    "required_source_paths",
    "required_asset_paths",
    "git_lfs_paths",
    "external_artifact_locations",
    "environment_template",
    "secret_references",
    "database_engine",
    "database_backup_strategy",
    "database_restore_reference",
    "persistent_upload_locations",
    "persistent_storage_backup_strategy",
    "web_server_template",
    "scheduled_jobs",
    "service_definitions",
    "deployment_method",
    "production_target_reference",
    "health_checks",
    "rollback_method",
    "rto_target",
    "rpo_target",
    "recovery_owner_role",
]

LIST_FIELDS = {
    "build_commands",
    "dependency_manifests",
    "dependency_lockfiles",
    "required_source_paths",
    "required_asset_paths",
    "git_lfs_paths",
    "external_artifact_locations",
    "secret_references",
    "persistent_upload_locations",
    "health_checks",
    "scheduled_jobs",
    "service_definitions",
}

NON_EMPTY_LIST_FIELDS = {
    "build_commands",
    "dependency_manifests",
    "dependency_lockfiles",
    "required_source_paths",
    "secret_references",
    "health_checks",
}

SECRET_VALUE_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |)PRIVATE KEY-----"),
    re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
    re.compile(r"(?i)\b(secret|token|api[_-]?key)\s*[:=]\s*['\"]?[^'\"\s]{10,}"),
]

SECRET_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|pwd|secret_value|token_value|api_key|access_key|private_key|credential_value)"
)

PERSON_DEPENDENT_PATTERNS = [
    re.compile(r"(?i)\bdeveloper laptop\b"),
    re.compile(r"(?i)\bask (?:the )?developer\b"),
    re.compile(r"(?i)\bcontact (?:the )?developer\b"),
    re.compile(r"(?i)\bget (?:it|this|files?) from\b"),
    re.compile(r"(?i)\bmanually preserved zip\b"),
    re.compile(r"(?i)\b(local-only|developer-only)\b"),
    re.compile(r"(?i)(^|[\"'\s])/(Users|home)/[^/\s]+/"),
    re.compile(r"(?i)\bC:\\\\Users\\\\"),
    re.compile(r"(?i)\b(Dropbox|Google Drive|OneDrive|Desktop|Downloads)\b"),
]

BROAD_IGNORE_PATTERNS = {
    "public/*",
    "assets/*",
    "uploads/*",
    "useruploads/*",
    "documents/*",
    "attachments/*",
    "storage/*",
    "storage/app/public/*",
    "public/uploads/*",
}

IGNORE_FILES = [
    ".gitignore",
    ".dockerignore",
    ".npmignore",
    ".artifactignore",
    ".deployignore",
    ".ebignore",
    ".vercelignore",
    ".serverlessignore",
    ".gcloudignore",
]

DEPENDENCY_LOCK_OPTIONS = {
    "package.json": ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"],
    "composer.json": ["composer.lock"],
    "go.mod": ["go.sum"],
    "Gemfile": ["Gemfile.lock"],
    "Podfile": ["Podfile.lock"],
    "pubspec.yaml": ["pubspec.lock"],
    "Cargo.toml": ["Cargo.lock"],
}

PYTHON_LOCK_OPTIONS = [
    "requirements.txt",
    "requirements.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "Pipfile.lock",
]


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    path: str = ""
    line: int | None = None


def strip_inline_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line.rstrip()


def parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if value == "":
        return ""
    if value in {"[]", "{}"}:
        return [] if value == "[]" else {}
    lowered = value.lower()
    if lowered in {"null", "~"}:
        return None
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        try:
            return json.loads(value.replace("'", '"'))
        except json.JSONDecodeError:
            return [item.strip().strip("'\"") for item in value[1:-1].split(",") if item.strip()]
    return value


def parse_yaml_subset(text: str) -> Any:
    tokens: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = strip_inline_comment(raw)
        if not line.strip():
            continue
        tokens.append((len(line) - len(line.lstrip(" ")), line.strip()))

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(tokens):
            return {}, index
        if tokens[index][1].startswith("- "):
            return parse_list(index, indent)
        return parse_dict(index, indent)

    def parse_dict(index: int, indent: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        while index < len(tokens):
            current_indent, content = tokens[index]
            if current_indent < indent:
                break
            if current_indent > indent:
                break
            if content.startswith("- "):
                break
            if ":" not in content:
                index += 1
                continue
            key, raw_value = content.split(":", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            index += 1
            if raw_value:
                result[key] = parse_scalar(raw_value)
            elif index < len(tokens) and tokens[index][0] > current_indent:
                result[key], index = parse_block(index, tokens[index][0])
            else:
                result[key] = None
        return result, index

    def parse_list(index: int, indent: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        while index < len(tokens):
            current_indent, content = tokens[index]
            if current_indent < indent:
                break
            if current_indent > indent:
                break
            if not content.startswith("- "):
                break
            item = content[2:].strip()
            index += 1
            if not item:
                if index < len(tokens) and tokens[index][0] > current_indent:
                    value, index = parse_block(index, tokens[index][0])
                else:
                    value = None
                result.append(value)
                continue
            if ":" in item and not item.startswith(("http://", "https://", "s3://", "arn:")):
                key, raw_value = item.split(":", 1)
                value_dict: dict[str, Any] = {key.strip(): parse_scalar(raw_value.strip()) if raw_value.strip() else None}
                if index < len(tokens) and tokens[index][0] > current_indent:
                    nested, index = parse_dict(index, tokens[index][0])
                    value_dict.update(nested)
                result.append(value_dict)
            else:
                result.append(parse_scalar(item))
        return result, index

    parsed, _ = parse_block(0, tokens[0][0] if tokens else 0)
    return parsed


def load_manifest(path: Path) -> dict[str, Any]:
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
        raise ValueError("Recovery manifest must be a mapping/object.")
    return data


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def scalar_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def walk_values(value: Any, key_path: str = "") -> list[tuple[str, Any]]:
    values: list[tuple[str, Any]] = [(key_path, value)]
    if isinstance(value, dict):
        for key, child in value.items():
            values.extend(walk_values(child, f"{key_path}.{key}" if key_path else str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            values.extend(walk_values(child, f"{key_path}[{index}]"))
    return values


class RecoveryPolicy:
    def __init__(self, repo: Path, manifest_path: Path, mode: str) -> None:
        self.repo = repo
        self.manifest_path = manifest_path
        self.mode = mode
        self.findings: list[Finding] = []
        self.warnings: list[Finding] = []
        self.manifest: dict[str, Any] = {}

    def run(self) -> int:
        self.load()
        if self.findings:
            return 1
        self.validate_required_fields()
        self.validate_no_secrets_or_person_dependencies()
        self.validate_required_paths()
        self.validate_environment_template()
        self.validate_dependency_locks()
        self.validate_external_artifacts()
        self.validate_git_lfs()
        self.validate_ignore_rules()
        self.validate_secret_references()
        self.validate_production_requirements()
        return 1 if self.findings else 0

    def fail(self, code: str, message: str, path: str = "", line: int | None = None) -> None:
        self.findings.append(Finding("fail", code, message, path, line))

    def warn(self, code: str, message: str, path: str = "", line: int | None = None) -> None:
        self.warnings.append(Finding("warn", code, message, path, line))

    def load(self) -> None:
        path = self.repo / self.manifest_path
        if not path.exists():
            self.fail(
                "RECOVERY MANIFEST MISSING",
                f"Missing required recovery manifest: {self.manifest_path}",
                str(self.manifest_path),
            )
            return
        try:
            self.manifest = load_manifest(path)
        except Exception as exc:
            self.fail(
                "RECOVERY MANIFEST INVALID",
                f"Recovery manifest could not be parsed: {exc}",
                str(self.manifest_path),
            )

    def validate_required_fields(self) -> None:
        for field in REQUIRED_FIELDS:
            if field not in self.manifest:
                self.fail("RECOVERY MANIFEST FIELD MISSING", f"Required recovery manifest field is missing: {field}", str(self.manifest_path))
                continue
            value = self.manifest[field]
            if field in NON_EMPTY_LIST_FIELDS and not as_list(value):
                self.fail("RECOVERY MANIFEST FIELD EMPTY", f"Required recovery manifest list is empty: {field}", str(self.manifest_path))
            elif field not in LIST_FIELDS and not scalar_text(value).strip():
                self.fail("RECOVERY MANIFEST FIELD EMPTY", f"Required recovery manifest field is empty: {field}", str(self.manifest_path))

    def validate_no_secrets_or_person_dependencies(self) -> None:
        for key_path, value in walk_values(self.manifest):
            last_key = key_path.rsplit(".", 1)[-1].split("[", 1)[0]
            if SECRET_KEY_PATTERN.fullmatch(last_key or ""):
                self.fail("RECOVERY MANIFEST CONTAINS SECRET FIELD", "Do not put secret values or secret-value fields in the recovery manifest.", str(self.manifest_path))
            text = scalar_text(value)
            if not text:
                continue
            if any(pattern.search(text) for pattern in SECRET_VALUE_PATTERNS):
                self.fail("RECOVERY MANIFEST CONTAINS SECRET VALUE", "Do not put secret values in the recovery manifest.", str(self.manifest_path))
            if any(pattern.search(text) for pattern in PERSON_DEPENDENT_PATTERNS):
                self.fail("PERSON-DEPENDENT RECOVERY ASSET", "Recovery depends on a developer laptop, local folder, private note, or person-specific asset.", str(self.manifest_path))

    def manifest_paths(self, field: str) -> list[str]:
        paths: list[str] = []
        for item in as_list(self.manifest.get(field)):
            if isinstance(item, str):
                paths.append(item)
            elif isinstance(item, dict):
                for key in ("path", "local_path", "required_path"):
                    if item.get(key):
                        paths.append(str(item[key]))
                        break
        return paths

    def resolve_matches(self, pattern: str) -> list[Path]:
        pattern = pattern.strip()
        if not pattern:
            return []
        if any(char in pattern for char in "*?["):
            return sorted(Path(match).relative_to(self.repo) for match in self.repo.glob(pattern) if match.exists())
        path = self.repo / pattern
        return [Path(pattern)] if path.exists() else []

    def validate_required_paths(self) -> None:
        for field in ("dependency_manifests", "dependency_lockfiles", "required_source_paths", "required_asset_paths"):
            for pattern in self.manifest_paths(field):
                if not self.resolve_matches(pattern):
                    self.fail("RECOVERY REQUIRED PATH MISSING", f"Recovery manifest references a missing required path: {pattern}", pattern)
        for field in ("web_server_template", "environment_template"):
            value = scalar_text(self.manifest.get(field)).strip()
            if value and not (self.repo / value).exists():
                self.fail("RECOVERY REQUIRED PATH MISSING", f"Recovery manifest references a missing required path: {value}", value)

    def validate_environment_template(self) -> None:
        template = scalar_text(self.manifest.get("environment_template")).strip()
        if template in {".env", ".env.production", ".env.prod"}:
            self.fail("RECOVERY ENV TEMPLATE UNSAFE", "Recovery manifest must reference a non-secret environment template such as .env.example.", template)

    def validate_dependency_locks(self) -> None:
        for manifest, lock_options in DEPENDENCY_LOCK_OPTIONS.items():
            if (self.repo / manifest).exists() and not any((self.repo / lock).exists() for lock in lock_options):
                self.fail("RECOVERY DEPENDENCY LOCKFILE MISSING", f"{manifest} is present but no approved lockfile exists: {', '.join(lock_options)}", manifest)

        if (self.repo / "pyproject.toml").exists() and not any((self.repo / lock).exists() for lock in PYTHON_LOCK_OPTIONS):
            self.fail("RECOVERY DEPENDENCY LOCKFILE MISSING", "Python project is missing an approved deterministic dependency lock.", "pyproject.toml")

        for path in self.manifest_paths("dependency_lockfiles"):
            if not (self.repo / path).exists():
                self.fail("RECOVERY DEPENDENCY LOCKFILE MISSING", f"Declared dependency lockfile is missing: {path}", path)

    def artifact_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for item in as_list(self.manifest.get("external_artifact_locations")):
            if isinstance(item, dict):
                entries.append(item)
            elif isinstance(item, str):
                entries.append({"uri": item})
        return entries

    def artifact_covers(self, path: str) -> bool:
        normalized = path.rstrip("/")
        for entry in self.artifact_entries():
            candidate = str(entry.get("path") or entry.get("local_path") or entry.get("required_path") or "").rstrip("/")
            if candidate and (normalized == candidate or normalized.startswith(candidate + "/") or fnmatch.fnmatch(normalized, candidate)):
                return True
        return False

    def lfs_covers(self, path: str) -> bool:
        normalized = path.rstrip("/")
        for pattern in self.manifest_paths("git_lfs_paths"):
            candidate = pattern.rstrip("/")
            if normalized == candidate or normalized.startswith(candidate + "/") or fnmatch.fnmatch(normalized, candidate):
                return True
        return False

    def validate_external_artifacts(self) -> None:
        for entry in self.artifact_entries():
            uri = str(entry.get("uri") or entry.get("location") or "")
            checksum = str(entry.get("checksum_sha256") or entry.get("sha256") or "")
            version = str(entry.get("version") or entry.get("object_version") or entry.get("artifact_version") or "")
            immutable = bool(entry.get("immutable") is True or entry.get("versioned") is True)
            if not uri:
                self.fail("RECOVERY ARTIFACT LOCATION INVALID", "External artifact entry is missing a URI.", str(self.manifest_path))
                continue
            if uri.startswith(("file://", "/")) or any(pattern.search(uri) for pattern in PERSON_DEPENDENT_PATTERNS):
                self.fail("PERSON-DEPENDENT RECOVERY ASSET", "External artifact must be stored in a company-controlled system, not a local/person-specific path.", str(self.manifest_path))
            if not checksum or not re.fullmatch(r"[A-Fa-f0-9]{64}", checksum):
                self.fail("RECOVERY ARTIFACT CHECKSUM MISSING", "External artifact entry must include a SHA-256 checksum.", str(self.manifest_path))
            if not (version or immutable):
                self.fail("RECOVERY ARTIFACT NOT VERSIONED", "External artifact entry must be immutable or include an object/artifact version.", str(self.manifest_path))

    def validate_git_lfs(self) -> None:
        lfs_paths = self.manifest_paths("git_lfs_paths")
        if not lfs_paths:
            return
        attributes = self.repo / ".gitattributes"
        if not attributes.exists():
            self.fail("RECOVERY LFS ATTRIBUTES MISSING", "git_lfs_paths are declared but .gitattributes is missing.", ".gitattributes")
            return
        text = attributes.read_text(encoding="utf-8", errors="replace")
        for path in lfs_paths:
            basename = Path(path).name
            if "filter=lfs" not in text or (path not in text and basename not in text and "*" not in text):
                self.fail("RECOVERY LFS PATH NOT TRACKED", f"Declared Git LFS path is not covered by .gitattributes: {path}", ".gitattributes")
        if shutil.which("git"):
            version = subprocess.run(["git", "lfs", "version"], cwd=self.repo, text=True, capture_output=True, check=False)
            if version.returncode != 0:
                self.warn("RECOVERY LFS FSCK NOT AVAILABLE", "Git LFS fsck could not be executed in this environment.", ".gitattributes")
                return
            cp = subprocess.run(["git", "lfs", "fsck"], cwd=self.repo, text=True, capture_output=True, check=False)
            if cp.returncode != 0:
                self.fail("RECOVERY LFS OBJECT MISSING", "Git LFS object validation failed; a referenced LFS object may be missing.", ".gitattributes")

    def git_ignored(self, path: str) -> str | None:
        cp = subprocess.run(
            ["git", "check-ignore", "-v", "--no-index", "--", path],
            cwd=self.repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return cp.stdout.strip() if cp.returncode == 0 else None

    def pattern_matches_path(self, pattern: str, path: str) -> bool:
        normalized_pattern = pattern.lstrip("/")
        normalized_path = path.strip("/")
        if normalized_pattern.endswith("/"):
            return normalized_path.startswith(normalized_pattern.rstrip("/") + "/")
        if "/" not in normalized_pattern:
            return any(part == normalized_pattern or fnmatch.fnmatch(part, normalized_pattern) for part in normalized_path.split("/"))
        return fnmatch.fnmatch(normalized_path, normalized_pattern) or normalized_path.startswith(normalized_pattern.rstrip("*").rstrip("/") + "/")

    def collect_packaging_ignore_matches(self, path: str) -> list[str]:
        matches: list[str] = []
        for ignore_name in IGNORE_FILES[1:]:
            ignore_path = self.repo / ignore_name
            if not ignore_path.exists():
                continue
            for number, raw in enumerate(ignore_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                line = strip_inline_comment(raw).strip()
                if not line or line.startswith("!") or line.startswith("#"):
                    continue
                if self.pattern_matches_path(line, path):
                    matches.append(f"{ignore_name}:{number}:{line}")
        return matches

    def validate_ignore_rules(self) -> None:
        required_paths = self.manifest_paths("required_source_paths") + self.manifest_paths("required_asset_paths")
        for pattern in required_paths:
            candidates = self.resolve_matches(pattern) or [Path(pattern)]
            for candidate in candidates:
                path = str(candidate)
                ignored_by_git = self.git_ignored(path)
                packaging_matches = self.collect_packaging_ignore_matches(path)
                if (ignored_by_git or packaging_matches) and not (self.lfs_covers(path) or self.artifact_covers(path)):
                    source = ignored_by_git or ", ".join(packaging_matches)
                    self.fail(
                        "RECOVERY-CRITICAL FILE EXCLUDED FROM SOURCE OF TRUTH",
                        f"Recovery-critical path is ignored without an approved alternate source of truth: {path} ({source})",
                        path,
                    )

        persistent_roots = {item.rstrip("/") for item in self.manifest_paths("persistent_upload_locations")}
        for ignore_name in IGNORE_FILES:
            ignore_path = self.repo / ignore_name
            if not ignore_path.exists():
                continue
            for number, raw in enumerate(ignore_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                line = strip_inline_comment(raw).strip()
                if not line or line.startswith("!") or line.startswith("#"):
                    continue
                comparable = line.rstrip("/")
                if comparable in BROAD_IGNORE_PATTERNS or comparable + "/*" in BROAD_IGNORE_PATTERNS:
                    root = comparable.rstrip("*").rstrip("/")
                    if root in persistent_roots or self.artifact_covers(root):
                        continue
                    self.fail(
                        "DANGEROUS RECOVERY IGNORE RULE",
                        f"Broad ignore rule requires explicit recovery classification/source of truth: {line}",
                        ignore_name,
                        number,
                    )

    def validate_secret_references(self) -> None:
        refs = [scalar_text(item) for item in as_list(self.manifest.get("secret_references"))]
        for ref in refs:
            if not ref:
                continue
            if any(pattern.search(ref) for pattern in PERSON_DEPENDENT_PATTERNS):
                self.fail("PERSON-DEPENDENT RECOVERY ASSET", "Secret reference points to a person/local source.", str(self.manifest_path))
                continue
            allowed = ref.startswith(("arn:aws:secretsmanager:", "arn:aws:ssm:", "ssm:/", "ssm://", "secretsmanager:", "/synergie/"))
            if not allowed:
                self.warn("RECOVERY SECRET REFERENCE UNRECOGNIZED", f"Secret reference does not look like AWS Secrets Manager or SSM Parameter Store: {ref}", str(self.manifest_path))

    def validate_production_requirements(self) -> None:
        if self.mode != "production":
            return
        audit = self.manifest.get("server_file_audit")
        if not isinstance(audit, dict):
            self.fail("RECOVERY SERVER FILE AUDIT MISSING", "Production recoverability requires server file audit evidence.", str(self.manifest_path))
        else:
            count = audit.get("recovery_critical_server_only_count")
            try:
                numeric_count = int(count)
            except (TypeError, ValueError):
                self.fail("RECOVERY SERVER FILE AUDIT INVALID", "server_file_audit.recovery_critical_server_only_count must be numeric.", str(self.manifest_path))
            else:
                if numeric_count > 0:
                    self.fail("RECOVERY-CRITICAL SERVER-ONLY FILE", "Production cannot be certified while recovery-critical server-only files remain.", str(self.manifest_path))

        deployment = self.manifest.get("deployment_traceability")
        if not isinstance(deployment, dict):
            self.fail("DEPLOYED COMMIT UNKNOWN", "Production recoverability requires deployment traceability metadata.", str(self.manifest_path))
        else:
            required = ["commit_marker", "artifact_manifest", "artifact_checksum_algorithm", "release_artifact_retention"]
            for key in required:
                if not scalar_text(deployment.get(key)).strip():
                    self.fail("DEPLOYMENT NOT REPRODUCIBLE", f"deployment_traceability.{key} is required.", str(self.manifest_path))


def write_report(out: Path, json_out: Path, policy: RecoveryPolicy, status: str) -> None:
    findings = policy.findings + policy.warnings
    lines = [
        "# Synergie Application Recoverability Report",
        "",
        f"Status: **{status}**",
        f"Mode: `{policy.mode}`",
        f"Manifest: `{policy.manifest_path}`",
        "",
    ]
    if not findings:
        lines.append("No recoverability findings.")
    else:
        lines.extend(["## Findings", ""])
        for finding in findings:
            location = f" `{finding.path}`" if finding.path else ""
            line = f":{finding.line}" if finding.line else ""
            lines.append(f"- **{finding.severity.upper()}** `{finding.code}`{location}{line} - {finding.message}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    json_out.write_text(
        json.dumps(
            {
                "status": status,
                "mode": policy.mode,
                "manifest": str(policy.manifest_path),
                "failures": [asdict(finding) for finding in policy.findings],
                "warnings": [asdict(finding) for finding in policy.warnings],
                "manifest_sha256": hashlib.sha256((policy.repo / policy.manifest_path).read_bytes()).hexdigest()
                if (policy.repo / policy.manifest_path).exists()
                else None,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Synergie application recoverability policy.")
    parser.add_argument("--repo", default=".", help="Repository root to scan.")
    parser.add_argument("--manifest", default=".github/synergie-recovery.yml", help="Recovery manifest path.")
    parser.add_argument("--mode", choices=["staging", "production"], default="staging", help="Validation mode.")
    parser.add_argument("--out", default="recovery-policy-report.md", help="Markdown report output path.")
    parser.add_argument("--json-out", default="recovery-policy-report.json", help="JSON report output path.")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    policy = RecoveryPolicy(repo, Path(args.manifest), args.mode)
    code = policy.run()
    status = "FAIL" if code else "PASS"

    for finding in policy.findings:
        location = f" {finding.path}" if finding.path else ""
        print(f"{finding.code}:{location} {finding.message}", file=sys.stderr)
    for finding in policy.warnings:
        location = f" {finding.path}" if finding.path else ""
        print(f"WARNING {finding.code}:{location} {finding.message}", file=sys.stderr)

    write_report(Path(args.out), Path(args.json_out), policy, status)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
