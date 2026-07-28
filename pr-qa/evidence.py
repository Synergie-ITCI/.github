from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SUPPORTED_QA_SCHEMA_VERSIONS = {1}
MAX_EVIDENCE_FILE_SIZE = 5 * 1024 * 1024
ALLOWED_EVIDENCE_FILES = {
    "pr-quality-report.json",
    "pr-quality-report.md",
    "gitleaks.json",
    "emergency-override-audit.json",
}
VALID_QA_STATUSES = {"PASS", "FAIL"}
ALLOWED_REPORT_FIELDS = {
    "schema_version",
    "report_complete",
    "sanitization",
    "summary",
    "results",
    "inline_review",
    "commands",
}
ALLOWED_SUMMARY_FIELDS = {
    "repository",
    "pull_request_number",
    "base_ref",
    "head_ref",
    "base_sha",
    "head_sha",
    "detected_technologies",
    "changed_files",
    "additions",
    "deletions",
    "gate_statuses",
    "overall_result",
    "merge_readiness",
    "risk_score",
    "policy_id",
}
ALLOWED_SANITIZATION_FIELDS = {"status", "redaction"}
ALLOWED_RESULT_FIELDS = {"gate", "status", "message", "details", "technology", "score", "blocking"}
ALLOWED_INLINE_REVIEW_FIELDS = {"schema_version", "findings"}
ALLOWED_INLINE_FINDING_FIELDS = {
    "fingerprint",
    "path",
    "line",
    "side",
    "gate",
    "technology",
    "status",
    "severity",
    "title",
    "explanation",
    "recommendation",
}
ALLOWED_COMMAND_FIELDS = {
    "command",
    "cwd",
    "exit_code",
    "timed_out",
    "skipped",
    "duration_seconds",
    "output_excerpt",
}


@dataclass
class EvidenceValidation:
    valid: bool
    report: dict[str, Any]
    reason: str
    repository: str = ""
    pr_number: int = 0
    head_sha: str = ""
    qa_status: str = ""


def validate_qa_evidence(report_path: str, event: dict[str, Any], *, require_pass: bool = False) -> EvidenceValidation:
    if not str(report_path or "").strip():
        return invalid("authoritative Enterprise QA evidence path is missing")
    path = Path(report_path)
    bundle_error = validate_evidence_bundle(path)
    if bundle_error:
        return invalid(bundle_error)

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return invalid("authoritative Enterprise QA evidence is malformed JSON")
    except OSError as exc:
        return invalid(f"authoritative Enterprise QA evidence could not be read: {exc}")

    if not isinstance(payload, dict):
        return invalid("authoritative Enterprise QA evidence must be a JSON object")

    field_error = validate_report_fields(payload)
    if field_error:
        return invalid(field_error)

    schema_version = payload.get("schema_version")
    if schema_version not in SUPPORTED_QA_SCHEMA_VERSIONS:
        return invalid("authoritative Enterprise QA evidence has unsupported schema version")

    if payload.get("report_complete") is not True:
        return invalid("authoritative Enterprise QA evidence is not marked complete")

    sanitisation = payload.get("sanitization", {})
    if not isinstance(sanitisation, dict) or sanitisation.get("status") != "PASS":
        return invalid("authoritative Enterprise QA evidence sanitisation status is invalid")

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        return invalid("authoritative Enterprise QA evidence summary is missing")

    qa_status = str(summary.get("overall_result") or "").upper()
    if qa_status not in VALID_QA_STATUSES:
        return invalid("authoritative Enterprise QA evidence summary status is missing or unsupported")
    if require_pass and qa_status != "PASS":
        return invalid("authoritative Enterprise QA PASS evidence was not available", qa_status=qa_status)

    expected_repository = expected_event_repository(event)
    expected_pr_number = expected_event_pr_number(event)
    expected_head_sha = expected_event_head_sha(event)
    if not expected_repository:
        return invalid("authoritative Enterprise QA evidence cannot be matched because pull request repository context is missing")
    if not expected_pr_number:
        return invalid("authoritative Enterprise QA evidence cannot be matched because pull request number context is missing")
    if not expected_head_sha:
        return invalid("authoritative Enterprise QA evidence cannot be matched because pull request head SHA context is missing")
    report_repository = str(summary.get("repository") or "")
    report_pr_number = safe_int(summary.get("pull_request_number"))
    report_head_sha = str(summary.get("head_sha") or "")

    if report_repository != expected_repository:
        return invalid("authoritative Enterprise QA evidence repository does not match the pull request")
    if report_pr_number != expected_pr_number:
        return invalid("authoritative Enterprise QA evidence pull request number does not match")
    if report_head_sha != expected_head_sha:
        return invalid("authoritative Enterprise QA evidence head SHA does not match")

    return EvidenceValidation(
        valid=True,
        report=payload,
        reason="validated",
        repository=report_repository,
        pr_number=report_pr_number,
        head_sha=report_head_sha,
        qa_status=qa_status,
    )


def validate_report_fields(payload: dict[str, Any]) -> str:
    unexpected = sorted(set(payload) - ALLOWED_REPORT_FIELDS)
    if unexpected:
        return f"authoritative Enterprise QA evidence contains unsupported top-level fields: {', '.join(unexpected)}"

    sanitization = payload.get("sanitization")
    if sanitization is not None:
        if not isinstance(sanitization, dict):
            return "authoritative Enterprise QA evidence sanitization metadata must be an object"
        unexpected = sorted(set(sanitization) - ALLOWED_SANITIZATION_FIELDS)
        if unexpected:
            return f"authoritative Enterprise QA evidence sanitization metadata contains unsupported fields: {', '.join(unexpected)}"

    summary = payload.get("summary")
    if summary is not None:
        if not isinstance(summary, dict):
            return "authoritative Enterprise QA evidence summary must be an object"
        unexpected = sorted(set(summary) - ALLOWED_SUMMARY_FIELDS)
        if unexpected:
            return f"authoritative Enterprise QA evidence summary contains unsupported fields: {', '.join(unexpected)}"
        if "gate_statuses" in summary and not isinstance(summary.get("gate_statuses"), dict):
            return "authoritative Enterprise QA evidence gate statuses must be an object"
        if "detected_technologies" in summary and not isinstance(summary.get("detected_technologies"), list):
            return "authoritative Enterprise QA evidence detected technologies must be a list"

    results = payload.get("results")
    if results is not None:
        if not isinstance(results, list):
            return "authoritative Enterprise QA evidence results must be a list"
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                return f"authoritative Enterprise QA evidence result {index} must be an object"
            unexpected = sorted(set(result) - ALLOWED_RESULT_FIELDS)
            if unexpected:
                return f"authoritative Enterprise QA evidence result {index} contains unsupported fields: {', '.join(unexpected)}"

    inline_review = payload.get("inline_review")
    if inline_review is not None:
        if not isinstance(inline_review, dict):
            return "authoritative Enterprise QA evidence inline review metadata must be an object"
        unexpected = sorted(set(inline_review) - ALLOWED_INLINE_REVIEW_FIELDS)
        if unexpected:
            return f"authoritative Enterprise QA evidence inline review metadata contains unsupported fields: {', '.join(unexpected)}"
        findings = inline_review.get("findings", [])
        if not isinstance(findings, list):
            return "authoritative Enterprise QA evidence inline review findings must be a list"
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                return f"authoritative Enterprise QA evidence inline review finding {index} must be an object"
            unexpected = sorted(set(finding) - ALLOWED_INLINE_FINDING_FIELDS)
            if unexpected:
                return f"authoritative Enterprise QA evidence inline review finding {index} contains unsupported fields: {', '.join(unexpected)}"

    commands = payload.get("commands")
    if commands is not None:
        if not isinstance(commands, list):
            return "authoritative Enterprise QA evidence commands must be a list"
        for index, command in enumerate(commands):
            if not isinstance(command, dict):
                return f"authoritative Enterprise QA evidence command {index} must be an object"
            unexpected = sorted(set(command) - ALLOWED_COMMAND_FIELDS)
            if unexpected:
                return f"authoritative Enterprise QA evidence command {index} contains unsupported fields: {', '.join(unexpected)}"

    return ""


def validate_evidence_bundle(report_path: Path) -> str:
    if report_path.name != "pr-quality-report.json":
        return "authoritative Enterprise QA evidence filename is not approved"
    if not report_path.exists():
        return "authoritative Enterprise QA evidence is missing"
    parent = report_path.parent
    if not parent.exists() or not parent.is_dir():
        return "authoritative Enterprise QA evidence directory is missing"

    for path in parent.rglob("*"):
        try:
            relative = path.relative_to(parent)
        except ValueError:
            return "authoritative Enterprise QA evidence path escapes the evidence directory"
        if path.is_symlink():
            return f"authoritative Enterprise QA evidence contains an unsupported symlink: {relative.as_posix()}"
        if path.is_dir():
            return f"authoritative Enterprise QA evidence contains an unsupported directory: {relative.as_posix()}"
        if not path.is_file():
            return f"authoritative Enterprise QA evidence contains an unsupported file type: {relative.as_posix()}"
        if relative.as_posix() != path.name or path.name not in ALLOWED_EVIDENCE_FILES:
            return f"authoritative Enterprise QA evidence contains an unexpected file: {relative.as_posix()}"
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            return f"authoritative Enterprise QA evidence cannot be inspected: {exc}"
        if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            return f"authoritative Enterprise QA evidence contains an executable file: {relative.as_posix()}"
        if path.stat().st_size > MAX_EVIDENCE_FILE_SIZE:
            return f"authoritative Enterprise QA evidence file is too large: {relative.as_posix()}"
    return ""


def expected_event_repository(event: dict[str, Any]) -> str:
    repository = event.get("repository", {}) if isinstance(event, dict) else {}
    return str((repository or {}).get("full_name") or os.environ.get("GITHUB_REPOSITORY", ""))


def expected_event_pr_number(event: dict[str, Any]) -> int:
    pull_request = event.get("pull_request", {}) if isinstance(event, dict) else {}
    return safe_int((pull_request or {}).get("number") or event.get("number"))


def expected_event_head_sha(event: dict[str, Any]) -> str:
    pull_request = event.get("pull_request", {}) if isinstance(event, dict) else {}
    head = (pull_request or {}).get("head", {}) or {}
    return str(head.get("sha") or "")


def invalid(reason: str, *, qa_status: str = "") -> EvidenceValidation:
    return EvidenceValidation(valid=False, report={}, reason=reason, qa_status=qa_status)


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
