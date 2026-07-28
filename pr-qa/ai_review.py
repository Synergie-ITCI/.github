#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidence import validate_qa_evidence
from review_comments import (
    AI_MARKER_NAMESPACE,
    DEFAULT_TRUSTED_COMMENT_AUTHORS,
    GitHubClient,
    extract_pr_number,
    extract_repository,
    parse_trusted_authors,
    read_json_file,
    redact,
    safe_int,
    synchronize_inline_review_comments,
)


SCHEMA_VERSION = 1
COMPLETED = "COMPLETED"
SKIPPED = "SKIPPED"
UNAVAILABLE = "UNAVAILABLE"
SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
DEFAULT_PROVIDER = "codex"
DEFAULT_MODEL = "codex-review-v1"
DEFAULT_REVIEW_BODY = "Synergie AI Engineering Review findings."
GENERATED_COMPONENTS = {
    ".git",
    ".hg",
    ".svn",
    ".pr-qa-framework",
    "node_modules",
    "vendor",
    "Pods",
    "build",
    "dist",
    "coverage",
    ".next",
    ".gradle",
    "target",
    "__pycache__",
}
LOCK_FILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
    "composer.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
}
FRAMEWORK_FIXTURE_PATTERNS = {
    ".gitleaks.toml",
    "tests/test_pr_qa_regressions.py",
}
BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".jar",
    ".war",
    ".class",
    ".so",
    ".dll",
    ".dylib",
    ".a",
}


def main() -> int:
    args = parse_args()
    try:
        report = execute_ai_review(args)
    except Exception as exc:
        report = unavailable_report(args, f"AI review internal error: {redact(str(exc))}")
    write_reports(args, report)
    print(render_markdown_report(report))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run advisory Synergie AI engineering review for a pull request.")
    parser.add_argument("--repo", default=".", help="Repository checkout root.")
    parser.add_argument("--event-path", default=os.environ.get("GITHUB_EVENT_PATH", ""), help="GitHub pull_request event payload path.")
    parser.add_argument("--qa-report-json", default="pr-qa-results/pr-quality-report.json", help="Enterprise QA JSON report path.")
    parser.add_argument("--out", default="pr-qa-results/ai-review-report.md", help="AI review Markdown report path.")
    parser.add_argument("--json-out", default="pr-qa-results/ai-review-report.json", help="AI review JSON report path.")
    parser.add_argument("--provider", default=os.environ.get("AI_REVIEW_PROVIDER", DEFAULT_PROVIDER), help="AI review provider name.")
    parser.add_argument("--model", default=os.environ.get("AI_REVIEW_MODEL", DEFAULT_MODEL), help="AI review model or provider profile.")
    parser.add_argument("--provider-url", default=os.environ.get("AI_REVIEW_PROVIDER_URL", ""), help="Approved AI review provider HTTPS endpoint.")
    parser.add_argument("--provider-token-env", default="AI_REVIEW_PROVIDER_TOKEN", help="Environment variable containing the provider token.")
    parser.add_argument("--approved-provider-hosts", default=os.environ.get("AI_REVIEW_APPROVED_HOSTS", ""), help="Comma-separated exact hostnames approved for AI provider traffic.")
    parser.add_argument("--approved-internal-provider-hosts", default=os.environ.get("AI_REVIEW_APPROVED_INTERNAL_HOSTS", ""), help="Comma-separated exact internal hostnames or IPs explicitly governed for AI provider traffic.")
    parser.add_argument("--github-token-env", default="GITHUB_TOKEN", help="Environment variable containing the GitHub token.")
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"), help="GitHub API base URL.")
    parser.add_argument(
        "--trusted-comment-authors",
        default=os.environ.get("SYNERGIE_TRUSTED_COMMENT_AUTHORS", DEFAULT_TRUSTED_COMMENT_AUTHORS),
        help="Comma-separated GitHub logins whose AI marker comments may be managed.",
    )
    parser.add_argument("--max-files", type=int, default=80)
    parser.add_argument("--max-patch-chars", type=int, default=120000)
    parser.add_argument("--max-findings", type=int, default=50)
    parser.add_argument("--provider-timeout-seconds", type=int, default=60)
    parser.add_argument("--fixture-json", default=os.environ.get("AI_REVIEW_FIXTURE_JSON", ""), help="Deterministic fixture payload for regression tests.")
    parser.add_argument("--publish-comments", action="store_true", help="Publish inline GitHub review comments.")
    return parser.parse_args()


def execute_ai_review(args: argparse.Namespace, client: Any | None = None, provider: "AIReviewProvider | None" = None) -> dict[str, Any]:
    event = read_json_file(args.event_path)
    evidence = validate_qa_evidence(args.qa_report_json, event, require_pass=True)
    if not evidence.valid:
        return unavailable_report(args, f"AI Review Unavailable: {evidence.reason}.")

    pr_number = extract_pr_number(event)
    repository = extract_repository(event) or os.environ.get("GITHUB_REPOSITORY", "")
    if not pr_number or not repository:
        return skipped_report(args, "Pull request context is unavailable.")

    if "/" not in repository:
        return unavailable_report(args, f"Invalid GitHub repository identifier `{redact(repository)}`.")

    github_token = os.environ.get(args.github_token_env, "")
    if client is None:
        if not github_token:
            return unavailable_report(args, f"${args.github_token_env} is unavailable; cannot read PR diff or publish review comments.")
        owner, repo = repository.split("/", 1)
        client = GitHubClient(args.api_url, github_token, owner, repo)

    files = client.list_pull_files(int(pr_number))
    context = build_review_context(args, event, files)
    if not context["files"]:
        report = completed_report(args, context, [], {"message": "No reviewable changed files."})
        if args.publish_comments:
            report["comment_sync"] = synchronize_inline_review_comments(
                client,
                int(pr_number),
                [],
                marker_namespace=AI_MARKER_NAMESPACE,
                review_body=DEFAULT_REVIEW_BODY,
                expected_head_sha=evidence.head_sha,
                trusted_author_logins=parse_trusted_authors(args.trusted_comment_authors),
            )
        return report

    provider = provider or provider_from_args(args)
    provider_result = provider.review(context)
    if provider_result.status != COMPLETED:
        return unavailable_report(args, provider_result.message, context)

    findings = normalize_provider_findings(provider_result.payload, context, args.provider, args.max_findings)
    report = completed_report(args, context, findings, provider_result.payload)
    if args.publish_comments:
        try:
            report["comment_sync"] = synchronize_inline_review_comments(
                client,
                int(pr_number),
                findings,
                marker_namespace=AI_MARKER_NAMESPACE,
                review_body=DEFAULT_REVIEW_BODY,
                expected_head_sha=evidence.head_sha,
                trusted_author_logins=parse_trusted_authors(args.trusted_comment_authors),
            )
        except Exception as exc:
            report["status"] = UNAVAILABLE
            report["unavailable_reason"] = f"AI review completed, but GitHub inline comment publication failed: {redact(str(exc))}"
    return report


def build_review_context(args: argparse.Namespace, event: dict[str, Any], files: list[dict[str, Any]]) -> dict[str, Any]:
    pull_request = event.get("pull_request", {}) or {}
    context: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repository": extract_repository(event),
        "pull_request": {
            "number": extract_pr_number(event),
            "title": redact(str(pull_request.get("title") or "")),
            "body": redact(str(pull_request.get("body") or ""))[:4000],
            "base_ref": (pull_request.get("base", {}) or {}).get("ref", ""),
            "head_ref": (pull_request.get("head", {}) or {}).get("ref", ""),
            "base_sha": (pull_request.get("base", {}) or {}).get("sha", ""),
            "head_sha": (pull_request.get("head", {}) or {}).get("sha", ""),
        },
        "instructions": provider_instructions(),
        "files": [],
        "reviewable_lines": {},
        "skipped_files": [],
    }
    total_chars = 0
    for item in files:
        filename = str(item.get("filename") or "")
        patch = str(item.get("patch") or "")
        if should_skip_file(filename, patch):
            context["skipped_files"].append(filename)
            continue
        if len(context["files"]) >= args.max_files:
            context["skipped_files"].append(filename)
            continue
        changed_lines = parse_added_lines(patch)
        if not changed_lines:
            context["skipped_files"].append(filename)
            continue
        remaining = args.max_patch_chars - total_chars
        if remaining <= 0:
            context["skipped_files"].append(filename)
            continue
        patch_excerpt = redact(patch[:remaining])
        total_chars += len(patch_excerpt)
        context["files"].append(
            {
                "path": filename,
                "status": item.get("status", ""),
                "previous_filename": item.get("previous_filename", ""),
                "additions": item.get("additions", 0),
                "deletions": item.get("deletions", 0),
                "patch": patch_excerpt,
                "changed_lines": [{"line": line_number, "text": redact(text)} for line_number, text in changed_lines[:120]],
            }
        )
        context["reviewable_lines"][filename] = [line_number for line_number, _ in changed_lines]
    return context


def provider_instructions() -> dict[str, Any]:
    return {
        "role": "Staff Engineer pull request reviewer",
        "scope": "Review only the changed lines in the provided pull request diff. Use unchanged hunk context only to understand the changed code.",
        "responsibilities": [
            "architecture",
            "design consistency",
            "maintainability",
            "readability",
            "code duplication",
            "possible bugs",
            "null handling",
            "error handling",
            "performance",
            "security observations",
            "race conditions",
            "API misuse",
            "resource leaks",
            "dead code",
            "naming",
            "test coverage observations",
            "framework best practices",
        ],
        "non_goals": [
            "Do not score or gate the pull request.",
            "Do not duplicate Enterprise QA responsibilities such as build, tests, secrets, dependency scanning, deployment safety, migration safety, or repository governance.",
            "Do not ask for broad rewrites when a focused recommendation is enough.",
        ],
        "output_schema": {
            "findings": [
                {
                    "path": "changed file path",
                    "line": "changed line number",
                    "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL",
                    "category": "Architecture|Maintainability|Performance|Possible Bug|Security|Duplication|Null Handling|Naming|Tests|Documentation",
                    "observation": "concise observation",
                    "why_it_matters": "concise impact",
                    "recommendation": "specific improvement",
                    "stable_id": "optional provider-stable identifier",
                }
            ],
            "summary": "short review summary",
        },
    }


def parse_added_lines(patch: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    new_line = 0
    for raw in patch.splitlines():
        hunk = re.match(r"@@ -\d+(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@", raw)
        if hunk:
            new_line = int(hunk.group("new"))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            lines.append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        elif raw.startswith(" "):
            new_line += 1
    return lines


def should_skip_file(path_text: str, patch: str) -> bool:
    path = Path(path_text)
    if not path_text or not patch:
        return True
    if any(part in GENERATED_COMPONENTS for part in path.parts):
        return True
    if path.name in LOCK_FILE_NAMES:
        return True
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    return any(match_path(path_text, pattern) for pattern in FRAMEWORK_FIXTURE_PATTERNS)


def match_path(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-3].rstrip("/") + "/")
    return path == pattern or path.endswith("/" + pattern)


@dataclass
class ProviderResult:
    status: str
    message: str
    payload: dict[str, Any]


class AIReviewProvider:
    name = "base"

    def review(self, context: dict[str, Any]) -> ProviderResult:
        raise NotImplementedError


class UnavailableProvider(AIReviewProvider):
    name = "unavailable"

    def __init__(self, message: str) -> None:
        self.message = message

    def review(self, context: dict[str, Any]) -> ProviderResult:
        return ProviderResult(UNAVAILABLE, self.message, {})


class FixtureProvider(AIReviewProvider):
    name = "fixture"

    def __init__(self, payload_text: str) -> None:
        self.payload_text = payload_text

    def review(self, context: dict[str, Any]) -> ProviderResult:
        try:
            payload = json.loads(self.payload_text or "{}")
        except json.JSONDecodeError as exc:
            return ProviderResult(UNAVAILABLE, f"AI fixture payload is invalid JSON: {exc}", {})
        if not isinstance(payload, dict):
            return ProviderResult(UNAVAILABLE, "AI fixture payload must be a JSON object.", {})
        return ProviderResult(COMPLETED, "AI fixture review completed.", payload)


class HttpProvider(AIReviewProvider):
    def __init__(self, name: str, model: str, url: str, token: str, timeout_seconds: int) -> None:
        self.name = name
        self.model = model
        self.url = url
        self.token = token
        self.timeout_seconds = timeout_seconds

    def review(self, context: dict[str, Any]) -> ProviderResult:
        payload = {
            "provider": self.name,
            "model": self.model,
            "context": context,
        }
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "synergie-ai-pr-review",
            },
        )
        try:
            opener = urllib.request.build_opener(NoRedirectHandler)
            with opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            message = exc.read().decode("utf-8", errors="replace")[:600]
            return ProviderResult(UNAVAILABLE, f"AI provider returned HTTP {exc.code}: {redact(message)}", {})
        except OSError as exc:
            return ProviderResult(UNAVAILABLE, f"AI provider request failed: {redact(str(exc))}", {})
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            return ProviderResult(UNAVAILABLE, f"AI provider returned invalid JSON: {exc}", {})
        if not isinstance(decoded, dict):
            return ProviderResult(UNAVAILABLE, "AI provider response must be a JSON object.", {})
        return ProviderResult(COMPLETED, "AI provider review completed.", decoded)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def provider_from_args(args: argparse.Namespace) -> AIReviewProvider:
    provider = str(args.provider or DEFAULT_PROVIDER).strip().lower()
    if provider == "fixture":
        return FixtureProvider(args.fixture_json)
    token = os.environ.get(args.provider_token_env, "")
    if not args.provider_url:
        return UnavailableProvider("AI Review unavailable: approved provider endpoint is not configured.")
    if not token:
        return UnavailableProvider(f"AI Review unavailable: ${args.provider_token_env} is not configured.")
    validation_error = validate_provider_destination(args.provider_url, args.approved_provider_hosts, args.approved_internal_provider_hosts)
    if validation_error:
        return UnavailableProvider(f"AI Review unavailable: {validation_error}.")
    return HttpProvider(provider, args.model, args.provider_url, token, args.provider_timeout_seconds)


def validate_provider_destination(url: str, approved_hosts_raw: str, approved_internal_hosts_raw: str = "") -> str:
    approved_hosts = parse_host_set(approved_hosts_raw)
    approved_internal_hosts = parse_host_set(approved_internal_hosts_raw)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        return "provider endpoint must use HTTPS"
    if parsed.username or parsed.password:
        return "provider endpoint must not contain embedded credentials"
    host = normalize_host(parsed.hostname or "")
    if not host:
        return "provider endpoint hostname is missing"
    if host not in approved_hosts and host not in approved_internal_hosts:
        return "provider endpoint hostname is not approved"
    network_error = prohibited_network_host(host, approved_internal_hosts)
    if network_error:
        return network_error
    return ""


def parse_host_set(raw: str) -> set[str]:
    return {normalize_host(item) for item in raw.split(",") if normalize_host(item)}


def normalize_host(host: str) -> str:
    return host.strip().strip("[]").rstrip(".").lower()


def prohibited_network_host(host: str, approved_internal_hosts: set[str]) -> str:
    if host in {"localhost", "localhost.localdomain"}:
        return "provider endpoint must not target localhost"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ""
    if ip.is_loopback:
        return "provider endpoint must not target loopback addresses"
    if ip.is_link_local:
        return "provider endpoint must not target link-local addresses"
    if ip.is_private and host not in approved_internal_hosts:
        return "provider endpoint must not target private network addresses without explicit internal-provider governance"
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return "provider endpoint must not target unsupported network addresses"
    return ""


def normalize_provider_findings(payload: dict[str, Any], context: dict[str, Any], provider_name: str, max_findings: int) -> list[dict[str, Any]]:
    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        return []
    reviewable_lines = {path: set(lines) for path, lines in context.get("reviewable_lines", {}).items()}
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        line = safe_int(item.get("line"))
        if path not in reviewable_lines or line not in reviewable_lines[path]:
            continue
        severity = normalize_severity(item.get("severity"))
        category = sanitize_short(item.get("category") or "Engineering Review")
        observation = sanitize_text(item.get("observation") or item.get("explanation") or "")
        why = sanitize_text(item.get("why_it_matters") or item.get("why") or "")
        recommendation = sanitize_text(item.get("recommendation") or "")
        if not observation or not recommendation:
            continue
        stable_id = sanitize_short(item.get("stable_id") or item.get("id") or observation[:80])
        fingerprint = ai_fingerprint(path, line, category, stable_id)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        normalized.append(
            {
                "review_type": "ai",
                "fingerprint": fingerprint,
                "path": path,
                "line": line,
                "side": "RIGHT",
                "severity": severity,
                "category": category,
                "title": f"AI REVIEW: {category.upper()}",
                "observation": observation,
                "why_it_matters": why or "This may affect maintainability, correctness, performance, security, or clarity.",
                "recommendation": recommendation,
                "provider": provider_name,
                "blocking": False,
            }
        )
        if len(normalized) >= max_findings:
            break
    return normalized


def normalize_severity(value: Any) -> str:
    severity = str(value or "INFO").strip().upper()
    return severity if severity in SEVERITIES else "INFO"


def sanitize_short(value: Any) -> str:
    return re.sub(r"\s+", " ", redact(str(value))).strip()[:120]


def sanitize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", redact(str(value))).strip()[:700]


def ai_fingerprint(path: str, line: int, category: str, stable_id: str) -> str:
    identity = json.dumps(
        {
            "type": "ai-review-v1",
            "path": path,
            "line": line,
            "category": category.lower(),
            "stable_id": stable_id.lower(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def completed_report(args: argparse.Namespace, context: dict[str, Any], findings: list[dict[str, Any]], provider_payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": COMPLETED,
        "provider": args.provider,
        "model": args.model,
        "summary": summarize_findings(findings),
        "provider_summary": sanitize_text(provider_payload.get("summary", "")) if isinstance(provider_payload, dict) else "",
        "reviewed_files": [item["path"] for item in context.get("files", [])],
        "skipped_files": context.get("skipped_files", []),
        "findings": findings,
        "governance": governance_invariants(),
    }


def skipped_report(args: argparse.Namespace, reason: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": SKIPPED,
        "provider": args.provider,
        "model": args.model,
        "skipped_reason": reason,
        "summary": summarize_findings([]),
        "findings": [],
        "governance": governance_invariants(),
    }


def unavailable_report(args: argparse.Namespace, reason: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": UNAVAILABLE,
        "provider": args.provider,
        "model": args.model,
        "unavailable_reason": reason,
        "summary": summarize_findings([]),
        "reviewed_files": [item["path"] for item in (context or {}).get("files", [])],
        "skipped_files": (context or {}).get("skipped_files", []),
        "findings": [],
        "governance": governance_invariants(),
    }


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = {severity: 0 for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    category_counts: dict[str, int] = {}
    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        severity_counts[severity] += 1
        category = str(finding.get("category") or "Engineering Review")
        category_counts[category] = category_counts.get(category, 0) + 1
    return {
        "observations": len(findings),
        "severity_counts": severity_counts,
        "category_counts": dict(sorted(category_counts.items())),
        "merge_effect": "NONE",
    }


def governance_invariants() -> list[str]:
    return [
        "AI Review is advisory only and never changes Enterprise QA results.",
        "AI Review does not change risk score, merge readiness, approvals, Branch Protection, CODEOWNERS, deployment policy, or release governance.",
        "Enterprise QA remains the only automated blocking quality gate.",
        "Executive Release Authority review remains required before merge.",
    ]


def write_reports(args: argparse.Namespace, report: dict[str, Any]) -> None:
    markdown = render_markdown_report(report)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(markdown, encoding="utf-8")
    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# AI ENGINEERING REVIEW",
        "",
        f"Status: `{redact(str(report.get('status', UNAVAILABLE)))}`",
        f"Provider: `{redact(str(report.get('provider', 'unknown')))}`",
        f"Model: `{redact(str(report.get('model', 'unknown')))}`",
        "",
    ]
    if report.get("status") == UNAVAILABLE:
        lines.extend(
            [
                "AI Review unavailable.",
                "",
                redact(str(report.get("unavailable_reason", "Provider unavailable."))),
                "",
                "Enterprise QA completed independently. This advisory review failure does not change QA or merge governance.",
                "",
            ]
        )
        return "\n".join(lines)
    if report.get("status") == SKIPPED:
        lines.extend([redact(str(report.get("skipped_reason", "AI Review skipped."))), ""])
        return "\n".join(lines)

    summary = report.get("summary", {}) or {}
    severity_counts = summary.get("severity_counts", {}) or {}
    lines.extend(
        [
            f"Observations: {safe_int(summary.get('observations'))}",
            "",
            "| Severity | Count |",
            "| --- | ---: |",
        ]
    )
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {severity} | {safe_int(severity_counts.get(severity))} |")
    provider_summary = str(report.get("provider_summary") or "").strip()
    if provider_summary:
        lines.extend(["", "## Summary", redact(provider_summary)])
    findings = report.get("findings", []) or []
    if findings:
        lines.extend(["", "## Observations"])
        for finding in findings[:20]:
            lines.append(
                f"- {redact(str(finding.get('severity')))} {redact(str(finding.get('category')))} "
                f"at `{redact(str(finding.get('path')))}:{safe_int(finding.get('line'))}`: "
                f"{redact(str(finding.get('observation')))}"
            )
    lines.extend(["", "## Governance Note", "AI Review is advisory only. Enterprise QA, GitHub Branch Protection, and Executive Release Authority remain authoritative."])
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
