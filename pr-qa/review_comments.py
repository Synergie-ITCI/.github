#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


MARKER_RE = re.compile(r"<!-- synergie-pr-qa:inline-review fingerprint=([a-f0-9]{16,64}) -->")
MARKER_TEMPLATE = "<!-- synergie-pr-qa:inline-review fingerprint={fingerprint} -->"
MAX_BATCH_COMMENTS = 50


def main() -> int:
    args = parse_args()
    event = read_json_file(args.event_path)
    report = read_json_file(args.report_json)
    pr_number = extract_pr_number(event)
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY", "") or extract_repository(event)
    if not pr_number or not repository:
        print("Synergie inline review comments skipped: pull request context is unavailable.")
        return 0

    findings = list(report.get("inline_review", {}).get("findings", []) or [])
    if args.dry_run:
        result = dry_run_payload(event, findings)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    token = os.environ.get(args.token_env, "")
    if not token:
        print(f"Synergie inline review comments skipped: ${args.token_env} is unavailable.")
        return 0

    owner, repo = repository.split("/", 1)
    client = GitHubClient(args.api_url, token, owner, repo)
    outcome = synchronize_inline_review_comments(client, int(pr_number), findings)
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Publish Synergie PR QA inline review comments.")
    parser.add_argument("--event-path", default=os.environ.get("GITHUB_EVENT_PATH", ""), help="GitHub pull_request event payload path.")
    parser.add_argument("--report-json", default="pr-qa-results/pr-quality-report.json", help="PR QA JSON report path.")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""), help="owner/repo override.")
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"), help="GitHub API base URL.")
    parser.add_argument("--token-env", default="GITHUB_TOKEN", help="Environment variable containing the GitHub token.")
    parser.add_argument("--dry-run", action="store_true", help="Print comment plan without calling GitHub.")
    return parser.parse_args()


def read_json_file(path_text: str) -> dict[str, Any]:
    if not path_text:
        return {}
    try:
        with open(path_text, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def extract_pr_number(event: dict[str, Any]) -> int | str:
    pull_request = event.get("pull_request", {}) or {}
    return pull_request.get("number") or event.get("number") or ""


def extract_repository(event: dict[str, Any]) -> str:
    repository = event.get("repository", {}) or {}
    return str(repository.get("full_name") or "")


def dry_run_payload(event: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "repository": extract_repository(event),
        "pull_request": extract_pr_number(event),
        "candidate_findings": len(findings),
        "deduplicated_findings": len(dedupe_findings(findings)),
    }


@dataclass
class GitHubClient:
    api_url: str
    token: str
    owner: str
    repo: str

    def list_pull_files(self, pr_number: int) -> list[dict[str, Any]]:
        return self.paginated(f"/repos/{self.owner}/{self.repo}/pulls/{pr_number}/files")

    def list_review_comments(self, pr_number: int) -> list[dict[str, Any]]:
        return self.paginated(f"/repos/{self.owner}/{self.repo}/pulls/{pr_number}/comments")

    def create_review(self, pr_number: int, comments: list[dict[str, Any]]) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/repos/{self.owner}/{self.repo}/pulls/{pr_number}/reviews",
            {
                "event": "COMMENT",
                "body": "Synergie Enterprise PR QA inline review findings.",
                "comments": comments,
            },
        )

    def update_comment(self, comment_id: int, body: str) -> dict[str, Any]:
        return self.request_json("PATCH", f"/repos/{self.owner}/{self.repo}/pulls/comments/{comment_id}", {"body": body})

    def delete_comment(self, comment_id: int) -> dict[str, Any]:
        return self.request_json("DELETE", f"/repos/{self.owner}/{self.repo}/pulls/comments/{comment_id}")

    def paginated(self, path: str) -> list[dict[str, Any]]:
        page = 1
        items: list[dict[str, Any]] = []
        while True:
            sep = "&" if "?" in path else "?"
            payload = self.request_json("GET", f"{path}{sep}per_page=100&page={page}")
            if not isinstance(payload, list) or not payload:
                break
            items.extend(item for item in payload if isinstance(item, dict))
            if len(payload) < 100:
                break
            page += 1
        return items

    def request_json(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        base = self.api_url.rstrip("/")
        url = base + path
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "synergie-pr-qa-inline-review",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            message = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API {method} {path} failed with HTTP {exc.code}: {message}") from exc
        if not data:
            return {}
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return {}


def synchronize_inline_review_comments(client: Any, pr_number: int, findings: list[dict[str, Any]]) -> dict[str, Any]:
    files = client.list_pull_files(pr_number)
    positions = build_diff_positions(files)
    desired = map_findings_to_diff(dedupe_findings(findings), positions)
    existing_comments = synergie_comments(client.list_review_comments(pr_number))
    desired_by_fingerprint = {finding["fingerprint"]: finding for finding in desired[:MAX_BATCH_COMMENTS]}

    created: list[str] = []
    updated: list[str] = []
    deleted: list[str] = []
    new_comments: list[dict[str, Any]] = []

    existing_by_fingerprint: dict[str, dict[str, Any]] = {}
    duplicate_existing: list[dict[str, Any]] = []
    for comment in existing_comments:
        fingerprint = comment["fingerprint"]
        if fingerprint in existing_by_fingerprint:
            duplicate_existing.append(comment)
        else:
            existing_by_fingerprint[fingerprint] = comment

    for comment in duplicate_existing:
        client.delete_comment(int(comment["id"]))
        deleted.append(comment["fingerprint"])

    for fingerprint, comment in existing_by_fingerprint.items():
        desired_finding = desired_by_fingerprint.get(fingerprint)
        if not desired_finding:
            client.delete_comment(int(comment["id"]))
            deleted.append(fingerprint)
            continue
        body = render_comment_body(desired_finding)
        if location_changed(comment, desired_finding):
            client.delete_comment(int(comment["id"]))
            deleted.append(fingerprint)
            new_comments.append(review_comment_payload(desired_finding, body))
            created.append(fingerprint)
        elif str(comment.get("body") or "") != body:
            client.update_comment(int(comment["id"]), body)
            updated.append(fingerprint)

    for fingerprint, desired_finding in desired_by_fingerprint.items():
        if fingerprint not in existing_by_fingerprint:
            body = render_comment_body(desired_finding)
            new_comments.append(review_comment_payload(desired_finding, body))
            created.append(fingerprint)

    if new_comments:
        client.create_review(pr_number, new_comments)

    return {
        "candidate_findings": len(findings),
        "diff_mappable_findings": len(desired),
        "published_findings": len(desired_by_fingerprint),
        "created": len(created),
        "updated": len(updated),
        "removed": len(deleted),
        "skipped": max(0, len(desired) - len(desired_by_fingerprint)),
        "fingerprints": {
            "created": created,
            "updated": updated,
            "removed": deleted,
        },
    }


def build_diff_positions(files: list[dict[str, Any]]) -> dict[str, dict[str, set[int]]]:
    positions: dict[str, dict[str, set[int]]] = {}
    for item in files:
        path = str(item.get("filename") or "")
        previous = str(item.get("previous_filename") or "")
        patch = str(item.get("patch") or "")
        if not path:
            continue
        positions.setdefault(path, {"RIGHT": set(), "LEFT": set()})
        if previous:
            positions.setdefault(previous, {"RIGHT": set(), "LEFT": set()})
        old_line = 0
        new_line = 0
        for line in patch.splitlines():
            hunk = re.match(r"@@ -(?P<old>\d+)(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@", line)
            if hunk:
                old_line = int(hunk.group("old"))
                new_line = int(hunk.group("new"))
                continue
            if not line:
                continue
            prefix = line[0]
            if prefix == "+" and not line.startswith("+++"):
                positions[path]["RIGHT"].add(new_line)
                new_line += 1
            elif prefix == "-" and not line.startswith("---"):
                positions[path]["LEFT"].add(old_line)
                if previous:
                    positions[previous]["LEFT"].add(old_line)
                old_line += 1
            elif prefix == " ":
                positions[path]["RIGHT"].add(new_line)
                positions[path]["LEFT"].add(old_line)
                if previous:
                    positions[previous]["LEFT"].add(old_line)
                old_line += 1
                new_line += 1
    return positions


def map_findings_to_diff(findings: list[dict[str, Any]], positions: dict[str, dict[str, set[int]]]) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    for finding in findings:
        path = str(finding.get("path") or "")
        side = str(finding.get("side") or "RIGHT").upper()
        line = safe_int(finding.get("line"))
        if not path or side not in {"RIGHT", "LEFT"} or line <= 0:
            continue
        if line not in positions.get(path, {}).get(side, set()):
            continue
        copied = dict(finding)
        copied["side"] = side
        copied["line"] = line
        mapped.append(copied)
    return mapped


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        fingerprint = str(finding.get("fingerprint") or "")
        if not fingerprint or fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(finding)
    return deduped


def synergie_comments(comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matched = []
    for comment in comments:
        body = str(comment.get("body") or "")
        marker = MARKER_RE.search(body)
        if not marker:
            continue
        copied = dict(comment)
        copied["fingerprint"] = marker.group(1)
        matched.append(copied)
    return matched


def render_comment_body(finding: dict[str, Any]) -> str:
    fingerprint = str(finding["fingerprint"])
    return "\n".join(
        [
            MARKER_TEMPLATE.format(fingerprint=fingerprint),
            f"**{sanitize_line(finding.get('title', 'PR QA FINDING'))}**",
            "",
            f"Severity: {sanitize_line(finding.get('severity', 'WARNING'))}",
            "",
            f"Explanation: {sanitize_paragraph(finding.get('explanation', 'QA reported a finding at this location.'))}",
            "",
            f"Recommendation: {sanitize_paragraph(finding.get('recommendation', 'Review and address this finding before merge.'))}",
            "",
            f"Gate: {sanitize_line(finding.get('gate', 'Unknown'))}",
        ]
    )


def review_comment_payload(finding: dict[str, Any], body: str) -> dict[str, Any]:
    return {
        "path": str(finding["path"]),
        "line": int(finding["line"]),
        "side": str(finding.get("side") or "RIGHT").upper(),
        "body": body,
    }


def location_changed(comment: dict[str, Any], finding: dict[str, Any]) -> bool:
    return (
        str(comment.get("path") or "") != str(finding.get("path") or "")
        or safe_int(comment.get("line") or comment.get("original_line")) != safe_int(finding.get("line"))
        or str(comment.get("side") or "RIGHT").upper() != str(finding.get("side") or "RIGHT").upper()
    )


def sanitize_line(value: Any) -> str:
    return redact(str(value)).replace("\n", " ").strip()


def sanitize_paragraph(value: Any) -> str:
    return redact(str(value)).replace("\r", "").strip()


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


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"Synergie inline review comments failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
