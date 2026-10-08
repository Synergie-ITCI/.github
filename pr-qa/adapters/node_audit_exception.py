"""Fail-closed, single-PR acceptance of a documented mobile tooling audit result."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .base import CheckResult, CommandOutcome, PRContext, warning

EXCEPTION_FILE = Path(__file__).resolve().parents[2] / "policy/exceptions/fieldzilla-pr476-mobile-audit.json"
DEPENDENCY_FILES = {"apps/mobile/package.json", "apps/mobile/package-lock.json"}
ADVISORY_ID = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _advisories(audit: dict) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    vulnerabilities = audit["vulnerabilities"]
    if not isinstance(vulnerabilities, dict) or not vulnerabilities:
        raise ValueError("missing vulnerabilities")
    for package, vulnerability in vulnerabilities.items():
        if not isinstance(vulnerability, dict):
            raise ValueError("invalid vulnerability")
        for advisory in vulnerability["via"]:
            if not isinstance(advisory, dict):
                continue  # npm's string entries are inherited dependency chains.
            identifier = advisory["url"].rsplit("/", 1)[-1]
            if not ADVISORY_ID.fullmatch(identifier):
                raise ValueError("invalid advisory identity")
            findings.append({
                "package": package,
                "id": identifier,
                "severity": advisory["severity"],
                "range": advisory["range"],
            })
    return sorted(findings, key=lambda item: (item["package"], item["id"]))


def _github_list(ctx: PRContext, endpoint: str, key: str) -> set[str]:
    if not os.environ.get("GH_TOKEN"):
        raise ValueError("GitHub token unavailable")
    outcome = ctx.run(["gh", "api", f"repos/Synergie-ITCI/programme-management-platform/{endpoint}?per_page=100"], cwd=ctx.repo)
    if not outcome.ok or outcome.skipped:
        raise ValueError("GitHub release state unavailable")
    entries = json.loads(outcome.stdout)
    if not isinstance(entries, list) or len(entries) >= 100:
        raise ValueError("GitHub release list incomplete")
    names = [entry[key] for entry in entries]
    if not all(isinstance(name, str) and name for name in names):
        raise ValueError("invalid GitHub release state")
    return set(names)


def evaluate_mobile_audit_exception(ctx: PRContext, root: Path, original: CommandOutcome) -> CheckResult | None:
    """Return a visible warning only when every approved boundary still matches.

    None means the original audit failure remains blocking. The regular audit is
    always executed before this function; its raw result is never discarded.
    """
    event_pr = ctx.event.get("pull_request") or {}
    repository = (ctx.event.get("repository") or {}).get("full_name")
    if repository != "Synergie-ITCI/programme-management-platform" or event_pr.get("number") != 476:
        return None
    if ctx.rel(root) != "apps/mobile" or original.ok or original.skipped or original.timed_out:
        return None
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        if package.get("scripts", {}).get("audit:ci") != "npm audit --audit-level=high":
            return None
        manifest = json.loads(EXCEPTION_FILE.read_text(encoding="utf-8"))
        evidence = EXCEPTION_FILE.parent / manifest["evidence_file"]
        if not evidence.is_file() or _digest(evidence) != manifest["evidence_sha256"]:
            return None
        if not all(manifest.get(field) for field in ("approver", "reason", "residual_risk", "remediation_owner")):
            return None
        if manifest["repository"] != repository or manifest["pr"] != event_pr["number"]:
            return None
        head = event_pr["head"]["sha"]
        if head != manifest["head_sha"]:
            return None
        actual_head = ctx.run(["git", "rev-parse", "HEAD"], cwd=ctx.repo)
        if not actual_head.ok or actual_head.stdout.strip() != head:
            return None
        if DEPENDENCY_FILES.intersection(ctx.changed_files):
            return None
        if any(_digest(ctx.repo / name) != digest for name, digest in manifest["dependency_sha256"].items()):
            return None
        if set(manifest["dependency_sha256"]) != DEPENDENCY_FILES:
            return None
        expiry = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) >= expiry:
            return None
        if _github_list(ctx, "tags", "name") != set(manifest["baseline_tags"]):
            return None
        if _github_list(ctx, "releases", "tag_name") != set(manifest["baseline_releases"]):
            return None
        audit = ctx.run(["npm", "audit", "--json"], cwd=root)
        if audit.skipped or audit.timed_out:
            return None
        audit_report = json.loads(audit.stdout)
        observed = _advisories(audit_report)
        if observed != manifest["advisories"]:
            return None
        result = {
            "decision": "time-boxed exception; audit remains vulnerable",
            "repository": repository,
            "pr": manifest["pr"],
            "head_sha": head,
            "approver": manifest["approver"],
            "remediation_owner": manifest["remediation_owner"],
            "expires_at": manifest["expires_at"],
            "advisories": observed,
            "audit_metadata": audit_report.get("metadata", {}).get("vulnerabilities", {}),
        }
        output = ctx.repo / "pr-qa-results/mobile-audit-exception.json"
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return warning(
            "Dependencies", "Node.js",
            "apps/mobile: npm audit failed; PR #476 exact-head mobile tooling exception accepted until expiry or next tag/release. Residual build risk remains.",
            [f"Audit report: pr-qa-results/mobile-audit-exception.json; approver: {manifest['approver']}; remediation owner: {manifest['remediation_owner']}"],
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
