"""Fail-closed acceptance of explicitly documented, exact-PR mobile audits."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .base import CheckResult, CommandOutcome, PRContext, warning

EXCEPTION_DIRECTORY = Path(__file__).resolve().parents[2] / "policy/exceptions"
EXCEPTION_FILES = {
    476: EXCEPTION_DIRECTORY / "fieldzilla-pr476-mobile-audit.json",
    477: EXCEPTION_DIRECTORY / "fieldzilla-pr477-mobile-audit.json",
    485: EXCEPTION_DIRECTORY / "fieldzilla-pr485-mobile-audit.json",
    487: EXCEPTION_DIRECTORY / "fieldzilla-pr487-mobile-audit.json",
}
EVIDENCE_GATED_PRS = {485, 487}
DEPENDENCY_FILES = {"apps/mobile/package.json", "apps/mobile/package-lock.json"}
ADVISORY_ID = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
NON_RUNTIME_PACKAGES = {"braces", "micromatch", "shell-quote", "compression", "joi", "sprintf-js", "metro-config", "@react-native-community/cli", "jest"}


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


def _validate_bundle_evidence(manifest: dict, exception_file: Path, head: str, number: int) -> bool:
    if manifest.get("environment") != "staging" or manifest.get("production_excluded") is not True:
        return False
    bundles = manifest.get("bundle_evidence")
    if not isinstance(bundles, dict) or set(bundles) != {"android", "ios"}:
        return False
    for platform in ("android", "ios"):
        item = bundles[platform]
        expected_name = f"fieldzilla-pr{number}-{platform}-sources.json"
        if not isinstance(item, dict) or item.get("source_file") != expected_name:
            return False
        if not all(re.fullmatch(r"[0-9a-f]{64}", item.get(key, "")) for key in ("source_sha256", "map_sha256", "bundle_sha256")):
            return False
        source_file = exception_file.with_name(expected_name)
        if not source_file.is_file() or _digest(source_file) != item["source_sha256"]:
            return False
        source_data = json.loads(source_file.read_text(encoding="utf-8"))
        if not isinstance(source_data, dict):
            return False
        sources = source_data.get("sources")
        if source_data.get("platform") != platform or source_data.get("head_sha") != head:
            return False
        if not isinstance(sources, list) or len(sources) != item.get("source_count") or len(sources) < 1000:
            return False
        if not all(isinstance(source, str) for source in sources):
            return False
        if any(any(f"node_modules/{package}/" in f"{source}/" for package in NON_RUNTIME_PACKAGES) for source in sources):
            return False
    return True


def evaluate_mobile_audit_exception(ctx: PRContext, root: Path, original: CommandOutcome) -> CheckResult | None:
    """Return a visible warning only when every approved boundary still matches.

    None means the original audit failure remains blocking. The regular audit is
    always executed before this function; its raw result is never discarded.
    """
    event_pr = ctx.event.get("pull_request") or {}
    repository = (ctx.event.get("repository") or {}).get("full_name")
    number = event_pr.get("number")
    if type(number) is not int:
        return None
    exception_file = EXCEPTION_FILES.get(number)
    if repository != "Synergie-ITCI/programme-management-platform" or exception_file is None:
        return None
    if ctx.rel(root) != "apps/mobile" or original.ok or original.skipped or original.timed_out:
        return None
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        if package.get("scripts", {}).get("audit:ci") != "npm audit --audit-level=high":
            return None
        manifest = json.loads(exception_file.read_text(encoding="utf-8"))
        evidence = exception_file.parent / manifest["evidence_file"]
        if not evidence.is_file() or _digest(evidence) != manifest["evidence_sha256"]:
            return None
        if not all(manifest.get(field) for field in ("approver", "reason", "residual_risk", "remediation_owner")):
            return None
        if number in EVIDENCE_GATED_PRS and any(path.startswith("policy/exceptions/") or path.startswith("pr-qa/adapters/node_audit_exception.py") for path in ctx.changed_files):
            return None
        if manifest["repository"] != repository or manifest["pr"] != event_pr["number"]:
            return None
        if number in EVIDENCE_GATED_PRS and event_pr.get("base", {}).get("ref") != "development":
            return None
        head = event_pr["head"]["sha"]
        if head != manifest["head_sha"]:
            return None
        if number in EVIDENCE_GATED_PRS and not _validate_bundle_evidence(manifest, exception_file, head, number):
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
        if number in EVIDENCE_GATED_PRS:
            script = package["scripts"]["audit:ci"]
            if hashlib.sha256(script.encode()).hexdigest() != manifest["audit_script_sha256"]:
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
        if number in EVIDENCE_GATED_PRS:
            expected_paths = manifest["package_paths"]
            if set(expected_paths) != {item["package"] for item in observed}:
                return None
            for package_name, vulnerability in audit_report["vulnerabilities"].items():
                if package_name in expected_paths and sorted(vulnerability["nodes"]) != sorted(expected_paths[package_name]):
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
        if number in EVIDENCE_GATED_PRS:
            result["bundle_evidence"] = manifest["bundle_evidence"]
        output = ctx.repo / "pr-qa-results/mobile-audit-exception.json"
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return warning(
            "Dependencies", "Node.js",
            f"apps/mobile: npm audit failed; PR #{manifest['pr']} exact-head mobile tooling exception accepted until expiry or next tag/release. Residual build risk remains.",
            [f"Audit report: pr-qa-results/mobile-audit-exception.json; approver: {manifest['approver']}; remediation owner: {manifest['remediation_owner']}"],
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
