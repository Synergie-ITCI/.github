#!/usr/bin/env python3
"""Read-only organization governance attestation using the existing inventory API.

This reports drift. It never creates or edits repositories, rules, or workflows.
"""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from github_governance_inventory import gh_api


REQUIRED_CONTEXT = "pr-qa / Pull Request Quality Assurance"
CALLER_PATH = ".github/workflows/pr-qa.yml"
CENTRAL_USES = "Synergie-ITCI/.github/.github/workflows/pr-qa.yml@"


def findings_for_repository(record: dict[str, Any]) -> list[dict[str, str]]:
    """Classify observations without equating missing evidence with bypass."""
    findings: list[dict[str, str]] = []
    name = str(record.get("name", "unknown"))

    def add(code: str, detail: str) -> None:
        findings.append({"repository": name, "code": code, "detail": detail})

    if record.get("query_error"):
        add("EVIDENCE_UNAVAILABLE", str(record["query_error"]))
        return findings
    if record.get("archived") or record.get("disabled"):
        return findings
    caller = record.get("caller") or {}
    if not caller.get("present"):
        add("MISSING_CALLER", f"{CALLER_PATH} absent on {record.get('default_branch')}")
    elif not caller.get("central") and name != ".github":
        add("NONCENTRAL_CALLER", "PR-QA caller does not invoke the central reusable workflow")
    elif str(caller.get("workflow_state") or "").startswith("disabled"):
        add("DISABLED_CALLER", f"workflow state={caller.get('workflow_state')}")
    elif caller.get("workflow_state") != "active":
        add("CALLER_STATE_UNVERIFIED", f"workflow state={caller.get('workflow_state') or 'unknown'}")
    if REQUIRED_CONTEXT not in record.get("required_checks", []):
        add("UNENFORCED_CHECK", f"{REQUIRED_CONTEXT} is not effective on {record.get('default_branch')}")
    if not record.get("pull_request_rule"):
        add("MISSING_PR_RULE", f"no effective pull-request rule on {record.get('default_branch')}")
    for branch, protected in sorted((record.get("promotion_branches") or {}).items()):
        if protected is False:
            add("UNPROTECTED_PROMOTION_BRANCH", branch)
    if record.get("declares_production") and not record.get("release_workflow_candidate"):
        add("MISSING_RELEASE_CONTROL_EVIDENCE", "production environment declared; no repository release workflow identified; external route may exist")
    return findings


def expired_exception_findings(root: Path, now: datetime) -> list[dict[str, str]]:
    """Report expiration as review evidence; old one-time records may be historical."""
    findings: list[dict[str, str]] = []
    for path in sorted((root / "policy" / "exceptions").glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            findings.append({"repository": "Synergie-ITCI/.github", "code": "EXCEPTION_UNREADABLE", "detail": path.name})
            continue
        expiry = data.get("expires_at") or data.get("expires_after")
        if not isinstance(expiry, str):
            continue
        try:
            deadline = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        except ValueError:
            findings.append({"repository": "Synergie-ITCI/.github", "code": "EXCEPTION_EXPIRY_INVALID", "detail": path.name})
            continue
        if deadline <= now:
            findings.append({"repository": str(data.get("repository") or "Synergie-ITCI/.github"), "code": "EXPIRED_EXCEPTION_RECORD", "detail": path.name})
    return findings


def _api_data(path: str) -> Any:
    result = gh_api(path)
    if not result.ok:
        raise RuntimeError(f"GET {path}: {result.error[:160]}")
    return result.data


def live_record(owner: str, name: str) -> dict[str, Any]:
    full = f"{owner}/{name}"
    try:
        repo = _api_data(f"repos/{full}")
        branch = repo["default_branch"]
        rules = _api_data(f"repos/{full}/rules/branches/{branch}")
        workflows = _api_data(f"repos/{full}/actions/workflows?per_page=100")
        contents = gh_api(f"repos/{full}/contents/{CALLER_PATH}?ref={branch}")
        if contents.ok and isinstance(contents.data, dict):
            text = base64.b64decode(contents.data["content"]).decode("utf-8", "replace")
            central = CENTRAL_USES in text
            present = True
        elif "404" in contents.error or "Not Found" in contents.error:
            central, present = False, False
        else:
            raise RuntimeError(f"GET {CALLER_PATH}: {contents.error[:160]}")
        matching = [w for w in workflows.get("workflows", []) if w.get("path") == CALLER_PATH]
        state = matching[0].get("state") if matching else ("absent" if not present else "unknown")
        checks = [c.get("context") for rule in rules if rule.get("type") == "required_status_checks"
                  for c in (rule.get("parameters") or {}).get("required_status_checks", [])]
        environments = _api_data(f"repos/{full}/environments?per_page=100").get("environments", [])
        env_names = [str(e.get("name", "")) for e in environments]
        promotion: dict[str, bool] = {}
        for promotion_branch in ("development", "staging"):
            result = gh_api(f"repos/{full}/branches/{promotion_branch}")
            if result.ok and isinstance(result.data, dict):
                promotion[promotion_branch] = bool(result.data.get("protected"))
            elif "404" not in result.error and "Not Found" not in result.error:
                raise RuntimeError(f"GET branch {promotion_branch}: {result.error[:160]}")
        release_workflow_candidate = any(re.search(r"(production.*deploy|controlled.*release|gate.?d)",
                                                   str(w.get("path", "")), re.IGNORECASE)
                                         for w in workflows.get("workflows", []))
        return {"name": name, "default_branch": branch, "archived": repo.get("archived"),
                "disabled": repo.get("disabled"), "caller": {"present": present, "central": central,
                "workflow_state": state}, "required_checks": checks,
                "pull_request_rule": any(rule.get("type") == "pull_request" for rule in rules),
                "promotion_branches": promotion,
                "declares_production": any("prod" in e.lower() for e in env_names),
                "release_workflow_candidate": release_workflow_candidate}
    except (RuntimeError, KeyError, TypeError, ValueError) as exc:
        return {"name": name, "query_error": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default="Synergie-ITCI")
    parser.add_argument("--repository", action="append", help="Limit live run to selected repository name; repeatable")
    parser.add_argument("--snapshot", type=Path, help="Read records from a local fixture instead of GitHub")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.snapshot:
        records = json.loads(args.snapshot.read_text(encoding="utf-8"))
    else:
        names = args.repository
        if not names:
            names = []
            page = 1
            while True:
                repos = _api_data(f"orgs/{args.owner}/repos?per_page=100&type=all&page={page}")
                names.extend(str(r["name"]) for r in repos)
                if len(repos) < 100:
                    break
                page += 1
        # Bound concurrency so an organization scan remains timely without
        # flooding the GitHub API or multiplying full PR-QA scans.
        with ThreadPoolExecutor(max_workers=6) as executor:
            records = list(executor.map(lambda name: live_record(args.owner, name), names))
    now = datetime.now(timezone.utc)
    findings = [f for record in records for f in findings_for_repository(record)]
    findings.extend(expired_exception_findings(Path(__file__).resolve().parents[1], now))
    report = {"schema_version": 1, "mode": "report-only", "observed_at": now.isoformat(),
              "source_sha": os.environ.get("GITHUB_SHA"),
              "repository_count": len(records), "records": records, "findings": findings}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Attested {len(records)} repositories; {len(findings)} report-only findings; output={args.output}")
    return 1 if any(record.get("query_error") for record in records) else 0


if __name__ == "__main__":
    raise SystemExit(main())
