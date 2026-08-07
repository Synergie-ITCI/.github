#!/usr/bin/env python3
"""Read-only GitHub governance inventory helper.

This tool intentionally does not create branches, rulesets, protections,
workflows, environments, or repository files. It gathers the evidence needed
before adopting the Synergie branch and release governance standard.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GhResult:
    ok: bool
    data: Any
    error: str = ""


def gh_api(path: str) -> GhResult:
    command = ["gh", "api", path]
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        return GhResult(False, None, completed.stderr.strip())
    if not completed.stdout.strip():
        return GhResult(True, None)
    try:
        return GhResult(True, json.loads(completed.stdout))
    except json.JSONDecodeError as exc:
        return GhResult(False, None, f"Invalid JSON from gh api {path}: {exc}")


def names(items: Any, key: str = "name") -> list[str]:
    if not isinstance(items, list):
        return []
    values: list[str] = []
    for item in items:
        if isinstance(item, dict) and item.get(key):
            values.append(str(item[key]))
    return sorted(values)


def repo_inventory(owner: str, repo: str) -> dict[str, Any]:
    full = f"{owner}/{repo}"
    result: dict[str, Any] = {
        "repository": full,
        "classification": {
            "create_or_update_governance_adapter": "REVIEW",
            "branch_rulesets": "REVIEW",
            "branch_bootstrap": "REVIEW",
        },
        "errors": [],
    }

    repo_info = gh_api(f"repos/{full}")
    if repo_info.ok and isinstance(repo_info.data, dict):
        result["default_branch"] = repo_info.data.get("default_branch")
        result["private"] = repo_info.data.get("private")
        result["archived"] = repo_info.data.get("archived")
    else:
        result["errors"].append(repo_info.error)
        return result

    branches = gh_api(f"repos/{full}/branches?per_page=100")
    if branches.ok:
        result["branches"] = [
            {
                "name": item.get("name"),
                "protected": item.get("protected"),
            }
            for item in branches.data or []
            if isinstance(item, dict)
        ]
    else:
        result["errors"].append(branches.error)

    rulesets = gh_api(f"repos/{full}/rulesets")
    if rulesets.ok:
        result["rulesets"] = [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "target": item.get("target"),
                "enforcement": item.get("enforcement"),
            }
            for item in rulesets.data or []
            if isinstance(item, dict)
        ]
    else:
        result["errors"].append(rulesets.error)

    workflows = gh_api(f"repos/{full}/actions/workflows")
    if workflows.ok and isinstance(workflows.data, dict):
        result["workflows"] = names(workflows.data.get("workflows"))
    else:
        result["errors"].append(workflows.error)

    environments = gh_api(f"repos/{full}/environments")
    if environments.ok and isinstance(environments.data, dict):
        result["environments"] = names(environments.data.get("environments"))
    else:
        result["errors"].append(environments.error)

    for path in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]:
        encoded_path = path.replace("/", "%2F")
        codeowners = gh_api(f"repos/{full}/contents/{encoded_path}")
        if codeowners.ok:
            result["codeowners_path"] = path
            break
    else:
        result["codeowners_path"] = None

    branch_names = {item["name"] for item in result.get("branches", [])}
    missing = [branch for branch in ["development", "staging", "main"] if branch not in branch_names]
    result["canonical_branch_status"] = {
        "missing": missing,
        "has_development": "development" in branch_names,
        "has_staging": "staging" in branch_names,
        "has_main": "main" in branch_names,
        "has_master": "master" in branch_names,
    }

    if result.get("archived"):
        result["classification"]["create_or_update_governance_adapter"] = "CONFLICT"
        result["classification"]["branch_rulesets"] = "CONFLICT"
        result["classification"]["branch_bootstrap"] = "CONFLICT"
    elif any("synergie" in item.lower() and "governance" in item.lower() for item in result.get("workflows", [])):
        result["classification"]["create_or_update_governance_adapter"] = "PRESERVE"
    else:
        result["classification"]["create_or_update_governance_adapter"] = "ADD"

    if result.get("rulesets"):
        result["classification"]["branch_rulesets"] = "PRESERVE_OR_ADD"
    else:
        result["classification"]["branch_rulesets"] = "ADD"

    if missing:
        result["classification"]["branch_bootstrap"] = "ADD_AFTER_SOURCE_COMMIT_REVIEW"
    else:
        result["classification"]["branch_bootstrap"] = "PRESERVE"

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", help="Repository in owner/name form.")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output.",
    )
    args = parser.parse_args()

    if "/" not in args.repository:
        print("repository must be in owner/name form", file=sys.stderr)
        return 2

    owner, repo = args.repository.split("/", 1)
    inventory = repo_inventory(owner, repo)
    print(json.dumps(inventory, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if not inventory.get("errors") else 1


if __name__ == "__main__":
    raise SystemExit(main())
