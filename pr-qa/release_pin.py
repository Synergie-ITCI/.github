"""Validate the centrally reviewed release pin and its live tag protection."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime
from pathlib import Path

from pr_qa import parse_workflow_yaml

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Synergie-ITCI/.github"
PIN = "PR_QA_FRAMEWORK_RELEASE"


def validate_workflow(workflow: str, manifest: dict) -> tuple[str, dict]:
    """Require an explicit registered tag and preserve trusted checkout boundaries."""
    # The dependency-free YAML reader supports block scalars without chomping
    # suffixes. These suffixes affect trailing newlines, not checkout identities.
    normalized = re.sub(r"(?m)(:\s*[|>])[-+](\s*)$", r"\1\2", workflow)
    parsed = parse_workflow_yaml(normalized)
    release = parsed.get("env", {}).get(PIN)
    if manifest.get("version") != 1 or manifest.get("repository") != REPOSITORY:
        raise ValueError("Invalid central release manifest")
    if not isinstance(release, str) or release not in manifest.get("releases", {}):
        raise ValueError("Framework release is not registered")
    entry = manifest["releases"][release]
    if not re.fullmatch(r"pr-qa-v1-rc[1-9][0-9]*", release):
        raise ValueError("Registered reference is not a release tag")
    if not re.fullmatch(r"[0-9a-f]{40}", entry.get("commit", "")):
        raise ValueError("Release must bind an exact commit")
    if type(entry.get("ruleset_id")) is not int or entry["ruleset_id"] < 1:
        raise ValueError("Release must bind a tag-protection ruleset")
    if not entry.get("ruleset_updated_at") or entry.get("bypass_actors") != []:
        raise ValueError("Release requires reviewed no-bypass ruleset evidence")
    if workflow.count(PIN) != 3 or "framework-ref" in workflow:
        raise ValueError("Framework overrides are forbidden")
    checkout_count = 0
    for job in parsed.get("jobs", {}).values():
        if PIN in job.get("env", {}):
            raise ValueError("Job framework override is forbidden")
        for step in job.get("steps", []):
            if PIN in step.get("env", {}):
                raise ValueError("Step framework override is forbidden")
            if PIN in step.get("run", ""):
                raise ValueError("Shell framework override is forbidden")
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                settings = step.get("with", {})
                if str(settings.get("persist-credentials")).lower() != "false":
                    raise ValueError("Checkout credentials must not persist")
                if any(key in settings for key in ("token", "ssh-key")):
                    raise ValueError("Custom checkout credentials are forbidden")
                if settings.get("repository") == REPOSITORY:
                    checkout_count += 1
                    if settings.get("ref") != "${{ env.PR_QA_FRAMEWORK_RELEASE }}":
                        raise ValueError("Framework checkout bypasses registered pin")
                    if settings.get("path") != ".pr-qa-framework":
                        raise ValueError("Unexpected framework checkout path")
    if checkout_count != 2:
        raise ValueError("Both framework checkouts must use the registered pin")
    return release, entry


def github_json(path: str) -> dict:
    result = subprocess.run(
        ["gh", "api", f"repos/{REPOSITORY}/{path}"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise ValueError("Live release verification unavailable")
    return json.loads(result.stdout)


def same_timestamp(actual: object, expected: object) -> bool:
    """Compare exact timezone-aware instants without discarding subsecond precision."""
    try:
        left = datetime.fromisoformat(actual)
        right = datetime.fromisoformat(expected)
        return left.tzinfo is not None and right.tzinfo is not None and left == right
    except (TypeError, ValueError):
        return False


def verify_live_release(release: str, entry: dict, lookup=github_json) -> None:
    """Freshly verify tag resolution and exact, non-bypassable update/delete protection."""
    ref = lookup(f"git/ref/tags/{release}")
    if ref.get("ref") != f"refs/tags/{release}":
        raise ValueError("Unexpected release reference")
    obj = ref["object"]
    if obj["type"] == "tag":
        obj = lookup(f"git/tags/{obj['sha']}")["object"]
    if obj.get("type") != "commit" or obj.get("sha") != entry["commit"]:
        raise ValueError("Release tag does not resolve to registered commit")
    ruleset = lookup(f"rulesets/{entry['ruleset_id']}")
    expected_refs = {"include": [f"refs/tags/{release}"], "exclude": []}
    if (
        ruleset.get("id") != entry["ruleset_id"]
        or ruleset.get("target") != "tag"
        or ruleset.get("enforcement") != "active"
        # GitHub omits bypass_actors for read-only tokens. Bind the reviewed
        # no-bypass snapshot to the exact live modification timestamp; any
        # ruleset change requires renewed privileged inspection and central review.
        or not same_timestamp(ruleset.get("updated_at"), entry["ruleset_updated_at"])
        or ("bypass_actors" in ruleset and ruleset["bypass_actors"] != [])
        or ruleset.get("conditions", {}).get("ref_name") != expected_refs
        or not {"update", "deletion"}.issubset(
            {rule.get("type") for rule in ruleset.get("rules", [])}
        )
    ):
        checks = {
            "ruleset_id": ruleset.get("id") == entry["ruleset_id"],
            "tag_target": ruleset.get("target") == "tag",
            "active": ruleset.get("enforcement") == "active",
            "reviewed_timestamp": same_timestamp(ruleset.get("updated_at"), entry["ruleset_updated_at"]),
            "visible_bypass_empty": "bypass_actors" not in ruleset or ruleset["bypass_actors"] == [],
            "exact_tag_scope": ruleset.get("conditions", {}).get("ref_name") == expected_refs,
            "update_delete_rules": {"update", "deletion"}.issubset(
                {rule.get("type") for rule in ruleset.get("rules", [])}
            ),
        }
        failed = ", ".join(name for name, passed in checks.items() if not passed)
        raise ValueError(
            f"Release tag protection verification failed: {failed}; "
            f"live updated_at={ruleset.get('updated_at')!r}"
        )


if __name__ == "__main__":
    workflow = (ROOT / ".github/workflows/pr-qa.yml").read_text()
    manifest = json.loads((ROOT / "policy/framework-releases.json").read_text())
    release, entry = validate_workflow(workflow, manifest)
    verify_live_release(release, entry)
    print(f"Verified registered release {release} at {entry['commit']}")
