"""Validate the centrally reviewed release pin and its live tag protection."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

from pr_qa import parse_workflow_yaml

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Synergie-ITCI/.github"
PIN = "PR_QA_FRAMEWORK_RELEASE"
RELEASE_RE = re.compile(r"pr-qa-v1-rc([1-9][0-9]*)")
EVIDENCE_HEADER = "SYNERGIE_PR_QA_RELEASE_EVIDENCE_V1"
MAIN_BRANCH = "main"
RELEASE_SOURCE_ANNOTATED_TAG = "annotated-tag"
RELEASE_SOURCE_LEGACY_REGISTRY = "legacy-registry"
ALLOWED_RELEASE_WORKFLOW_PATHS = {".github/workflows/pr-qa-release.yml"}
ALLOWED_RELEASE_ACTORS = {"SaurabhVermaIN"}
REQUIRED_RELEASE_CHECKS = {
    "Architecture Governance",
    "pr-qa / Pull Request Quality Assurance",
}


def validate_workflow(workflow: str, manifest: dict) -> tuple[str, dict]:
    """Require runtime active-release resolution and preserve trusted checkout boundaries."""
    # The dependency-free YAML reader supports block scalars without chomping
    # suffixes. These suffixes affect trailing newlines, not checkout identities.
    normalized = re.sub(r"(?m)(:\s*[|>])[-+](\s*)$", r"\1\2", workflow)
    parsed = parse_workflow_yaml(normalized)
    if manifest.get("version") != 1 or manifest.get("repository") != REPOSITORY:
        raise ValueError("Invalid central release manifest")
    release, entry = active_release_from_manifest(manifest)
    if not re.fullmatch(r"[0-9a-f]{40}", entry.get("commit", "")):
        raise ValueError("Release must bind an exact commit")
    if type(entry.get("ruleset_id")) is not int or entry["ruleset_id"] < 1:
        raise ValueError("Release must bind a tag-protection ruleset")
    if not entry.get("ruleset_updated_at") or entry.get("bypass_actors") != []:
        raise ValueError("Release requires reviewed no-bypass ruleset evidence")
    if "framework-ref" in workflow:
        raise ValueError("Framework overrides are forbidden")
    resolver_checkout_count = 0
    framework_checkout_refs: list[object] = []
    for job in parsed.get("jobs", {}).values():
        if PIN in job.get("env", {}):
            raise ValueError("Job framework override is forbidden")
        for step in job.get("steps", []):
            if PIN in step.get("env", {}) and step.get("env", {}).get(PIN) != "${{ needs.detect.outputs.framework_release }}":
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
                    if settings.get("path") == ".pr-qa-release-resolver":
                        resolver_checkout_count += 1
                        if settings.get("ref") != "${{ job.workflow_sha || github.workflow_sha }}":
                            raise ValueError("Release resolver checkout must use the running workflow SHA")
                    elif settings.get("path") == ".pr-qa-framework":
                        framework_checkout_refs.append(settings.get("ref"))
                    else:
                        raise ValueError("Unexpected framework checkout path")
    if resolver_checkout_count != 1:
        raise ValueError("Release resolver must be checked out exactly once")
    if framework_checkout_refs != ["${{ steps.active-framework.outputs.release }}", "${{ needs.detect.outputs.framework_release }}"]:
        raise ValueError("Framework checkouts must use the resolved active immutable release")
    return release, entry


def active_release_from_manifest(manifest: dict) -> tuple[str, dict]:
    releases = manifest.get("releases", {})
    candidates: list[tuple[int, str, dict]] = []
    if isinstance(releases, dict):
        for release, entry in releases.items():
            match = RELEASE_RE.fullmatch(str(release))
            if match and isinstance(entry, dict):
                candidates.append((int(match.group(1)), release, entry))
    if not candidates:
        raise ValueError("Framework release is not registered")
    _, release, entry = max(candidates)
    return release, entry


def github_json(path: str) -> dict:
    result = subprocess.run(
        ["gh", "api", f"repos/{REPOSITORY}/{path}"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise ValueError("Live release verification unavailable")
    return json.loads(result.stdout)


def github_list(path: str) -> list[dict]:
    result = subprocess.run(
        ["gh", "api", f"repos/{REPOSITORY}/{path}"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise ValueError("Live release verification unavailable")
    payload = json.loads(result.stdout)
    if not isinstance(payload, list):
        raise ValueError("Live release verification unavailable")
    return payload


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
    if not re.fullmatch(r"[0-9a-f]{40}", str(entry.get("commit", ""))):
        raise ValueError("Release must bind an exact commit")
    if type(entry.get("ruleset_id")) is not int or entry["ruleset_id"] < 1:
        raise ValueError("Release must bind a tag-protection ruleset")
    if not entry.get("ruleset_updated_at") or entry.get("bypass_actors") != []:
        raise ValueError("Release requires reviewed no-bypass ruleset evidence")
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


def verify_release_provenance(
    release: str,
    entry: dict,
    lookup=github_json,
    list_endpoint=github_list,
) -> None:
    """Require future tag-evidence releases to be backed by independent GitHub provenance."""
    commit = str(entry.get("commit", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Release evidence must bind an exact 40-character commit")

    compare = lookup(f"compare/{commit}...{MAIN_BRANCH}")
    if compare.get("status") not in {"behind", "identical"}:
        raise ValueError(f"Release commit is not reachable from protected {MAIN_BRANCH}")

    pulls = list_endpoint(f"commits/{commit}/pulls")
    merged_pr = next((
        pr
        for pr in pulls
        if (
        pr.get("merged_at")
        and pr.get("merge_commit_sha") == commit
        and pr.get("base", {}).get("ref") == MAIN_BRANCH
        and pr.get("base", {}).get("repo", {}).get("full_name") == REPOSITORY
        )
    ), None)
    if merged_pr is None:
        raise ValueError("Release commit is not a governed merged PR commit on main")

    check_shas = [commit]
    pr_head_sha = str(merged_pr.get("head", {}).get("sha", ""))
    if re.fullmatch(r"[0-9a-f]{40}", pr_head_sha) and pr_head_sha != commit:
        check_shas.append(pr_head_sha)
    successful_checks = set()
    for check_sha in check_shas:
        check_runs = lookup(f"commits/{check_sha}/check-runs").get("check_runs", [])
        successful_checks.update(
            run.get("name")
            for run in check_runs
            if run.get("status") == "completed" and run.get("conclusion") == "success"
        )
    missing_checks = sorted(REQUIRED_RELEASE_CHECKS - successful_checks)
    if missing_checks:
        raise ValueError("Release commit is missing required successful checks: " + ", ".join(missing_checks))

    workflow_run_id = entry.get("release_workflow_run_id")
    if type(workflow_run_id) is not int or workflow_run_id < 1:
        raise ValueError("Release evidence must bind an audited release workflow run")
    workflow_run = lookup(f"actions/runs/{workflow_run_id}")
    actor = (workflow_run.get("actor") or {}).get("login")
    if (
        workflow_run.get("status") != "completed"
        or workflow_run.get("conclusion") != "success"
        or workflow_run.get("head_sha") != commit
        or workflow_run.get("path") not in ALLOWED_RELEASE_WORKFLOW_PATHS
        or actor not in ALLOWED_RELEASE_ACTORS
    ):
        raise ValueError("Release workflow provenance verification failed")


def evidence_from_annotated_tag(release: str, ref: dict, lookup=github_json) -> dict | None:
    obj = ref.get("object", {})
    if obj.get("type") != "tag":
        return None
    tag = lookup(f"git/tags/{obj.get('sha', '')}")
    if tag.get("tag") != release:
        raise ValueError("Release evidence tag name mismatch")
    target = tag.get("object", {})
    if target.get("type") != "commit" or not re.fullmatch(r"[0-9a-f]{40}", str(target.get("sha", ""))):
        raise ValueError("Release evidence tag must target an exact commit")
    message = str(tag.get("message", "")).strip()
    if not message.startswith(EVIDENCE_HEADER + "\n"):
        raise ValueError("Release evidence tag is missing the required header")
    try:
        evidence = json.loads(message.split("\n", 1)[1])
    except json.JSONDecodeError as exc:
        raise ValueError("Release evidence is malformed") from exc
    if not isinstance(evidence, dict):
        raise ValueError("Release evidence is malformed")
    if evidence.get("release") != release:
        raise ValueError("Release evidence name mismatch")
    if evidence.get("commit") != target["sha"]:
        raise ValueError("Release evidence commit mismatch")
    if evidence.get("bypass_actors") != []:
        raise ValueError("Release evidence requires zero bypass actors")
    return {
        "commit": evidence.get("commit", ""),
        "ruleset_id": evidence.get("ruleset_id"),
        "ruleset_updated_at": evidence.get("ruleset_updated_at", ""),
        "bypass_actors": evidence.get("bypass_actors", []),
        "release_workflow_run_id": evidence.get("release_workflow_run_id"),
        "_source": RELEASE_SOURCE_ANNOTATED_TAG,
    }


def resolve_active_release(
    manifest: dict | None = None,
    lookup=github_json,
    list_refs=github_list,
) -> tuple[str, dict]:
    refs = list_refs("git/matching-refs/tags/pr-qa-v1-rc")
    candidates: list[tuple[int, str, dict]] = []
    manifest_releases = (manifest or {}).get("releases", {}) if isinstance(manifest, dict) else {}
    for ref in refs:
        release = str(ref.get("ref", "")).removeprefix("refs/tags/")
        match = RELEASE_RE.fullmatch(release)
        if not match:
            continue
        entry = None
        try:
            entry = evidence_from_annotated_tag(release, ref, lookup)
        except ValueError:
            legacy = manifest_releases.get(release) if isinstance(manifest_releases, dict) else None
            if not isinstance(legacy, dict):
                candidates.append((int(match.group(1)), release, {"invalid": True}))
                continue
        if entry is None and isinstance(manifest_releases, dict):
            legacy = manifest_releases.get(release)
            if isinstance(legacy, dict):
                entry = {**legacy, "_source": RELEASE_SOURCE_LEGACY_REGISTRY}
        if entry is None:
            candidates.append((int(match.group(1)), release, {"invalid": True}))
            continue
        candidates.append((int(match.group(1)), release, entry))
    if not candidates:
        raise ValueError("No verified active PR-QA release is available")
    for _, release, entry in sorted(candidates, reverse=True):
        if entry.get("invalid") is True:
            raise ValueError(f"Newest PR-QA release {release} has invalid immutable evidence")
        verify_live_release(release, entry, lookup)
        if entry.get("_source") == RELEASE_SOURCE_ANNOTATED_TAG:
            verify_release_provenance(release, entry, lookup, list_refs)
        return release, entry
    raise ValueError("No verified active PR-QA release is available")


def write_github_output(release: str, entry: dict) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"release={release}\n")
            handle.write(f"commit={entry['commit']}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolve-active", action="store_true")
    args = parser.parse_args()
    workflow = (ROOT / ".github/workflows/pr-qa.yml").read_text()
    manifest = json.loads((ROOT / "policy/framework-releases.json").read_text())
    validate_workflow(workflow, manifest)
    if args.resolve_active:
        release, entry = resolve_active_release(manifest)
        write_github_output(release, entry)
        print(f"Resolved active release {release} at {entry['commit']}")
    else:
        release, entry = resolve_active_release(manifest)
        print(f"Verified active release {release} at {entry['commit']}")
