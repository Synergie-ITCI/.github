#!/usr/bin/env python3
"""Offline validation of a reviewed migration deployment path."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
from pathlib import Path

VERSION = "1"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
HEAD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_]+\Z")
PLAN_KEYS = {
    "schema_version", "plan_id", "repository", "environment", "service",
    "migration_tool", "expected_pre_head", "expected_post_head",
    "allowed_changed_paths", "allowed_non_runtime_paths", "forbidden_paths", "migration_runner",
    "allowed_services", "image_rule", "rollback_note",
}
EVIDENCE_KEYS = {
    "evidence_schema_version", "plan_id", "workflow_sha", "artifact_sha",
    "artifact_is_ancestor_of_workflow", "paths_changed_between_artifact_and_workflow", "repository",
    "environment", "service", "migration_tool", "migration_runner", "base_sha",
    "changed_paths", "live_db_head", "target_head", "image_evidence",
    "task_definition_diff",
}


def object_keys(value: object, required: set[str], optional: set[str] = frozenset()) -> bool:
    return isinstance(value, dict) and required <= value.keys() and value.keys() <= required | optional


def nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def safe_path(value: object, glob: bool = False) -> bool:
    if not nonempty(value) or value.startswith("/") or "\\" in value:
        return False
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    if any("[" in part or "]" in part or "?" in part for part in parts):
        return False
    if not glob and "*" in value:
        return False
    if not all(part == "**" or "**" not in part for part in parts):
        return False
    if glob and "*" in value:
        first_glob = next(i for i, part in enumerate(parts) if "*" in part)
        if first_glob < 2:
            return False
    return True


def path_matches(path: str, pattern: str) -> bool:
    if pattern == "*.md":
        return path.endswith(".md")
    if "*" not in pattern:
        return path == pattern
    segments = pattern.split("/")
    target = path.split("/")

    def match(i: int, j: int) -> bool:
        if i == len(segments):
            return j == len(target)
        if segments[i] == "**":
            return match(i + 1, j) or (j < len(target) and match(i, j + 1))
        return j < len(target) and fnmatch.fnmatchcase(target[j], segments[i]) and match(i + 1, j + 1)

    return match(0, 0)


NON_RUNTIME_PATTERNS = {".github/workflows/**", "docs/**", "**/tests/**", "*.md"}


def centrally_non_runtime(path: str) -> bool:
    return (
        path.startswith(".github/workflows/") or path.startswith("docs/") or
        "tests" in path.split("/") or path.endswith(".md")
    )


def allowed_non_runtime_pattern(pattern: object) -> bool:
    return isinstance(pattern, str) and (pattern in NON_RUNTIME_PATTERNS or
        safe_path(pattern) and centrally_non_runtime(pattern)
    )


def parse_json(payload: str) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(payload, object_pairs_hook=unique)


def load_json(path: Path) -> object:
    return parse_json(path.read_text(encoding="utf-8"))


def load_plan_from_commit(tree: Path, workflow_sha: str, plan_id: str) -> object:
    path = f".github/migration-plans/{plan_id}.json"
    result = subprocess.run(
        ["git", "-C", str(tree), "show", f"{workflow_sha}:{path}"],
        capture_output=True, check=False,
    )
    if result.returncode:
        raise ValueError("plan not found in workflow commit tree")
    return parse_json(result.stdout.decode("utf-8"))


def valid_plan(plan: object) -> list[str]:
    if not object_keys(plan, PLAN_KEYS, {"baseline_ancestor_sha"}):
        return ["plan fields are missing or unknown"]
    errors = []
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        errors.append("unknown plan schema version")
    for key in ("plan_id", "repository", "environment", "service", "migration_tool", "migration_runner", "rollback_note"):
        if not nonempty(plan[key]):
            errors.append(f"invalid {key}")
    if not ID.fullmatch(str(plan["plan_id"])):
        errors.append("invalid plan_id")
    for key in ("expected_pre_head", "expected_post_head"):
        if not isinstance(plan[key], str) or not HEAD.fullmatch(plan[key]):
            errors.append(f"invalid {key}; exactly one head is required")
    if plan["expected_pre_head"] == plan["expected_post_head"]:
        errors.append("migration transition must change head")
    for key in ("allowed_changed_paths", "forbidden_paths"):
        values = plan[key]
        if not isinstance(values, list) or not values or not all(safe_path(v, glob=True) for v in values):
            errors.append(f"invalid {key}")
    non_runtime = plan["allowed_non_runtime_paths"]
    if not isinstance(non_runtime, list) or not all(allowed_non_runtime_pattern(v) for v in non_runtime):
        errors.append("allowed_non_runtime_paths exceeds central policy")
    services = plan["allowed_services"]
    if not isinstance(services, list) or not services or not all(nonempty(v) for v in services) or len(services) != len(set(map(str, services))):
        errors.append("invalid allowed_services")
    elif plan["service"] not in services:
        errors.append("service absent from allowed_services")
    rule = plan["image_rule"]
    if (not object_keys(rule, {"registries", "repositories", "task_definition_families"}) or
        not isinstance(rule["registries"], list) or not rule["registries"] or
        not all(nonempty(v) for v in rule["registries"]) or
        not isinstance(rule["repositories"], dict) or
        not isinstance(rule["task_definition_families"], dict) or
        set(rule["repositories"]) != set(services) or
        set(rule["task_definition_families"]) != set(services) or
        not all(nonempty(v) for v in rule["repositories"].values()) or
        not all(nonempty(v) for v in rule["task_definition_families"].values())):
        errors.append("invalid image_rule")
    if "baseline_ancestor_sha" in plan and not SHA.fullmatch(str(plan["baseline_ancestor_sha"])):
        errors.append("invalid baseline_ancestor_sha")
    return errors


def valid_evidence(evidence: object) -> list[str]:
    if not object_keys(evidence, EVIDENCE_KEYS):
        return ["evidence fields are missing or unknown"]
    errors = []
    if type(evidence["evidence_schema_version"]) is not int or evidence["evidence_schema_version"] != 1:
        errors.append("unknown evidence schema version")
    for key in ("plan_id", "repository", "environment", "service", "migration_tool", "migration_runner"):
        if not nonempty(evidence[key]):
            errors.append(f"invalid {key}")
    for key in ("workflow_sha", "artifact_sha", "base_sha"):
        if not SHA.fullmatch(str(evidence[key])):
            errors.append(f"invalid {key}")
    if evidence["artifact_is_ancestor_of_workflow"] is not True:
        errors.append("artifact ancestry is not proven")
    artifact_paths = evidence["paths_changed_between_artifact_and_workflow"]
    if not isinstance(artifact_paths, list) or not all(safe_path(v) for v in artifact_paths) or len(artifact_paths) != len(set(map(str, artifact_paths))):
        errors.append("invalid artifact-to-workflow path diff")
    for key in ("live_db_head", "target_head"):
        if not isinstance(evidence[key], str) or not HEAD.fullmatch(evidence[key]):
            errors.append(f"invalid {key}; exactly one head is required")
    changes = evidence["changed_paths"]
    if not isinstance(changes, list) or not changes:
        errors.append("empty change set")
    else:
        for change in changes:
            if not object_keys(change, {"status", "path"}, {"previous_path"}) or change["status"] not in {"added", "modified", "deleted", "renamed"} or not safe_path(change["path"]):
                errors.append("invalid changed path")
                continue
            if (change["status"] == "renamed") != ("previous_path" in change):
                errors.append("rename requires previous_path only")
            if "previous_path" in change and not safe_path(change["previous_path"]):
                errors.append("invalid previous_path")
    images = evidence["image_evidence"]
    if not isinstance(images, list) or not images or not all(
        object_keys(item, {"service", "registry", "repository", "tag", "digest"}) and
        all(nonempty(item[k]) for k in ("service", "registry", "repository", "tag")) and
        bool(DIGEST.fullmatch(str(item["digest"])))
        for item in images
    ):
        errors.append("invalid image_evidence")
    diffs = evidence["task_definition_diff"]
    if not isinstance(diffs, list) or not diffs or not all(
        object_keys(item, {"service", "family", "changes"}) and nonempty(item["service"]) and
        nonempty(item["family"]) and isinstance(item["changes"], list) and item["changes"] and
        all(object_keys(change, {"path", "before", "after"}) and
            all(isinstance(change[k], str) for k in ("path", "before", "after")) for change in item["changes"])
        for item in diffs
    ):
        errors.append("invalid task_definition_diff")
    return errors


def check_ancestor(tree: Path, ancestor: str, workflow_sha: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(tree), "merge-base", "--is-ancestor", ancestor, workflow_sha],
        capture_output=True, check=False,
    )
    return result.returncode == 0


def actual_artifact_paths(tree: Path, artifact_sha: str, workflow_sha: str) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(tree), "diff", "--name-only", "-z", "--no-renames",
         artifact_sha, workflow_sha], capture_output=True, check=False,
    )
    if result.returncode:
        raise ValueError("artifact-to-workflow git diff unavailable")
    return sorted(path.decode("utf-8") for path in result.stdout.split(b"\0") if path)


def validate(plan: dict, evidence: dict, *, tree: Path, workflow_sha: str,
             base_sha: str, repository: str, environment: str, service: str) -> dict:
    checks = {}

    def check(name: str, condition: bool, reason: str) -> None:
        checks[name] = {"pass": bool(condition), "reason": "" if condition else reason}

    check("identity", plan["plan_id"] == evidence["plan_id"] and
          plan["repository"] == evidence["repository"] == repository and
          plan["environment"] == evidence["environment"] == environment and
          plan["service"] == evidence["service"] == service and
          plan["migration_tool"] == evidence["migration_tool"], "plan/evidence/trusted context mismatch")
    check("workflow_sha", bool(SHA.fullmatch(workflow_sha)) and evidence["workflow_sha"] == workflow_sha,
          "evidence workflow_sha differs from trusted github.sha")
    check("artifact_ancestry", evidence["artifact_is_ancestor_of_workflow"] is True,
          "artifact is not an ancestor of workflow")
    artifact_paths = evidence["paths_changed_between_artifact_and_workflow"]
    check("artifact_paths", all(
        centrally_non_runtime(path) and
        any(path_matches(path, pattern) for pattern in plan["allowed_non_runtime_paths"])
        for path in artifact_paths), "runtime or unapproved artifact-to-workflow path changed")
    check("base_sha", bool(SHA.fullmatch(base_sha)) and evidence["base_sha"] == base_sha and
          base_sha != workflow_sha, "base_sha differs from trusted last deployed SHA")
    check("heads", evidence["live_db_head"] == plan["expected_pre_head"] and
          evidence["target_head"] == plan["expected_post_head"], "migration heads differ from plan")
    check("runner", evidence["migration_runner"] == plan["migration_runner"], "migration runner mismatch")
    check("service_allowed", service in plan["allowed_services"], "service is not allowed")
    paths = [p for change in evidence["changed_paths"] for p in
             (change["path"], *([change["previous_path"]] if "previous_path" in change else []))]
    check("changed_paths", all(any(path_matches(p, allowed) for allowed in plan["allowed_changed_paths"]) for p in paths),
          "changed path outside allowed paths")
    check("forbidden_paths", not any(path_matches(p, forbidden) for p in paths for forbidden in plan["forbidden_paths"]),
          "forbidden path changed")
    images = evidence["image_evidence"]
    expected_services = set(plan["allowed_services"])
    check("images", len(images) == len(expected_services) and {item["service"] for item in images} == expected_services and
          all(item["registry"] in plan["image_rule"]["registries"] and
              item["repository"] == plan["image_rule"]["repositories"].get(item["service"]) and
              item["tag"] == evidence["artifact_sha"] for item in images),
          "missing, duplicate, or mismatched image evidence")
    diffs = evidence["task_definition_diff"]
    images_by_service = {item["service"]: item for item in images}
    check("task_definition_diff", len(diffs) == len(expected_services) and
          {item["service"] for item in diffs} == expected_services and
          all(item["family"] == plan["image_rule"]["task_definition_families"].get(item["service"])
              for item in diffs) and
          all(re.fullmatch(r"/containerDefinitions/[0-9]+/image", change["path"]) and
              change["before"] != change["after"] and
              item["service"] in images_by_service and
              change["after"] == "{registry}/{repository}@{digest}".format(**images_by_service[item["service"]])
              for item in diffs for change in item["changes"]),
          "task definition change is not image-only or runner differs")
    if "baseline_ancestor_sha" in plan:
        check("baseline_ancestor", check_ancestor(tree, plan["baseline_ancestor_sha"], workflow_sha),
              "baseline SHA is not an ancestor of workflow SHA")
    return {"validator_version": VERSION, "plan_id": plan["plan_id"],
            "evidence_schema_version": evidence["evidence_schema_version"], "checks": checks,
            "pass": all(item["pass"] for item in checks.values())}


def run(args: argparse.Namespace) -> dict:
    report = {"validator_version": VERSION, "plan_id": args.plan_id,
              "evidence_schema_version": None, "checks": {}, "pass": False, "reasons": []}
    try:
        if not SHA.fullmatch(args.tree_head) or args.tree_head != args.workflow_sha:
            raise ValueError("plan tree is not checked out at trusted workflow SHA")
        if not ID.fullmatch(args.plan_id):
            raise ValueError("invalid plan ID")
        tree = Path(args.tree).resolve(strict=True)
        plan = load_plan_from_commit(tree, args.workflow_sha, args.plan_id)
        evidence = load_json(Path(args.evidence))
        if isinstance(evidence, dict):
            report["evidence_schema_version"] = evidence.get("evidence_schema_version")
        errors = valid_plan(plan) + valid_evidence(evidence)
        if errors:
            raise ValueError("; ".join(errors))
        if not check_ancestor(tree, evidence["artifact_sha"], args.workflow_sha):
            raise ValueError("artifact is not an ancestor of workflow")
        if actual_artifact_paths(tree, evidence["artifact_sha"], args.workflow_sha) != sorted(
            evidence["paths_changed_between_artifact_and_workflow"]
        ):
            raise ValueError("artifact-to-workflow path diff differs from git")
        report = validate(plan, evidence, tree=tree, workflow_sha=args.workflow_sha,
                          base_sha=args.base_sha,
                          repository=args.repository, environment=args.environment,
                          service=args.service)
        report["reasons"] = [item["reason"] for item in report["checks"].values() if not item["pass"]]
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
        report["reasons"] = [str(exc)]
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tree", "tree-head", "plan-id", "evidence", "workflow-sha", "base-sha", "repository", "environment", "service", "report"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    report = run(args)
    Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
