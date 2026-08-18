#!/usr/bin/env python3
"""Deterministic Governance V2 shadow verifier.

This tool deliberately has no GitHub write capability. Workflows use its JSON
evidence to publish check-runs, while v1 remains the authoritative gate.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "policy" / "governance-v2-policy.json"
EVIDENCE_MARKER = "synergie-governance-v2-evidence"


class GovernanceError(Exception):
    pass


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    policy = load_json(Path(args.policy), "policy")
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY", "")
    if not repository:
        raise GovernanceError("repository is required")

    head_sha = resolve_commit(repo, args.head_sha or "HEAD")
    base_sha = resolve_commit(repo, args.base_sha) if args.base_sha else ""
    result: dict[str, Any] = {
        "schema_version": 1,
        "governance_version": policy["version"],
        "mode": args.mode,
        "repository": repository,
        "head_sha": head_sha,
        "base_sha": base_sha or None,
        "checked_at": now(),
        "status": "PASS",
        "findings": [],
    }

    current_pr = load_optional_json(args.current_pr_json)
    if current_pr:
        result["current_pr"] = validate_current_pr(current_pr, args.pr_number, head_sha, args.base_ref, args.head_ref)

    evidence = None
    if args.mode == "feature":
        try:
            evidence = extract_evidence(current_pr or load_optional_json(args.event_json))
            result["evidence"] = validate_evidence(evidence)
        except GovernanceError as exc:
            result["evidence"] = {"status": "FAIL", "errors": [str(exc)]}

    feature_records = load_records(Path(args.provenance_dir) if args.provenance_dir else None)
    enrollment_record = load_repository_enrollment(args, repository, base_sha, head_sha)
    if args.mode in {"promotion", "release"}:
        result["provenance"] = verify_provenance(repo, repository, base_sha, head_sha, feature_records, policy, enrollment_record)
        if enrollment_record:
            result["repository_enrollment"] = verify_repository_enrollment(repo, repository, base_sha, head_sha, enrollment_record, policy)
            if result["repository_enrollment"].get("status") == "PASS" and args.repository_enrollment_consumption_out:
                write_json(args.repository_enrollment_consumption_out, build_enrollment_consumption(result["repository_enrollment"], head_sha))

    candidate = build_candidate(repo, repository, head_sha, policy, feature_records)
    result["candidate"] = candidate

    if args.mode == "feature":
        result["feature_provenance"] = build_feature_provenance(repo, repository, base_sha, head_sha, candidate, evidence)

    if args.candidate_json:
        supplied = load_json(Path(args.candidate_json), "candidate")
        result["candidate_binding"] = verify_candidate(supplied, candidate)

    if args.qa_record:
        qa_record = load_json(Path(args.qa_record), "QA record")
        result["independent_qa"] = verify_qa_record(qa_record, candidate, policy, repository)
    elif args.mode == "release":
        result["independent_qa"] = {"status": "FAIL", "errors": ["no independent QA record binds the current staging candidate"]}

    if args.authorization_registry and args.authorization_id:
        registry = load_json(Path(args.authorization_registry), "authorization registry")
        result["authorization"] = verify_authorization(
            registry,
            args.authorization_id,
            repository,
            args.pr_number,
            args.boundary,
            base_sha,
            head_sha,
            candidate,
            policy,
        )

    if args.mode == "production-preflight":
        result["production"] = production_selection(candidate, args.production_approval, policy, repository)

    if args.status_registry:
        result["status_registry"] = validate_status_registry(Path(args.status_registry), Path(args.workflow_root or ROOT))

    for section in result.values():
        if isinstance(section, dict) and section.get("status") == "FAIL":
            result["status"] = "FAIL"
    write_json(args.json_out, result)
    write_markdown(args.out, result)
    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8") as output:
            output.write(f"candidate_id={candidate['candidate_id']}\nstatus={result['status']}\n")
    return 0 if result["status"] == "PASS" or args.shadow else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synergie Governance V2 shadow verifier")
    parser.add_argument("--repo", default=".")
    parser.add_argument("--repository", default="")
    parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    parser.add_argument("--mode", choices=["feature", "promotion", "candidate", "release", "production-preflight"], required=True)
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--head-sha", default="")
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--head-ref", default="")
    parser.add_argument("--pr-number", type=int, default=0)
    parser.add_argument("--event-json", default="")
    parser.add_argument("--current-pr-json", default="")
    parser.add_argument("--provenance-dir", default="")
    parser.add_argument("--repository-enrollment", default="")
    parser.add_argument("--repository-enrollment-registry", default="")
    parser.add_argument("--repository-enrollment-id", default="")
    parser.add_argument("--repository-enrollment-consumption-out", default="")
    parser.add_argument("--candidate-json", default="")
    parser.add_argument("--qa-record", default="")
    parser.add_argument("--authorization-registry", default="")
    parser.add_argument("--authorization-id", default="")
    parser.add_argument("--boundary", default="")
    parser.add_argument("--production-approval", default="")
    parser.add_argument("--status-registry", default="")
    parser.add_argument("--workflow-root", default="")
    parser.add_argument("--out", default="")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--github-output", default="")
    parser.add_argument("--shadow", action="store_true")
    return parser.parse_args()


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GovernanceError(f"{label} is unavailable: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GovernanceError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise GovernanceError(f"{label} must be a JSON object")
    return value


def load_optional_json(raw: str) -> dict[str, Any]:
    return load_json(Path(raw), "input") if raw else {}


def load_repository_enrollment(args: argparse.Namespace, repository: str, base_sha: str, head_sha: str) -> dict[str, Any]:
    if args.repository_enrollment:
        return load_json(Path(args.repository_enrollment), "repository enrollment")
    if not args.repository_enrollment_registry:
        return {}
    registry = load_json(Path(args.repository_enrollment_registry), "repository enrollment registry")
    records = registry.get("repository_enrollments", [])
    if records is None:
        return {}
    if not isinstance(records, list):
        raise GovernanceError("repository enrollment registry must contain repository_enrollments as a list")
    matches = []
    for record in records:
        if not isinstance(record, dict):
            raise GovernanceError("repository enrollment registry entries must be JSON objects")
        if args.repository_enrollment_id and record.get("enrollment_id") != args.repository_enrollment_id:
            continue
        if record.get("repository") != repository:
            continue
        if record.get("source_sha") != base_sha:
            continue
        if record.get("staging_sha") != head_sha:
            continue
        matches.append(record)
    if args.repository_enrollment_id and not matches:
        raise GovernanceError(f"repository enrollment was not found for id {args.repository_enrollment_id}")
    if len(matches) > 1:
        raise GovernanceError("repository enrollment registry matched multiple records")
    if not matches:
        return {}
    record = dict(matches[0])
    consumptions = registry.get("repository_enrollment_consumptions", [])
    if consumptions is None:
        consumptions = []
    if not isinstance(consumptions, list):
        raise GovernanceError("repository enrollment registry consumption records must be a list")
    consumed_by = [
        item.get("consumed_by", "")
        for item in consumptions
        if isinstance(item, dict) and item.get("enrollment_id") == record.get("enrollment_id")
    ]
    if consumed_by and not record.get("consumed_by"):
        record["consumed_by"] = consumed_by[-1]
    return record


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise GovernanceError(completed.stderr.strip() or f"git {' '.join(args)} failed")
    return completed.stdout.strip()


def resolve_commit(repo: Path, ref: str) -> str:
    value = git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise GovernanceError(f"invalid commit identity for {ref}")
    return value


def tree_entries(repo: Path, sha: str) -> dict[str, str]:
    raw = subprocess.run(["git", "ls-tree", "-r", "-z", sha], cwd=repo, capture_output=True, check=True).stdout
    entries: dict[str, str] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        _mode, _kind, blob = metadata.decode("ascii").split()
        entries[path.decode("utf-8")] = blob
    return entries


def matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def digest_mapping(values: dict[str, str]) -> str:
    payload = "".join(f"{path}\0{values[path]}\n" for path in sorted(values))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def changed_paths(repo: Path, base_sha: str, head_sha: str) -> list[str]:
    if not base_sha:
        return sorted(tree_entries(repo, head_sha))
    return [line for line in git(repo, "diff", "--name-only", "--diff-filter=ACMRTUXB", f"{base_sha}..{head_sha}").splitlines() if line]


def build_candidate(repo: Path, repository: str, head_sha: str, policy: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    entries = tree_entries(repo, head_sha)
    tree_sha = git(repo, "rev-parse", f"{head_sha}^{{tree}}")
    protected = {path: blob for path, blob in entries.items() if matches(path, policy["protected_path_patterns"])}
    migrations = {path: blob for path, blob in entries.items() if matches(path, policy["migration_path_patterns"])}
    dependencies = {path: blob for path, blob in entries.items() if matches(path, policy["dependency_path_patterns"])}
    workflows = {path: blob for path, blob in entries.items() if matches(path, policy["workflow_path_patterns"])}
    content_digest = digest_mapping(entries)
    identity = {
        "repository": repository,
        "staging_sha": head_sha,
        "tree_sha": tree_sha,
        "content_digest": content_digest,
        "protected_digest": digest_mapping(protected),
        "migration_digest": digest_mapping(migrations),
        "dependency_digest": digest_mapping(dependencies),
        "workflow_digest": digest_mapping(workflows),
        "governance_version": policy["version"],
    }
    candidate_id = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "schema_version": 1,
        "candidate_id": candidate_id,
        **identity,
        "protected_resources": protected,
        "constituent_provenance": sorted(record.get("provenance_id", "") for record in records if record.get("provenance_id")),
        "created_at": now(),
    }


def build_feature_provenance(repo: Path, repository: str, base_sha: str, head_sha: str, candidate: dict[str, Any], evidence: dict[str, Any] | None) -> dict[str, Any]:
    entries = tree_entries(repo, head_sha)
    paths = changed_paths(repo, base_sha, head_sha)
    approved_blobs = {path: entries.get(path, "__deleted__") for path in paths}
    identity = {
        "repository": repository,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "tree_sha": candidate["tree_sha"],
        "approved_blobs": approved_blobs,
    }
    return {
        "schema_version": 1,
        "provenance_id": hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
        **identity,
        "evidence_digest": hashlib.sha256(json.dumps(evidence or {}, sort_keys=True).encode("utf-8")).hexdigest(),
        "created_at": now(),
    }


def load_records(directory: Path | None) -> list[dict[str, Any]]:
    if directory is None:
        return []
    if not directory.is_dir():
        raise GovernanceError(f"provenance directory is unavailable: {directory}")
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        record = load_json(path, "provenance record")
        if "provenance_id" not in record or not isinstance(record.get("approved_blobs"), dict):
            raise GovernanceError(f"invalid provenance record: {path}")
        identity = {
            "repository": record.get("repository"),
            "base_sha": record.get("base_sha"),
            "head_sha": record.get("head_sha"),
            "tree_sha": record.get("tree_sha"),
            "approved_blobs": record.get("approved_blobs"),
        }
        expected_id = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if record.get("provenance_id") != expected_id:
            raise GovernanceError(f"provenance record digest is invalid: {path}")
        records.append(record)
    return records


def verify_provenance(
    repo: Path,
    repository: str,
    base_sha: str,
    head_sha: str,
    records: list[dict[str, Any]],
    policy: dict[str, Any],
    enrollment_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not base_sha:
        return {"status": "FAIL", "reason": "promotion provenance requires an exact base SHA"}
    entries = tree_entries(repo, head_sha)
    baseline_entries: dict[str, str] = {}
    baseline = policy.get("bootstrap_baselines", {}).get(repository, {})
    if baseline:
        baseline_sha = resolve_commit(repo, str(baseline.get("commit_sha", "")))
        expected_tree = str(baseline.get("tree_sha", ""))
        if git(repo, "rev-parse", f"{baseline_sha}^{{tree}}") != expected_tree:
            return {"status": "FAIL", "reason": "configured bootstrap baseline tree does not match its commit"}
        baseline_entries = tree_entries(repo, baseline_sha)
    enrollment = verify_repository_enrollment(repo, repository, base_sha, head_sha, enrollment_record, policy) if enrollment_record else {}
    missing: list[str] = []
    foreign: list[str] = []
    bootstrap_covered: list[str] = []
    enrolled: list[str] = []
    for path in changed_paths(repo, base_sha, head_sha):
        expected = entries.get(path, "__deleted__")
        matching = [record for record in records if record.get("approved_blobs", {}).get(path) == expected]
        if not matching and enrollment.get("status") == "PASS" and path in set(enrollment.get("covered_paths", [])):
            enrolled.append(path)
        elif not matching and baseline_entries.get(path, "__deleted__") == expected:
            bootstrap_covered.append(path)
        elif not matching:
            missing.append(path)
        elif not any(record.get("repository") == repository for record in matching):
            foreign.append(path)
    if missing or foreign:
        details = []
        if missing:
            details.append(f"un-attested paths: {', '.join(missing[:20])}")
        if foreign:
            details.append(f"wrong-repository attestations: {', '.join(foreign[:20])}")
        return {
            "status": "FAIL",
            "reason": "; ".join(details),
            "record_count": len(records),
            "bootstrap_covered_paths": len(bootstrap_covered),
            "enrolled_paths": len(enrolled),
        }
    return {
        "status": "PASS",
        "record_count": len(records),
        "covered_paths": len(changed_paths(repo, base_sha, head_sha)),
        "bootstrap_covered_paths": len(bootstrap_covered),
        "enrolled_paths": len(enrolled),
    }


def verify_repository_enrollment(
    repo: Path,
    repository: str,
    base_sha: str,
    head_sha: str,
    record: dict[str, Any] | None,
    policy: dict[str, Any],
) -> dict[str, Any]:
    if not record:
        return {"status": "FAIL", "errors": ["repository enrollment record is unavailable"]}
    settings = policy.get("repository_enrollment", {}) or {}
    errors: list[str] = []
    if record.get("schema_version") != 1:
        errors.append("unsupported enrollment schema")
    if record.get("type") != "governance_v2_repository_enrollment":
        errors.append("invalid enrollment type")
    if record.get("repository") != repository:
        errors.append("enrollment repository does not match")
    if record.get("source_sha") != base_sha:
        errors.append("enrollment source SHA does not match")
    if record.get("staging_sha") != head_sha:
        errors.append("enrollment staging SHA does not match")
    if record.get("governance_version") != policy.get("version"):
        errors.append("enrollment governance version does not match policy")
    if record.get("authorized_by") not in set(settings.get("authorized_actors", [])):
        errors.append("enrollment actor is not authorized")
    if record.get("consumed_by"):
        errors.append("enrollment was already consumed")
    try:
        expires_at = parse_timestamp(str(record.get("expires_at", "")))
        if expires_at <= datetime.now(timezone.utc):
            errors.append("enrollment is expired")
    except ValueError:
        errors.append("enrollment expiry is invalid")

    entries = tree_entries(repo, head_sha)
    actual_tree = git(repo, "rev-parse", f"{head_sha}^{{tree}}")
    if record.get("tree_sha") != actual_tree:
        errors.append("enrollment tree SHA does not match")

    raw_paths = record.get("paths", [])
    paths = raw_paths if isinstance(raw_paths, list) else []
    allowed_patterns = list(settings.get("allowed_path_patterns", []) or [])
    if not paths:
        errors.append("enrollment paths are empty")
    changed = set(changed_paths(repo, base_sha, head_sha))
    application_paths = []
    for path in paths:
        if not isinstance(path, str):
            errors.append("enrollment path must be a string")
            continue
        if path not in changed:
            errors.append(f"enrollment path is not changed in this promotion: {path}")
        if not matches(path, allowed_patterns):
            application_paths.append(path)
    if application_paths:
        errors.append("enrollment includes non-governance/application paths: " + ", ".join(application_paths[:20]))

    blob_hashes = record.get("blob_hashes", {})
    if not isinstance(blob_hashes, dict):
        errors.append("enrollment blob_hashes must be an object")
        blob_hashes = {}
    content_hashes: dict[str, str] = {}
    for path in paths:
        if not isinstance(path, str):
            continue
        blob = entries.get(path)
        if not blob:
            errors.append(f"enrollment path is not present at staging SHA: {path}")
            continue
        content_hashes[path] = blob
        if blob_hashes.get(path) != blob:
            errors.append(f"enrollment blob hash does not match: {path}")
    if record.get("paths_digest") != digest_mapping(content_hashes):
        errors.append("enrollment paths digest does not match")

    evidence = record.get("evidence", {})
    required_evidence = settings.get("required_evidence", []) or []
    if not isinstance(evidence, dict):
        errors.append("enrollment evidence must be an object")
        evidence = {}
    for key in required_evidence:
        item = evidence.get(key)
        if not isinstance(item, dict) or item.get("status") != "PASS" or not item.get("reference"):
            errors.append(f"enrollment evidence {key} must be PASS with a reference")

    identity = enrollment_identity(record)
    expected_id = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    if record.get("enrollment_id") != expected_id:
        errors.append("enrollment id digest is invalid")

    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "enrollment_id": record.get("enrollment_id", ""),
        "covered_paths": sorted(path for path in paths if isinstance(path, str)),
        "authorized_by": record.get("authorized_by", ""),
    }


def enrollment_identity(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": record.get("repository"),
        "source_sha": record.get("source_sha"),
        "staging_sha": record.get("staging_sha"),
        "tree_sha": record.get("tree_sha"),
        "governance_version": record.get("governance_version"),
        "paths": record.get("paths"),
        "blob_hashes": record.get("blob_hashes"),
        "paths_digest": record.get("paths_digest"),
        "authorized_by": record.get("authorized_by"),
        "expires_at": record.get("expires_at"),
        "evidence": record.get("evidence"),
    }


def build_enrollment_consumption(enrollment: dict[str, Any], head_sha: str) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "type": "governance_v2_repository_enrollment_consumption",
        "enrollment_id": enrollment.get("enrollment_id", ""),
        "consumed_by": head_sha,
        "covered_paths": enrollment.get("covered_paths", []),
        "consumed_at": now(),
        "single_use": True,
    }
    value["record_sha256"] = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return value


def extract_evidence(pr: dict[str, Any]) -> dict[str, Any]:
    body = str(pr.get("body") or "")
    body = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)
    marker = re.compile(rf"```(?:json)?\s*{re.escape(EVIDENCE_MARKER)}\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
    match = marker.search(body)
    if not match:
        raise GovernanceError(f"current PR body has no `{EVIDENCE_MARKER}` JSON block")
    try:
        evidence = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise GovernanceError(f"current PR evidence JSON is invalid: {exc}") from exc
    if not isinstance(evidence, dict):
        raise GovernanceError("current PR evidence must be a JSON object")
    return evidence


def validate_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if evidence.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if not isinstance(evidence.get("change_summary"), str) or not evidence["change_summary"].strip():
        errors.append("change_summary must be a non-empty string")
    for field in ["testing", "migration", "privacy", "screenshots"]:
        value = evidence.get(field)
        if not isinstance(value, dict) or not isinstance(value.get("applicable"), bool):
            errors.append(f"{field}.applicable must be boolean")
            continue
        companion = "details" if value["applicable"] else "reason"
        if not isinstance(value.get(companion), str) or not value[companion].strip():
            errors.append(f"{field}.{companion} is required when applicable={str(value['applicable']).lower()}")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def validate_current_pr(pr: dict[str, Any], pr_number: int, head_sha: str, base_ref: str, head_ref: str) -> dict[str, Any]:
    errors: list[str] = []
    if pr_number and int(pr.get("number") or 0) != pr_number:
        errors.append("current PR number differs from workflow input")
    if pr.get("head", {}).get("sha") != head_sha:
        errors.append("workflow head SHA is stale")
    if base_ref and pr.get("base", {}).get("ref") != base_ref:
        errors.append("current base branch differs from workflow input")
    if head_ref and pr.get("head", {}).get("ref") != head_ref:
        errors.append("current head branch differs from workflow input")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors, "updated_at": pr.get("updated_at", "")}


def verify_candidate(supplied: dict[str, Any], computed: dict[str, Any]) -> dict[str, Any]:
    keys = ["candidate_id", "repository", "staging_sha", "tree_sha", "content_digest", "protected_digest", "migration_digest", "dependency_digest", "workflow_digest", "governance_version"]
    errors = [key for key in keys if supplied.get(key) != computed.get(key)]
    return {"status": "PASS" if not errors else "FAIL", "mismatched_fields": errors}


def verify_qa_record(record: dict[str, Any], candidate: dict[str, Any], policy: dict[str, Any], repository: str) -> dict[str, Any]:
    required = ["schema_version", "repository", "candidate_id", "staging_sha", "tree_sha", "content_digest", "verdict", "reviewer", "timestamp", "evidence_reference"]
    errors = [f"missing {key}" for key in required if not record.get(key)]
    if record.get("schema_version") != 1:
        errors.append("unsupported QA record schema")
    for key in ["repository", "candidate_id", "staging_sha", "tree_sha", "content_digest"]:
        if record.get(key) != candidate.get(key):
            errors.append(f"QA record {key} does not bind the current candidate")
    reviewers = policy.get("pilot_repositories", {}).get(repository, {}).get("independent_qa_reviewers", [])
    if record.get("reviewer") not in reviewers:
        errors.append("QA reviewer is not authorized")
    if record.get("verdict") != "PASS":
        errors.append("independent QA verdict is not PASS")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def verify_authorization(registry: dict[str, Any], authorization_id: str, repository: str, pr_number: int, boundary: str, base_sha: str, head_sha: str, candidate: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    records = registry.get("authorizations", [])
    record = next((item for item in records if item.get("authorization_id") == authorization_id), None)
    if not isinstance(record, dict):
        return {"status": "FAIL", "reason": "authorization is unavailable"}
    errors: list[str] = []
    for key, expected in {"repository": repository, "pr_number": pr_number, "boundary": boundary, "base_sha": base_sha, "head_sha": head_sha, "tree_sha": candidate["tree_sha"]}.items():
        if record.get(key) != expected:
            errors.append(f"authorization {key} does not match")
    if record.get("consumed_by"):
        errors.append("authorization was already consumed")
    try:
        expiry = parse_timestamp(str(record.get("expires_at", "")))
        if expiry <= datetime.now(timezone.utc):
            errors.append("authorization is expired")
    except ValueError:
        errors.append("authorization expiry is invalid")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def production_selection(candidate: dict[str, Any], approval: str, policy: dict[str, Any], repository: str) -> dict[str, Any]:
    approvers = policy.get("pilot_repositories", {}).get(repository, {}).get("production_approvers", [])
    approved = approval in approvers
    return {
        "status": "PASS" if approved else "FAIL",
        "deployment_started": False,
        "selected_candidate_id": candidate["candidate_id"],
        "selected_content_digest": candidate["content_digest"],
        "reason": "authorized dry-run selection" if approved else "explicit human production approval is required",
    }


def build_migration_preflight_report(input_data: dict[str, Any]) -> dict[str, Any]:
    blockers: list[str] = []
    checks = input_data.get("checks", {}) if isinstance(input_data.get("checks", {}), dict) else {}
    producers = input_data.get("producers", {}) if isinstance(input_data.get("producers", {}), dict) else {}
    workflows = input_data.get("workflows", {}) if isinstance(input_data.get("workflows", {}), dict) else {}
    permissions = input_data.get("permissions", {}) if isinstance(input_data.get("permissions", {}), dict) else {}
    plan = input_data.get("planned_steps", []) if isinstance(input_data.get("planned_steps", []), list) else []

    for name, required in sorted(checks.items()):
        if required and not producers.get(name):
            blockers.append(f"missing workflow producer for required check: {name}")
    release_gate = workflows.get("release_gate", {}) if isinstance(workflows.get("release_gate", {}), dict) else {}
    required_args = [
        "--repository-enrollment-registry",
        "--repository-enrollment-consumption-out",
    ]
    args = set(release_gate.get("arguments", []) or [])
    for arg in required_args:
        if arg not in args:
            blockers.append(f"missing V2 wrapper argument: {arg}")
    for capability in ["independent_qa", "architecture_governance", "repository_enrollment"]:
        if not workflows.get(capability):
            blockers.append(f"{capability.replace('_', ' ')} is unavailable")
    if not permissions.get("can_merge_release_pr"):
        blockers.append("authenticated actor cannot merge the release PR under current ruleset")
    if workflows.get("main_auto_deploys_production"):
        blockers.append("main branch push can auto-deploy production")
    if not input_data.get("rollback_ready", False):
        blockers.append("rollback readiness is unavailable")

    step_reports: list[dict[str, Any]] = []
    prior_evidence = False
    loop = False
    for index, step in enumerate(plan, start=1):
        if not isinstance(step, dict):
            continue
        changes_candidate = bool(step.get("changes_candidate"))
        invalidates_enrollment = bool(step.get("invalidates_enrollment"))
        invalidates_qa = bool(step.get("invalidates_qa"))
        requires_new_v2_release = bool(step.get("requires_new_v2_release"))
        creates_loop = bool(step.get("creates_loop") or (changes_candidate and prior_evidence and invalidates_enrollment))
        if creates_loop:
            loop = True
            blockers.append(f"candidate/enrollment loop detected at step {index}: {step.get('name', 'unnamed')}")
        if requires_new_v2_release:
            blockers.append(f"step {index} requires a new V2 release: {step.get('name', 'unnamed')}")
        if changes_candidate and (invalidates_enrollment or invalidates_qa):
            prior_evidence = True
        step_reports.append({
            "name": step.get("name", f"step {index}"),
            "changes_candidate": changes_candidate,
            "invalidates_enrollment": invalidates_enrollment,
            "invalidates_qa": invalidates_qa,
            "requires_new_v2_release": requires_new_v2_release,
            "creates_loop": creates_loop,
        })

    return {
        "schema_version": 1,
        "status": "BLOCKED" if blockers else "READY",
        "blockers": blockers,
        "steps": step_reports,
        "loop_detected": loop,
    }


def classify_qa_risk(changed_files: list[str], summary: str = "") -> dict[str, Any]:
    text = " ".join(changed_files + [summary]).lower()
    high_terms = [
        "auth", "authorization", "tenant", "privacy", "finance", "payment",
        "migration", "schema", "security", "crypto", "deploy", "production",
        "recovery", "governance",
    ]
    reasons = sorted(term for term in high_terms if term in text)
    if reasons:
        return {"level": "HIGH", "reasons": reasons}
    if len(changed_files) > 8 or any(path.startswith(("app/", "src/", "services/")) for path in changed_files):
        return {"level": "MEDIUM", "reasons": ["business logic or multi-file delta"]}
    return {"level": "LOW", "reasons": ["localized non-sensitive delta"]}


def build_qa_packet(input_data: dict[str, Any]) -> dict[str, Any]:
    candidate = input_data.get("candidate", {}) if isinstance(input_data.get("candidate", {}), dict) else {}
    expected_candidate = input_data.get("expected_candidate_id")
    if expected_candidate and candidate.get("candidate_id") != expected_candidate:
        return {
            "schema_version": 1,
            "status": "FAIL",
            "reason": "stale candidate rejected",
            "candidate_id": candidate.get("candidate_id", ""),
        }
    changed_files = [str(path) for path in input_data.get("changed_files", []) if isinstance(path, str)]
    summary = str(input_data.get("diff_summary", ""))
    risk = classify_qa_risk(changed_files, summary)
    protected_changes = [
        path for path in changed_files
        if path.startswith(".github/") or path in {"CODEOWNERS", "docs/CODEOWNERS"} or "/migrations/" in path or path.endswith(".sql")
    ]
    packet = {
        "schema_version": 1,
        "status": "PASS",
        "repository": input_data.get("repository", ""),
        "candidate": {
            "candidate_id": candidate.get("candidate_id", ""),
            "staging_sha": candidate.get("staging_sha", ""),
            "tree_sha": candidate.get("tree_sha", ""),
            "content_digest": candidate.get("content_digest", ""),
        },
        "base_sha": input_data.get("base_sha", ""),
        "previous_approved_release": input_data.get("previous_approved_release", ""),
        "changed_files": changed_files,
        "diff_summary": summary,
        "affected_modules": input_data.get("affected_modules", []),
        "ci": input_data.get("ci", {}),
        "tests": input_data.get("tests", {}),
        "security": input_data.get("security", {}),
        "migrations": input_data.get("migrations", {}),
        "staging": input_data.get("staging", {}),
        "protected_path_changes": protected_changes,
        "unresolved_prior_findings": input_data.get("unresolved_prior_findings", []),
        "evidence_references": input_data.get("evidence_references", []),
        "risk": risk,
        "qa_protocol": {
            "read_only": ["qa_packet", "changed_code", "impacted_interfaces", "unresolved_prior_findings"],
            "do_not": ["rerun_valid_ci", "manual_lint_reinspection", "repeated_polling", "fix_code"],
            "operation": "trigger_once_wait_once",
        },
    }
    return secret_safe(packet)


def build_delta_qa_packet(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    previous_files = set(previous.get("changed_files", []) or [])
    current_files = set(current.get("changed_files", []) or [])
    changed_files = sorted(current_files.symmetric_difference(previous_files) or current_files)
    packet_input = dict(current)
    packet_input["changed_files"] = changed_files
    packet = build_qa_packet(packet_input)
    packet["delta_from_candidate"] = (previous.get("candidate", {}) or {}).get("candidate_id", "")
    packet["review_scope"] = ["fix_delta", "impacted_dependencies", "unresolved_findings", "new_risk_triggers"]
    return packet


def secret_safe(value: Any) -> Any:
    secret_keys = {"secret", "token", "password", "private_key", "api_key"}
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if any(marker in str(key).lower() for marker in secret_keys) else secret_safe(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [secret_safe(item) for item in value]
    if isinstance(value, str) and any(marker in value.lower() for marker in ["ghp_", "github_pat_", "-----begin private key-----"]):
        return "[REDACTED]"
    return value


def validate_status_registry(path: Path, workflow_root: Path) -> dict[str, Any]:
    registry = load_json(path, "status registry")
    errors: list[str] = []
    contexts: set[str] = set()
    for entry in registry.get("entries", []):
        context = entry.get("context")
        if not context or context in contexts:
            errors.append(f"invalid or duplicate context: {context}")
        contexts.add(context)
        workflow = entry.get("workflow", "")
        if workflow.endswith(".yml") and not (workflow_root / ".github" / "workflows" / workflow).exists():
            errors.append(f"workflow producer is unavailable: {workflow}")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors, "contexts": sorted(contexts)}


def write_json(raw: str, value: dict[str, Any]) -> None:
    if raw:
        Path(raw).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(raw: str, result: dict[str, Any]) -> None:
    if not raw:
        return
    lines = ["# Governance V2 Shadow Report", "", f"Status: **{result['status']}**", "", f"Mode: `{result['mode']}`", f"Candidate: `{result['candidate']['candidate_id']}`"]
    for key, value in result.items():
        if isinstance(value, dict) and value.get("status") == "FAIL":
            lines.extend(["", f"## {key}", "```json", json.dumps(value, indent=2, sort_keys=True), "```"])
    Path(raw).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GovernanceError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(2)
