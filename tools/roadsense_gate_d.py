#!/usr/bin/env python3
"""Proposed, inactive RoadSense Gate D approval verifier.

The caller must run ``verify`` and ``mark-used`` in a no-OIDC job before any
production job. This module does not grant credentials or perform deployment.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from typing import Any

REPO = "Synergie-ITCI/roadsense-production-dashboard"
REPO_ID = 1426678649
AUTHORITY = ("SaurabhVermaIN", 52234089)
ENVIRONMENT = "roadsense-production"
SSM_TARGET = "mi-0dade13fd68d1b435"
INTENT_PATH = ".github/workflows/roadsense-release-intent.yml"
APPROVAL_PATH = ".github/workflows/roadsense-gate-d-approve.yml"
ARTIFACT_NAME = "roadsense-gate-d-approval"
INTENT_ARTIFACT_NAME = "roadsense-release-intent"
MARKER_TASK = "roadsense-gate-d-approval"
MARKER_ENVIRONMENT = "roadsense-gate-d-ledger"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{7,79}\Z")
POLICY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{3,99}\Z")
VERSION = re.compile(r"[A-Za-z0-9+/=._-]{1,128}\Z")
FIELDS = {
    "repository", "repository_id", "requester_login", "requester_id",
    "approver_login", "approver_id", "intent_run_id", "approval_run_id",
    "release_id", "source_sha", "image_digest", "image_archive_sha256",
    "image_s3_version", "database_sha256",
    "database_s3_version", "policy_version", "environment", "ssm_target",
    "rollback_image_digest", "rollback_database_sha256", "issued_at", "expires_at",
}
TUPLE = (
    "release_id", "source_sha", "image_digest", "image_archive_sha256",
    "image_s3_version", "database_sha256",
    "database_s3_version", "policy_version", "environment", "ssm_target",
    "rollback_image_digest", "rollback_database_sha256",
)
INTENT_FIELDS = set(TUPLE) | {
    "repository", "repository_id", "requester_login", "requester_id", "intent_run_id",
}


class Rejected(Exception):
    """Approval is absent, unverifiable, or inconsistent."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Rejected(reason)


def strict_json(raw: bytes, fields: set[str] = FIELDS) -> dict[str, Any]:
    require(len(raw) <= 16384, "record too large")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise Rejected("invalid JSON") from exc
    require(isinstance(data, dict) and set(data) == fields, "record schema mismatch")
    return data


def timestamp(value: Any) -> dt.datetime:
    require(isinstance(value, str) and value.endswith("Z"), "timestamp format mismatch")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Rejected("invalid timestamp") from exc
    require(parsed.utcoffset() == dt.timedelta(0), "timestamp timezone mismatch")
    return parsed


def identity(run: dict[str, Any], key: str) -> tuple[str, int]:
    actor = run.get(key)
    require(isinstance(actor, dict), "GitHub actor unavailable")
    login, actor_id = actor.get("login"), actor.get("id")
    require(isinstance(login, str) and type(actor_id) is int and actor_id > 0, "GitHub actor invalid")
    return login, actor_id


def run_valid(run: dict[str, Any], path: str, sha: str, now: dt.datetime) -> None:
    repo = run.get("head_repository")
    require(isinstance(repo, dict) and repo.get("full_name") == REPO and repo.get("id") == REPO_ID, "run repository mismatch")
    require(run.get("path") == path, "workflow path mismatch")
    require(run.get("event") == "workflow_dispatch", "workflow event mismatch")
    require(run.get("head_branch") == "main" and run.get("head_sha") == sha, "workflow source mismatch")
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "workflow unsuccessful")
    require(run.get("run_attempt") == 1, "rerun is not an approval")
    require(identity(run, "actor") == identity(run, "triggering_actor"), "run actor changed")
    require(timestamp(run.get("created_at")) <= now, "run creation is in future")


def validate(
    record: dict[str, Any], expected: dict[str, Any], intent: dict[str, Any],
    approval: dict[str, Any], artifact: dict[str, Any], artifact_zip: bytes,
    intent_artifact: dict[str, Any], intent_zip: bytes,
    main_sha: str, deployments: list[dict[str, Any]], now: dt.datetime,
    deploy_actor: tuple[str, int], require_used: bool = False,
) -> None:
    require(set(record) == FIELDS, "record schema mismatch")
    require(record["repository"] == REPO and type(record["repository_id"]) is int and record["repository_id"] == REPO_ID, "record repository mismatch")
    require(set(expected) == set(TUPLE), "expected release tuple schema mismatch")
    validate_release_tuple(record, main_sha)
    validate_release_tuple(expected, main_sha)
    for key in TUPLE:
        require(record[key] == expected[key], f"release tuple mismatch: {key}")
    issued, expires = timestamp(record["issued_at"]), timestamp(record["expires_at"])
    require(issued <= now < expires and expires - issued <= dt.timedelta(minutes=60), "approval stale or expired")
    require(type(record["intent_run_id"]) is int and record["intent_run_id"] > 0, "intent run ID invalid")
    require(type(record["approval_run_id"]) is int and record["approval_run_id"] > 0, "approval run ID invalid")
    require(record["intent_run_id"] != record["approval_run_id"], "approval is not separate")
    require(intent.get("id") == record["intent_run_id"] and approval.get("id") == record["approval_run_id"], "run ID mismatch")
    run_valid(intent, INTENT_PATH, main_sha, now)
    run_valid(approval, APPROVAL_PATH, main_sha, now)
    require(timestamp(intent["created_at"]) <= timestamp(approval["created_at"]) <= issued, "approval order mismatch")
    requester, approver = identity(intent, "actor"), identity(approval, "actor")
    require(requester == (record["requester_login"], record["requester_id"]), "requester identity mismatch")
    require(deploy_actor == requester, "deployment actor differs from approved requester")
    require(approver == (record["approver_login"], record["approver_id"]), "approver identity mismatch")
    require(approver == AUTHORITY, "Gate D approver unauthorized")
    require(requester != approver or requester == AUTHORITY, "self approval unauthorized")
    intent_record = read_artifact_json(intent_artifact, intent_zip, INTENT_ARTIFACT_NAME, intent["id"], INTENT_FIELDS)
    require(intent_record["repository"] == REPO and intent_record["repository_id"] == REPO_ID, "intent repository mismatch")
    require(intent_record["intent_run_id"] == intent["id"], "intent run binding mismatch")
    require((intent_record["requester_login"], intent_record["requester_id"]) == requester, "intent requester mismatch")
    for key in TUPLE:
        require(intent_record[key] == record[key], f"intent release tuple mismatch: {key}")
    stored = read_artifact_json(artifact, artifact_zip, ARTIFACT_NAME, approval["id"], FIELDS)
    require(stored == record, "approval artifact record mismatch")
    check_replay(record, deployments, require_used)


def validate_release_tuple(values: dict[str, Any], main_sha: str) -> None:
    require(set(TUPLE).issubset(values), "release tuple missing field")
    for key in TUPLE:
        require(isinstance(values[key], str), f"release tuple type mismatch: {key}")
    require(HEX40.fullmatch(values["source_sha"]) is not None, "source SHA invalid")
    require(DIGEST.fullmatch(values["image_digest"]) is not None, "image digest invalid")
    require(HEX64.fullmatch(values["image_archive_sha256"]) is not None, "image archive hash invalid")
    require(VERSION.fullmatch(values["image_s3_version"]) is not None, "image S3 version invalid")
    require(HEX64.fullmatch(values["database_sha256"]) is not None, "database hash invalid")
    require(DIGEST.fullmatch(values["rollback_image_digest"]) is not None, "rollback image digest invalid")
    require(HEX64.fullmatch(values["rollback_database_sha256"]) is not None, "rollback database hash invalid")
    require(VERSION.fullmatch(values["database_s3_version"]) is not None, "database version invalid")
    require(POLICY.fullmatch(values["policy_version"]) is not None, "policy version invalid")
    require(RELEASE_ID.fullmatch(values["release_id"]) is not None, "release ID invalid")
    require(values["environment"] == ENVIRONMENT and values["ssm_target"] == SSM_TARGET, "production target mismatch")
    require(values["source_sha"] == main_sha, "protected main moved")


def read_artifact_json(
    artifact: dict[str, Any], blob: bytes, name: str, run_id: int,
    fields: set[str],
) -> dict[str, Any]:
    require(artifact.get("name") == name and isinstance(artifact.get("workflow_run"), dict) and artifact["workflow_run"].get("id") == run_id, "artifact origin mismatch")
    require(artifact.get("expired") is False and type(artifact.get("size_in_bytes")) is int and artifact["size_in_bytes"] <= 65536, "artifact unavailable")
    require(DIGEST.fullmatch(artifact.get("digest") or "") is not None, "artifact digest unavailable")
    require(hashlib.sha256(blob).hexdigest() == artifact["digest"][7:], "artifact digest mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            names = archive.namelist()
            filename = "approval.json" if name == ARTIFACT_NAME else "intent.json"
            require(names == [filename], "artifact files mismatch")
            info = archive.getinfo(filename)
            require(info.file_size <= 16384 and not info.is_dir(), "artifact record size invalid")
            stored = strict_json(archive.read(info), fields)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise Rejected("artifact invalid") from exc
    return stored


def check_replay(record: dict[str, Any], deployments: list[dict[str, Any]], require_used: bool = False) -> None:
    matches = []
    for deployment in deployments:
        require(deployment.get("environment") == MARKER_ENVIRONMENT, "deployment ledger mismatch")
        payload = deployment.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                payload = None
        if isinstance(payload, dict) and (payload.get("release_id") == record["release_id"] or payload.get("approval_run_id") == record["approval_run_id"]):
            matches.append((deployment, payload))
    if require_used:
        require(len(matches) == 1, "consumed approval marker missing or ambiguous")
        deployment, payload = matches[0]
        require(deployment.get("ref") == record["source_sha"], "consumed approval ref mismatch")
        for key in ("release_id", "approval_run_id", "source_sha", "image_digest", "database_sha256", "policy_version"):
            require(payload.get(key) == record[key], f"consumed approval marker mismatch: {key}")
    else:
        require(not matches, "approval or release already used")


def gh_json(path: str) -> Any:
    result = subprocess.run(["gh", "api", f"repos/{REPO}/{path}"], capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 1048576, "GitHub evidence unavailable")
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise Rejected("GitHub evidence invalid") from exc


def gh_binary(path: str) -> bytes:
    result = subprocess.run(["gh", "api", f"repos/{REPO}/{path}"], capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 65536, "approval artifact download unavailable")
    return result.stdout


def get_artifact(run_id: int, name: str) -> tuple[dict[str, Any], bytes]:
    require(type(run_id) is int and run_id > 0, "artifact run ID invalid")
    listing = gh_json(f"actions/runs/{run_id}/artifacts?per_page=100")
    artifacts = listing.get("artifacts", [])
    require(isinstance(artifacts, list) and len(artifacts) < 100, "artifact listing unavailable or truncated")
    matches = [item for item in artifacts if item.get("name") == name]
    require(len(matches) == 1, "artifact absent or ambiguous")
    artifact = matches[0]
    require(type(artifact.get("id")) is int, "artifact ID invalid")
    return artifact, gh_binary(f"actions/artifacts/{artifact['id']}/zip")


def load_approval_record(approval_run_id: int) -> dict[str, Any]:
    artifact, blob = get_artifact(approval_run_id, ARTIFACT_NAME)
    return read_artifact_json(artifact, blob, ARTIFACT_NAME, approval_run_id, FIELDS)


def live_evidence(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes, dict[str, Any], bytes, str, list[dict[str, Any]]]:
    main = gh_json("branches/main")
    intent = gh_json(f"actions/runs/{record['intent_run_id']}")
    approval = gh_json(f"actions/runs/{record['approval_run_id']}")
    artifact, blob = get_artifact(record["approval_run_id"], ARTIFACT_NAME)
    intent_artifact, intent_blob = get_artifact(record["intent_run_id"], INTENT_ARTIFACT_NAME)
    deployments = gh_json(f"deployments?environment={MARKER_ENVIRONMENT}&per_page=100")
    require(isinstance(deployments, list) and len(deployments) < 100, "deployment marker history unavailable or truncated")
    return intent, approval, artifact, blob, intent_artifact, intent_blob, main.get("commit", {}).get("sha"), deployments


def mark_used(record: dict[str, Any]) -> None:
    """Write a GitHub deployment marker before any OIDC/SSM step.

    The eventual workflow must serialize this call with a repository-wide
    concurrency group. This marker is an audit/anti-replay control, not a
    production deployment or approval on its own.
    """
    payload = {
        "ref": record["source_sha"],
        "environment": MARKER_ENVIRONMENT,
        "task": MARKER_TASK,
        "auto_merge": False,
        "required_contexts": [],
        "description": "RoadSense Gate D approval consumed before production credentials",
        "payload": {
            "release_id": record["release_id"],
            "approval_run_id": record["approval_run_id"],
            "source_sha": record["source_sha"],
            "image_digest": record["image_digest"],
            "database_sha256": record["database_sha256"],
            "policy_version": record["policy_version"],
        },
    }
    result = subprocess.run(
        ["gh", "api", "-X", "POST", f"repos/{REPO}/deployments", "--input", "-"],
        input=json.dumps(payload, separators=(",", ":")).encode(),
        capture_output=True, timeout=30, check=False,
    )
    require(result.returncode == 0 and len(result.stdout) <= 65536, "deployment marker creation failed")
    try:
        created = json.loads(result.stdout)
    except ValueError as exc:
        raise Rejected("deployment marker response invalid") from exc
    require(type(created.get("id")) is int and created.get("ref") == record["source_sha"] and created.get("environment") == MARKER_ENVIRONMENT, "deployment marker response mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected_json", help="Exact release tuple from the protected deployment request")
    parser.add_argument("approval_run_id", type=int, help="Completed authenticated approval workflow run ID")
    parser.add_argument("--mark-used", action="store_true", help="Record single use after verification; never grants production access")
    parser.add_argument("--require-used", action="store_true", help="Reverify the exact consumed approval immediately before OIDC")
    args = parser.parse_args()
    try:
        expected = strict_expected(open(args.expected_json, "rb").read())
        record = load_approval_record(args.approval_run_id)
        evidence = live_evidence(record)
        actor_login = os.environ.get("GATE_D_DEPLOY_ACTOR", "")
        actor_id_text = os.environ.get("GATE_D_DEPLOY_ACTOR_ID", "")
        require(actor_login and actor_id_text.isdecimal(), "deployment actor context unavailable")
        require(os.environ.get("GATE_D_RUN_ATTEMPT") == "1", "deployment rerun is not authorized")
        require(not (args.mark_used and args.require_used), "conflicting ledger mode")
        validate(record, expected, *evidence, dt.datetime.now(dt.UTC), (actor_login, int(actor_id_text)), args.require_used)
        if args.mark_used:
            mark_used(record)
    except (Rejected, OSError, subprocess.TimeoutExpired) as exc:
        print(f"GATE_D_REJECTED: {exc}", file=sys.stderr)
        return 1
    print("GATE_D_APPROVAL_VERIFIED=true")
    return 0


def strict_expected(raw: bytes) -> dict[str, Any]:
    require(len(raw) <= 8192, "expected release tuple too large")
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in out, "duplicate expected key")
            out[key] = value
        return out
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise Rejected("invalid expected release tuple") from exc
    require(isinstance(data, dict) and set(data) == set(TUPLE), "expected release tuple schema mismatch")
    return data


if __name__ == "__main__":
    sys.exit(main())
