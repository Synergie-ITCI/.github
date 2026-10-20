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
    "release_id", "source_sha", "image_digest", "database_sha256",
    "database_s3_version", "policy_version", "environment", "ssm_target",
    "rollback_image_digest", "rollback_database_sha256", "issued_at", "expires_at",
}
TUPLE = (
    "release_id", "source_sha", "image_digest", "database_sha256",
    "database_s3_version", "policy_version", "environment", "ssm_target",
    "rollback_image_digest", "rollback_database_sha256",
)


class Rejected(Exception):
    """Approval is absent, unverifiable, or inconsistent."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Rejected(reason)


def strict_json(raw: bytes) -> dict[str, Any]:
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
    require(isinstance(data, dict) and set(data) == FIELDS, "record schema mismatch")
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
    main_sha: str, deployments: list[dict[str, Any]], now: dt.datetime,
) -> None:
    require(set(record) == FIELDS, "record schema mismatch")
    require(record["repository"] == REPO and type(record["repository_id"]) is int and record["repository_id"] == REPO_ID, "record repository mismatch")
    require(set(expected) == set(TUPLE), "expected release tuple schema mismatch")
    for key in TUPLE:
        require(isinstance(record[key], str) and isinstance(expected[key], str), f"release tuple type mismatch: {key}")
    require(HEX40.fullmatch(record["source_sha"]) is not None, "source SHA invalid")
    require(DIGEST.fullmatch(record["image_digest"] or "") is not None, "image digest invalid")
    require(HEX64.fullmatch(record["database_sha256"] or "") is not None, "database hash invalid")
    require(DIGEST.fullmatch(record["rollback_image_digest"] or "") is not None, "rollback image digest invalid")
    require(HEX64.fullmatch(record["rollback_database_sha256"] or "") is not None, "rollback database hash invalid")
    require(VERSION.fullmatch(record["database_s3_version"] or "") is not None, "database version invalid")
    require(POLICY.fullmatch(record["policy_version"] or "") is not None, "policy version invalid")
    require(RELEASE_ID.fullmatch(record["release_id"] or "") is not None, "release ID invalid")
    require(record["environment"] == ENVIRONMENT and record["ssm_target"] == SSM_TARGET, "production target mismatch")
    require(record["source_sha"] == main_sha, "protected main moved")
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
    require(approver == (record["approver_login"], record["approver_id"]), "approver identity mismatch")
    require(approver == AUTHORITY, "Gate D approver unauthorized")
    require(requester != approver or requester == AUTHORITY, "self approval unauthorized")
    require(artifact.get("name") == ARTIFACT_NAME and isinstance(artifact.get("workflow_run"), dict) and artifact["workflow_run"].get("id") == approval["id"], "approval artifact origin mismatch")
    require(artifact.get("expired") is False and type(artifact.get("size_in_bytes")) is int and artifact["size_in_bytes"] <= 65536, "approval artifact unavailable")
    require(DIGEST.fullmatch(artifact.get("digest") or "") is not None, "approval artifact digest unavailable")
    require(hashlib.sha256(artifact_zip).hexdigest() == artifact["digest"][7:], "approval artifact digest mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(artifact_zip)) as archive:
            names = archive.namelist()
            require(names == ["approval.json"], "approval artifact files mismatch")
            info = archive.getinfo("approval.json")
            require(info.file_size <= 16384 and not info.is_dir(), "approval record size invalid")
            stored = strict_json(archive.read(info))
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise Rejected("approval artifact invalid") from exc
    require(stored == record, "approval artifact record mismatch")
    for deployment in deployments:
        require(deployment.get("environment") == MARKER_ENVIRONMENT, "deployment ledger mismatch")
        payload = deployment.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                payload = None
        if isinstance(payload, dict) and (payload.get("release_id") == record["release_id"] or payload.get("approval_run_id") == record["approval_run_id"]):
            raise Rejected("approval or release already used")


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


def live_evidence(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes, str, list[dict[str, Any]]]:
    main = gh_json("branches/main")
    intent = gh_json(f"actions/runs/{record['intent_run_id']}")
    approval = gh_json(f"actions/runs/{record['approval_run_id']}")
    listing = gh_json(f"actions/runs/{record['approval_run_id']}/artifacts?per_page=100")
    artifacts = listing.get("artifacts", [])
    require(isinstance(artifacts, list), "approval artifact listing invalid")
    matches = [item for item in artifacts if item.get("name") == ARTIFACT_NAME]
    require(len(matches) == 1, "approval artifact absent or ambiguous")
    artifact = matches[0]
    require(type(artifact.get("id")) is int, "approval artifact ID invalid")
    blob = gh_binary(f"actions/artifacts/{artifact['id']}/zip")
    deployments = gh_json(f"deployments?environment={MARKER_ENVIRONMENT}&per_page=100")
    require(isinstance(deployments, list) and len(deployments) < 100, "deployment marker history unavailable or truncated")
    return intent, approval, artifact, blob, main.get("commit", {}).get("sha"), deployments


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
    parser.add_argument("approval_json", help="Approval record downloaded from the identified artifact")
    parser.add_argument("--mark-used", action="store_true", help="Record single use after verification; never grants production access")
    args = parser.parse_args()
    try:
        expected = strict_expected(open(args.expected_json, "rb").read())
        record = strict_json(open(args.approval_json, "rb").read())
        evidence = live_evidence(record)
        validate(record, expected, *evidence, dt.datetime.now(dt.UTC))
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
