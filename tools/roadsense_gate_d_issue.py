#!/usr/bin/env python3
"""Create separate RoadSense release intent and authenticated Gate D approval artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import roadsense_gate_d as gate


def context() -> tuple[str, int, int, str]:
    gate.require(os.environ.get("GITHUB_REPOSITORY") == gate.REPO, "repository context mismatch")
    gate.require(os.environ.get("GITHUB_REF") == "refs/heads/main", "protected main required")
    gate.require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "rerun cannot issue approval")
    gate.require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "manual dispatch required")
    login = os.environ.get("GITHUB_ACTOR", "")
    actor_id = os.environ.get("GITHUB_ACTOR_ID", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    sha = os.environ.get("GITHUB_SHA", "")
    gate.require(login and actor_id.isdecimal() and run_id.isdecimal() and gate.HEX40.fullmatch(sha) is not None, "authenticated GitHub context unavailable")
    gate.require(int(actor_id) > 0 and int(run_id) > 0, "GitHub identity invalid")
    main = gate.gh_json("branches/main")
    gate.require(main.get("commit", {}).get("sha") == sha, "protected main moved")
    return login, int(actor_id), int(run_id), sha


def canonical(data: dict) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def issue_intent(expected: dict, actor: tuple[str, int, int, str]) -> dict:
    login, actor_id, run_id, sha = actor
    gate.require(set(expected) == set(gate.TUPLE), "intent release tuple schema mismatch")
    gate.validate_release_tuple(expected, sha)
    record = {
        **expected,
        "repository": gate.REPO,
        "repository_id": gate.REPO_ID,
        "requester_login": login,
        "requester_id": actor_id,
        "intent_run_id": run_id,
    }
    gate.require(set(record) == gate.INTENT_FIELDS, "intent schema mismatch")
    return record


def issue_approval(intent_run_id: int, expected_intent_sha256: str, actor: tuple[str, int, int, str], now: dt.datetime) -> dict:
    login, actor_id, approval_run_id, sha = actor
    gate.require((login, actor_id) == gate.AUTHORITY, "Gate D approver unauthorized")
    gate.require(type(intent_run_id) is int and intent_run_id > 0, "intent run ID invalid")
    gate.require(gate.HEX64.fullmatch(expected_intent_sha256 or "") is not None, "intent hash invalid")
    intent_run = gate.gh_json(f"actions/runs/{intent_run_id}")
    gate.run_valid(intent_run, gate.INTENT_PATH, sha, now)
    artifact, blob = gate.get_artifact(intent_run_id, gate.INTENT_ARTIFACT_NAME)
    intent = gate.read_artifact_json(artifact, blob, gate.INTENT_ARTIFACT_NAME, intent_run_id, gate.INTENT_FIELDS)
    gate.require(intent["repository"] == gate.REPO and intent["repository_id"] == gate.REPO_ID, "intent repository mismatch")
    gate.require(intent["intent_run_id"] == intent_run_id, "intent run mismatch")
    gate.require((intent["requester_login"], intent["requester_id"]) == gate.identity(intent_run, "actor"), "intent requester mismatch")
    gate.validate_release_tuple(intent, sha)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        actual_intent_hash = hashlib.sha256(archive.read("intent.json")).hexdigest()
    gate.require(actual_intent_hash == expected_intent_sha256, "approved intent hash mismatch")
    gate.require(gate.timestamp(intent_run["created_at"]) <= now, "intent issued in future")
    issued = now.replace(microsecond=0)
    record = {
        **{key: intent[key] for key in gate.TUPLE},
        "repository": gate.REPO,
        "repository_id": gate.REPO_ID,
        "requester_login": intent["requester_login"],
        "requester_id": intent["requester_id"],
        "approver_login": login,
        "approver_id": actor_id,
        "intent_run_id": intent_run_id,
        "approval_run_id": approval_run_id,
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued + dt.timedelta(minutes=60)).isoformat().replace("+00:00", "Z"),
    }
    gate.require(set(record) == gate.FIELDS, "approval schema mismatch")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    intent = sub.add_parser("intent")
    intent.add_argument("expected_json", type=Path)
    intent.add_argument("output_json", type=Path)
    approve = sub.add_parser("approve")
    approve.add_argument("intent_run_id", type=int)
    approve.add_argument("expected_intent_sha256")
    approve.add_argument("output_json", type=Path)
    args = parser.parse_args()
    try:
        actor = context()
        if args.command == "intent":
            expected = gate.strict_expected(args.expected_json.read_bytes())
            record = issue_intent(expected, actor)
        else:
            record = issue_approval(args.intent_run_id, args.expected_intent_sha256, actor, dt.datetime.now(dt.UTC))
        raw = canonical(record)
        args.output_json.write_bytes(raw)
        print(f"RECORD_SHA256={hashlib.sha256(raw).hexdigest()}")
    except (gate.Rejected, OSError, ValueError, RuntimeError) as exc:
        print(f"GATE_D_ISSUANCE_REJECTED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
