"""Centrally reviewed, exact-content approval of runtime SQL deletion definitions.

This is not a SQL safety parser. A maintainer audits the complete file; its byte
hash and every DELETE statement fingerprint are then bound to one live PR.
Repository configuration, PR text and cached reports cannot grant approval.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from baseline_authorization import read_live_pr, schema_errors

ROOT = Path(__file__).resolve().parents[1]
AUTH_PATH = ROOT / "policy/audited-migration-authorizations.json"
SCHEMA_PATH = ROOT / "schemas/audited-migration-authorizations.schema.json"
DELETE = re.compile(rb"\bDELETE\s+FROM\b[^;]*;", re.IGNORECASE)


def load_authorizations():
    records = json.loads(AUTH_PATH.read_text())
    errors = schema_errors(records, json.loads(SCHEMA_PATH.read_text()))
    if errors:
        raise ValueError("Malformed bundled migration authorization")
    identities = set()
    for record in records:
        identity = (record["repository_id"], record["pr_number"])
        if identity in identities:
            raise ValueError("Duplicate migration authorization binding")
        identities.add(identity)
    if len({record["authorization_id"] for record in records}) != len(records):
        raise ValueError("Reused migration authorization UUID")
    return records


def git_output(repo, *args):
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, check=False)
    if result.returncode:
        raise ValueError("Git binding unavailable")
    return result.stdout


def validate(ctx, record):
    """Return classifier text only after all local and live checks succeed."""
    issued = datetime.fromisoformat(record["issued_at"].replace("Z", "+00:00"))
    expiry = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    if (
        issued.utcoffset() is None
        or expiry.utcoffset() is None
        or not issued <= now < expiry
        or not timedelta(0) < expiry - issued <= timedelta(hours=24)
    ):
        raise ValueError("Migration authorization window invalid or expired")
    reviewer = record["approved_reviewer"]
    reviewers = ctx.policy.get("governance", {}).get("migration_sql_reviewers", [])
    if reviewer not in reviewers:
        raise ValueError("Migration reviewer is not centrally approved")
    repository = record["repository"]
    number = record["pr_number"]
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
        or os.environ.get("GITHUB_REPOSITORY") != repository
        or os.environ.get("GITHUB_REPOSITORY_ID") != str(record["repository_id"])
        or os.environ.get("GITHUB_REF")
        not in (f"refs/pull/{number}/merge", f"refs/pull/{number}/head")
        or not token
        or not os.environ.get("GITHUB_WORKSPACE")
        or Path(os.environ["GITHUB_WORKSPACE"]).resolve() != ctx.repo.resolve()
    ):
        raise ValueError("Trusted migration review execution context unavailable")
    event = ctx.event
    pr = event["pull_request"]
    if (
        event["repository"]["id"] != record["repository_id"]
        or event["repository"]["full_name"] != repository
        or type(pr["number"]) is not int
        or pr["number"] != number
        or pr["state"] != "open"
        or pr.get("merged", False) is not False
        or pr["draft"] is not False
        or ctx.head_ref != record["head_ref"]
        or ctx.base_ref != record["base_ref"]
    ):
        raise ValueError("Event migration binding differs")
    for side in ("head", "base"):
        if (
            pr[side]["sha"] != record[f"expected_{side}_sha"]
            or pr[side]["ref"] != record[f"{side}_ref"]
        ):
            raise ValueError("Event migration SHA or ref differs")
    if (
        git_output(ctx.repo, "rev-parse", "HEAD").decode().strip()
        != record["expected_head_sha"]
    ):
        raise ValueError("Checkout migration SHA differs")
    rel = record["migration_path"]
    path = PurePosixPath(rel)
    if (
        path.is_absolute()
        or str(path) != rel
        or ".." in path.parts
        or "\\" in rel
        or ":" in rel
        or not rel.endswith(".sql")
        or rel not in ctx.changed_files
    ):
        raise ValueError("Migration path is not an exact changed SQL path")
    absolute = ctx.repo / rel
    if absolute.resolve() != ctx.repo.resolve() / rel or not absolute.is_file():
        raise ValueError("Migration path is not a regular in-repository file")
    data = absolute.read_bytes()
    if (
        hashlib.sha256(data).hexdigest() != record["migration_sha256"]
        or git_output(ctx.repo, "show", f"{record['expected_head_sha']}:{rel}") != data
    ):
        raise ValueError("Migration bytes differ from approved commit and hash")
    matches = list(DELETE.finditer(data))
    fingerprints = [
        {
            "line": data[: match.start()].count(b"\n") + 1,
            "sha256": hashlib.sha256(match.group()).hexdigest(),
        }
        for match in matches
    ]
    if not fingerprints or fingerprints != record["delete_fingerprints"]:
        raise ValueError("Migration DELETE fingerprints differ")
    # No API/event replay can grant approval for a moved, closed or merged PR.
    live = read_live_pr(repository, number, token)
    if (
        type(live["number"]) is not int
        or live["number"] != number
        or live["state"] != "open"
        or live["merged"] is not False
        or live["draft"] is not False
    ):
        raise ValueError("Live migration PR is not open and unmerged")
    for side in ("head", "base"):
        ref = live[side]
        if (
            ref["sha"] != record[f"expected_{side}_sha"]
            or ref["ref"] != record[f"{side}_ref"]
            or type(ref["repo"]["id"]) is not int
            or ref["repo"]["id"] != record["repository_id"]
            or ref["repo"]["full_name"] != repository
        ):
            raise ValueError("Live migration PR identity differs")
    if not issued <= datetime.now(timezone.utc) < expiry:
        raise ValueError("Migration authorization expired during live verification")
    # Suppress only the exact approved statement spans for classification. The
    # original file is never changed; all other destructive tokens still fail.
    return DELETE.sub(b"/* centrally audited runtime statement */", data).decode(
        "utf-8"
    )


def reviewed_migration_texts(ctx):
    """Unmatched consumers receive no exception; every matching use revalidates."""
    try:
        records = load_authorizations()
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        event_pr = ctx.event.get("pull_request") or {}
        number = event_pr.get("number")
        candidates = [
            record
            for record in records
            if record["repository"] == repository and record["pr_number"] == number
        ]
        if not candidates:
            return {}, []
        record = candidates[0]
        return {record["migration_path"]: validate(ctx, record)}, []
    except (ValueError, OSError, KeyError, TypeError, AttributeError, OverflowError):
        # Neither credentials nor raw API/SQL contents appear in diagnostics.
        return {}, [
            "Audited migration authorization failed closed; binding, content, reviewer, expiry or live verification differs."
        ]
