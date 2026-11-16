"""Narrow, reviewed recovery for an inconsistent GitHub PR merge record.

This never changes GitHub state. Normal merged PRs do not use this path. A
recovery requires the same record on protected central main and in the selected
immutable QA policy release, plus live Git and owner-comment evidence.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import UTC, datetime, timedelta

from execution_artifact import _unique_object
from execution_gate import REPOSITORY

POLICY_PATH = "policy/fieldzilla-merge-metadata-recoveries.json"
CENTRAL = "repos/Synergie-ITCI/.github/"
SHA = re.compile(r"[0-9a-f]{40}\Z")
RULESETS = (19620452, 20796933)
CHECKS = {"Architecture Governance", "pr-qa / Pull Request Quality Assurance"}


def _read_policy(api, sha):
    reply = api(f"{CENTRAL}contents/{POLICY_PATH}?ref={sha}")
    if reply.get("type") != "file" or reply.get("encoding") != "base64":
        raise ValueError("Merge recovery policy is unavailable")
    encoded = reply.get("content", "")
    if not isinstance(encoded, str) or len(encoded) > 32768:
        raise ValueError("Merge recovery policy is oversized")
    payload = json.loads(
        base64.b64decode(encoded.replace("\n", ""), validate=True),
        object_pairs_hook=_unique_object,
    )
    if not isinstance(payload, dict) or set(payload) != {"version", "recoveries"}:
        raise ValueError("Merge recovery policy schema differs")
    if payload["version"] != 1 or not isinstance(payload["recoveries"], list):
        raise ValueError("Merge recovery policy version differs")
    return payload["recoveries"]


def _record(manifest, api, *, activated_sha=None):
    main = api(f"{CENTRAL}git/ref/heads/main").get("object", {}).get("sha", "")
    if not SHA.fullmatch(main):
        raise ValueError("Protected central source is unavailable")
    rows = _read_policy(api, main)
    matches = [r for r in rows if isinstance(r, dict) and r.get("pr_number") == manifest.get("promotion_pr")]
    if len(matches) != 1:
        raise ValueError("Unique merge recovery record is unavailable")
    record = matches[0]
    if activated_sha is not None:
        if not SHA.fullmatch(activated_sha):
            raise ValueError("Immutable policy source is unavailable")
        activated = _read_policy(api, activated_sha)
        if [r for r in activated if isinstance(r, dict) and r.get("pr_number") == manifest.get("promotion_pr")] != [record]:
            raise ValueError("Merge recovery was not in the selected immutable policy")
    return record


def verify_merge_metadata_recovery(manifest, *, api, activated_sha=None, now=None):
    """Return only after every independently read live proof matches exactly."""
    if manifest.get("scope") not in {"production", "production-images"}:
        raise ValueError("Merge recovery is production-only")
    if manifest.get("merge_metadata_recovery") is not True:
        raise ValueError("Merge recovery requires an explicit exact manifest opt-in")
    record = _record(manifest, api, activated_sha=activated_sha)
    required = {
        "repository", "pr_number", "head_sha", "base_sha", "merge_sha",
        "tree_sha", "owner_comment_id", "issued_at", "expires_at",
        "support_ticket", "enabled",
    }
    if set(record) != required or record["enabled"] is not True:
        raise ValueError("Merge recovery record is disabled or malformed")
    source = manifest.get("application", {}).get("source_sha")
    base = manifest.get("base_sha")
    caller = manifest.get("caller_sha")
    if (
        record["repository"] != REPOSITORY
        or type(record["pr_number"]) is not int
        or record["pr_number"] != manifest.get("promotion_pr")
        or record["head_sha"] != source
        or record["base_sha"] != base
        or not all(isinstance(record[k], str) and SHA.fullmatch(record[k]) for k in ("head_sha", "base_sha", "merge_sha", "tree_sha"))
        or not isinstance(caller, str) or not SHA.fullmatch(caller)
        or type(record["owner_comment_id"]) is not int or record["owner_comment_id"] < 1
        or not isinstance(record["support_ticket"], str)
        or not re.fullmatch(r"https://help\.github\.com/ticket/(?:personal|organization)/[0-9]+/[0-9]+", record["support_ticket"])
    ):
        raise ValueError("Merge recovery differs from exact reviewed source")
    issued = datetime.fromisoformat(record["issued_at"].replace("Z", "+00:00"))
    expiry = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
    now = now or datetime.now(UTC)
    if (
        issued.utcoffset() is None or expiry.utcoffset() is None
        or not issued <= now < expiry
        or not timedelta(0) < expiry - issued <= timedelta(hours=24)
    ):
        raise ValueError("Merge recovery window is invalid or expired")
    pr = api(f"repos/{REPOSITORY}/pulls/{record['pr_number']}")
    if (
        pr.get("state") != "open" or pr.get("merged_at") is not None
        or pr.get("merged") is not False or pr.get("draft") is not False
        or pr.get("head", {}).get("sha") != source
        or pr.get("head", {}).get("repo", {}).get("full_name") != REPOSITORY
        or pr.get("base", {}).get("ref") != "main"
        or pr.get("base", {}).get("sha") != base
        or pr.get("base", {}).get("repo", {}).get("full_name") != REPOSITORY
    ):
        raise ValueError("PR does not have the exact metadata incident state")
    main = api(f"repos/{REPOSITORY}/git/ref/heads/main").get("object", {}).get("sha")
    if main != caller or api(f"repos/{REPOSITORY}/compare/{record['merge_sha']}...{caller}").get("status") not in {"identical", "ahead"}:
        raise ValueError("Reviewed merge is absent from executing protected main")
    merge = api(f"repos/{REPOSITORY}/git/commits/{record['merge_sha']}")
    head = api(f"repos/{REPOSITORY}/git/commits/{source}")
    if (
        merge.get("sha") != record["merge_sha"]
        or [p.get("sha") for p in merge.get("parents", [])] != [base, source]
        or merge.get("tree", {}).get("sha") != record["tree_sha"]
        or head.get("tree", {}).get("sha") != record["tree_sha"]
        or merge.get("verification", {}).get("verified") is not True
        or not merge.get("message", "").startswith(f"Merge pull request #{record['pr_number']} ")
    ):
        raise ValueError("Merge ancestry, tree, or GitHub signature differs")
    committed = datetime.fromisoformat(merge["committer"]["date"].replace("Z", "+00:00"))
    for ruleset_id in RULESETS:
        rule = api(f"repos/{REPOSITORY}/rulesets/{ruleset_id}")
        updated = datetime.fromisoformat(rule["updated_at"])
        types = {r.get("type") for r in rule.get("rules", [])}
        checks = {
            c.get("context") for r in rule.get("rules", [])
            if r.get("type") == "required_status_checks"
            for c in r.get("parameters", {}).get("required_status_checks", [])
        }
        if (
            rule.get("id") != ruleset_id or rule.get("enforcement") != "active"
            or rule.get("bypass_actors") != [] or updated > committed
            or rule.get("conditions") != {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}
            or not (
                {"pr-qa / Pull Request Quality Assurance"} <= checks
                if ruleset_id == RULESETS[0] else CHECKS <= checks
            )
            or (ruleset_id == RULESETS[0] and "pull_request" not in types)
        ):
            raise ValueError("Protected main governance at merge time is unproven")
    comment = api(f"repos/{REPOSITORY}/issues/comments/{record['owner_comment_id']}")
    expected = (
        "FIELDZILLA MERGE METADATA RECOVERY V1 "
        f"repo={REPOSITORY} pr={record['pr_number']} head={source} base={base} "
        f"merge={record['merge_sha']} tree={record['tree_sha']} expires_at={record['expires_at']}"
    )
    if (
        comment.get("body") != expected
        or comment.get("user", {}).get("login") != "SaurabhVermaIN"
        or comment.get("user", {}).get("id") != 52234089
        or comment.get("issue_url") != f"https://api.github.com/repos/{REPOSITORY}/issues/{record['pr_number']}"
        or comment.get("created_at") != comment.get("updated_at")
        or not issued <= datetime.fromisoformat(comment["created_at"].replace("Z", "+00:00")) < expiry
    ):
        raise ValueError("Unedited exact owner recovery approval is unavailable")
    return record
