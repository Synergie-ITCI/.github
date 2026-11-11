#!/usr/bin/env python3
"""Authorize one exact FieldZilla production hosting plan through GitHub evidence.

This action is deliberately independent of the staging-only OpenTofu authorizer.
It never grants an approval: it verifies an existing owner-authored approval.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
from urllib.error import HTTPError
from datetime import datetime, timezone
from pathlib import Path


REPOSITORY = "Synergie-ITCI/programme-management-platform"
OWNER = "SaurabhVermaIN"
ENVIRONMENT = "synergie-app-production"
STATE_KEY = "programme-management-platform/fieldzilla/production/hosting/opentofu.tfstate"
REHEARSAL_STATE_KEY = "programme-management-platform/fieldzilla/production-rehearsal/opentofu.tfstate"
WORKFLOW = ".github/workflows/fieldzilla-production-hosting.yml"
ALLOWED_ACTIONS = {"create", "no-op"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def fail(message):
    raise SystemExit(message)


def api(path, method="GET", payload=None):
    token = os.environ["GITHUB_TOKEN"]
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        permissions = error.headers.get("X-Accepted-GitHub-Permissions", "not supplied")
        remaining = error.headers.get("X-RateLimit-Remaining", "not supplied")
        fail(f"GitHub API {method} {path}: HTTP {error.code}; "
             f"accepted permissions: {permissions}; rate limit remaining: {remaining}")


def require_identity(args):
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        fail("unexpected repository")
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        fail("production workflow must run from main")
    if not SHA40.fullmatch(args.source_sha) or not SHA40.fullmatch(args.caller_sha):
        fail("source/caller SHA must be exact commits")
    if os.environ.get("GITHUB_SHA") != args.caller_sha:
        fail("caller commit mismatch")
    if not re.fullmatch(r"refs/tags/pr-qa-v1-rc[0-9]+", args.workflow_tag):
        fail("central workflow must use immutable approved release tag")
    expected = f"Synergie-ITCI/.github/{WORKFLOW}@{args.workflow_tag}"
    if os.environ.get("CENTRAL_WORKFLOW_REF") != expected:
        fail("central workflow identity mismatch")
    if args.target == "rehearsal":
        try:
            expires = datetime.fromisoformat(args.expires_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            fail("rehearsal expiry must be exact UTC")
        remaining = (expires - datetime.now(timezone.utc)).total_seconds()
        if not 0 < remaining <= 4 * 3600:
            fail("rehearsal expiry must be within four hours and in the future")
        if args.phase != "phase1" and not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", args.resource_expires_at or ""):
            fail("cleanup must bind original resource expiry")


def check_plan(path, phase):
    doc = json.loads(Path(path).read_text())
    changes = [c for c in doc.get("resource_changes", []) if c.get("mode") == "managed"]
    if not changes:
        fail("empty managed-resource plan")
    shared = []
    creates = 0
    unchanged = 0
    for change in changes:
        address = change["address"]
        actions = change["change"]["actions"]
        if len(actions) != 1 or actions[0] not in ALLOWED_ACTIONS:
            fail(f"non-additive action: {address}: {actions}")
        if change.get("previous_address") or change["change"].get("importing"):
            fail(f"state move or import is not authorized: {address}")
        if actions == ["no-op"]:
            if change["change"].get("before") != change["change"].get("after"):
                fail(f"inconsistent no-op: {address}")
            unchanged += 1
        else:
            creates += 1
        if "staging" in address.lower():
            fail(f"staging resource: {address}")
        after = change["change"].get("after")
        if after is not None and "staging" in json.dumps(after, sort_keys=True).lower():
            fail(f"staging reference or name in planned resource: {address}")
        if change["type"].startswith("aws_lb_") and change["type"] != "aws_lb_target_group":
            if phase == "phase1":
                fail("phase 1 cannot include the shared ALB")
            if actions == ["create"]:
                shared.append(address.split("[")[0])
    expected_shared = {
        "aws_lb_listener_certificate.production",
        "aws_lb_listener_rule.hosting_health",
        "aws_lb_listener_rule.application_pending",
    }
    if not creates:
        fail("plan contains no infrastructure additions")
    if phase == "phase1" and shared:
        fail("phase 1 cannot change the shared ALB")
    if phase == "phase2" and (set(shared) != expected_shared or creates != 3):
        fail("phase 2 shared ALB additions differ from reviewed allowlist")
    print(json.dumps({"phase": phase, "creates": creates, "unchanged": unchanged, "shared_alb_additions": shared}, sort_keys=True))


def check_rehearsal_plan(path, phase="phase1"):
    doc = json.loads(Path(path).read_text())
    changes = [c for c in doc.get("resource_changes", []) if c.get("mode") == "managed"]
    creates = 0
    required = {
        "aws_vpc.rehearsal", "aws_db_instance.rehearsal",
        "aws_s3_bucket.attachments", "aws_s3_bucket_logging.attachments",
        "aws_lb.rehearsal", "aws_ecs_cluster.rehearsal",
    }
    addresses = {c["address"].split("[")[0] for c in changes}
    if phase == "phase1" and not required.issubset(addresses):
        fail("isolated rehearsal target is incomplete")
    for change in changes:
        address = change["address"]
        actions = change["change"]["actions"]
        allowed = {
            "phase1": (["create"], ["no-op"]),
            "cleanup-protection": (["update"], ["no-op"]),
            "cleanup-destroy": (["delete"],),
        }[phase]
        if actions not in allowed:
            fail(f"rehearsal phase cannot perform this action: {address}: {actions}")
        if change.get("previous_address") or change["change"].get("importing"):
            fail(f"rehearsal state move or import: {address}")
        if actions == ["no-op"] and change["change"].get("before") != change["change"].get("after"):
            fail(f"inconsistent rehearsal no-op: {address}")
        after = json.dumps(change["change"].get("after") if phase != "cleanup-destroy" else change["change"].get("before"), sort_keys=True).lower()
        # Production-rehearsal names are allowed; standalone production and all
        # staging references are forbidden in managed resource values.
        isolated = after.replace("production-rehearsal", "rehearsal").replace("productionrehearsal", "rehearsal")
        if "staging" in address.lower() or "staging" in isolated or "production" in isolated:
            fail(f"rehearsal references staging or production: {address}")
        if actions == ["create"]:
            creates += 1
        if phase == "cleanup-protection" and actions == ["update"]:
            if address != "aws_db_instance.rehearsal" or change["change"]["before"].get("deletion_protection") is not True or change["change"]["after"].get("deletion_protection") is not False:
                fail("cleanup protection must only disable isolated RDS deletion protection")
    if phase == "phase1" and creates == 0:
        fail("rehearsal plan has no isolated additions")
    if phase == "cleanup-protection" and sum(c["change"]["actions"] == ["update"] for c in changes) != 1:
        fail("cleanup protection plan must have exactly one RDS update")
    if phase == "cleanup-destroy" and not required.issubset(addresses):
        fail("cleanup destroy must own the complete isolated target")
    print(json.dumps({"target": "rehearsal", "phase": phase, "creates": creates, "managed": len(changes)}, sort_keys=True))


def verify_artifact(args):
    run = api(f"repos/{REPOSITORY}/actions/runs/{args.plan_run_id}")
    if run["conclusion"] != "success" or run["head_sha"] != args.caller_sha:
        fail("source plan run is not successful on approved caller commit")
    if run["name"] != "FieldZilla Production Hosting":
        fail("source plan workflow mismatch")
    artifact = api(f"repos/{REPOSITORY}/actions/artifacts/{args.artifact_id}")
    if artifact["expired"] or artifact["workflow_run"]["id"] != args.plan_run_id:
        fail("artifact expired or belongs to another run")
    if artifact["name"] != args.artifact_name:
        fail("artifact name mismatch")
    if artifact.get("digest") != "sha256:" + args.artifact_digest:
        fail("GitHub artifact digest mismatch")
    plan = Path(args.artifact_dir) / "hosting.tfplan"
    if hashlib.sha256(plan.read_bytes()).hexdigest() != args.plan_sha256:
        fail("binary plan SHA-256 mismatch")
    metadata = json.loads((Path(args.artifact_dir) / "metadata.json").read_text())
    required = {
        "repository": REPOSITORY,
        "source_sha": args.source_sha,
        "caller_sha": args.caller_sha,
        "phase": args.phase,
        "state_key": REHEARSAL_STATE_KEY if args.target == "rehearsal" else STATE_KEY,
        "plan_sha256": args.plan_sha256,
    }
    if args.target == "rehearsal":
        required["target"] = "rehearsal"
        required["expires_at"] = args.expires_at
        required["resource_expires_at"] = args.resource_expires_at or ""
    if any(metadata.get(key) != value for key, value in required.items()):
        fail("artifact metadata mismatch")
    lock = Path(args.artifact_dir) / ".terraform.lock.hcl"
    if hashlib.sha256(lock.read_bytes()).hexdigest() != metadata.get("provider_lock_sha256"):
        fail("provider lock mismatch")


def probe_owner_comment(args):
    """Prove exact owner-comment read access without granting or consuming approval."""
    if args.approval_comment_id < 1:
        fail("exact comment ID is required for the read-only probe")
    path = f"repos/{REPOSITORY}/issues/comments/{args.approval_comment_id}"
    comment = api(path)
    target = getattr(args, "target", "production")
    if (comment.get("id") != args.approval_comment_id
            or comment["user"]["login"] != OWNER or comment["user"]["id"] != 52234089
            or comment.get("author_association") not in ("OWNER", "MEMBER", "COLLABORATOR")
            or comment.get("issue_url") != f"https://api.github.com/repos/{REPOSITORY}/issues/{717 if target == 'rehearsal' else 674}"):
        fail("probe did not read the designated owner's comment on the target PR")
    print(json.dumps({
        "probe": "owner_comment_read", "result": "PASS", "comment_id": comment["id"],
        "author": OWNER, "issue_url": comment["issue_url"],
        "body_sha256": hashlib.sha256(comment["body"].encode()).hexdigest(),
        "approval_granted": False, "approval_consumed": False,
    }, sort_keys=True))


def verify_owner_approval(args):
    target = getattr(args, "target", "production")
    environment = api(f"repos/{REPOSITORY}/environments/{ENVIRONMENT}")
    if any(rule["type"] == "required_reviewers" for rule in environment.get("protection_rules", [])):
        fail("native environment reviewers are available; fallback must not be used")
    if args.approval_comment_id < 1:
        fail("exact owner approval comment is required")
    comment = api(f"repos/{REPOSITORY}/issues/comments/{args.approval_comment_id}")
    if (comment["user"]["login"] != OWNER or comment["user"]["id"] != 52234089
            or comment.get("author_association") not in ("OWNER", "MEMBER", "COLLABORATOR")):
        fail("approval is not from the designated owner")
    issue = 717 if target == "rehearsal" else 674
    if comment.get("issue_url") != f"https://api.github.com/repos/{REPOSITORY}/issues/{issue}":
        fail("approval must be on the exact target PR")
    state_key = REHEARSAL_STATE_KEY if target == "rehearsal" else STATE_KEY
    title = ("PRODUCTION REHEARSAL" + (" " + args.phase.upper() if args.phase != "phase1" else "")) if target == "rehearsal" else f"PRODUCTION HOSTING {args.phase}"
    expected = (
        f"APPROVE FIELDZILLA {title}\n"
        f"Source: {args.source_sha}\nCaller: {args.caller_sha}\n"
        f"Plan run: {args.plan_run_id}\nArtifact ID: {args.artifact_id}\n"
        f"Artifact SHA-256: {args.artifact_digest}\nPlan SHA-256: {args.plan_sha256}\n"
        f"State key: {state_key}"
    )
    if target == "rehearsal":
        expected += f"\nExpires at: {args.expires_at}\nBudget USD: 5"
        if args.phase != "phase1":
            expected += f"\nOriginal resource expiry: {args.resource_expires_at}"
    if comment["body"].strip() != expected:
        fail("owner approval does not match this exact release")
    created = datetime.fromisoformat(comment["created_at"].replace("Z", "+00:00"))
    updated = datetime.fromisoformat(comment["updated_at"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    if updated != created or not 0 <= (now - created).total_seconds() <= 3600:
        fail("approval was edited, expired, or is future-dated")
    marker = ("fieldzilla-rehearsal-hosting-approval" if target == "rehearsal" else "fieldzilla-hosting-approval") + f":{args.approval_comment_id}"
    def payload_of(deployment):
        payload = deployment.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return {}
        return payload if isinstance(payload, dict) else {}
    for page in range(1, 101):
        deployments = api(f"repos/{REPOSITORY}/deployments?environment={ENVIRONMENT}&per_page=100&page={page}")
        if any(payload_of(d).get("authorization") == marker for d in deployments):
            fail("approval comment was already consumed")
        if len(deployments) < 100:
            break
    else:
        fail("deployment history too large to prove approval is unused")
    return marker


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["probe", "plan", "apply", "consume"])
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--caller-sha", required=True)
    parser.add_argument("--workflow-tag", required=True)
    parser.add_argument("--phase", required=True, choices=["phase1", "phase2", "cleanup-protection", "cleanup-destroy"])
    parser.add_argument("--target", choices=["production", "rehearsal"], default="production")
    parser.add_argument("--expires-at")
    parser.add_argument("--resource-expires-at")
    parser.add_argument("--plan-json")
    parser.add_argument("--plan-run-id", type=int)
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--artifact-name")
    parser.add_argument("--artifact-digest")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--artifact-dir")
    parser.add_argument("--approval-comment-id", type=int, default=0)
    args = parser.parse_args()
    require_identity(args)
    if args.target == "rehearsal" and (args.phase == "phase2" or not args.expires_at):
        fail("rehearsal requires an isolated phase and an exact expiry")
    if args.target == "production" and args.phase not in {"phase1", "phase2"}:
        fail("production hosting cannot run rehearsal cleanup")
    if args.mode == "probe":
        probe_owner_comment(args)
        return
    if args.mode == "plan":
        (check_rehearsal_plan(args.plan_json, args.phase) if args.target == "rehearsal" else check_plan(args.plan_json, args.phase))
        return
    if not SHA256.fullmatch(args.plan_sha256 or "") or not SHA256.fullmatch(args.artifact_digest or ""):
        fail("exact plan and artifact digests required")
    verify_artifact(args)
    (check_rehearsal_plan(args.plan_json, args.phase) if args.target == "rehearsal" else check_plan(args.plan_json, args.phase))
    marker = verify_owner_approval(args)
    if args.mode == "consume":
        api(f"repos/{REPOSITORY}/deployments", "POST", {
            "ref": args.caller_sha,
            "environment": ENVIRONMENT,
            "task": "fieldzilla-production-hosting-apply",
            "auto_merge": False,
            "required_contexts": [],
            "payload": {"authorization": marker, "plan_sha256": args.plan_sha256},
        })
        print("exact owner approval consumed")
    else:
        print("exact owner approval verified")


if __name__ == "__main__":
    main()
