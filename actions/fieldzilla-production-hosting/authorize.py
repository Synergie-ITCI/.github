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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_partial_state import EXPIRY as PARTIAL_EXPIRY, EXPECTED_TAGS, PARTIAL_COUNTS, SOURCE as PARTIAL_SOURCE
from verify_interrupted_state import COUNTS as INTERRUPTED_COUNTS, EXPIRY as INTERRUPTED_EXPIRY, ID_SHA256 as INTERRUPTED_ID_SHA256, SOURCE as INTERRUPTED_SOURCE, TAGS as INTERRUPTED_TAGS, identity_digest
from verify_kms_residual_state import ALIAS as KMS_RESIDUAL_ALIAS, COUNTS as KMS_RESIDUAL_COUNTS, EXPIRY as KMS_RESIDUAL_EXPIRY, ID_SHA256 as KMS_RESIDUAL_ID_SHA256, KEY_ID as KMS_RESIDUAL_KEY_ID, SOURCE as KMS_RESIDUAL_SOURCE, TAGS as KMS_RESIDUAL_TAGS


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
    if phase == "production-routing":
        check_production_routing_plan(changes)
        return
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
    if phase == "production-bootstrap":
        expected = {
            "aws_lb_listener_rule.private_validation_api": (
                302, "api.fieldzilla-validation.invalid",
                "arn:aws:elasticloadbalancing:ap-south-1:918870682888:targetgroup/pmp-production-api/07cce0ebb89838ce",
            ),
            "aws_lb_listener_rule.private_validation_admin": (
                303, "admin.fieldzilla-validation.invalid",
                "arn:aws:elasticloadbalancing:ap-south-1:918870682888:targetgroup/pmp-production-admin/25d953f6c0365619",
            ),
        }
        bootstrap = {
            "aws_secretsmanager_secret.migration",
            "aws_iam_role.admin_execution",
            "aws_iam_role_policy_attachment.admin_execution",
            "aws_iam_role.migration_execution",
            "aws_iam_role_policy_attachment.migration_execution",
            "aws_iam_role_policy.migration_secret",
        }
        added = {c["address"].split("[")[0] for c in changes if c["change"]["actions"] == ["create"]}
        initial = (set(shared) == set(expected) and len(shared) == 2
                   and added == bootstrap | set(expected) and creates == 8)
        residual = (not shared and added == {
            "aws_secretsmanager_secret.migration", "aws_iam_role_policy.migration_secret"
        } and creates == 2)
        if not initial and not residual:
            fail("production bootstrap must add only the reviewed initial or residual resources")
        if residual:
            existing = (bootstrap | set(expected)) - added
            noops = [c["address"].split("[")[0] for c in changes
                     if c["change"]["actions"] == ["no-op"]]
            if not existing <= set(noops) or any(noops.count(address) != 1 for address in existing):
                fail("residual bootstrap is missing a previously created resource")
            role_names = {
                "aws_iam_role.admin_execution": "SynergieFieldzillaProductionAdminExecution",
                "aws_iam_role.migration_execution": "SynergieFieldzillaProductionMigrationExecution",
            }
            for change in changes:
                base = change["address"].split("[")[0]
                if base in role_names and change["change"]["actions"] == ["no-op"]:
                    if (change["change"].get("after") or {}).get("name") != role_names[base]:
                        fail(f"residual bootstrap role identity differs: {base}")
                if base in {"aws_iam_role_policy_attachment.admin_execution",
                            "aws_iam_role_policy_attachment.migration_execution"} and change["change"]["actions"] == ["no-op"]:
                    after = change["change"].get("after") or {}
                    if (after.get("role") != role_names[base.replace("aws_iam_role_policy_attachment", "aws_iam_role")]
                            or after.get("policy_arn") != "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"):
                        fail(f"residual bootstrap task policy attachment differs: {base}")
        for change in changes:
            if (change["change"]["actions"] not in (["create"], ["no-op"])
                    or change["address"].split("[")[0] not in expected):
                continue
            base = change["address"].split("[")[0]
            priority, hostname, target = expected[base]
            after = change["change"].get("after") or {}
            actions = after.get("action") or []
            conditions = after.get("condition") or []
            if (after.get("priority") != priority
                    or after.get("listener_arn") != "arn:aws:elasticloadbalancing:ap-south-1:918870682888:listener/app/fieldzilla/abd764c361a9627c/a6e9b94e09bf76f8"
                    or len(actions) != 1 or actions[0].get("type") != "forward"
                    or actions[0].get("target_group_arn") != target
                    or len(conditions) != 2):
                fail(f"private validation listener identity differs: {base}")
            observed = []
            for condition in conditions:
                populated = {key: value for key, value in condition.items() if value not in (None, [], {}, "")}
                populated.pop("field", None)
                if set(populated) == {"host_header"}:
                    observed.append(("host", populated["host_header"]))
                elif set(populated) == {"source_ip"}:
                    observed.append(("source", populated["source_ip"]))
                else:
                    fail(f"private validation has an unexpected condition: {base}")
            if sorted(observed, key=str) != sorted([
                ("host", [{"values": [hostname]}]),
                ("source", [{"values": ["192.0.2.1/32"]}]),
            ], key=str):
                fail(f"private validation conditions differ: {base}")
    if phase == "production-network-repair":
        expected_ports = {
            "aws_vpc_security_group_egress_rule.production_admin_from_alb": 80,
            "aws_vpc_security_group_egress_rule.production_api_from_alb": 8000,
        }
        added = [c for c in changes if c["change"]["actions"] == ["create"]]
        if set(shared) or {c["address"] for c in added} != set(expected_ports) or creates != 2:
            fail("network repair must add only the two production ALB egress rules")
        for change in added:
            after = change["change"].get("after") or {}
            port = expected_ports[change["address"]]
            if (
                after.get("security_group_id") != "sg-0d86252daff26172b"
                or after.get("referenced_security_group_id") != "sg-0d9cdc2a3d5ef9243"
                or after.get("ip_protocol") != "tcp"
                or after.get("from_port") != port
                or after.get("to_port") != port
                or after.get("cidr_ipv4") not in (None, "")
                or after.get("cidr_ipv6") not in (None, "")
                or after.get("prefix_list_id") not in (None, "")
            ):
                fail("network repair target or port differs from the reviewed boundary")
    print(json.dumps({"phase": phase, "creates": creates, "unchanged": unchanged, "shared_alb_additions": shared}, sort_keys=True))


def check_production_routing_plan(changes):
    """Allow only the reviewed production-host API addition and Admin cutover."""
    listener = "arn:aws:elasticloadbalancing:ap-south-1:918870682888:listener/app/fieldzilla/abd764c361a9627c/a6e9b94e09bf76f8"
    api_target = "arn:aws:elasticloadbalancing:ap-south-1:918870682888:targetgroup/pmp-production-api/07cce0ebb89838ce"
    admin_target = "arn:aws:elasticloadbalancing:ap-south-1:918870682888:targetgroup/pmp-production-admin/25d953f6c0365619"
    expected = {
        "aws_lb_listener_rule.application_api[0]": ["create"],
        "aws_lb_listener_rule.application_pending[0]": ["update"],
    }
    changed = {}
    for change in changes:
        address = change["address"]
        actions = change["change"]["actions"]
        if change.get("previous_address") or change["change"].get("importing"):
            fail(f"routing plan contains a state move or import: {address}")
        if actions == ["no-op"]:
            if change["change"].get("before") != change["change"].get("after"):
                fail(f"inconsistent routing no-op: {address}")
            continue
        if address not in expected or actions != expected[address] or address in changed:
            fail(f"unreviewed production routing action: {address}: {actions}")
        changed[address] = change
    if set(changed) != set(expected):
        fail("routing plan must contain exactly the API addition and Admin cutover")

    def conditions(after):
        observed = []
        for condition in after.get("condition") or []:
            populated = {key: value for key, value in condition.items() if value not in (None, [], {}, "")}
            if set(populated) == {"host_header"}:
                observed.append(("host", populated["host_header"]))
            elif set(populated) == {"path_pattern"}:
                observed.append(("path", populated["path_pattern"]))
            else:
                fail("routing rule has an unexpected condition")
        return observed

    def forward(after, target):
        actions = after.get("action") or []
        return (len(actions) == 1 and actions[0].get("type") == "forward"
                and actions[0].get("target_group_arn") == target
                and not actions[0].get("fixed_response")
                and not actions[0].get("redirect")
                and not actions[0].get("authenticate_oidc")
                and not actions[0].get("authenticate_cognito"))

    api = changed["aws_lb_listener_rule.application_api[0]"]["change"]["after"] or {}
    if (api.get("listener_arn") != listener or api.get("priority") != 299
            or not forward(api, api_target)
            or conditions(api) != [
                ("host", [{"values": ["fieldzilla.synergieinsights.in"]}]),
                ("path", [{"values": ["/api/v1/*"]}]),
            ]):
        fail("production API routing identity differs")

    cutover = changed["aws_lb_listener_rule.application_pending[0]"]["change"]
    before, after = cutover.get("before") or {}, cutover.get("after") or {}
    if (before.get("listener_arn") != listener or after.get("listener_arn") != listener
            or before.get("priority") != 301 or after.get("priority") != 301
            or conditions(before) != [("host", [{"values": ["fieldzilla.synergieinsights.in"]}])]
            or conditions(after) != conditions(before)
            or len(before.get("action") or []) != 1
            or before["action"][0].get("type") != "fixed-response"
            or before["action"][0].get("fixed_response") != [{
                "content_type": "text/plain",
                "message_body": "FieldZilla team application not deployed",
                "status_code": "503",
            }]
            or len(after.get("action") or []) != 1
            or after["action"][0] != {
                **before["action"][0],
                "type": "forward",
                "target_group_arn": admin_target,
            }
            or {key: value for key, value in before.items() if key != "action"}
               != {key: value for key, value in after.items() if key != "action"}):
        fail("production Admin cutover changes more than the reviewed 503 action")
    print(json.dumps({"phase": "production-routing", "creates": 1, "updates": 1}, sort_keys=True))


def check_rehearsal_plan(path, phase="phase1", source=None, resource_expiry=None):
    doc = json.loads(Path(path).read_text())
    changes = [c for c in doc.get("resource_changes", []) if c.get("mode") == "managed"]
    creates = 0
    required = {
        "aws_vpc.rehearsal", "aws_db_instance.rehearsal",
        "aws_s3_bucket.attachments", "aws_s3_bucket_logging.attachments",
        "aws_lb.rehearsal", "aws_ecs_cluster.rehearsal",
        "aws_cloudwatch_log_group.container_insights",
    }
    addresses = {c["address"].split("[")[0] for c in changes}
    if phase == "phase1" and not required.issubset(addresses):
        fail("isolated rehearsal target is incomplete")
    partial_counts = {}
    interrupted_identities = []
    if phase == "cleanup-partial" and (source != PARTIAL_SOURCE or resource_expiry != PARTIAL_EXPIRY):
        fail("partial cleanup does not bind the exact failed source and resource expiry")
    if phase == "cleanup-interrupted" and (source != INTERRUPTED_SOURCE or resource_expiry != INTERRUPTED_EXPIRY):
        fail("interrupted cleanup does not bind the exact failed source and resource expiry")
    if phase == "cleanup-kms-residual" and (source != KMS_RESIDUAL_SOURCE or resource_expiry != KMS_RESIDUAL_EXPIRY):
        fail("KMS residual cleanup does not bind the exact failed source and resource expiry")
    for change in changes:
        address = change["address"]
        base_address = address.split("[")[0]
        actions = change["change"]["actions"]
        allowed = {
            "phase1": (["create"], ["no-op"]),
            "cleanup-protection": (["update"], ["no-op"]),
            "cleanup-destroy": (["delete"],),
            "cleanup-partial": (["delete"],),
            "cleanup-interrupted": (["delete"],),
            "cleanup-kms-residual": (["delete"],),
        }[phase]
        if actions not in allowed:
            fail(f"rehearsal phase cannot perform this action: {address}: {actions}")
        if change.get("previous_address") or change["change"].get("importing"):
            fail(f"rehearsal state move or import: {address}")
        if actions == ["no-op"] and change["change"].get("before") != change["change"].get("after"):
            fail(f"inconsistent rehearsal no-op: {address}")
        after = json.dumps(change["change"].get("before") if phase in {"cleanup-destroy", "cleanup-partial", "cleanup-interrupted", "cleanup-kms-residual"} else change["change"].get("after"), sort_keys=True).lower()
        # Production-rehearsal names are allowed; standalone production and all
        # staging references are forbidden in managed resource values.
        isolated = after.replace("production-rehearsal", "rehearsal").replace("productionrehearsal", "rehearsal")
        if "staging" in address.lower() or "staging" in isolated or "production" in isolated:
            fail(f"rehearsal references staging or production: {address}")
        if actions == ["create"]:
            creates += 1
        if phase == "cleanup-partial":
            partial_counts[base_address] = partial_counts.get(base_address, 0) + 1
            before = change["change"].get("before") or {}
            tags = before.get("tags_all") or {}
            # The failed S3 create left this exact isolated bucket without tags.
            # Its state was checked separately; refresh reports the live empty set.
            untagged_partial_bucket = (
                address == "aws_s3_bucket.attachments"
                and before.get("id") == "syn-fz-rehearsal-attachments-918870682888-aps1"
                and before.get("bucket") == before.get("id")
                and before.get("tags") == {}
                and tags == {}
            )
            if not untagged_partial_bucket and any(tags.get(key) != value for key, value in EXPECTED_TAGS.items()):
                fail(f"partial cleanup plan resource tags differ from the failed rehearsal: {address}")
        if phase == "cleanup-interrupted":
            partial_counts[base_address] = partial_counts.get(base_address, 0) + 1
            before = change["change"].get("before") or {}
            interrupted_identities.append((base_address, change.get("index"), before.get("id")))
            tags = before.get("tags_all")
            if tags is not None and any(tags.get(key) != value for key, value in INTERRUPTED_TAGS.items()):
                fail(f"interrupted cleanup plan resource tags differ: {address}")
        if phase == "cleanup-kms-residual":
            partial_counts[base_address] = partial_counts.get(base_address, 0) + 1
            before = change["change"].get("before") or {}
            interrupted_identities.append((base_address, change.get("index"), before.get("id")))
            if base_address == "aws_kms_alias.rehearsal":
                if (before.get("id"), before.get("name"), before.get("target_key_id")) != (KMS_RESIDUAL_ALIAS, KMS_RESIDUAL_ALIAS, KMS_RESIDUAL_KEY_ID):
                    fail("KMS residual alias identity differs from exact state")
            elif base_address == "aws_kms_key.rehearsal":
                if (before.get("id") != KMS_RESIDUAL_KEY_ID or before.get("tags_all") != KMS_RESIDUAL_TAGS
                        or before.get("deletion_window_in_days") != 7 or before.get("is_enabled") is not True):
                    fail("KMS residual key identity or lifecycle differs from exact state")
        if phase == "cleanup-protection" and actions == ["update"]:
            if address != "aws_db_instance.rehearsal" or change["change"]["before"].get("deletion_protection") is not True or change["change"]["after"].get("deletion_protection") is not False:
                fail("cleanup protection must only disable isolated RDS deletion protection")
    if phase == "phase1" and creates == 0:
        fail("rehearsal plan has no isolated additions")
    if phase == "cleanup-protection" and sum(c["change"]["actions"] == ["update"] for c in changes) != 1:
        fail("cleanup protection plan must have exactly one RDS update")
    if phase == "cleanup-destroy" and not required.issubset(addresses):
        fail("cleanup destroy must own the complete isolated target")
    if phase == "cleanup-partial" and partial_counts != PARTIAL_COUNTS:
        fail("partial cleanup plan does not match the exact failed-state inventory")
    if phase == "cleanup-interrupted" and partial_counts != INTERRUPTED_COUNTS:
        fail("interrupted cleanup plan does not match the exact failed-state inventory")
    if phase == "cleanup-interrupted" and identity_digest(interrupted_identities) != INTERRUPTED_ID_SHA256:
        fail("interrupted cleanup plan resource identities differ from exact state")
    if phase == "cleanup-kms-residual" and partial_counts != KMS_RESIDUAL_COUNTS:
        fail("KMS residual cleanup plan does not match exact two-resource inventory")
    if phase == "cleanup-kms-residual" and identity_digest(interrupted_identities) != KMS_RESIDUAL_ID_SHA256:
        fail("KMS residual cleanup plan resource identities differ from exact state")
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
    # GitHub's comment editor can persist CRLF for an otherwise exact owner
    # approval. Normalize only that transport representation; all fields,
    # ordering, author, edit timestamp and single-use checks remain exact.
    if comment["body"].replace("\r\n", "\n").strip() != expected:
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
    parser.add_argument("--phase", required=True, choices=["phase1", "phase2", "production-bootstrap", "production-network-repair", "production-routing", "cleanup-protection", "cleanup-destroy", "cleanup-partial", "cleanup-interrupted", "cleanup-kms-residual"])
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
    if args.target == "production" and args.phase not in {"phase1", "phase2", "production-bootstrap", "production-network-repair", "production-routing"}:
        fail("production hosting cannot run rehearsal cleanup")
    if args.mode == "probe":
        probe_owner_comment(args)
        return
    if args.mode == "plan":
        (check_rehearsal_plan(args.plan_json, args.phase, args.source_sha, args.resource_expires_at) if args.target == "rehearsal" else check_plan(args.plan_json, args.phase))
        return
    if not SHA256.fullmatch(args.plan_sha256 or "") or not SHA256.fullmatch(args.artifact_digest or ""):
        fail("exact plan and artifact digests required")
    verify_artifact(args)
    (check_rehearsal_plan(args.plan_json, args.phase, args.source_sha, args.resource_expires_at) if args.target == "rehearsal" else check_plan(args.plan_json, args.phase))
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
