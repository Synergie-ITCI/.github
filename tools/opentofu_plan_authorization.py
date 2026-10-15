#!/usr/bin/env python3
"""Fail-closed exact-plan authorization checks for FieldZilla remote-state applies."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple

APPROVER = "SaurabhVermaIN"
REPOSITORY = "Synergie-ITCI/programme-management-platform"
REPOSITORY_ID = 1315697868
ENVIRONMENT = "synergie-app-staging"
CENTRAL_REPOSITORY = "Synergie-ITCI/.github"
WORKFLOW_PATH = ".github/workflows/fieldzilla-staging-opentofu-apply.yml"
CALLER_WORKFLOW_PATH = ".github/workflows/fieldzilla-staging-iac.yml"
AWS_ACCOUNT = "918870682888"
AWS_REGION = "ap-south-1"
STATE_BUCKET = "synergie-fieldzilla-opentofu-state-918870682888-ap-south-1"
STATE_LOCK_TABLE = "synergie-fieldzilla-opentofu-locks"
STATE_KEY = "programme-management-platform/fieldzilla/staging/opentofu.tfstate"
FIELDZILLA_RUNTIME_STATE_KEY = (
    "programme-management-platform/fieldzilla/staging/runtime/opentofu.tfstate"
)
FIELDZILLA_RUNTIME_BOOTSTRAP_RESOURCES = {
    "aws_iam_role.ssm_hybrid": "aws_iam_role",
    "aws_iam_role_policy.runtime": "aws_iam_role_policy",
    "aws_iam_role_policy_attachment.ssm_managed_instance_core": "aws_iam_role_policy_attachment",
    "aws_ssm_activation.staging_runtime": "aws_ssm_activation",
}
STAGING_MIGRATION_IAM_SOURCE_SHA = "362109240192e6ac817d180a6d1e6b6a422c469b"
STAGING_MIGRATION_IAM_ADDRESS = "aws_iam_role_policy.staging_migration_task_run"
PR521_SOURCE_SHA = "a06e6f827d540a716b155ace2b33bb65491c29cf"
PR521_ROLE_NAME = "SynergieFieldzillaStagingMigrationExecution"
PR521_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT}:role/{PR521_ROLE_NAME}"
PR521_BOUNDARY_ARN = f"arn:aws:iam::{AWS_ACCOUNT}:policy/SynergieFieldzillaStagingMigrationExecutionBoundary"
PR521_RDS_SECRET_ARN = (
    f"arn:aws:secretsmanager:{AWS_REGION}:{AWS_ACCOUNT}:secret:"
    "rds!db-66dc9146-2f00-40bf-a0ae-c78f4b984dbc-gbUi1V"
)
PR521_KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION}:{AWS_ACCOUNT}:key/97b547d5-8bb8-463b-aee5-5fbdc471cb1e"
PR521_CHANGES = {
    "aws_iam_role.staging_migration_execution": ("aws_iam_role", ["create"]),
    "aws_iam_role_policy_attachment.staging_migration_execution": ("aws_iam_role_policy_attachment", ["create"]),
    "aws_iam_role_policy.staging_migration_execution_secrets": ("aws_iam_role_policy", ["create"]),
    'aws_ecs_task_definition.migration["staging"]': ("aws_ecs_task_definition", ["delete", "create"]),
    'aws_iam_role_policy.deploy["staging"]': ("aws_iam_role_policy", ["update"]),
    "aws_iam_role_policy.staging_infra_plan_discovery": ("aws_iam_role_policy", ["update"]),
    "aws_iam_policy.staging_infra_ecs_rollout": ("aws_iam_policy", ["update"]),
}
STAGING_INFRA_APPLY_ROLE = "SynergieProgrammeManagementPlatformStagingInfraApplyRole"
SECRET_VALUE_KEY_RE = re.compile(
    r"(activation[_-]?code|password|passwd|secret|token|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)
SENSITIVE_MARKER_KEYS = {"sensitive_values", "before_sensitive", "after_sensitive"}
SECRET_STRING_RE = re.compile(
    r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}|"
    r"(?i:password|passwd|token)\s*=\s*[^\s,;]{4,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@",
)
SECRETS_MANAGER_ARN_RE = re.compile(
    r"arn:aws(?:-us-gov|-cn)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:"
    r"(?:[A-Za-z0-9/_+=.@-]+|rds!db-[A-Za-z0-9-]+)\Z"
)
RUNTIME_SECRET_ARN_PREFIX = (
    f"arn:aws:secretsmanager:{AWS_REGION}:{AWS_ACCOUNT}:secret:"
    "/synergie/fieldzilla/staging/runtime-"
)
APPROVED_CONTAINER_INSTANCE_TYPES = {"t4g.small", "c6g.medium"}
MAX_EXPIRY_MINUTES = 60
APPROVED_FIELDZILLA_TASK_FAMILIES = {
    "fieldzilla-staging-api",
    "fieldzilla-staging-admin-web",
    "fieldzilla-staging-worker",
    "fieldzilla-staging-migration",
}
# Exact approved design baseline used ONLY when a task-definition create has no prior
# Terraform-tracked state to diff against (see _is_approved_new_staging_task_definition).
#
# PROVENANCE: every field below is taken directly from the reviewed, merged Terraform
# source at programme-management-platform commit 2c8a4015fd4a97d1c582475a6939cf8fb988b2fb
# (infra/aws/compute.tf: aws_ecs_task_definition.api/admin/worker/migration,
# infra/aws/locals.tf: local.environments.staging and local.runtime_secret_keys), NOT from
# live AWS state -- a manually created live revision (exactly the kind of out-of-band
# artifact this path exists to supersede) must never be treated as authoritative. Each
# container's key set intentionally matches only what that family's container object
# literal sets in the .tf source: a key the .tf never sets (e.g. "command" on admin-web,
# or "cpu"/"privileged"/"linuxParameters" on any of them) is simply absent from the
# baseline, so the exact-shape equality check in _is_approved_baseline_container rejects
# it the moment a plan's container carries that key at all -- there is no separate
# allowlist of "forbidden" fields to fall out of sync with the baseline.
_EXECUTION_ROLE_ARN = "arn:aws:iam::918870682888:role/SynergieFieldzillaStagingEcsExecution"
_TASK_ROLE_ARN = "arn:aws:iam::918870682888:role/SynergieFieldzillaStagingTask"
_API_ECR_REPOSITORY = "synergie/fieldzilla/staging/api"
_ADMIN_WEB_ECR_REPOSITORY = "synergie/fieldzilla/staging/admin-web"
# Both approved ECR repositories -- worker and migration share the api repository (they run
# the same image with a different command), matching aws_ecs_task_definition.worker/migration
# referencing aws_ecr_repository.api in the reviewed source, not their own repository.
APPROVED_ECR_REPOSITORIES = {_API_ECR_REPOSITORY, _ADMIN_WEB_ECR_REPOSITORY}
FAMILY_ECR_REPOSITORY = {
    "fieldzilla-staging-api": _API_ECR_REPOSITORY,
    "fieldzilla-staging-admin-web": _ADMIN_WEB_ECR_REPOSITORY,
    "fieldzilla-staging-worker": _API_ECR_REPOSITORY,
    "fieldzilla-staging-migration": _API_ECR_REPOSITORY,
}
# The exact approved staging runtime secret ARN (not a name prefix -- a same-prefixed but
# different Secrets Manager resource must never be treated as equivalent).
EXACT_RUNTIME_SECRET_ARN = (
    f"arn:aws:secretsmanager:{AWS_REGION}:{AWS_ACCOUNT}:secret:"
    "/synergie/fieldzilla/staging/runtime-pp9aAx"
)
# local.runtime_secret_keys in infra/aws/locals.tf -- the full set referenced anywhere.
_ALL_RUNTIME_SECRET_KEYS = frozenset({
    "APP_SECRET_KEY", "APP_DATABASE_CONTEXT_SECRET", "APP_DATABASE_URL",
    "APP_FIELD_ENCRYPTION_MASTER_KEY", "APP_CORS_ORIGINS", "APP_WORKER_TENANT_IDS",
    "APP_ADMIN_WEB_BASE_URL",
})
# api and migration filter out APP_WORKER_TENANT_IDS (`if key != "APP_WORKER_TENANT_IDS"`
# in the reviewed .tf); worker takes the full unfiltered list; admin-web has no secrets
# block in the .tf at all.
_API_SECRET_KEYS = _ALL_RUNTIME_SECRET_KEYS - {"APP_WORKER_TENANT_IDS"}
_MIGRATION_SECRET_KEYS = _ALL_RUNTIME_SECRET_KEYS - {"APP_WORKER_TENANT_IDS"}
_WORKER_SECRET_KEYS = _ALL_RUNTIME_SECRET_KEYS

FIELDZILLA_TASK_DEFINITION_BASELINE: dict[str, dict[str, Any]] = {
    "fieldzilla-staging-api": {
        "ecr_repository": _API_ECR_REPOSITORY,
        "cpu": "256",
        "memory": "512",
        "execution_role_arn": _EXECUTION_ROLE_ARN,
        "task_role_arn": _TASK_ROLE_ARN,
        "network_mode": "bridge",
        "requires_compatibilities": ["EC2"],
        # OpenTofu's plan JSON represents these unset optional nested-block
        # attributes as an empty list, not null, for aws_ecs_task_definition --
        # matching that here (rather than the AWS API's own null convention)
        # is what the baseline is actually diffed against.
        "runtime_platform": [],
        "volume": [],
        "placement_constraints": [],
        "proxy_configuration": [],
        "ephemeral_storage": [],
        "container": {
            "name": "api",
            "essential": True,
            "portMappings": [{"containerPort": 8000, "hostPort": 0, "protocol": "tcp"}],
            "command": ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"],
            "mountPoints": [],
            "systemControls": [],
            "volumesFrom": [],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/synergie/fieldzilla/staging/api",
                    "awslogs-region": AWS_REGION,
                    "awslogs-stream-prefix": "ecs",
                },
            },
            "environment": [
                {"name": "APP_ENVIRONMENT", "value": "staging"},
                {"name": "APP_OBJECT_STORAGE_BACKEND", "value": "s3_private"},
                {"name": "APP_OBJECT_STORAGE_BUCKET", "value": "fz-evidence-918870682888-20260912185211995900000002"},
                {"name": "APP_OBJECT_STORAGE_PREFIX", "value": "staging"},
                {"name": "APP_OBJECT_STORAGE_REGION", "value": AWS_REGION},
                {"name": "APP_OBJECT_STORAGE_KMS_KEY_ID", "value": "arn:aws:kms:ap-south-1:918870682888:key/97b547d5-8bb8-463b-aee5-5fbdc471cb1e"},
                {"name": "APP_FIELD_ENCRYPTION_KMS_KEY_ID", "value": "arn:aws:kms:ap-south-1:918870682888:key/97b547d5-8bb8-463b-aee5-5fbdc471cb1e"},
                {"name": "APP_FIELD_ENCRYPTION_KMS_KEY_VERSION", "value": "1"},
                {"name": "APP_FIELD_ENCRYPTION_KMS_AVAILABLE", "value": "true"},
                {"name": "APP_DEBUG", "value": "false"},
            ],
            "secret_keys": _API_SECRET_KEYS,
        },
    },
    "fieldzilla-staging-admin-web": {
        "ecr_repository": _ADMIN_WEB_ECR_REPOSITORY,
        "cpu": "256",
        "memory": "512",
        "execution_role_arn": _EXECUTION_ROLE_ARN,
        "task_role_arn": None,
        "network_mode": "bridge",
        "requires_compatibilities": ["EC2"],
        # OpenTofu's plan JSON represents these unset optional nested-block
        # attributes as an empty list, not null, for aws_ecs_task_definition --
        # matching that here (rather than the AWS API's own null convention)
        # is what the baseline is actually diffed against.
        "runtime_platform": [],
        "volume": [],
        "placement_constraints": [],
        "proxy_configuration": [],
        "ephemeral_storage": [],
        "container": {
            "name": "admin-web",
            "essential": True,
            "portMappings": [{"containerPort": 80, "hostPort": 0, "protocol": "tcp"}],
            "environment": [],
            "mountPoints": [],
            "systemControls": [],
            "volumesFrom": [],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/synergie/fieldzilla/staging/admin-web",
                    "awslogs-region": AWS_REGION,
                    "awslogs-stream-prefix": "ecs",
                },
            },
            "secret_keys": frozenset(),
        },
    },
    "fieldzilla-staging-worker": {
        "ecr_repository": _API_ECR_REPOSITORY,
        "cpu": "256",
        "memory": "512",
        "execution_role_arn": _EXECUTION_ROLE_ARN,
        "task_role_arn": _TASK_ROLE_ARN,
        "network_mode": "bridge",
        "requires_compatibilities": ["EC2"],
        # OpenTofu's plan JSON represents these unset optional nested-block
        # attributes as an empty list, not null, for aws_ecs_task_definition --
        # matching that here (rather than the AWS API's own null convention)
        # is what the baseline is actually diffed against.
        "runtime_platform": [],
        "volume": [],
        "placement_constraints": [],
        "proxy_configuration": [],
        "ephemeral_storage": [],
        "container": {
            "name": "worker",
            "essential": True,
            "command": ["python", "-m", "app.worker.loop"],
            "environment": [],
            "mountPoints": [],
            "portMappings": [],
            "systemControls": [],
            "volumesFrom": [],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/synergie/fieldzilla/staging/worker",
                    "awslogs-region": AWS_REGION,
                    "awslogs-stream-prefix": "ecs",
                },
            },
            "secret_keys": _WORKER_SECRET_KEYS,
        },
    },
    "fieldzilla-staging-migration": {
        "ecr_repository": _API_ECR_REPOSITORY,
        "cpu": "256",
        "memory": "512",
        "execution_role_arn": _EXECUTION_ROLE_ARN,
        "task_role_arn": _TASK_ROLE_ARN,
        "network_mode": "bridge",
        "requires_compatibilities": ["EC2"],
        # OpenTofu's plan JSON represents these unset optional nested-block
        # attributes as an empty list, not null, for aws_ecs_task_definition --
        # matching that here (rather than the AWS API's own null convention)
        # is what the baseline is actually diffed against.
        "runtime_platform": [],
        "volume": [],
        "placement_constraints": [],
        "proxy_configuration": [],
        "ephemeral_storage": [],
        "container": {
            "name": "migration",
            "essential": True,
            "command": ["alembic", "upgrade", "head"],
            "environment": [],
            "mountPoints": [],
            "portMappings": [],
            "systemControls": [],
            "volumesFrom": [],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/synergie/fieldzilla/staging/migration",
                    "awslogs-region": AWS_REGION,
                    "awslogs-stream-prefix": "ecs",
                },
            },
            "secret_keys": _MIGRATION_SECRET_KEYS,
        },
    },
}
AUTH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{7,79}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[1-9][0-9]{5,}$")
ARTIFACT_ID = re.compile(r"^[1-9][0-9]*$")
ARTIFACT_NAME = re.compile(r"^fieldzilla-staging-(plan|post-import|drift)-[0-9a-f]{40}-[1-9][0-9]*$")
ARTIFACT_DIGEST = re.compile(r"^(sha256:)?[0-9a-f]{64}$")
TAG_REF = re.compile(
    rf"^{re.escape(CENTRAL_REPOSITORY)}/{re.escape(WORKFLOW_PATH)}"
    r"@refs/tags/pr-qa-v1-rc[1-9][0-9]*$"
)
ALLOWED_IMPORT_TYPES = {
    "aws_acm_certificate",
    "aws_db_subnet_group",
    "aws_ecs_cluster",
    "aws_internet_gateway",
    "aws_kms_alias",
    "aws_kms_key",
    "aws_lb_target_group",
    "aws_route_table",
    "aws_route_table_association",
    "aws_s3_bucket",
    "aws_s3_bucket_lifecycle_configuration",
    "aws_s3_bucket_logging",
    "aws_s3_bucket_public_access_block",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_versioning",
    "aws_security_group",
    "aws_subnet",
    "aws_vpc",
}


def die(message: str) -> None:
    print(f"authorization failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_time(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        die("expiry is not valid ISO-8601")
    if parsed.tzinfo is None:
        die("expiry must include timezone")
    return parsed.astimezone(dt.UTC)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_caller_sha_match(github_sha: str, expected_caller_sha: str) -> None:
    """The commit that this workflow run was actually dispatched from must exactly equal
    the operator-declared expected-caller-sha. This is deliberately independent of
    expected-sha, which is the approved application/IaC source and image SHA (checked out
    explicitly via `ref: inputs.expected-sha`, regardless of which commit dispatched the
    run) -- conflating the two would require the caller ref to be pinned at the exact
    approved application commit forever, which breaks the moment any later, unrelated
    commit (e.g. a governance pin bump) lands on top of it. Keeping them separate lets the
    caller workflow advance independently while still proving, exactly, which version of
    the caller workflow (and therefore which pinned central authorizer release) actually
    executed this run."""
    if not SHA.fullmatch(expected_caller_sha or ""):
        die("expected caller commit SHA must be exact 40-character lowercase hex")
    if github_sha != expected_caller_sha:
        die("workflow commit SHA does not match approved caller SHA")


def verify_caller_sha(args: argparse.Namespace) -> None:
    _require_caller_sha_match(args.github_sha, args.expected_caller_sha)


def verify_inputs(args: argparse.Namespace, now: dt.datetime | None = None) -> None:
    current = now or dt.datetime.now(dt.UTC)
    if args.actor != APPROVER:
        die("actor must be SaurabhVermaIN")
    if args.repository != REPOSITORY:
        die("repository mismatch")
    if args.environment != ENVIRONMENT:
        die("environment mismatch")
    if not SHA.fullmatch(args.expected_sha or ""):
        die("expected commit SHA must be exact 40-character lowercase hex")
    _require_caller_sha_match(args.github_sha, args.expected_caller_sha)
    if getattr(args, "repository_id", REPOSITORY_ID) != REPOSITORY_ID:
        die("repository id mismatch")
    if getattr(args, "image_digest_map", "") and _parse_image_digest_map(args.image_digest_map) is None:
        die("image digest map must be canonical JSON with exact sha256 digests for both approved repositories")
    if getattr(args, "image_digest", "") and not IMAGE_DIGEST.fullmatch(args.image_digest):
        die("image digest must be exact sha256 digest")  # deprecated legacy single-digest form
    if getattr(args, "ecs_families", ""):
        families = set(args.ecs_families.split(","))
        if families != APPROVED_FIELDZILLA_TASK_FAMILIES:
            die("ECS family authorization mismatch")
    if args.expected_plan_sha256 and not SHA256.fullmatch(args.expected_plan_sha256):
        die("plan SHA-256 must be exact 64-character lowercase hex")
    if args.expected_import_map_sha256 and not SHA256.fullmatch(args.expected_import_map_sha256):
        die("import map SHA-256 must be exact 64-character lowercase hex")
    if not AUTH_ID.fullmatch(args.authorization_id or ""):
        die("authorization id format is invalid")
    expires_at = parse_time(args.expires_at)
    if expires_at <= current:
        die("authorization expired")
    if expires_at - current > dt.timedelta(minutes=MAX_EXPIRY_MINUTES):
        die("authorization expiry window is too long")
    if args.native_reviewers_available.lower() not in {"true", "false"}:
        die("native reviewer availability must be true or false")
    if args.native_reviewers_available.lower() == "true":
        die("native environment reviewers are available; fallback is not allowed")
    if not TAG_REF.fullmatch(args.job_workflow_ref or ""):
        die("job workflow must be the immutable central FieldZilla workflow tag")


def verify_native_reviewers(args: argparse.Namespace) -> None:
    if args.native_reviewers_available.lower() != "false":
        die("fallback requires native-reviewers-available=false")
    environment = github_api(f"environments/{ENVIRONMENT}")
    rules = environment.get("protection_rules")
    if not isinstance(rules, list):
        die("native environment reviewer availability is unavailable")
    for rule in rules:
        if rule.get("type") == "required_reviewers" or rule.get("reviewers"):
            die("native environment reviewers are available; fallback is not allowed")


def b64url_json(segment: str) -> dict[str, Any]:
    padded = segment + ("=" * (-len(segment) % 4))
    return json.loads(base64.urlsafe_b64decode(padded.encode()).decode())


def verify_oidc(args: argparse.Namespace) -> None:
    # args.job_workflow_ref here must be the ACTUAL, current tag this run was invoked
    # through (the caller's own uses: pin) -- never CENTRAL_WORKFLOW_REF's self-referential
    # value, which is deliberately one release behind (see _require_caller_sha_match and
    # the internal opentofu-plan-authorizer@ self-pins for why). Confusing the two here
    # would compare the real OIDC claim against a stale expectation.
    if not TAG_REF.fullmatch(args.job_workflow_ref or ""):
        die("job workflow must be the immutable central FieldZilla workflow tag")
    token = args.token_file.read_text(encoding="utf-8").strip()
    parts = token.split(".")
    if len(parts) < 2:
        die("OIDC token is malformed")
    claims = b64url_json(parts[1])
    if claims.get("aud") != "sts.amazonaws.com":
        die("OIDC audience mismatch")
    if claims.get("repository") != REPOSITORY:
        die("OIDC repository mismatch")
    if claims.get("job_workflow_ref") != args.job_workflow_ref:
        die("OIDC workflow identity mismatch")
    if claims.get("sub") != (
        "repo:Synergie-ITCI@209829096/"
        "programme-management-platform@1315697868:environment:synergie-app-staging"
    ):
        die("OIDC subject mismatch")


def verify_backend(args: argparse.Namespace) -> None:
    doc = json.loads(args.backend_metadata_path.read_text(encoding="utf-8"))
    expected_state_key = _expected_state_key(args)
    expected = {
        "account_id": AWS_ACCOUNT,
        "region": AWS_REGION,
        "bucket": STATE_BUCKET,
        "key": expected_state_key,
        "dynamodb_table": STATE_LOCK_TABLE,
        "bucket_versioning": "Enabled",
        "bucket_encryption": "aws:kms",
        "public_access_blocked": True,
    }
    for key, value in expected.items():
        if doc.get(key) != value:
            die(f"remote backend evidence mismatch for {key}")
    print("REMOTE_BACKEND_VERIFIED=true")


def _expected_state_key(args: argparse.Namespace) -> str:
    value = getattr(args, "expected_state_key", "") or STATE_KEY
    if value not in {STATE_KEY, FIELDZILLA_RUNTIME_STATE_KEY}:
        die("expected state key is not approved")
    return value


def _require_artifact_inputs(args: argparse.Namespace) -> None:
    if not RUN_ID.fullmatch(args.source_run_id or ""):
        die("source run id is invalid")
    if not ARTIFACT_ID.fullmatch(args.artifact_id or ""):
        die("artifact id is invalid")
    if not ARTIFACT_NAME.fullmatch(args.artifact_name or ""):
        die("artifact name is invalid")
    if args.expected_sha not in args.artifact_name:
        die("artifact name is not bound to approved commit")
    if not ARTIFACT_DIGEST.fullmatch(args.expected_artifact_digest or ""):
        die("artifact digest is invalid")
    if not SHA.fullmatch(getattr(args, "expected_caller_sha", "") or ""):
        die("expected caller commit SHA must be exact 40-character lowercase hex")


def verify_source_artifact(args: argparse.Namespace) -> None:
    _require_artifact_inputs(args)
    run = github_api(f"actions/runs/{args.source_run_id}")
    if run.get("head_repository", {}).get("full_name") != REPOSITORY:
        die("source run repository mismatch")
    if run.get("head_repository", {}).get("id") != REPOSITORY_ID:
        die("source run repository id mismatch")
    # head_sha is the commit the SOURCE (plan-generation) run was actually dispatched
    # from -- the caller-commit concept, not the approved application/IaC source SHA.
    if run.get("head_sha") != args.expected_caller_sha:
        die("source run caller commit mismatch")
    if run.get("conclusion") != "success":
        die("source run did not succeed")
    if run.get("path") != CALLER_WORKFLOW_PATH:
        die("source workflow mismatch")
    if str(run.get("run_attempt", "")) != "1":
        die("source run attempt mismatch")

    artifacts = github_api(f"actions/runs/{args.source_run_id}/artifacts?per_page=100")
    matches = [
        artifact
        for artifact in artifacts.get("artifacts", [])
        if str(artifact.get("id")) == args.artifact_id
    ]
    if len(matches) != 1:
        die("approved artifact id is unavailable")
    artifact = matches[0]
    if artifact.get("name") != args.artifact_name:
        die("approved artifact name mismatch")
    if artifact.get("expired"):
        die("approved artifact expired")
    digest = artifact.get("digest")
    if not digest or digest.removeprefix("sha256:") != args.expected_artifact_digest.removeprefix("sha256:"):
        die("approved artifact digest mismatch")
    print(f"ARTIFACT_ID={args.artifact_id}")


def verify_artifact_files(args: argparse.Namespace) -> None:
    allowed = {
        "fieldzilla-staging.tfplan",
        "fieldzilla-staging.plan.txt",
        "fieldzilla-staging.plan.json",
        "metadata.json",
        "SHA256SUMS",
        "import-map.json",
        "backend.json",
        "drift.plan.json",
        "drift.plan.txt",
    }
    prohibited = []
    for path in args.artifact_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(args.artifact_dir).as_posix()
        if rel not in allowed:
            prohibited.append(rel)
        lower = rel.lower()
        if any(marker in lower for marker in ("tfstate", "credential", ".env", "token", "secret")):
            prohibited.append(rel)
    if prohibited:
        die("artifact contains prohibited files")
    for rel in ("metadata.json", "SHA256SUMS"):
        if not (args.artifact_dir / rel).exists():
            die("artifact is incomplete")


def verify_artifact_metadata(args: argparse.Namespace) -> None:
    _require_artifact_inputs(args)
    metadata_path = args.artifact_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected_state_key = _expected_state_key(args)
    checks = {
        "repository": REPOSITORY,
        "commit_sha": args.expected_sha,
        # Binds this apply's claimed expected-caller-sha to the exact caller commit the
        # plan was actually generated from -- if staging advances between plan and apply
        # (a later commit becomes the tip), a plan regenerated/re-dispatched there records
        # a different caller_sha here, and an apply attempting to reuse the older, now-stale
        # plan artifact fails closed instead of silently applying it.
        "caller_sha": args.expected_caller_sha,
        "workflow_run_id": args.source_run_id,
        "artifact_name": args.artifact_name,
        "environment": ENVIRONMENT,
        "state_backend": "s3",
        "state_bucket": STATE_BUCKET,
        "state_key": expected_state_key,
        "lock_table": STATE_LOCK_TABLE,
    }
    for key, expected in checks.items():
        if str(metadata.get(key, "")) != expected:
            die(f"artifact metadata {key} mismatch")
    if args.expected_plan_sha256:
        plan_path = args.artifact_dir / "fieldzilla-staging.tfplan"
        if not plan_path.is_file() or sha256_file(plan_path) != args.expected_plan_sha256:
            die("downloaded OpenTofu plan hash mismatch")
    if getattr(args, "image_digest_map", "") and metadata.get("image_digest_map") != _parse_image_digest_map(args.image_digest_map):
        die("artifact image digest map mismatch")
    if getattr(args, "image_digest", "") and metadata.get("image_digest") != args.image_digest:
        die("artifact image digest mismatch")  # deprecated legacy single-digest form
    if getattr(args, "ecs_families", ""):
        families = metadata.get("ecs_families")
        if families != sorted(APPROVED_FIELDZILLA_TASK_FAMILIES):
            die("artifact ECS family authorization mismatch")
    if args.expected_import_map_sha256:
        import_path = args.artifact_dir / "import-map.json"
        if not import_path.is_file() or sha256_file(import_path) != args.expected_import_map_sha256:
            die("downloaded import map hash mismatch")


def verify_plan_safety(args: argparse.Namespace) -> None:
    doc = json.loads(args.plan_json_path.read_text(encoding="utf-8"))
    if args.plan_kind == "fieldzilla-runtime-bootstrap":
        verify_fieldzilla_runtime_bootstrap_plan(doc)
        return
    if args.plan_kind == "fieldzilla-staging-migration-iam":
        verify_staging_migration_iam_plan(doc, args)
        return
    if args.plan_kind == "fieldzilla-pr521-staging-plan":
        verify_pr521_staging_plan(doc, args)
        return

    variables = {key: item.get("value") for key, item in doc.get("variables", {}).items()}
    if variables.get("enable_production") is not False:
        die("production resources are enabled")
    if variables.get("route53_zone_id") not in ("", None):
        die("DNS changes are enabled")
    if variables.get("container_instance_type") not in APPROVED_CONTAINER_INSTANCE_TYPES:
        die("container host size is outside approved design")
    if str(variables.get("monthly_budget_usd")) != "100":
        die("monthly budget guardrail mismatch")
    routine_ecs_only = bool(getattr(args, "image_digest_map", "")) or bool(getattr(args, "image_digest", ""))
    resource_changes = doc.get("resource_changes", [])

    def _is_harmless_data_source_read(change: dict[str, Any]) -> bool:
        """The ONLY exemption from routine_ecs_only's blanket approved-ECS-change
        requirement: a pure, read-only data-source evaluation. All three must hold --
        mode is exactly "data" (missing or any other/unknown mode fails closed, never
        exempted), and every action is "read" and/or "no-op" -- never create, update,
        delete, replace, or any other mutation, managed or otherwise. This never touches
        the task-definition, service, image-digest, family, role, secret, networking,
        volume, CPU/memory, or artifact checks -- it only widens what routine_ecs_only
        tolerates alongside them."""
        if change.get("mode") != "data":
            return False
        actions = change.get("change", {}).get("actions", [])
        if not actions:
            return False
        return all(action in ("read", "no-op") for action in actions)

    approved_task_definition_addresses = {
        change.get("address", "")
        for change in resource_changes
        if change.get("type") == "aws_ecs_task_definition"
        and is_approved_ecs_task_definition_revision(change, variables, args)
    }

    counts: dict[str, int] = {}
    for change in resource_changes:
        actions = change.get("change", {}).get("actions", [])
        key = ",".join(actions)
        counts[key] = counts.get(key, 0) + 1
        address = change.get("address", "")
        rtype = change.get("type", "")
        if routine_ecs_only and actions != ["no-op"]:
            if not (
                _is_harmless_data_source_read(change)
                or is_approved_ecs_task_definition_revision(change, variables, args)
                or is_approved_ecs_service_update(change, approved_task_definition_addresses)
            ):
                die("routine ECS deployment contains non-ECS or unapproved changes")
        if (
            ("delete" in actions or actions in (["create", "delete"], ["delete", "create"]))
            and not is_approved_ecs_task_definition_revision(change, variables, args)
        ):
            die("plan contains destructive actions")
        # A bare "create" (no prior Terraform state) is not "destructive" and is not caught
        # by the check above, but for aws_ecs_task_definition it must still be validated --
        # otherwise a create of an unapproved family/role/image/secret would pass through
        # this loop with no check at all. Non-task-definition creates are unaffected.
        if (
            rtype == "aws_ecs_task_definition"
            and actions == ["create"]
            and not is_approved_ecs_task_definition_revision(change, variables, args)
        ):
            die("plan contains an unapproved ECS task-definition change")
        if "route53" in rtype.lower() or "route53" in address.lower():
            die("plan contains DNS resources")
        after = json.dumps(change.get("change", {}).get("after", {}), sort_keys=True).lower()
        if "production" in address.lower() or '"environment": "production"' in after:
            die("plan contains production resources")
    if args.plan_kind == "drift" and counts not in ({}, {"no-op": len(doc.get("resource_changes", []))}):
        die("drift plan is not clean")
    print("PLAN_COUNTS=" + json.dumps(counts, sort_keys=True))


def verify_plan_capture(args: argparse.Namespace) -> None:
    """Permit diagnostic upload only after the established plaintext-secret scan."""
    diagnostic_path = getattr(args, "diagnostic_path", None)
    if (args.expected_sha, args.repository, args.environment) != (PR521_SOURCE_SHA, REPOSITORY, ENVIRONMENT):
        _write_plan_diagnostic(diagnostic_path, None, PlanSecretFinding((), "unknown", "identity_mismatch"))
        die("PR 521 diagnostic plan identity mismatch")
    try:
        doc = json.loads(args.plan_json_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _write_plan_diagnostic(diagnostic_path, None, PlanSecretFinding((), "unknown", "plan_unavailable_or_malformed"))
        die("PR 521 diagnostic plan is unavailable or malformed")
    if not isinstance(doc, dict) or not isinstance(doc.get("resource_changes"), list):
        _write_plan_diagnostic(diagnostic_path, None, PlanSecretFinding((), _json_type(doc), "plan_unavailable_or_malformed"))
        die("PR 521 diagnostic plan is unavailable or malformed")
    finding = classify_plan_secret(doc)
    if finding:
        _write_plan_diagnostic(diagnostic_path, doc, finding)
        die(f"PR 521 diagnostic plan rejected {finding.reason} at `{_safe_diagnostic_path(finding.path)}`")


def verify_staging_migration_iam_plan(doc: dict[str, Any], args: argparse.Namespace) -> None:
    if args.expected_sha != STAGING_MIGRATION_IAM_SOURCE_SHA:
        die("migration IAM plan source SHA mismatch")
    variables = {key: item.get("value") for key, item in doc.get("variables", {}).items()}
    if variables.get("enable_production") is not False or variables.get("route53_zone_id") not in ("", None):
        die("migration IAM plan is not staging-only")
    if known_plaintext_secret_path(doc):
        die("migration IAM plan contains sensitive plaintext")

    expected_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RunOnlyFieldZillaStagingMigration",
                "Effect": "Allow",
                "Action": "ecs:RunTask",
                "Resource": f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT}:task-definition/fieldzilla-staging-migration:*",
                "Condition": {"ArnEquals": {"ecs:cluster": f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT}:cluster/fieldzilla"}},
            },
            {
                "Sid": "InspectOnlyFieldZillaStagingMigrationTasks",
                "Effect": "Allow",
                "Action": "ecs:DescribeTasks",
                "Resource": f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT}:task/fieldzilla/*",
                "Condition": {"ArnEquals": {"ecs:cluster": f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT}:cluster/fieldzilla"}},
            },
        ],
    }
    changes = doc.get("resource_changes")
    if not isinstance(changes, list):
        die("migration IAM plan has invalid resource changes")
    created = 0
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
            die("migration IAM plan has invalid resource change")
        change = item["change"]
        actions = change.get("actions")
        if item.get("mode") == "data" and actions in (["read"], ["no-op"]):
            continue
        if actions == ["no-op"]:
            continue
        if (item.get("mode"), item.get("address"), item.get("type"), actions) != (
            "managed", STAGING_MIGRATION_IAM_ADDRESS, "aws_iam_role_policy", ["create"]
        ):
            die("migration IAM plan contains an unrelated mutation")
        after = change.get("after")
        unknown = change.get("after_unknown") or {}
        if change.get("before") is not None or not isinstance(after, dict):
            die("migration IAM policy is not a new resource")
        if any(unknown.get(key) for key in ("name", "role", "policy")):
            die("migration IAM policy has unknown security fields")
        if after.get("name") != "SynergieFieldZillaStagingMigrationRun" or after.get("role") != STAGING_INFRA_APPLY_ROLE:
            die("migration IAM policy target mismatch")
        try:
            policy = json.loads(after["policy"])
        except (KeyError, TypeError, json.JSONDecodeError):
            die("migration IAM policy is not known JSON")
        if policy != expected_policy:
            die("migration IAM policy exceeds reviewed staging permissions")
        created += 1
    if created != 1:
        die("migration IAM plan must create exactly the reviewed policy")
    for item in doc.get("resource_drift", []):
        if item.get("change", {}).get("actions") not in (["no-op"],):
            die("migration IAM plan contains resource drift")
    for item in doc.get("output_changes", {}).values():
        if item.get("actions") not in (["no-op"],):
            die("migration IAM plan changes outputs")
    print('PLAN_COUNTS={"create": 1}')


def _pr521_json(value: Any, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        die(f"PR 521 {label} is not known JSON")
    if not isinstance(parsed, dict):
        die(f"PR 521 {label} is not a JSON object")
    return parsed


def _pr521_unknown_paths(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, dict):
        return [path for key, item in value.items()
                for path in _pr521_unknown_paths(item, f"{prefix}.{key}" if prefix else key)]
    if isinstance(value, list):
        return [path for index, item in enumerate(value)
                for path in _pr521_unknown_paths(item, f"{prefix}[{index}]")]
    return [prefix] if value is True else []


def _pr521_statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("Statement")
    if policy.get("Version") != "2012-10-17" or not isinstance(statements, list):
        die("PR 521 IAM policy has invalid version or statements")
    return statements


def _pr521_exact_secret_policy(policy: dict[str, Any]) -> bool:
    statements = _pr521_statements(policy)
    if len(statements) != 2:
        return False
    secrets = {EXACT_RUNTIME_SECRET_ARN, PR521_RDS_SECRET_ARN}
    expected = {
        ("secretsmanager:GetSecretValue", tuple(sorted(secrets)), ""),
        ("kms:Decrypt", (PR521_KMS_KEY_ARN,), "kms"),
    }
    actual = set()
    for statement in statements:
        if set(statement) - {"Sid", "Effect", "Action", "Resource", "Condition"} or statement.get("Effect") != "Allow":
            return False
        action = statement.get("Action")
        actions = [action] if isinstance(action, str) else action
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(actions, list) or not isinstance(resources, list) or len(actions) != 1:
            return False
        condition = statement.get("Condition")
        if actions[0] == "kms:Decrypt":
            if condition != {"StringEquals": {
                "kms:ViaService": f"secretsmanager.{AWS_REGION}.amazonaws.com",
                "kms:EncryptionContext:SecretARN": sorted(secrets),
            }}:
                # The provider may preserve the reviewed source ordering rather than sort it.
                values = (condition or {}).get("StringEquals", {}).get("kms:EncryptionContext:SecretARN")
                if not isinstance(values, list) or set(values) != secrets or len(values) != 2 or (
                    (condition or {}).get("StringEquals", {}).get("kms:ViaService")
                    != f"secretsmanager.{AWS_REGION}.amazonaws.com"
                ) or set(condition) != {"StringEquals"} or set(condition["StringEquals"]) != {
                    "kms:ViaService", "kms:EncryptionContext:SecretARN"
                }:
                    return False
            kind = "kms"
        elif condition is None:
            kind = ""
        else:
            return False
        actual.add((actions[0], tuple(sorted(resources)), kind))
    return actual == expected


def _pr521_only_role_added(before: dict[str, Any], after: dict[str, Any], action: str) -> bool:
    old = _pr521_statements(before)
    new = _pr521_statements(after)
    if len(old) != len(new) or set(before) != set(after):
        return False
    matches = 0
    for prior, current in zip(old, new, strict=True):
        if prior == current:
            continue
        if prior.get("Effect") != "Allow" or current.get("Effect") != "Allow":
            return False
        actions = prior.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or action not in actions:
            return False
        old_resources = prior.get("Resource")
        new_resources = current.get("Resource")
        old_resources = [old_resources] if isinstance(old_resources, str) else old_resources
        new_resources = [new_resources] if isinstance(new_resources, str) else new_resources
        if not isinstance(old_resources, list) or not isinstance(new_resources, list):
            return False
        if PR521_ROLE_ARN in old_resources or new_resources.count(PR521_ROLE_ARN) != 1:
            return False
        reduced = dict(current)
        reduced["Resource"] = [item for item in new_resources if item != PR521_ROLE_ARN]
        original = dict(prior)
        original["Resource"] = old_resources
        if reduced != original:
            return False
        matches += 1
    return matches == 1


def verify_pr521_staging_plan(doc: dict[str, Any], args: argparse.Namespace) -> None:
    """Authorize only a complete, concrete PR 521 plan. Unknown security values fail closed."""
    if (args.expected_sha, args.repository, args.environment) != (PR521_SOURCE_SHA, REPOSITORY, ENVIRONMENT):
        die("PR 521 plan repository, environment, or exact source SHA mismatch")
    try:
        metadata = json.loads((args.plan_json_path.parent / "metadata.json").read_text(encoding="utf-8"))
    except (AttributeError, OSError, ValueError):
        die("PR 521 plan has no generated artifact metadata")
    if (metadata.get("commit_sha"), metadata.get("repository"), metadata.get("environment"),
        metadata.get("state_key")) != (
        PR521_SOURCE_SHA, REPOSITORY, ENVIRONMENT, STATE_KEY
    ):
        die("PR 521 plan artifact metadata is not exact-head staging evidence")
    digest_map = _parse_image_digest_map(json.dumps(metadata.get("image_digest_map")))
    if digest_map is None:
        die("PR 521 plan has no complete ECR-verified image digest map")
    variables = {key: item.get("value") for key, item in doc.get("variables", {}).items()}
    if (variables.get("enable_production") is not False
        or variables.get("route53_zone_id") not in ("", None)
        or variables.get("image_tag") != "b1679598ea9dfbbac3b8244887fc113636169e6f"):
        die("PR 521 plan is not staging-only")
    if known_plaintext_secret_path(doc):
        die("PR 521 plan contains sensitive plaintext")
    changes = doc.get("resource_changes")
    if not isinstance(changes, list):
        die("PR 521 plan has invalid resource changes")
    mutations: dict[str, dict[str, Any]] = {}
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
            die("PR 521 plan has malformed resource change")
        change = item["change"]
        actions = change.get("actions")
        if item.get("mode") == "data" and actions in (["read"], ["no-op"]):
            continue
        if actions == ["no-op"]:
            continue
        address = item.get("address")
        expected = PR521_CHANGES.get(address)
        expected_actions = expected[1] if expected else None
        if address == 'aws_ecs_task_definition.migration["staging"]' and actions == ["create", "delete"]:
            expected_actions = actions
        if item.get("mode") != "managed" or expected is None or (
            item.get("type"), actions
        ) != (expected[0], expected_actions) or address in mutations:
            die(f"PR 521 plan contains unrelated or duplicate mutation: {address}")
        unknowns = _pr521_unknown_paths(change.get("after_unknown") or {})
        computed_only = {"id"}
        if address == 'aws_ecs_task_definition.migration["staging"]':
            computed_only |= {"arn", "arn_without_revision", "revision"}
        if address == "aws_iam_role.staging_migration_execution":
            computed_only |= {"create_date", "unique_id"}
        # Every other unknown may conceal a security-sensitive result. In particular,
        # the new role ARN is NOT a harmless provider-computed field for this gate.
        sensitive = [path for path in unknowns if path not in computed_only]
        if sensitive:
            die(f"PR 521 plan has unknown security-sensitive values at {address}: {', '.join(sensitive)}")
        mutations[address] = change
    if set(mutations) != set(PR521_CHANGES):
        die("PR 521 plan does not contain exactly the reviewed staging changes")

    role = mutations["aws_iam_role.staging_migration_execution"]
    role_after = role.get("after")
    if role.get("before") is not None or not isinstance(role_after, dict) or (
        role_after.get("name"), role_after.get("arn"), role_after.get("permissions_boundary")
    ) != (PR521_ROLE_NAME, PR521_ROLE_ARN, PR521_BOUNDARY_ARN):
        die("PR 521 migration execution role or boundary mismatch")
    trust = _pr521_json(role_after.get("assume_role_policy"), "role trust policy")
    if trust != {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "ecs-tasks.amazonaws.com"}
    }]}:
        die("PR 521 role trust policy mismatch")
    if role_after.get("tags") not in ({}, None) or role_after.get("tags_all") != {
        "Application": "fieldzilla",
        "Repository": REPOSITORY,
        "ManagedBy": "opentofu",
        "Governance": "synergie-pr-qa",
    }:
        die("PR 521 role tags mismatch")

    attachment = mutations["aws_iam_role_policy_attachment.staging_migration_execution"]
    attached = attachment.get("after")
    if attachment.get("before") is not None or not isinstance(attached, dict) or (
        attached.get("role"), attached.get("policy_arn")
    ) != (PR521_ROLE_NAME, "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"):
        die("PR 521 policy attachment mismatch")

    inline = mutations["aws_iam_role_policy.staging_migration_execution_secrets"]
    inline_after = inline.get("after")
    if inline.get("before") is not None or not isinstance(inline_after, dict) or (
        inline_after.get("name"), inline_after.get("role")
    ) != ("fieldzilla-staging-migration-execution-secrets", PR521_ROLE_NAME) or not _pr521_exact_secret_policy(
        _pr521_json(inline_after.get("policy") if isinstance(inline_after, dict) else None, "secret policy")
    ):
        die("PR 521 secret/KMS policy exceeds reviewed scope")

    for address, action in (
        ('aws_iam_role_policy.deploy["staging"]', "iam:PassRole"),
        ("aws_iam_role_policy.staging_infra_plan_discovery", "iam:GetRole"),
        ("aws_iam_policy.staging_infra_ecs_rollout", "iam:PassRole"),
    ):
        change = mutations[address]
        before, after = change.get("before"), change.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            die(f"PR 521 {address} is not a known policy update")
        before_policy = _pr521_json(before.get("policy"), address)
        after_policy = _pr521_json(after.get("policy"), address)
        if not _pr521_only_role_added(before_policy, after_policy, action):
            die(f"PR 521 {address} changes more than the exact role resource")
        if {key: value for key, value in before.items() if key != "policy"} != {
            key: value for key, value in after.items() if key != "policy"
        }:
            die(f"PR 521 {address} changes other policy fields")

    task = mutations['aws_ecs_task_definition.migration["staging"]']
    before, after = task.get("before"), task.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict) or (
        before.get("family"), after.get("family"), before.get("execution_role_arn"),
        after.get("execution_role_arn"), before.get("task_role_arn"), after.get("task_role_arn")
    ) != ("fieldzilla-staging-migration", "fieldzilla-staging-migration", _EXECUTION_ROLE_ARN,
          PR521_ROLE_ARN, _TASK_ROLE_ARN, _TASK_ROLE_ARN):
        die("PR 521 staging migration task role mismatch")
    before_containers = _decode_container_definitions(before.get("container_definitions"))
    after_containers = _decode_container_definitions(after.get("container_definitions"))
    if len(before_containers) != 1 or len(after_containers) != 1:
        die("PR 521 migration task must contain exactly one container")
    previous, current = before_containers[0], after_containers[0]
    if previous.get("name") != "migration" or previous.get("command") != ["alembic", "upgrade", "head"]:
        die("PR 521 prior migration container mismatch")
    prior_secrets = previous.get("secrets")
    if not isinstance(prior_secrets, list) or len(prior_secrets) != len(_MIGRATION_SECRET_KEYS) or {
        (item.get("name"), item.get("valueFrom")) for item in prior_secrets if isinstance(item, dict)
    } != {(name, f"{EXACT_RUNTIME_SECRET_ARN}:{name}::") for name in _MIGRATION_SECRET_KEYS}:
        die("PR 521 prior migration secrets mismatch")
    image = current.get("image", "")
    digest_prefix = f"{AWS_ACCOUNT}.dkr.ecr.{AWS_REGION}.amazonaws.com/{_API_ECR_REPOSITORY}@"
    if not isinstance(image, str) or image != digest_prefix + digest_map[_API_ECR_REPOSITORY]:
        die("PR 521 migration image is not an exact staging API digest")
    expected_secrets = list(previous.get("secrets") or []) + [{
        "name": "APP_MIGRATION_DB_PASSWORD", "valueFrom": f"{PR521_RDS_SECRET_ARN}:password::"
    }]
    expected_container = dict(previous, image=image, secrets=expected_secrets)
    if current != expected_container or current.get("command") != ["alembic", "upgrade", "head"]:
        die("PR 521 migration container changes more than image and database secret")
    ignored_computed = {"arn", "arn_without_revision", "id", "revision"}
    old_fields = {key: value for key, value in before.items() if key not in ignored_computed | {"container_definitions", "execution_role_arn"}}
    new_fields = {key: value for key, value in after.items() if key not in ignored_computed | {"container_definitions", "execution_role_arn"}}
    if old_fields != new_fields:
        die("PR 521 migration task changes unrelated fields")
    for item in doc.get("resource_drift", []):
        if item.get("change", {}).get("actions") != ["no-op"]:
            die("PR 521 plan contains resource drift")
    for item in doc.get("output_changes", {}).values():
        if item.get("actions") != ["no-op"]:
            die("PR 521 plan changes outputs")
    print('PLAN_COUNTS={"create": 3, "update": 3, "replace": 1}')


def verify_fieldzilla_runtime_bootstrap_plan(doc: dict[str, Any]) -> None:
    resource_changes = doc.get("resource_changes", [])
    counts: dict[str, int] = {}
    created: dict[str, str] = {}
    seen: set[str] = set()

    if not isinstance(resource_changes, list):
        die("runtime bootstrap plan has invalid resource changes")

    leaked = known_plaintext_secret_path(doc)
    if leaked:
        die(f"runtime bootstrap plan exposes known plaintext secret value at `{leaked}`")

    for change in resource_changes:
        if not isinstance(change, dict) or not isinstance(change.get("change"), dict):
            die("runtime bootstrap plan has invalid resource change shape")
        actions = change.get("change", {}).get("actions", [])
        if not isinstance(actions, list) or not all(isinstance(action, str) for action in actions):
            die("runtime bootstrap plan has invalid action shape")
        key = ",".join(actions)
        counts[key] = counts.get(key, 0) + 1
        address = str(change.get("address", ""))
        rtype = str(change.get("type", ""))
        if FIELDZILLA_RUNTIME_BOOTSTRAP_RESOURCES.get(address) != rtype:
            die(f"runtime bootstrap plan contains unapproved resource `{address}`")
        if address in seen:
            die(f"runtime bootstrap plan contains duplicate resource `{address}`")
        seen.add(address)
        if actions == ["no-op"]:
            continue
        if actions != ["create"]:
            die("runtime bootstrap plan must contain only approved creates and no-ops")
        created[address] = rtype

    if not created:
        die("runtime bootstrap recovery plan must create at least one approved resource")
    if any(FIELDZILLA_RUNTIME_BOOTSTRAP_RESOURCES.get(address) != rtype for address, rtype in created.items()):
        die("runtime bootstrap plan does not match the approved resource allowlist")
    if any(action not in {"create", "no-op"} for action in counts):
        die("runtime bootstrap plan must contain 0 update, 0 replace and 0 destroy")
    print("PLAN_COUNTS=" + json.dumps(counts, sort_keys=True))


class PlanSecretFinding(NamedTuple):
    path: tuple[str, ...]
    json_type: str
    reason: str


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _sensitive_string(value: Any, *, secret_key: bool = False) -> bool:
    return isinstance(value, str) and bool(value) and (
        secret_key or bool(SECRET_STRING_RE.search(value))
    )


def _secret_arn_reference(key: str, value: str) -> bool:
    """An ARN identifies a secret; it is not the secret's plaintext value."""
    return (
        key.endswith("_arn")
        and SECRETS_MANAGER_ARN_RE.fullmatch(value) is not None
        and SECRET_STRING_RE.search(value) is None
    )


# RDS-managed master-user secret metadata on aws_db_instance. These attributes
# name a secret or its KMS key; they are not credentials. Each is accepted only
# at its exact path, on that resource type, with a value of its expected shape.
MANAGED_SECRET_STATUSES = frozenset({"creating", "active", "rotating", "impaired"})
_KMS_KEY_UUID = r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})"
KMS_KEY_REFERENCE_RE = re.compile(
    rf"{_KMS_KEY_UUID}|arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{{12}}:key/{_KMS_KEY_UUID}"
)
_RESOURCE_ATTRIBUTE_CONTAINERS = frozenset({"values", "before", "after"})


def _managed_rds_secret_attribute(
    resource_type: str | None, path: tuple[str, ...], key: str, value: str
) -> bool:
    """Accept aws_db_instance.master_user_secret_kms_key_id and
    master_user_secret[<index>].secret_status, nothing else."""
    if resource_type != "aws_db_instance" or not path:
        return False
    if key == "master_user_secret_kms_key_id":
        return (
            path[-1] in _RESOURCE_ATTRIBUTE_CONTAINERS
            and KMS_KEY_REFERENCE_RE.fullmatch(value) is not None
        )
    return (
        key == "secret_status"
        and value in MANAGED_SECRET_STATUSES
        and len(path) >= 3
        and path[-3] in _RESOURCE_ATTRIBUTE_CONTAINERS
        and path[-2] == "master_user_secret"
        and path[-1].isdigit()
    )


def _invalid_sensitive_marker_path(
    value: Any, path: tuple[str, ...], *, list_element: bool = False
) -> PlanSecretFinding | None:
    """Allow true markers and false list placeholders, never secret values."""
    if isinstance(value, dict):
        for key, child in value.items():
            found = _invalid_sensitive_marker_path(child, path + (str(key),))
            if found:
                return found
        return None
    if isinstance(value, list):
        for index, child in enumerate(value):
            found = _invalid_sensitive_marker_path(child, path + (str(index),), list_element=True)
            if found:
                return found
        return None
    # OpenTofu retains false entries in arrays to preserve indices, but omits
    # false entries from objects/maps. All other scalar marker values are invalid.
    return None if value is True or (list_element and value is False) else PlanSecretFinding(
        path, _json_type(value), "invalid_sensitivity_marker"
    )


def classify_plan_secret(
    value: Any, path: tuple[str, ...] = (), resource_type: str | None = None
) -> PlanSecretFinding | None:
    """Classify JSON primitives by type; never mistake booleans for strings."""
    if _sensitive_string(value):
        return PlanSecretFinding(path, "string", "secret_pattern_string")
    if isinstance(value, dict):
        if isinstance(value.get("address"), str) and isinstance(value.get("type"), str):
            resource_type = value["type"]
        if value.get("sensitive") is True:
            marked_value = value.get("value")
            if (isinstance(marked_value, str) and bool(marked_value)) or type(marked_value) in (int, float):
                return PlanSecretFinding(
                    path + ("value",), _json_type(marked_value), "marked_sensitive_primitive"
                )
            if isinstance(marked_value, (dict, list)) and marked_value:
                return PlanSecretFinding(
                    path + ("value",), _json_type(marked_value), "marked_sensitive_structure"
                )
        for key, child in value.items():
            key_text = str(key)
            child_path = path + (key_text,)
            if key_text == "after_unknown":
                continue
            if key_text in SENSITIVE_MARKER_KEYS:
                # A whole before/after value can be non-sensitive (for example,
                # the null "before" side of a create), which OpenTofu emits as false.
                if key_text in {"before_sensitive", "after_sensitive"} and child is False:
                    continue
                found = _invalid_sensitive_marker_path(child, child_path)
                if found:
                    return found
                continue
            if isinstance(child, str) and _sensitive_string(
                child, secret_key=bool(SECRET_VALUE_KEY_RE.search(key_text))
            ) and not _secret_arn_reference(key_text, child) and not _managed_rds_secret_attribute(resource_type, path, key_text, child):
                return PlanSecretFinding(child_path, "string", "sensitive_key_string" if SECRET_VALUE_KEY_RE.search(key_text) else "secret_pattern_string")
            if type(child) in (int, float) and SECRET_VALUE_KEY_RE.search(key_text):
                return PlanSecretFinding(child_path, "number", "sensitive_key_number")
            found = classify_plan_secret(child, child_path, resource_type)
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = classify_plan_secret(child, path + (str(index),), resource_type)
            if found:
                return found
    return None


def known_plaintext_secret_path(value: Any, path: tuple[str, ...] = ()) -> str | None:
    finding = classify_plan_secret(value, path)
    return ".".join(finding.path) if finding else None


_PLAN_STRUCTURE_SEGMENTS = {
    "planned_values", "prior_state", "root_module", "child_modules", "resources",
    "resource_changes", "resource_drift", "change", "values", "before", "after",
    "before_sensitive", "after_sensitive", "sensitive_values", "after_unknown",
    "variables", "value", "output_changes", "outputs",
}
_SAFE_DIAGNOSTIC_SEGMENT = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_ARRAY_INDEX = re.compile(r"[0-9]{1,8}\Z")
_SAFE_RESOURCE_ADDRESS = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*(?:\[[0-9]+\])?\Z")


def _safe_diagnostic_path(path: tuple[str, ...]) -> str:
    # Plan map keys can be user-controlled. Never place arbitrary keys in logs or artifacts.
    return ".".join(
        segment if segment in _PLAN_STRUCTURE_SEGMENTS or _ARRAY_INDEX.fullmatch(segment)
        else f"<key-sha256:{hashlib.sha256(segment.encode()).hexdigest()[:16]}>"
        for segment in path
    )


def _resource_context(doc: Any, path: tuple[str, ...]) -> tuple[str | None, str | None]:
    node = doc
    context: tuple[str | None, str | None] = (None, None)
    for segment in path:
        if isinstance(node, dict) and "address" in node and "type" in node:
            address, resource_type = node.get("address"), node.get("type")
            safe_type = resource_type if isinstance(resource_type, str) and _SAFE_DIAGNOSTIC_SEGMENT.fullmatch(resource_type) else None
            safe_address = None
            if safe_type and isinstance(address, str) and _SAFE_RESOURCE_ADDRESS.fullmatch(address) and address.startswith(safe_type + "."):
                suffix = address[len(safe_type) + 1:]
                safe_address = safe_type + ".<name-sha256:" + hashlib.sha256(suffix.encode()).hexdigest()[:16] + ">"
            context = (
                safe_address,
                safe_type,
            )
        if isinstance(node, dict):
            node = node.get(segment)
        elif isinstance(node, list) and segment.isdigit() and int(segment) < len(node):
            node = node[int(segment)]
        else:
            break
    return context


def _write_plan_diagnostic(path: Path | None, doc: Any, finding: PlanSecretFinding) -> None:
    if path is None:
        return
    address, resource_type = _resource_context(doc, finding.path)
    diagnostic = {
        "schema_version": 1,
        "path": _safe_diagnostic_path(finding.path),
        "json_type": finding.json_type,
        "reason": finding.reason,
        "resource_address": address,
        "resource_type": resource_type,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(diagnostic, handle, sort_keys=True)
        handle.write("\n")


def _decode_container_definitions(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            die("ECS task definition container definitions are not valid JSON")
    else:
        parsed = value
    if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
        die("ECS task definition container definitions are invalid")
    return parsed


def _without_image(container: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in container.items() if key not in {"image", "imageDigest", "image_digest"}}


def _normalize_environment(shape: dict[str, Any]) -> dict[str, Any]:
    """Return `shape` with its "environment" list (if present) sorted by name.

    The "environment" list is order-independent -- ECS treats it as a set of
    name/value pairs, and OpenTofu's plan JSON re-serializes it in a
    provider-normalized (alphabetical-by-name) order that does not match the
    order container definitions are written in Terraform source, or the order
    the hardcoded per-family baseline lists them in. Sorting both sides the
    same way (keyed by name, the field these entries are always keyed by)
    means two container definitions that differ only in environment-entry
    order are correctly treated as identical, instead of failing closed on a
    cosmetic reordering. Every other field is still compared exactly as-is."""
    environment = shape.get("environment")
    if isinstance(environment, list) and all(isinstance(item, dict) for item in environment):
        shape = dict(shape)
        shape["environment"] = sorted(environment, key=lambda item: str(item.get("name", "")))
    return shape


_EMPTY_OPTIONAL_TASK_FIELDS = {
    "ephemeral_storage",
    "placement_constraints",
    "proxy_configuration",
    "runtime_platform",
    "volume",
}

_ORDER_INSENSITIVE_CONTAINER_LISTS = {
    "dependsOn",
    "environment",
    "environmentFiles",
    "extraHosts",
    "mountPoints",
    "portMappings",
    "secrets",
    "systemControls",
    "ulimits",
    "volumesFrom",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _normalize_task_field(field: str, value: Any) -> Any:
    if field in _EMPTY_OPTIONAL_TASK_FIELDS and value in (None, ""):
        return []
    if field == "requires_compatibilities" and isinstance(value, list):
        return sorted(value, key=str)
    return value


def _normalize_container_shape(shape: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(shape)
    for key in _ORDER_INSENSITIVE_CONTAINER_LISTS:
        if key not in normalized:
            continue
        value = normalized.get(key)
        if value in (None, ""):
            normalized[key] = []
        elif isinstance(value, list):
            normalized[key] = sorted(value, key=_canonical_json)
    return _normalize_environment(normalized)


def _container_base(container: dict[str, Any]) -> dict[str, Any]:
    """Container definition stripped of image and secrets fields for structural comparison."""
    base = {
        key: value
        for key, value in container.items()
        if key not in {"image", "imageDigest", "image_digest", "secrets"}
    }
    return _normalize_container_shape(base)


def _secrets_superset_ok(before_container: dict[str, Any], after_container: dict[str, Any]) -> bool:
    """Return True iff after_secrets is a superset of before_secrets and every new secret's
    valueFrom resolves to the approved runtime Secrets Manager entry."""
    before_secrets: list[dict[str, Any]] = before_container.get("secrets") or []
    after_secrets: list[dict[str, Any]] = after_container.get("secrets") or []
    before_map = {str(s.get("name", "")): s for s in before_secrets}
    after_map = {str(s.get("name", "")): s for s in after_secrets}
    # Every pre-existing secret must be present and unchanged.
    for name, before_entry in before_map.items():
        if after_map.get(name) != before_entry:
            return False
    # Every new secret must point at the approved runtime ARN.
    for name, after_entry in after_map.items():
        if name not in before_map:
            value_from = str(after_entry.get("valueFrom", ""))
            if not value_from.startswith(RUNTIME_SECRET_ARN_PREFIX):
                return False
    return True


def _empty_string_equivalent(value: Any) -> Any:
    return None if value == "" else value


def _authorized_image_sha(args: argparse.Namespace | None, variables: dict[str, Any]) -> str | None:
    if args is not None and getattr(args, "expected_sha", ""):
        return args.expected_sha
    value = variables.get("image_tag")
    return value if isinstance(value, str) and SHA.fullmatch(value) else None


def _parse_image_digest_map(raw: str) -> dict[str, str] | None:
    """Parse and strictly validate the repository -> digest evidence map. Real Terraform
    ECS container_definitions never carry a resolved digest of their own -- this is
    independently verified evidence the operator attaches to the authorization, not
    something derived from or checked against the plan JSON. Returns None if the input is
    empty, malformed, has duplicate/extra/missing keys, or any non-exact-digest value --
    there is no partial-credit path."""
    if not raw:
        return None

    def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                raise ValueError(f"duplicate key: {key}")
            seen.add(key)
            result[key] = value
        return result

    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    if set(parsed.keys()) != APPROVED_ECR_REPOSITORIES:
        return None
    for value in parsed.values():
        if not isinstance(value, str) or not IMAGE_DIGEST.fullmatch(value):
            return None
    return parsed


def _image_has_authorized_digest(repository: str, digest_map: dict[str, str] | None) -> bool:
    """True if no digest evidence was required for this authorization (digest_map is None),
    or if repository-scoped digest evidence for this exact repository was supplied. Once
    digest_map is not None it is already guaranteed (by _parse_image_digest_map) to carry
    both approved repositories -- an absent/missing entry can only mean repository itself
    is not one of the two approved repositories, which the caller rejects independently."""
    if digest_map is None:
        return True
    return repository in digest_map


def _image_has_authorized_digest_legacy(container: dict[str, Any], args: argparse.Namespace | None) -> bool:
    """Deprecated: the original container-embedded-digest check, kept only so a caller
    still using the legacy scalar --image-digest input does not regress. Real Terraform
    ECS container_definitions do not carry an imageDigest field, so this check is
    effectively inert against real plans -- it is retained purely for input-contract
    backward compatibility during the staged rollout of image_digest_map, not because it
    is an effective verification. New callers must use image_digest_map."""
    if args is None or not getattr(args, "image_digest", ""):
        return True
    digest = str(container.get("imageDigest") or container.get("image_digest") or "")
    if not digest:
        return False
    return digest == args.image_digest


def _is_approved_baseline_container(
    container: dict[str, Any],
    expected: dict[str, Any],
    authorized_sha: str,
    ecr_repository: str,
    digest_map: dict[str, str],
) -> bool:
    """Exact match against one family's approved container baseline. Every field the
    baseline does not explicitly name is, by construction of the equality check, an
    "unexpected field" that fails closed -- there is no separate allowlist to keep in
    sync, and no sidecar sneaks in because container COUNT is checked by the caller."""
    actual_shape = _container_base(container)  # strips image/imageDigest/image_digest/secrets
    expected_shape = _normalize_environment(
        {key: value for key, value in expected.items() if key != "secret_keys"}
    )
    if actual_shape != expected_shape:
        return False

    image = str(container.get("image", ""))
    if not image.startswith(f"918870682888.dkr.ecr.{AWS_REGION}.amazonaws.com/{ecr_repository}:"):
        return False
    if not image.endswith(f":{authorized_sha}"):
        return False
    # Digest evidence is mandatory for this path and is bound by repository, not read from
    # the container -- see _parse_image_digest_map / _is_approved_new_staging_task_definition.
    if not _image_has_authorized_digest(ecr_repository, digest_map):
        return False

    secrets = container.get("secrets") or []
    actual_keys = {str(s.get("name", "")) for s in secrets}
    if actual_keys != expected["secret_keys"]:
        return False
    for secret in secrets:
        name = str(secret.get("name", ""))
        value_from = str(secret.get("valueFrom", ""))
        if value_from != f"{EXACT_RUNTIME_SECRET_ARN}:{name}::":
            return False
    return True


def _is_approved_new_staging_task_definition(
    after: dict[str, Any], authorized_sha: str | None, args: argparse.Namespace | None
) -> bool:
    """Fail-closed approval path for an aws_ecs_task_definition create with NO prior
    Terraform-tracked state to diff against -- for example, a governed revision that
    supersedes one created manually, out-of-band, outside this pipeline. Because there is
    no "before" to compare, every field (task-level and per-container) is checked against
    an exact, per-family approved baseline instead of "unchanged from before"."""
    if authorized_sha is None:
        return False
    family = after.get("family")
    if family not in APPROVED_FIELDZILLA_TASK_FAMILIES:
        return False

    # The exception requires an explicit, complete run authorization for every approved
    # family -- an empty or partial ecs_families input must never authorize it.
    if args is None or not getattr(args, "ecs_families", ""):
        return False
    if set(args.ecs_families.split(",")) != APPROVED_FIELDZILLA_TASK_FAMILIES:
        return False
    # Digest evidence is mandatory for this path: Terraform's plan JSON never carries a
    # resolved digest on its own, so the operator must supply independently verified,
    # exact per-repository ECR digest evidence up front. Missing, malformed, or incomplete
    # evidence is always rejected -- there is no fallback to "no digest required" here.
    digest_map = _parse_image_digest_map(getattr(args, "image_digest_map", "") or "")
    if digest_map is None:
        return False

    baseline = FIELDZILLA_TASK_DEFINITION_BASELINE[family]
    for field in ("cpu", "memory", "execution_role_arn", "task_role_arn", "network_mode",
                  "requires_compatibilities", "runtime_platform", "volume",
                  "placement_constraints", "proxy_configuration", "ephemeral_storage"):
        if _normalize_task_field(field, after.get(field)) != _normalize_task_field(field, baseline[field]):
            return False

    containers = _decode_container_definitions(after.get("container_definitions"))
    if len(containers) != 1:
        return False
    ecr_repository = baseline["ecr_repository"]
    if FAMILY_ECR_REPOSITORY.get(family) != ecr_repository:
        return False
    return _is_approved_baseline_container(containers[0], baseline["container"], authorized_sha, ecr_repository, digest_map)


def is_approved_ecs_task_definition_revision(
    change: dict[str, Any], variables: dict[str, Any], args: argparse.Namespace | None = None
) -> bool:
    if change.get("type") != "aws_ecs_task_definition":
        return False
    address = change.get("address", "")
    if not address.startswith("aws_ecs_task_definition.") or '"staging"' not in address:
        return False
    actions = change.get("change", {}).get("actions", [])

    authorized_sha = _authorized_image_sha(args, variables)
    if variables.get("image_tag") != authorized_sha:
        return False

    if actions == ["create"]:
        before = change.get("change", {}).get("before")
        after = change.get("change", {}).get("after")
        # A pure create means Terraform has no prior state for this address at all -- there
        # is nothing safe to diff "unchanged" fields against, so this is intentionally the
        # most conservative path: see _is_approved_new_staging_task_definition.
        if before is not None:
            return False
        if not isinstance(after, dict):
            return False
        return _is_approved_new_staging_task_definition(after, authorized_sha, args)

    if actions not in (["delete"], ["delete", "create"], ["create", "delete"]):
        return False

    before = change.get("change", {}).get("before")
    after = change.get("change", {}).get("after")
    if not isinstance(before, dict):
        return False

    if before.get("family") not in APPROVED_FIELDZILLA_TASK_FAMILIES:
        return False

    if actions == ["delete"]:
        before_containers = _decode_container_definitions(before.get("container_definitions"))
        return all(
            str(container.get("image", "")).startswith("918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/")
            for container in before_containers
        )

    if not isinstance(after, dict):
        return False

    if after.get("family") != before.get("family"):
        return False

    immutable_fields = {
        "cpu",
        "execution_role_arn",
        "family",
        "ipc_mode",
        "memory",
        "network_mode",
        "pid_mode",
        "requires_compatibilities",
        "runtime_platform",
        "task_role_arn",
        "track_latest",
        "volume",
    }
    for field in immutable_fields:
        before_value = _normalize_task_field(field, _empty_string_equivalent(before.get(field)))
        after_value = _normalize_task_field(field, _empty_string_equivalent(after.get(field)))
        if before_value != after_value:
            return False

    before_containers = _decode_container_definitions(before.get("container_definitions"))
    after_containers = _decode_container_definitions(after.get("container_definitions"))
    if len(before_containers) != len(after_containers):
        return False

    for before_container, after_container in zip(before_containers, after_containers, strict=True):
        if _container_base(before_container) != _container_base(after_container):
            return False
        if not _secrets_superset_ok(before_container, after_container):
            return False
        before_image = str(before_container.get("image", ""))
        after_image = str(after_container.get("image", ""))
        if not before_image.startswith("918870682888.dkr.ecr.ap-south-1.amazonaws.com/synergie/fieldzilla/staging/"):
            return False
        repository = FAMILY_ECR_REPOSITORY.get(before.get("family"))
        if repository is None or not after_image.startswith(
            f"918870682888.dkr.ecr.{AWS_REGION}.amazonaws.com/{repository}:"
        ):
            return False
        if not after_image.endswith(f":{authorized_sha}"):
            return False
        # Digest evidence is opt-in for this path (only required when the caller supplied
        # image_digest_map or the deprecated image_digest at all -- e.g. a routine
        # single-family rollout). image_digest_map is bound by repository, not read from
        # the container, since real plan JSON never carries a resolved digest of its own;
        # image_digest is the deprecated legacy form, kept only for caller compatibility
        # during the staged rollout of image_digest_map.
        if getattr(args, "image_digest_map", ""):
            digest_map = _parse_image_digest_map(args.image_digest_map)
            if digest_map is None:
                return False
            if not _image_has_authorized_digest(repository, digest_map):
                return False
        elif getattr(args, "image_digest", ""):
            if not _image_has_authorized_digest_legacy(after_container, args):
                return False

    return True


def is_approved_ecs_service_update(
    change: dict[str, Any], approved_task_definition_addresses: set[str] | None = None
) -> bool:
    if change.get("type") != "aws_ecs_service":
        return False
    if '"staging"' not in change.get("address", ""):
        return False
    if change.get("change", {}).get("actions") != ["update"]:
        return False
    before = change.get("change", {}).get("before")
    after = change.get("change", {}).get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    changed = {key for key in set(before) | set(after) if before.get(key) != after.get(key)}
    if changed != {"task_definition"}:
        return False

    if change.get("change", {}).get("after_unknown", {}).get("task_definition") is True:
        # The new task-definition ARN is unknown until apply (e.g. the service points at a
        # task definition being created/replaced in the SAME plan). This is only approved
        # when that exact task-definition resource_changes entry -- matched by Terraform
        # address, not a generic expression/reference parse -- is itself independently
        # approved in this same plan; there is no other evidence to check an unknown value
        # against, and an unmatched or missing address is always rejected.
        if not approved_task_definition_addresses:
            return False
        match = re.match(r'^aws_ecs_service\.([^.\[]+)(\[.*\])?$', change.get("address", ""))
        if not match:
            return False
        name, key = match.group(1), match.group(2) or ""
        return f"aws_ecs_task_definition.{name}{key}" in approved_task_definition_addresses

    task_definition = str(after.get("task_definition", ""))
    return any(f":task-definition/{family}:" in task_definition for family in APPROVED_FIELDZILLA_TASK_FAMILIES)


def verify_import_map(args: argparse.Namespace) -> None:
    if sha256_file(args.import_map_path) != args.expected_import_map_sha256:
        die("import map SHA-256 mismatch")
    doc = json.loads(args.import_map_path.read_text(encoding="utf-8"))
    if doc.get("repository") != REPOSITORY or doc.get("environment") != ENVIRONMENT:
        die("import map target mismatch")
    imports = doc.get("imports")
    if not isinstance(imports, list) or not imports:
        die("import map is empty")
    seen: set[str] = set()
    for item in imports:
        address = item.get("address")
        resource_id = item.get("id")
        evidence = item.get("evidence")
        if not isinstance(address, str) or not isinstance(resource_id, str):
            die("import map entry missing address or id")
        if address in seen:
            die("duplicate import address")
        seen.add(address)
        rtype = address.split(".", 1)[0]
        if rtype not in ALLOWED_IMPORT_TYPES:
            die(f"unsupported import type {rtype}")
        if not isinstance(evidence, dict) or evidence.get("Application") != "fieldzilla":
            die("import evidence must prove FieldZilla ownership")
        if evidence.get("Repository") != REPOSITORY:
            die("import evidence repository mismatch")
    print(f"IMPORT_COUNT={len(imports)}")


def github_api(path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    cmd = ["gh", "api", f"repos/{REPOSITORY}/{path}", "--method", method]
    if payload is not None:
        cmd.extend(["--input", "-"])
    result = subprocess.run(
        cmd,
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        die("GitHub authorization state is unavailable")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def deployment_payload(args: argparse.Namespace) -> dict[str, str]:
    return {
        "authorization_id": args.authorization_id,
        "environment": ENVIRONMENT,
        "repository_id": str(REPOSITORY_ID),
        "commit_sha": args.expected_sha,
        "plan_sha256": args.expected_plan_sha256 or "",
        "image_digest_map": _parse_image_digest_map(getattr(args, "image_digest_map", "") or ""),
        "image_digest": getattr(args, "image_digest", ""),  # deprecated legacy single-digest form
        "ecs_families": getattr(args, "ecs_families", ""),
        "import_map_sha256": args.expected_import_map_sha256 or "",
        "source_run_id": getattr(args, "source_run_id", ""),
        "artifact_id": getattr(args, "artifact_id", ""),
        "artifact_name": getattr(args, "artifact_name", ""),
    }


def check_single_use(args: argparse.Namespace) -> None:
    deployments = github_api(
        f"deployments?environment={ENVIRONMENT}&ref={args.expected_sha}&task=fieldzilla-staging-opentofu-remote-state&per_page=100"
    )
    for deployment in deployments:
        payload = deployment.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}
        if isinstance(payload, dict) and payload.get("authorization_id") == args.authorization_id:
            die("authorization has already been used")


def mark_used(args: argparse.Namespace) -> None:
    check_single_use(args)
    github_api(
        "deployments",
        method="POST",
        payload={
            "ref": args.expected_sha,
            "task": "fieldzilla-staging-opentofu-remote-state",
            "environment": ENVIRONMENT,
            "description": "Single-use FieldZilla staging remote-state authorization marker",
            "auto_merge": False,
            "required_contexts": [],
            "payload": deployment_payload(args),
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--actor", required=True)
        target.add_argument("--repository", required=True)
        target.add_argument("--repository-id", type=int, default=REPOSITORY_ID)
        target.add_argument("--environment", required=True)
        target.add_argument("--expected-sha", required=True)
        target.add_argument("--expected-caller-sha", required=True)
        target.add_argument("--github-sha", required=True)
        target.add_argument("--expected-plan-sha256", default="")
        target.add_argument("--expected-import-map-sha256", default="")
        target.add_argument("--image-digest", default="")
        target.add_argument("--image-digest-map", default="")
        target.add_argument("--ecs-families", default="")
        target.add_argument("--expires-at", required=True)
        target.add_argument("--authorization-id", required=True)
        target.add_argument("--native-reviewers-available", required=True)
        target.add_argument("--job-workflow-ref", required=True)

    common_commands = ("verify-inputs", "check-single-use", "mark-used")
    for name in common_commands:
        add_common(sub.add_parser(name))
    caller = sub.add_parser("verify-caller-sha")
    caller.add_argument("--github-sha", required=True)
    caller.add_argument("--expected-caller-sha", required=True)
    oidc = sub.add_parser("verify-oidc")
    oidc.add_argument("--token-file", type=Path, required=True)
    oidc.add_argument("--job-workflow-ref", required=True)
    native = sub.add_parser("verify-native-reviewers")
    native.add_argument("--native-reviewers-available", required=True)
    backend = sub.add_parser("verify-backend")
    backend.add_argument("--backend-metadata-path", type=Path, required=True)
    backend.add_argument("--expected-state-key", default="")
    source = sub.add_parser("verify-source-artifact")
    add_common(source)
    source.add_argument("--source-run-id", required=True)
    source.add_argument("--artifact-id", required=True)
    source.add_argument("--artifact-name", required=True)
    source.add_argument("--expected-artifact-digest", required=True)
    meta = sub.add_parser("verify-artifact-metadata")
    meta.add_argument("--artifact-dir", type=Path, required=True)
    meta.add_argument("--expected-sha", required=True)
    meta.add_argument("--expected-caller-sha", required=True)
    meta.add_argument("--expected-plan-sha256", default="")
    meta.add_argument("--expected-import-map-sha256", default="")
    meta.add_argument("--image-digest", default="")
    meta.add_argument("--image-digest-map", default="")
    meta.add_argument("--ecs-families", default="")
    meta.add_argument("--source-run-id", required=True)
    meta.add_argument("--artifact-id", required=True)
    meta.add_argument("--artifact-name", required=True)
    meta.add_argument("--expected-artifact-digest", required=True)
    meta.add_argument("--expected-state-key", default="")
    files = sub.add_parser("verify-artifact-files")
    files.add_argument("--artifact-dir", type=Path, required=True)
    safety = sub.add_parser("verify-plan-safety")
    safety.add_argument("--plan-json-path", type=Path, required=True)
    safety.add_argument("--plan-kind", default="normal")
    safety.add_argument("--expected-sha", default="")
    safety.add_argument("--repository", default="")
    safety.add_argument("--environment", default="")
    safety.add_argument("--image-digest", default="")
    safety.add_argument("--image-digest-map", default="")
    safety.add_argument("--ecs-families", default="")
    capture = sub.add_parser("verify-plan-capture")
    capture.add_argument("--plan-json-path", type=Path, required=True)
    capture.add_argument("--expected-sha", required=True)
    capture.add_argument("--repository", required=True)
    capture.add_argument("--environment", required=True)
    capture.add_argument("--diagnostic-path", type=Path)
    imports = sub.add_parser("verify-import-map")
    imports.add_argument("--import-map-path", type=Path, required=True)
    imports.add_argument("--expected-import-map-sha256", required=True)

    args = parser.parse_args()
    dispatch = {
        "verify-inputs": verify_inputs,
        "verify-caller-sha": verify_caller_sha,
        "verify-oidc": verify_oidc,
        "verify-native-reviewers": verify_native_reviewers,
        "verify-backend": verify_backend,
        "verify-source-artifact": verify_source_artifact,
        "verify-artifact-metadata": verify_artifact_metadata,
        "verify-artifact-files": verify_artifact_files,
        "verify-plan-safety": verify_plan_safety,
        "verify-plan-capture": verify_plan_capture,
        "verify-import-map": verify_import_map,
        "check-single-use": check_single_use,
        "mark-used": mark_used,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
