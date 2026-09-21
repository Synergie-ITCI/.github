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
from typing import Any

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
SECRET_VALUE_KEY_RE = re.compile(
    r"(activation[_-]?code|password|passwd|secret|token|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
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


def _known_plaintext_value(value: Any) -> bool:
    return value not in (None, "", [], {})


def known_plaintext_secret_path(value: Any, path: tuple[str, ...] = ()) -> str | None:
    if isinstance(value, dict):
        if value.get("sensitive") is True and "value" in value and _known_plaintext_value(value.get("value")):
            return ".".join(path + ("value",))
        for key, child in value.items():
            key_text = str(key)
            child_path = path + (key_text,)
            if key_text == "after_unknown":
                continue
            if SECRET_VALUE_KEY_RE.search(key_text) and not isinstance(child, (dict, list)):
                if _known_plaintext_value(child):
                    return ".".join(child_path)
                continue
            found = known_plaintext_secret_path(child, child_path)
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = known_plaintext_secret_path(child, path + (str(index),))
            if found:
                return found
    return None


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
    safety.add_argument("--image-digest", default="")
    safety.add_argument("--image-digest-map", default="")
    safety.add_argument("--ecs-families", default="")
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
        "verify-import-map": verify_import_map,
        "check-single-use": check_single_use,
        "mark-used": mark_used,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
