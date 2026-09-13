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
ENVIRONMENT = "synergie-app-staging"
CENTRAL_REPOSITORY = "Synergie-ITCI/.github"
WORKFLOW_PATH = ".github/workflows/fieldzilla-staging-opentofu-apply.yml"
CALLER_WORKFLOW_PATH = ".github/workflows/fieldzilla-staging-iac.yml"
AWS_ACCOUNT = "918870682888"
AWS_REGION = "ap-south-1"
STATE_BUCKET = "synergie-fieldzilla-opentofu-state-918870682888-ap-south-1"
STATE_LOCK_TABLE = "synergie-fieldzilla-opentofu-locks"
STATE_KEY = "programme-management-platform/fieldzilla/staging/opentofu.tfstate"
MAX_EXPIRY_MINUTES = 60

AUTH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{7,79}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
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
    if args.github_sha != args.expected_sha:
        die("workflow commit SHA does not match approved SHA")
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
    expected = {
        "account_id": AWS_ACCOUNT,
        "region": AWS_REGION,
        "bucket": STATE_BUCKET,
        "key": STATE_KEY,
        "dynamodb_table": STATE_LOCK_TABLE,
        "bucket_versioning": "Enabled",
        "bucket_encryption": "aws:kms",
        "public_access_blocked": True,
    }
    for key, value in expected.items():
        if doc.get(key) != value:
            die(f"remote backend evidence mismatch for {key}")
    print("REMOTE_BACKEND_VERIFIED=true")


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


def verify_source_artifact(args: argparse.Namespace) -> None:
    _require_artifact_inputs(args)
    run = github_api(f"actions/runs/{args.source_run_id}")
    if run.get("head_repository", {}).get("full_name") != REPOSITORY:
        die("source run repository mismatch")
    if run.get("head_sha") != args.expected_sha:
        die("source run commit mismatch")
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
    checks = {
        "repository": REPOSITORY,
        "commit_sha": args.expected_sha,
        "workflow_run_id": args.source_run_id,
        "artifact_name": args.artifact_name,
        "environment": ENVIRONMENT,
        "state_backend": "s3",
        "state_bucket": STATE_BUCKET,
        "state_key": STATE_KEY,
        "lock_table": STATE_LOCK_TABLE,
    }
    for key, expected in checks.items():
        if str(metadata.get(key, "")) != expected:
            die(f"artifact metadata {key} mismatch")
    if args.expected_plan_sha256:
        plan_path = args.artifact_dir / "fieldzilla-staging.tfplan"
        if not plan_path.is_file() or sha256_file(plan_path) != args.expected_plan_sha256:
            die("downloaded OpenTofu plan hash mismatch")
    if args.expected_import_map_sha256:
        import_path = args.artifact_dir / "import-map.json"
        if not import_path.is_file() or sha256_file(import_path) != args.expected_import_map_sha256:
            die("downloaded import map hash mismatch")


def verify_plan_safety(args: argparse.Namespace) -> None:
    doc = json.loads(args.plan_json_path.read_text(encoding="utf-8"))
    variables = {key: item.get("value") for key, item in doc.get("variables", {}).items()}
    if variables.get("enable_production") is not False:
        die("production resources are enabled")
    if variables.get("route53_zone_id") not in ("", None):
        die("DNS changes are enabled")
    if variables.get("container_instance_type") != "t4g.small":
        die("container host size is outside approved design")
    if str(variables.get("monthly_budget_usd")) != "100":
        die("monthly budget guardrail mismatch")

    counts: dict[str, int] = {}
    for change in doc.get("resource_changes", []):
        actions = change.get("change", {}).get("actions", [])
        key = ",".join(actions)
        counts[key] = counts.get(key, 0) + 1
        address = change.get("address", "")
        rtype = change.get("type", "")
        if "delete" in actions or actions in (["create", "delete"], ["delete", "create"]):
            die("plan contains destructive actions")
        if "route53" in rtype.lower() or "route53" in address.lower():
            die("plan contains DNS resources")
        after = json.dumps(change.get("change", {}).get("after", {}), sort_keys=True).lower()
        if "production" in address.lower() or '"environment": "production"' in after:
            die("plan contains production resources")
    if args.plan_kind == "drift" and counts not in ({}, {"no-op": len(doc.get("resource_changes", []))}):
        die("drift plan is not clean")
    print("PLAN_COUNTS=" + json.dumps(counts, sort_keys=True))


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
        "commit_sha": args.expected_sha,
        "plan_sha256": args.expected_plan_sha256 or "",
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
        target.add_argument("--environment", required=True)
        target.add_argument("--expected-sha", required=True)
        target.add_argument("--github-sha", required=True)
        target.add_argument("--expected-plan-sha256", default="")
        target.add_argument("--expected-import-map-sha256", default="")
        target.add_argument("--expires-at", required=True)
        target.add_argument("--authorization-id", required=True)
        target.add_argument("--native-reviewers-available", required=True)
        target.add_argument("--job-workflow-ref", required=True)

    common_commands = ("verify-inputs", "check-single-use", "mark-used")
    for name in common_commands:
        add_common(sub.add_parser(name))
    oidc = sub.add_parser("verify-oidc")
    oidc.add_argument("--token-file", type=Path, required=True)
    oidc.add_argument("--job-workflow-ref", required=True)
    native = sub.add_parser("verify-native-reviewers")
    native.add_argument("--native-reviewers-available", required=True)
    backend = sub.add_parser("verify-backend")
    backend.add_argument("--backend-metadata-path", type=Path, required=True)
    source = sub.add_parser("verify-source-artifact")
    add_common(source)
    source.add_argument("--source-run-id", required=True)
    source.add_argument("--artifact-id", required=True)
    source.add_argument("--artifact-name", required=True)
    source.add_argument("--expected-artifact-digest", required=True)
    meta = sub.add_parser("verify-artifact-metadata")
    meta.add_argument("--artifact-dir", type=Path, required=True)
    meta.add_argument("--expected-sha", required=True)
    meta.add_argument("--expected-plan-sha256", default="")
    meta.add_argument("--expected-import-map-sha256", default="")
    meta.add_argument("--source-run-id", required=True)
    meta.add_argument("--artifact-id", required=True)
    meta.add_argument("--artifact-name", required=True)
    meta.add_argument("--expected-artifact-digest", required=True)
    files = sub.add_parser("verify-artifact-files")
    files.add_argument("--artifact-dir", type=Path, required=True)
    safety = sub.add_parser("verify-plan-safety")
    safety.add_argument("--plan-json-path", type=Path, required=True)
    safety.add_argument("--plan-kind", default="normal")
    imports = sub.add_parser("verify-import-map")
    imports.add_argument("--import-map-path", type=Path, required=True)
    imports.add_argument("--expected-import-map-sha256", required=True)

    args = parser.parse_args()
    dispatch = {
        "verify-inputs": verify_inputs,
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
