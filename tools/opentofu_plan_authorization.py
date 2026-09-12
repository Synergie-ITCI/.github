#!/usr/bin/env python3
"""Fail-closed exact-plan authorization checks for governed OpenTofu applies."""

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
MAX_EXPIRY_MINUTES = 60
AUTH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{7,79}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[1-9][0-9]{5,}$")
ARTIFACT_ID = re.compile(r"^[1-9][0-9]*$")
ARTIFACT_NAME = re.compile(r"^fieldzilla-staging-plan-[0-9a-f]{40}-[1-9][0-9]*$")
ARTIFACT_DIGEST = re.compile(r"^(sha256:)?[0-9a-f]{64}$")
TAG_REF = re.compile(
    rf"^{re.escape(CENTRAL_REPOSITORY)}/{re.escape(WORKFLOW_PATH)}"
    r"@refs/tags/pr-qa-v1-rc[1-9][0-9]*$"
)


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
    if not SHA256.fullmatch(args.expected_plan_sha256 or ""):
        die("plan SHA-256 must be exact 64-character lowercase hex")
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
        die("job workflow must be the immutable central FieldZilla apply workflow tag")


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


def verify_plan(args: argparse.Namespace) -> None:
    actual = hashlib.sha256(args.plan_path.read_bytes()).hexdigest()
    if actual != args.expected_plan_sha256:
        die("OpenTofu plan changed after approval")
    print(f"PLAN_SHA256={actual}")


def _normalize_digest(value: str) -> str:
    return value.removeprefix("sha256:")


def _require_artifact_inputs(args: argparse.Namespace) -> None:
    if not RUN_ID.fullmatch(args.source_run_id or ""):
        die("source plan run id is invalid")
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
        die("source plan run repository mismatch")
    if run.get("head_sha") != args.expected_sha:
        die("source plan run commit mismatch")
    if run.get("conclusion") != "success":
        die("source plan run did not succeed")
    if run.get("path") != CALLER_WORKFLOW_PATH:
        die("source plan workflow mismatch")
    if str(run.get("run_attempt", "")) != "1":
        die("source plan run attempt mismatch")

    artifacts = github_api(f"actions/runs/{args.source_run_id}/artifacts?per_page=100")
    matches = [
        artifact
        for artifact in artifacts.get("artifacts", [])
        if str(artifact.get("id")) == args.artifact_id
    ]
    if len(matches) != 1:
        die("approved plan artifact id is unavailable")
    artifact = matches[0]
    if artifact.get("name") != args.artifact_name:
        die("approved plan artifact name mismatch")
    if artifact.get("expired"):
        die("approved plan artifact expired")
    digest = artifact.get("digest")
    if not digest:
        die("approved plan artifact digest is unavailable")
    if _normalize_digest(digest) != _normalize_digest(args.expected_artifact_digest):
        die("approved plan artifact digest mismatch")
    print(f"ARTIFACT_ID={args.artifact_id}")


def verify_artifact_metadata(args: argparse.Namespace) -> None:
    _require_artifact_inputs(args)
    metadata_path = args.artifact_dir / "metadata.json"
    plan_path = args.artifact_dir / "fieldzilla-staging.tfplan"
    if not metadata_path.is_file():
        die("plan artifact metadata is missing")
    if not plan_path.is_file():
        die("binary plan artifact is missing")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    checks = {
        "repository": REPOSITORY,
        "commit_sha": args.expected_sha,
        "workflow_run_id": args.source_run_id,
        "artifact_name": args.artifact_name,
        "environment": ENVIRONMENT,
    }
    for key, expected in checks.items():
        if str(metadata.get(key, "")) != expected:
            die(f"plan artifact metadata {key} mismatch")
    actual = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    if actual != args.expected_plan_sha256:
        die("downloaded OpenTofu plan hash mismatch")
    if metadata.get("plan_sha256") != actual:
        die("plan metadata hash mismatch")
    print(f"PLAN_SHA256={actual}")


def verify_artifact_files(args: argparse.Namespace) -> None:
    allowed = {
        "fieldzilla-staging.tfplan",
        "fieldzilla-staging.plan.txt",
        "fieldzilla-staging.plan.json",
        "metadata.json",
        "SHA256SUMS",
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
        die("plan artifact contains prohibited files")

    secret_patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ASIA[0-9A-Z]{16}"),
        re.compile(r"aws_secret_access_key", re.IGNORECASE),
        re.compile(r"aws_session_token", re.IGNORECASE),
    ]
    for rel in ("fieldzilla-staging.plan.txt", "fieldzilla-staging.plan.json", "metadata.json", "SHA256SUMS"):
        path = args.artifact_dir / rel
        if not path.exists():
            die("plan artifact is incomplete")
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(pattern.search(text) for pattern in secret_patterns):
            die("plan artifact contains prohibited sensitive output")


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
        if "delete" in actions or actions == ["create", "delete"] or actions == ["delete", "create"]:
            die("plan contains destructive actions")
        if "route53" in rtype.lower() or "route53" in address.lower():
            die("plan contains DNS resources")
        haystack = json.dumps(change.get("change", {}).get("after", {}), sort_keys=True).lower()
        if "production" in address.lower() or '"environment": "production"' in haystack:
            die("plan contains production resources")
    print("PLAN_COUNTS=" + json.dumps(counts, sort_keys=True))


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
        die("GitHub deployment authorization state is unavailable")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def deployment_payload(args: argparse.Namespace) -> dict[str, str]:
    return {
        "authorization_id": args.authorization_id,
        "environment": ENVIRONMENT,
        "commit_sha": args.expected_sha,
        "plan_sha256": args.expected_plan_sha256,
        "source_run_id": getattr(args, "source_run_id", ""),
        "artifact_id": getattr(args, "artifact_id", ""),
        "artifact_name": getattr(args, "artifact_name", ""),
    }


def check_single_use(args: argparse.Namespace) -> None:
    deployments = github_api(
        f"deployments?environment={ENVIRONMENT}&ref={args.expected_sha}&task=fieldzilla-staging-opentofu-apply&per_page=100"
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
            "task": "fieldzilla-staging-opentofu-apply",
            "environment": ENVIRONMENT,
            "description": "Single-use FieldZilla staging OpenTofu apply authorization marker",
            "auto_merge": False,
            "required_contexts": [],
            "payload": deployment_payload(args),
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    def common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--actor", required=True)
        target.add_argument("--repository", required=True)
        target.add_argument("--environment", required=True)
        target.add_argument("--expected-sha", required=True)
        target.add_argument("--github-sha", required=True)
        target.add_argument("--expected-plan-sha256", required=True)
        target.add_argument("--expires-at", required=True)
        target.add_argument("--authorization-id", required=True)
        target.add_argument("--native-reviewers-available", required=True)
        target.add_argument("--job-workflow-ref", required=True)

    verify = sub.add_parser("verify-inputs")
    common(verify)
    oidc = sub.add_parser("verify-oidc")
    oidc.add_argument("--token-file", type=Path, required=True)
    oidc.add_argument("--job-workflow-ref", required=True)
    native = sub.add_parser("verify-native-reviewers")
    native.add_argument("--native-reviewers-available", required=True)
    plan = sub.add_parser("verify-plan")
    plan.add_argument("--plan-path", type=Path, required=True)
    plan.add_argument("--expected-plan-sha256", required=True)
    source = sub.add_parser("verify-source-artifact")
    common(source)
    source.add_argument("--source-run-id", required=True)
    source.add_argument("--artifact-id", required=True)
    source.add_argument("--artifact-name", required=True)
    source.add_argument("--expected-artifact-digest", required=True)
    meta = sub.add_parser("verify-artifact-metadata")
    meta.add_argument("--artifact-dir", type=Path, required=True)
    meta.add_argument("--expected-sha", required=True)
    meta.add_argument("--expected-plan-sha256", required=True)
    meta.add_argument("--source-run-id", required=True)
    meta.add_argument("--artifact-id", required=True)
    meta.add_argument("--artifact-name", required=True)
    meta.add_argument("--expected-artifact-digest", required=True)
    files = sub.add_parser("verify-artifact-files")
    files.add_argument("--artifact-dir", type=Path, required=True)
    safety = sub.add_parser("verify-plan-safety")
    safety.add_argument("--plan-json-path", type=Path, required=True)
    single = sub.add_parser("check-single-use")
    common(single)
    mark = sub.add_parser("mark-used")
    common(mark)

    args = parser.parse_args()
    if args.command == "verify-inputs":
        verify_inputs(args)
    elif args.command == "verify-oidc":
        verify_oidc(args)
    elif args.command == "verify-native-reviewers":
        verify_native_reviewers(args)
    elif args.command == "verify-plan":
        verify_plan(args)
    elif args.command == "verify-source-artifact":
        verify_source_artifact(args)
    elif args.command == "verify-artifact-metadata":
        verify_artifact_metadata(args)
    elif args.command == "verify-artifact-files":
        verify_artifact_files(args)
    elif args.command == "verify-plan-safety":
        verify_plan_safety(args)
    elif args.command == "check-single-use":
        check_single_use(args)
    elif args.command == "mark-used":
        mark_used(args)


if __name__ == "__main__":
    main()
