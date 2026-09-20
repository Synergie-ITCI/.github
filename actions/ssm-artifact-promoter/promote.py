#!/usr/bin/env python3
"""Promote a caller-built artifact through an explicit SSM target."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANCE_RE = re.compile(r"^(i|mi)-[0-9a-f]{17}$")
SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+=:-]*$")
SAFE_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


@dataclass(frozen=True)
class PromotionConfig:
    expected_repository: str
    expected_repository_id: str
    expected_environment: str
    aws_region: str
    ssm_instance_id: str
    artifact_bucket: str
    artifact_key: str
    artifact_sha256: str
    remote_script_key: str
    remote_script_sha256: str
    allowed_artifact_prefix: str
    deploy_ref: str
    rollback_ref: str
    app_root: str
    app_user: str
    validation_url: str
    api_health_url: str
    command_timeout_seconds: int
    poll_interval_seconds: int
    poll_attempts: int
    presign_expires_seconds: int
    evidence_path: str


def fail(message: str) -> None:
    raise ValueError(message)


def env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        fail(f"Missing required input {name}")
    return value


def env_int(name: str) -> int:
    value = env(name)
    try:
        parsed = int(value)
    except ValueError:
        fail(f"{name} must be an integer")
    if parsed < 1:
        fail(f"{name} must be positive")
    return parsed


def load_config() -> PromotionConfig:
    return PromotionConfig(
        expected_repository=env("INPUT_EXPECTED_REPOSITORY"),
        expected_repository_id=env("INPUT_EXPECTED_REPOSITORY_ID"),
        expected_environment=env("INPUT_EXPECTED_ENVIRONMENT"),
        aws_region=env("INPUT_AWS_REGION"),
        ssm_instance_id=env("INPUT_SSM_INSTANCE_ID"),
        artifact_bucket=env("INPUT_ARTIFACT_BUCKET"),
        artifact_key=env("INPUT_ARTIFACT_KEY"),
        artifact_sha256=env("INPUT_ARTIFACT_SHA256"),
        remote_script_key=env("INPUT_REMOTE_SCRIPT_KEY"),
        remote_script_sha256=env("INPUT_REMOTE_SCRIPT_SHA256"),
        allowed_artifact_prefix=env("INPUT_ALLOWED_ARTIFACT_PREFIX"),
        deploy_ref=env("INPUT_DEPLOY_REF"),
        rollback_ref=env("INPUT_ROLLBACK_REF"),
        app_root=env("INPUT_APP_ROOT"),
        app_user=env("INPUT_APP_USER"),
        validation_url=env("INPUT_VALIDATION_URL"),
        api_health_url=env("INPUT_API_HEALTH_URL"),
        command_timeout_seconds=env_int("INPUT_COMMAND_TIMEOUT_SECONDS"),
        poll_interval_seconds=env_int("INPUT_POLL_INTERVAL_SECONDS"),
        poll_attempts=env_int("INPUT_POLL_ATTEMPTS"),
        presign_expires_seconds=env_int("INPUT_PRESIGN_EXPIRES_SECONDS"),
        evidence_path=env("INPUT_EVIDENCE_PATH"),
    )


def validate_key(name: str, key: str, prefix: str) -> None:
    if key.startswith("/") or "/../" in f"/{key}/" or key.endswith("/.."):
        fail(f"{name} contains path traversal")
    if not SAFE_KEY_RE.fullmatch(key):
        fail(f"{name} contains unsafe characters")
    if not key.startswith(prefix):
        fail(f"{name} must stay under the allowed artifact prefix")


def validate_url(name: str, value: str) -> None:
    if not value.startswith("https://"):
        fail(f"{name} must be an https URL")
    if any(char in value for char in "\r\n"):
        fail(f"{name} contains a newline")


def validate_config(config: PromotionConfig) -> None:
    if os.environ.get("GITHUB_REPOSITORY") != config.expected_repository:
        fail("Caller repository mismatch")
    if os.environ.get("GITHUB_REPOSITORY_ID") != config.expected_repository_id:
        fail("Caller repository id mismatch")
    if config.expected_environment != "uat":
        fail("This pilot action is restricted to the UAT environment")
    if config.aws_region != "ap-south-1":
        fail("Unexpected AWS region")
    if not INSTANCE_RE.fullmatch(config.ssm_instance_id):
        fail("SSM instance id must be exact")
    if not SHA_RE.fullmatch(config.deploy_ref):
        fail("deploy-ref must be an exact commit SHA")
    if not SHA_RE.fullmatch(config.rollback_ref):
        fail("rollback-ref must be an exact commit SHA")
    if config.deploy_ref == config.rollback_ref:
        fail("deploy-ref must differ from rollback-ref")
    if not SHA256_RE.fullmatch(config.artifact_sha256):
        fail("artifact-sha256 must be exact")
    if not SHA256_RE.fullmatch(config.remote_script_sha256):
        fail("remote-script-sha256 must be exact")
    if not config.allowed_artifact_prefix.endswith("/"):
        fail("allowed-artifact-prefix must end with /")
    validate_key("artifact-key", config.artifact_key, config.allowed_artifact_prefix)
    validate_key("remote-script-key", config.remote_script_key, config.allowed_artifact_prefix)
    if not config.app_root.startswith("/") or "/../" in f"{config.app_root}/":
        fail("app-root must be an absolute safe path")
    if not SAFE_USER_RE.fullmatch(config.app_user):
        fail("app-user must be a safe local user name")
    validate_url("validation-url", config.validation_url)
    validate_url("api-health-url", config.api_health_url)
    if config.command_timeout_seconds > 900:
        fail("command timeout is too large")
    if config.poll_attempts > 180:
        fail("poll-attempts is too large")
    if config.presign_expires_seconds > 3600:
        fail("presign expiry is too large")


def run_json(args: list[str], *, check: bool = True) -> Any:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Command failed: {args[0]}")
    if not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def run_text(args: list[str], *, check: bool = True) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Command failed: {args[0]}")
    return result.stdout.strip()


def presign(bucket: str, key: str, region: str, expires: int) -> str:
    url = run_text([
        "aws", "s3", "presign", f"s3://{bucket}/{key}",
        "--region", region,
        "--expires-in", str(expires),
    ])
    if not url.startswith("https://"):
        fail("Presigned URL was not https")
    print(f"::add-mask::{url}")
    return url


def build_ssm_parameters(config: PromotionConfig, artifact_url: str, script_url: str) -> dict[str, list[str]]:
    values = {
        "APP_ROOT": config.app_root,
        "APP_USER": config.app_user,
        "DEPLOY_REF": config.deploy_ref,
        "ROLLBACK_REF": config.rollback_ref,
        "ARTIFACT_URL": artifact_url,
        "ARTIFACT_SHA256": config.artifact_sha256,
        "VALIDATION_URL": config.validation_url,
        "API_HEALTH_URL": config.api_health_url,
    }
    exports = " ".join(f"{name}={shlex.quote(value)}" for name, value in values.items())
    script_url_q = shlex.quote(script_url)
    script_sha_q = shlex.quote(config.remote_script_sha256)
    commands = [
        "set -eu",
        "umask 077",
        "install_dir=$(mktemp -d /var/tmp/synergie-ssm-artifact.XXXXXX)",
        "trap 'rm -rf \"$install_dir\"' EXIT",
        f"curl --fail --silent --show-error --location --max-time 120 {script_url_q} -o \"$install_dir/deploy.sh\"",
        f"printf '%s  %s\\n' {script_sha_q} \"$install_dir/deploy.sh\" | sha256sum -c -",
        "chmod 600 \"$install_dir/deploy.sh\"",
        f"sudo -u {shlex.quote(config.app_user)} -H env {exports} "
        f"timeout --signal=TERM --kill-after=15s {config.command_timeout_seconds}s "
        "bash -s < \"$install_dir/deploy.sh\"",
    ]
    return {"commands": commands, "executionTimeout": [str(config.command_timeout_seconds + 60)]}


def write_evidence(config: PromotionConfig, command_id: str, status: str, invocation: Any | None) -> None:
    evidence = {
        "repository": config.expected_repository,
        "repository_id": config.expected_repository_id,
        "environment": config.expected_environment,
        "aws_region": config.aws_region,
        "ssm_instance_id": config.ssm_instance_id,
        "deploy_ref": config.deploy_ref,
        "rollback_ref": config.rollback_ref,
        "artifact_bucket": config.artifact_bucket,
        "artifact_key": config.artifact_key,
        "artifact_sha256": config.artifact_sha256,
        "remote_script_key": config.remote_script_key,
        "remote_script_sha256": config.remote_script_sha256,
        "command_id": command_id,
        "status": status,
    }
    if isinstance(invocation, dict):
        evidence["response_code"] = invocation.get("ResponseCode")
    Path(config.evidence_path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def set_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def promote(config: PromotionConfig) -> int:
    validate_config(config)
    artifact_url = presign(config.artifact_bucket, config.artifact_key, config.aws_region, config.presign_expires_seconds)
    script_url = presign(config.artifact_bucket, config.remote_script_key, config.aws_region, config.presign_expires_seconds)
    parameters = build_ssm_parameters(config, artifact_url, script_url)
    comment = f"{config.expected_repository} {config.expected_environment} deploy {config.deploy_ref}"
    command = run_json([
        "aws", "ssm", "send-command",
        "--region", config.aws_region,
        "--instance-ids", config.ssm_instance_id,
        "--document-name", "AWS-RunShellScript",
        "--comment", comment,
        "--parameters", json.dumps(parameters),
        "--query", "Command",
        "--output", "json",
    ])
    command_id = command.get("CommandId")
    if not command_id:
        raise RuntimeError("SSM did not return a command id")
    set_output("command-id", command_id)
    set_output("evidence-path", config.evidence_path)
    print(f"SSM_COMMAND_ID={command_id}")

    status = ""
    invocation = None
    for _ in range(config.poll_attempts):
        invocation = run_json([
            "aws", "ssm", "get-command-invocation",
            "--region", config.aws_region,
            "--command-id", command_id,
            "--instance-id", config.ssm_instance_id,
            "--query", "{Status:Status,ResponseCode:ResponseCode,Stdout:StandardOutputContent,Stderr:StandardErrorContent}",
            "--output", "json",
        ], check=False)
        if isinstance(invocation, dict):
            status = str(invocation.get("Status", ""))
        if status == "Success":
            write_evidence(config, command_id, status, invocation)
            return 0
        if status in {"Failed", "Cancelled", "TimedOut", "Cancelling"}:
            write_evidence(config, command_id, status, invocation)
            return 1
        time.sleep(config.poll_interval_seconds)

    print("SSM command did not complete before the bounded deadline; cancelling.")
    run_text(["aws", "ssm", "cancel-command", "--region", config.aws_region, "--command-id", command_id], check=False)
    invocation = run_json([
        "aws", "ssm", "get-command-invocation",
        "--region", config.aws_region,
        "--command-id", command_id,
        "--instance-id", config.ssm_instance_id,
        "--query", "{Status:Status,ResponseCode:ResponseCode,Stdout:StandardOutputContent,Stderr:StandardErrorContent}",
        "--output", "json",
    ], check=False)
    status = str(invocation.get("Status", "TimedOut")) if isinstance(invocation, dict) else "TimedOut"
    write_evidence(config, command_id, status, invocation)
    return 1


def main() -> int:
    try:
        return promote(load_config())
    except Exception as exc:
        print(f"ssm-artifact-promoter failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
