"""Trusted image-build/publish adapters; workflow identity must be verified first.

Build mode cannot assume AWS. Publish mode never checks out or runs candidate
scripts/containers; it handles only a same-run immutable image artifact. The CLI
is preparation until its immutable reusable workflow and named IAM are approved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from application_runner import ContextBoundReceipt, github_api
from approval_receipts import ApprovalReceipt
from execution_artifact import read_manifest_artifact
from execution_gate import REPOSITORY
from image_artifact import MAX_ARCHIVE, checksum, extract_images, validate_origin
from image_publication import (
    KINDS,
    RECIPES,
    REGION,
    SOURCE,
    Publisher,
    validate_request,
    verify_local_image,
)
from issued_windows import verify_issued_windows
from qa_policy_evidence import verify_qa_policy_evidence
from rehearsal_context import verify_image_context

AWS_CREDENTIAL_INPUTS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
)


def command(arguments, *, cwd=None, env=None, input_bytes=None, timeout=120):
    result = subprocess.run(
        arguments,
        cwd=cwd,
        env=env,
        input=input_bytes,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        # CLI errors can include credential details or private source content.
        raise RuntimeError("Image command failed; inspect metadata before any retry")
    return result.stdout


def authority(raw, manifest, args, environment):
    validate_request(manifest)
    if manifest["expires_at"] != args.expires_at:
        raise ValueError("Approval and manifest expiry differ")
    receipt = ApprovalReceipt(
        api=github_api,
        raw_manifest=raw,
        operation="prepare",
        promotion_pr=manifest["promotion_pr"],
        comment_id=args.approval_comment_id,
        expires_at=args.expires_at,
        caller_sha=manifest["caller_sha"],
        run_id=environment["GITHUB_RUN_ID"],
        run_attempt=environment["GITHUB_RUN_ATTEMPT"],
    )

    def current():
        checks = verify_image_context(
            manifest=manifest,
            environment=environment,
            api=github_api,
            central_checkout_sha=args.central_sha,
        )
        policies = verify_qa_policy_evidence(manifest, checks=checks, api=github_api)
        verify_issued_windows(manifest, api=github_api, activated_policies=policies)

    result = ContextBoundReceipt(receipt, current)
    result.verify()
    return result


def build(manifest, candidate, output, *, environment, receipt):
    source = validate_request(manifest)
    # Do not rely only on the absence of a configure-credentials step. Refuse
    # inherited credentials and any production environment in this build job.
    if any(environment.get(key) for key in AWS_CREDENTIAL_INPUTS):
        raise ValueError("Image build must not receive AWS credentials or role inputs")
    require_head = command(["git", "rev-parse", "HEAD"], cwd=candidate).decode().strip()
    if require_head != source or command(
        ["git", "status", "--porcelain"], cwd=candidate
    ):
        raise ValueError("Candidate checkout does not match the clean approved source")
    output.mkdir(mode=0o700)
    metadata = {
        "source_sha": source,
        "caller_sha": manifest["caller_sha"],
        "run_id": int(environment["GITHUB_RUN_ID"]),
        "run_attempt": 1,
        "platform": "linux/arm64",
        "images": {},
    }
    # Candidate Docker instructions never inherit a GitHub token, OIDC request
    # token, AWS setting, credential helper, agent socket or arbitrary build arg.
    build_environment = {
        key: environment[key]
        for key in ("PATH", "HOME", "TMPDIR")
        if key in environment
    }
    config = Path(environment.get("DOCKER_CONFIG", ""))
    expected_config = (
        Path(environment["RUNNER_TEMP"]) / "fieldzilla-build-docker-config"
    )
    if config != expected_config or not config.is_dir():
        raise ValueError(
            "Build requires the workflow-owned credential-free Docker config"
        )
    auth_file = config / "config.json"
    if auth_file.exists():
        auth = json.loads(auth_file.read_text())
        if auth.get("auths") or auth.get("credsStore") or auth.get("credHelpers"):
            raise ValueError("Build Docker config must not contain authentication")
    if (Path(environment.get("HOME", "")) / ".aws/credentials").exists():
        raise ValueError("Build runner must not contain a default AWS credentials file")
    build_environment["DOCKER_CONFIG"] = str(config)
    if environment.get("BUILDX_BUILDER"):
        build_environment["BUILDX_BUILDER"] = environment["BUILDX_BUILDER"]
    for kind in KINDS:
        receipt.verify()
        context = candidate / "apps" / kind
        recipe = candidate / RECIPES[kind]
        if (
            not context.is_dir()
            or context.resolve() != context.absolute()
            or not recipe.is_file()
            or recipe.is_symlink()
        ):
            raise ValueError(
                "Build context/recipe must be the exact internal source path"
            )
        if (
            hashlib.sha256(recipe.read_bytes()).hexdigest()
            != manifest["recipes"][kind]["sha256"]
        ):
            raise ValueError("Reviewed Docker recipe bytes differ")
        symlinks = command(
            ["git", "ls-tree", "-r", "HEAD", "--", "apps/" + kind], cwd=candidate
        ).splitlines()
        if any(row.startswith(b"120000 ") for row in symlinks):
            raise ValueError("Candidate image context may not include tracked symlinks")
        tag = "fieldzilla-production-build-" + kind + ":" + source
        command(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                "linux/arm64",
                "--load",
                "--tag",
                tag,
                "--label",
                "org.opencontainers.image.revision=" + source,
                "--label",
                "org.opencontainers.image.source=" + SOURCE,
                "--file",
                str(recipe),
                str(context),
            ],
            env=build_environment,
            timeout=1800,
        )
        inspected = json.loads(
            command(["docker", "image", "inspect", tag], env=build_environment)
        )
        config_digest = inspected[0]["Id"]
        verify_local_image(inspected, config_digest, source)
        archive = output / (kind + ".tar")
        command(
            ["docker", "image", "save", "--output", str(archive), tag],
            env=build_environment,
            timeout=300,
        )
        os.chmod(archive, 0o600)
        if archive.stat().st_size > 4 * 1024**3:
            raise ValueError("Built image archive exceeds the bounded transfer limit")
        metadata["images"][kind] = {
            "config_digest": config_digest,
            "archive_sha256": checksum(archive),
            "archive_bytes": archive.stat().st_size,
        }
    # An expiring/revoked review stops before publishing a build artifact too.
    receipt.verify()
    with (output / "images.json").open("x") as handle:
        os.chmod(output / "images.json", 0o600)
        json.dump(metadata, handle, indent=2)
    return metadata


def download(path, output, max_bytes):
    if not path.startswith(
        f"repos/{REPOSITORY}/actions/artifacts/"
    ) or not path.endswith("/zip"):
        raise ValueError("Download must use the private application artifact API")
    process = subprocess.Popen(
        ["gh", "api", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline, count = time.monotonic() + 300, 0
    try:
        with output.open("xb") as destination:
            os.chmod(output, 0o600)
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        "Image artifact download exceeded its bounded window"
                    )
                if not selector.select(timeout=1):
                    continue
                block = os.read(process.stdout.fileno(), 1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > max_bytes:
                    raise ValueError("Image artifact download exceeds its bounded size")
                destination.write(block)
        if process.wait(timeout=10) != 0:
            raise RuntimeError("Private image artifact download failed")
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


class ImageAws:
    def __call__(self, service, action, request):
        allowed = {
            ("sts", "get-caller-identity"),
            ("ecr", "describe-repositories"),
            ("ecr", "batch-get-image"),
        }
        if (service, action) not in allowed:
            raise ValueError("Image metadata adapter forbids this AWS action")
        return json.loads(
            command(
                [
                    "aws",
                    service,
                    action,
                    "--region",
                    REGION,
                    "--output",
                    "json",
                    "--no-cli-pager",
                    "--cli-input-json",
                    json.dumps(request),
                ],
                env={**os.environ, "AWS_MAX_ATTEMPTS": "1"},
            )
        )


class ImageDocker:
    def __init__(self, folder):
        folder.mkdir(mode=0o700)
        self.environment = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "TMPDIR")
            if key in os.environ
        }
        self.environment["DOCKER_CONFIG"] = str(folder)
        self.config = folder / "config.json"

    def __call__(self, operation, *args):
        if operation == "inspect":
            return json.loads(
                command(["docker", "image", "inspect", args[0]], env=self.environment)
            )
        if operation == "login":
            password = command(
                ["aws", "ecr", "get-login-password", "--region", REGION],
                env={**os.environ, "AWS_MAX_ATTEMPTS": "1"},
            )
            command(
                ["docker", "login", "--username", "AWS", "--password-stdin", args[0]],
                env=self.environment,
                input_bytes=password,
            )
            if self.config.exists():
                os.chmod(self.config, 0o600)
            return None
        if operation not in {"tag", "push"}:
            raise ValueError(
                "Image publication must never run a container or arbitrary command"
            )
        return command(
            ["docker", "image", operation, *args], env=self.environment, timeout=600
        )

    def close(self):
        # Remove only this invocation's known generated authentication file.
        if self.config.exists():
            self.config.unlink()


def prepare_request(raw, args, environment):
    """Package reviewed metadata without consuming approval or assuming AWS."""
    if any(environment.get(key) for key in AWS_CREDENTIAL_INPUTS):
        raise ValueError("Metadata preparation must not receive AWS credentials")
    if len(raw) > 64 * 1024 or hashlib.sha256(raw).hexdigest() != args.manifest_sha256:
        raise ValueError("Exact bounded manifest bytes are required")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate image metadata property")
            result[key] = value
        return result

    manifest = json.loads(raw, object_pairs_hook=unique)
    validate_request(manifest)
    if manifest["expires_at"] != args.expires_at:
        raise ValueError("Manifest and execution expiry differ")
    print("Image preparation: verifying exact caller and governed checks", flush=True)
    checks = verify_image_context(
        manifest=manifest,
        environment=environment,
        api=github_api,
        central_checkout_sha=args.central_sha,
    )
    print("Image preparation: verifying immutable QA evidence", flush=True)
    policies = verify_qa_policy_evidence(manifest, checks=checks, api=github_api)
    print("Image preparation: verifying live review windows", flush=True)
    verify_issued_windows(manifest, api=github_api, activated_policies=policies)
    with args.output.open("xb") as output:
        os.chmod(args.output, 0o600)
        output.write(raw)
    print("Exact image metadata prepared; no AWS calls or approval consumption")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("prepare", "validate", "build", "load", "publish")
    )
    for name in ("artifact-id", "artifact-run-id", "approval-comment-id"):
        parser.add_argument("--" + name, type=int)
    for name in ("manifest-sha256", "expires-at", "central-sha"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-artifact-id", type=int)
    parser.add_argument("--image-artifact-digest")
    args = parser.parse_args()
    environment = dict(os.environ)
    actual = (
        command(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[2])
        .decode()
        .strip()
    )
    if actual != args.central_sha:
        raise ValueError("Executing central checkout differs")
    if args.mode == "prepare":
        prepare_request(
            environment.get("EXECUTION_MANIFEST", "").encode(), args, environment
        )
        return
    if any(
        type(getattr(args, key)) is not int or getattr(args, key) < 1
        for key in ("artifact_id", "artifact_run_id", "approval_comment_id")
    ):
        raise ValueError("Exact manifest artifact, run and owner approval are required")
    metadata = github_api(f"repos/{REPOSITORY}/actions/artifacts/{args.artifact_id}")
    if metadata.get("size_in_bytes", 1024 * 1024 + 1) > 1024 * 1024:
        raise ValueError("Request artifact exceeds the bounded manifest size")
    raw, manifest = read_manifest_artifact(
        metadata=metadata,
        archive=github_api(
            f"repos/{REPOSITORY}/actions/artifacts/{args.artifact_id}/zip"
        ),
        artifact_id=args.artifact_id,
        run_id=args.artifact_run_id,
        caller_sha=environment["GITHUB_SHA"],
        manifest_sha256=args.manifest_sha256,
    )
    receipt = authority(raw, manifest, args, environment)
    if args.mode == "validate":
        print(
            "Exact image request and unused approval verified; no AWS or image mutation"
        )
        if environment.get("GITHUB_OUTPUT"):
            with Path(environment["GITHUB_OUTPUT"]).open("a") as output:
                output.write(
                    "source_sha=" + manifest["application"]["source_sha"] + "\n"
                )
        return
    if args.mode == "build":
        build(
            manifest,
            args.candidate,
            args.output,
            environment=environment,
            receipt=receipt,
        )
        print("Reviewed image artifacts built without AWS; not published")
        return
    if type(args.image_artifact_id) is not int or args.image_artifact_id < 1:
        raise ValueError("Same-run image artifact is required")
    image_meta = github_api(
        f"repos/{REPOSITORY}/actions/artifacts/{args.image_artifact_id}"
    )
    validate_origin(
        image_meta,
        run_id=int(environment["GITHUB_RUN_ID"]),
        caller_sha=manifest["caller_sha"],
        source_sha=manifest["application"]["source_sha"],
        archive_digest=args.image_artifact_digest,
    )
    if args.mode == "load":
        if any(environment.get(key) for key in AWS_CREDENTIAL_INPUTS):
            raise ValueError("Image artifacts must be loaded before AWS credentials")
        args.output.mkdir(mode=0o700)
        archive = args.output / "images.zip"
        download(
            f"repos/{REPOSITORY}/actions/artifacts/{args.image_artifact_id}/zip",
            archive,
            MAX_ARCHIVE,
        )
        images = extract_images(
            archive,
            args.output / "verified-images",
            archive_digest=args.image_artifact_digest,
            source_sha=manifest["application"]["source_sha"],
            caller_sha=manifest["caller_sha"],
            run_id=int(environment["GITHUB_RUN_ID"]),
        )
        local_environment = {
            key: environment[key]
            for key in ("PATH", "HOME", "TMPDIR")
            if key in environment
        }
        config = args.output / "load-docker-config"
        config.mkdir(mode=0o700)
        local_environment["DOCKER_CONFIG"] = str(config)
        for kind in KINDS:
            command(
                [
                    "docker",
                    "image",
                    "load",
                    "--input",
                    str(args.output / "verified-images" / (kind + ".tar")),
                ],
                env=local_environment,
                timeout=300,
            )
            inspected = json.loads(
                command(
                    [
                        "docker",
                        "image",
                        "inspect",
                        images["images"][kind]["config_digest"],
                    ],
                    env=local_environment,
                )
            )
            verify_local_image(
                inspected,
                images["images"][kind]["config_digest"],
                manifest["application"]["source_sha"],
            )
        receipt.verify()
        prepared = {
            "request_sha256": args.manifest_sha256,
            "artifact_id": args.image_artifact_id,
            "artifact_digest": args.image_artifact_digest,
            "metadata": images,
        }
        with (args.output / "loaded.json").open("x") as handle:
            os.chmod(args.output / "loaded.json", 0o600)
            json.dump(prepared, handle)
        print("Same-run images verified and loaded without AWS; no container executed")
        return
    prepared = json.loads((args.output / "loaded.json").read_text())
    images = prepared["metadata"]
    if (
        prepared["request_sha256"] != args.manifest_sha256
        or prepared["artifact_id"] != args.image_artifact_id
        or prepared["artifact_digest"] != args.image_artifact_digest
        or images["source_sha"] != manifest["application"]["source_sha"]
        or images["caller_sha"] != manifest["caller_sha"]
        or images["run_id"] != int(environment["GITHUB_RUN_ID"])
        or images["run_attempt"] != 1
        or images["platform"] != "linux/arm64"
    ):
        raise ValueError(
            "Previously loaded image metadata differs from this invocation"
        )
    docker = ImageDocker(args.output / "publish-docker-config")
    engine = None
    try:
        engine = Publisher(
            manifest,
            {kind: images["images"][kind]["config_digest"] for kind in KINDS},
            aws=ImageAws(),
            docker=docker,
            authorize=receipt.verify,
            journal=args.output / "publication.jsonl",
        )
        engine.preflight()
        report = engine.publish(receipt.consume)
        report.update(
            run_id=int(environment["GITHUB_RUN_ID"]),
            run_attempt=1,
            image_artifact_id=args.image_artifact_id,
            image_artifact_digest=args.image_artifact_digest,
            approval_receipt_id=receipt.receipt.receipt_id,
        )
        with (args.output / "registry-receipt.json").open("x") as handle:
            json.dump(report, handle, indent=2)
        print(report["status"])
    finally:
        if engine is not None:
            engine.close()
        docker.close()


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RuntimeError,
        subprocess.SubprocessError,
        zipfile.BadZipFile,
    ):
        print(
            "Image operation stopped; preserve metadata and do not retry blindly",
            file=sys.stderr,
        )
        sys.exit(1)
