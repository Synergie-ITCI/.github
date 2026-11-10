"""Trusted entry point for the isolated infrastructure rehearsal increment.

This cannot execute production, restore a database, change routing, or declare
application acceptance. Authenticated sync and write-preserving recovery evidence
remain separate mandatory gates before this increment can become a full rehearsal.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from application_executor import Aws, Executor
from application_plan import render
from approval_receipts import ApprovalReceipt
from execution_artifact import read_manifest_artifact
from execution_gate import REPOSITORY
from rehearsal_context import verify_rehearsal_context


def github_api(path, method="GET", payload=None):
    # gh handles GitHub's artifact redirect without transporting our OAuth token
    # in a URL or exposing a private artifact download URL to shared output.
    if not path.startswith((f"repos/{REPOSITORY}/", "repos/Synergie-ITCI/.github/")):
        raise ValueError("GitHub operation is outside the release repositories")
    command = ["gh", "api", path, "--method", method]
    if payload is not None:
        command.extend(["--input", "-"])
    result = subprocess.run(
        command,
        input=None if payload is None else json.dumps(payload).encode(),
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("GitHub release evidence unavailable; no automatic retry")
    if path.endswith("/zip"):
        return result.stdout
    return json.loads(result.stdout)


class ContextBoundReceipt:
    """Recheck mutable source/check refs before every authorized mutation."""

    def __init__(self, receipt, verify_context):
        self.receipt = receipt
        self.verify_context = verify_context

    def verify(self):
        self.verify_context()
        return self.receipt.verify()

    def consume(self):
        self.verify_context()
        return self.receipt.consume()


def validate(raw, manifest, args, *, api, environment, central_sha):
    if manifest.get("operation") != "rehearsal":
        raise ValueError("Only the separately authorized isolated rehearsal is wired")
    if manifest.get("expires_at") != args.expires_at:
        raise ValueError("Manifest and approval expiry differ")
    verify_rehearsal_context(
        manifest=manifest,
        environment=environment,
        api=api,
        central_checkout_sha=central_sha,
    )
    # Validate requests before consuming a one-use approval or assuming AWS.
    render(manifest["application"], scope=manifest["scope"])
    receipt = ApprovalReceipt(
        api=api,
        raw_manifest=raw,
        operation="rehearsal",
        promotion_pr=manifest["promotion_pr"],
        comment_id=args.approval_comment_id,
        expires_at=args.expires_at,
        caller_sha=manifest["caller_sha"],
        run_id=environment["GITHUB_RUN_ID"],
        run_attempt=environment["GITHUB_RUN_ATTEMPT"],
    )
    bound = ContextBoundReceipt(
        receipt,
        lambda: verify_rehearsal_context(
            manifest=manifest,
            environment=environment,
            api=api,
            central_checkout_sha=central_sha,
        ),
    )
    bound.verify()
    return bound


def execute_infrastructure(manifest, receipt, journal, *, aws, executor=Executor):
    if manifest.get("scope") != "production-rehearsal":
        raise ValueError("Production is not enabled in this rehearsal increment")
    # Constructing the engine validates the host and reserves its exclusive
    # journal before consuming approval. No AWS mutation occurs in construction.
    engine = executor(manifest, aws=aws, authorize=receipt.verify, journal=journal)
    try:
        engine.preflight()
        receipt.consume()
        engine.prepare()
        engine.migrate()
        engine.start()
        services = engine.wait_runtime()
        report = {
            "status": "INFRASTRUCTURE_READY_APPLICATION_ACCEPTANCE_REQUIRED",
            "source_sha": manifest["application"]["source_sha"],
            "scope": manifest["scope"],
            "services": services,
            "rehearsal_passed": False,
            "remaining": [
                "authenticated API and Admin behavior",
                "submission, evidence and original-client-ID reconciliation",
                "write-preserving recovery exercised on the isolated target",
                "existing distributed-client pending-sync continuity",
            ],
        }
        engine.record("infrastructure_increment_complete", **report)
        return report
    finally:
        # A failure does not silently retry a migration, restore data, remove
        # resources, or change another service. Preserve the execution journal.
        engine.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("validate", "execute-infrastructure"))
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--artifact-run-id", type=int, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--approval-comment-id", type=int, required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--central-sha", required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    metadata = github_api(f"repos/{REPOSITORY}/actions/artifacts/{args.artifact_id}")
    if metadata.get("size_in_bytes", 1024 * 1024 + 1) > 1024 * 1024:
        raise ValueError("Execution artifact exceeds the bounded manifest limit")
    raw, manifest = read_manifest_artifact(
        metadata=metadata,
        archive=github_api(
            f"repos/{REPOSITORY}/actions/artifacts/{args.artifact_id}/zip"
        ),
        artifact_id=args.artifact_id,
        run_id=args.artifact_run_id,
        caller_sha=os.environ["GITHUB_SHA"],
        manifest_sha256=args.manifest_sha256,
    )
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if actual != args.central_sha:
        raise ValueError("Executing central checkout differs from the approved source")
    receipt = validate(
        raw,
        manifest,
        args,
        api=github_api,
        environment=dict(os.environ),
        central_sha=actual,
    )
    if args.mode == "validate":
        print(
            "Exact isolated execution artifact, refs and approval verified; no mutation"
        )
        return
    report = execute_infrastructure(manifest, receipt, args.journal, aws=Aws())
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(report["status"])


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
    ):
        # Runtime exceptions may contain database URLs, presigned URLs or HTTP
        # bodies. Preserve bounded engine metadata, never echo raw exceptions.
        print(
            "Execution stopped; inspect private metadata and do not retry blindly",
            file=sys.stderr,
        )
        sys.exit(1)
