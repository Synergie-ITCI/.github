"""Trusted entry point for the isolated infrastructure rehearsal increment.

This cannot execute production, restore a database, change routing, or declare
application acceptance. Authenticated sync and write-preserving recovery evidence
remain separate mandatory gates before this increment can become a full rehearsal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from application_executor import Aws, Executor
from application_plan import render
from approval_receipts import ApprovalReceipt
from execution_artifact import read_manifest_artifact
from execution_gate import REPOSITORY
from issued_windows import is_sql_free_update, verify_issued_windows
from qa_policy_evidence import verify_qa_policy_evidence
from rehearsal_context import verify_production_context, verify_rehearsal_context


def _read_failure_category(stderr):
    message = stderr.decode(errors="replace") if isinstance(stderr, bytes) else str(stderr)
    match = re.search(r"\bHTTP ([45][0-9]{2})\b", message)
    if match:
        return "HTTP " + match[1], match[1] in {"429", "500", "502", "503", "504"}
    if any(value in message.lower() for value in ("connection reset", "connection timed out", "tls handshake timeout")):
        return "transport", True
    return "unclassified", False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _github_log_bytes(path):
    """Follow GitHub's signed log redirect without forwarding GH_TOKEN."""
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise RuntimeError("GitHub Actions token is unavailable")
    opener = urllib.request.build_opener(_NoRedirect)
    source = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    for attempt in range(3):
        category, transient = "unclassified", False
        try:
            try:
                first = opener.open(source, timeout=20)
            except urllib.error.HTTPError as error:
                if error.code != 302:
                    raise
                location = error.headers.get("Location", "")
            else:
                with first:
                    if first.status != 200:
                        raise ValueError("GitHub log response status differs")
                    data = first.read(8 * 1024 * 1024 + 1)
                if len(data) <= 8 * 1024 * 1024:
                    return data
                raise ValueError("GitHub log download exceeds bounded read")
            parsed = urllib.parse.urlsplit(location)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("GitHub log redirect is invalid")
            # The signed URL is a capability. No Authorization header or token
            # is attached to the second request, and further redirects fail.
            with opener.open(urllib.request.Request(location), timeout=20) as response:
                if response.status != 200:
                    raise ValueError("GitHub log download status differs")
                data = response.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024:
                raise ValueError("GitHub log download exceeds bounded read")
            return data
        except urllib.error.HTTPError as error:
            category = f"HTTP {error.code}"
            transient = error.code in {429, 500, 502, 503, 504}
        except (TimeoutError, urllib.error.URLError):
            category, transient = "transport", True
        except ValueError:
            category = "invalid response"
        if not transient or attempt == 2:
            break
        time.sleep(attempt + 1)
    print(f"GitHub release evidence read failed at {path} ({category})", file=sys.stderr)
    raise RuntimeError("GitHub release evidence unavailable after bounded read attempts")


def github_api(path, method="GET", payload=None):
    # gh handles artifact redirects. Log redirects use the explicit two-step
    # reader above so the runner token never reaches the signed download host.
    if not path.startswith((f"repos/{REPOSITORY}/", "repos/Synergie-ITCI/.github/")):
        raise ValueError("GitHub operation is outside the release repositories")
    if method == "GET" and payload is None and path.endswith("/logs"):
        return _github_log_bytes(path)
    command = ["gh", "api", path, "--method", method]
    if payload is not None:
        command.extend(["--input", "-"])
    # Retry only identified transient read failures. Identity, approval and
    # content mismatches are evaluated after a successful response, not retried.
    attempts = 3 if method == "GET" and payload is None else 1
    category = "unclassified"
    for attempt in range(attempts):
        try:
            result = subprocess.run(
                command,
                input=None if payload is None else json.dumps(payload).encode(),
                capture_output=True,
                timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired:
            category, transient = "timeout", True
            result = None
        else:
            category, transient = _read_failure_category(result.stderr)
        if result is not None and result.returncode == 0:
            break
        if not transient or attempt + 1 == attempts:
            break
        if attempt + 1 < attempts:
            time.sleep(attempt + 1)
    if result is None or result.returncode:
        # Paths are limited to the two release repositories above. Emit only
        # the failed API path, never response bodies or redirected artifact URLs.
        print(f"GitHub release evidence read failed at {path} ({category})", file=sys.stderr)
        raise RuntimeError("GitHub release evidence unavailable after bounded read attempts")
    if path.endswith(("/zip", "/logs")):
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
    production = getattr(args, "execution_kind", "rehearsal") == "production"
    operation = "rollout" if production else "rehearsal"
    if manifest.get("operation") != operation:
        raise ValueError("Execution operation differs from the selected target")
    if production and (
        set(manifest.get("prior_tasks", {})) != {"api", "admin-web", "worker"}
        or not isinstance(manifest.get("worker_digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", manifest["worker_digest"]) is None
    ):
        raise ValueError("Production rollout must bind the prior worker and image")
    if production and "worker_target_digest" in manifest and (
        not isinstance(manifest["worker_target_digest"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", manifest["worker_target_digest"]) is None
        or manifest["worker_target_digest"] != manifest["application"].get("api_digest")
    ):
        raise ValueError("Worker target must be the approved API image digest")
    if manifest.get("expires_at") != args.expires_at:
        raise ValueError("Manifest and approval expiry differ")
    context = verify_production_context if production else verify_rehearsal_context
    context(
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
        operation=operation,
        promotion_pr=manifest["promotion_pr"],
        comment_id=args.approval_comment_id,
        expires_at=args.expires_at,
        caller_sha=manifest["caller_sha"],
        run_id=environment["GITHUB_RUN_ID"],
        run_attempt=environment["GITHUB_RUN_ATTEMPT"],
    )

    def current_authority():
        checks = context(
            manifest=manifest,
            environment=environment,
            api=api,
            central_checkout_sha=central_sha,
        )
        policies = verify_qa_policy_evidence(manifest, checks=checks, api=api)
        verify_issued_windows(manifest, api=api, activated_policies=policies)

    bound = ContextBoundReceipt(receipt, current_authority)
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


def execute_production(manifest, receipt, journal, *, aws, executor=Executor):
    if manifest.get("scope") != "production" or manifest.get("operation") != "rollout":
        raise ValueError("Only a separately approved production rollout is allowed")
    if (set(manifest.get("prior_tasks", {})) != {"api", "admin-web", "worker"}
            or not isinstance(manifest.get("worker_digest"), str)):
        raise ValueError("Production rollout must bind the prior worker and image")
    # The engine binds all three live services and the available snapshot before
    # approval consumption. It then stops writers and verifies a zero-task fence.
    engine = executor(manifest, aws=aws, authorize=receipt.verify, journal=journal)
    try:
        engine.preflight()
        receipt.consume()
        engine.prepare()
        if is_sql_free_update(manifest):
            engine.attest_database("before")
            engine.attest_database("after")
            engine.record(
                "migration_skipped",
                reason=f"exact_pr{manifest['promotion_pr']}_database_already_current",
            )
        else:
            engine.migrate()
        engine.start()
        services = engine.wait_runtime()
        engine.restore_worker()
        services["worker"] = engine.wait_worker()
        report = {
            "status": "PRODUCTION_RUNTIME_READY_CUTOVER_AND_ACCEPTANCE_REQUIRED",
            "source_sha": manifest["application"]["source_sha"],
            "scope": "production",
            "services": services,
            "production_live": False,
            "remaining": [
                "governed production-only routing cutover",
                "authenticated API/Admin and existing-client sync readback",
                "staging unchanged readback",
            ],
        }
        engine.record("production_runtime_prepared", **report)
        return report
    finally:
        engine.close()


def preserve_recovery_manifest(raw: bytes, journal: Path) -> Path:
    path = journal.with_suffix(".manifest.json")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("validate", "execute-infrastructure", "execute-production"))
    parser.add_argument("--execution-kind", choices=("rehearsal", "production"), default="rehearsal")
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--artifact-run-id", type=int, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--approval-comment-id", type=int, required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--central-sha", required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.mode != "validate" and args.mode != ("execute-production" if args.execution_kind == "production" else "execute-infrastructure"):
        raise ValueError("Execution mode and target differ")
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
    # Bind the read-only interruption report to the exact reviewed artifact.
    # An existing file stops before the one-use approval is consumed.
    preserve_recovery_manifest(raw, args.journal)
    execute = execute_production if args.execution_kind == "production" else execute_infrastructure
    report = execute(manifest, receipt, args.journal, aws=Aws())
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
