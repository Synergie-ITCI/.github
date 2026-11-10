"""One-use application approvals using the existing hosting deployment-receipt model.

The reusable caller must use the same non-cancelling hosting concurrency group.
This module consumes GitHub authorization only; it never assumes AWS authority.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from execution_gate import REPOSITORY, manifest_digest, verify_comment

ENVIRONMENT = "synergie-app-production"


def payload_of(deployment: dict[str, Any]) -> dict[str, Any]:
    value = deployment.get("payload") or {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    return value if isinstance(value, dict) else {}


class ApprovalReceipt:
    def __init__(
        self,
        *,
        api: Callable,
        raw_manifest: bytes,
        operation: str,
        promotion_pr: int,
        comment_id: int,
        expires_at: str,
        caller_sha: str,
        run_id: str,
        run_attempt: str,
    ):
        if (
            type(promotion_pr) is not int
            or promotion_pr < 1
            or type(comment_id) is not int
            or comment_id < 1
            or not re.fullmatch(r"[0-9a-f]{40}", caller_sha)
            or not re.fullmatch(r"[1-9][0-9]*", run_id)
            or run_attempt != "1"
        ):
            raise ValueError("Invalid or retried execution identity")
        self.api = api
        self.raw = raw_manifest
        self.operation = operation
        self.pr = promotion_pr
        self.comment = comment_id
        self.expiry = expires_at
        self.caller = caller_sha
        self.run = run_id
        self.digest = manifest_digest(raw_manifest)
        self.marker = f"fieldzilla-application-approval:{comment_id}"
        self.receipt_id: int | None = None

    def _existing(self) -> list[dict[str, Any]]:
        found = []
        for page in range(1, 101):
            rows = self.api(
                f"repos/{REPOSITORY}/deployments?environment={ENVIRONMENT}&per_page=100&page={page}"
            )
            if not isinstance(rows, list):
                raise TypeError("Approval deployment history unavailable")
            found.extend(
                row
                for row in rows
                if payload_of(row).get("authorization") == self.marker
            )
            if len(rows) < 100:
                return found
        raise ValueError("Approval deployment history too large to prove uniqueness")

    def verify(self):
        environment = self.api(f"repos/{REPOSITORY}/environments/{ENVIRONMENT}")
        if any(
            rule.get("type") == "required_reviewers"
            for rule in environment.get("protection_rules", [])
        ):
            raise ValueError(
                "Native environment review is available; comment fallback cannot replace it"
            )
        comment = self.api(f"repos/{REPOSITORY}/issues/comments/{self.comment}")
        if comment.get("id") != self.comment or comment.get(
            "author_association"
        ) not in {"OWNER", "MEMBER", "COLLABORATOR"}:
            raise ValueError("Execution approval comment identity/association differs")
        verify_comment(
            comment,
            operation=self.operation,
            raw_manifest=self.raw,
            promotion_pr=self.pr,
            expires_at=self.expiry,
        )
        existing = self._existing()
        if self.receipt_id is None:
            if existing:
                raise ValueError(
                    "Execution approval already consumed; use reviewed recovery/new approval"
                )
        elif (
            len(existing) != 1
            or existing[0].get("id") != self.receipt_id
            or payload_of(existing[0]).get("manifest_sha256") != self.digest
            or payload_of(existing[0]).get("run_id") != self.run
            or payload_of(existing[0]).get("run_attempt") != 1
            or payload_of(existing[0]).get("operation") != self.operation
            or payload_of(existing[0]).get("caller_sha") != self.caller
        ):
            raise ValueError("Execution receipt no longer uniquely belongs to this run")

    def consume(self):
        if self.receipt_id is not None:
            raise ValueError("Do not consume an approval twice")
        self.verify()
        created = self.api(
            f"repos/{REPOSITORY}/deployments",
            "POST",
            {
                "ref": self.caller,
                "environment": ENVIRONMENT,
                "task": "fieldzilla-production-application",
                "auto_merge": False,
                "required_contexts": [],
                "payload": {
                    "authorization": self.marker,
                    "manifest_sha256": self.digest,
                    "operation": self.operation,
                    "run_id": self.run,
                    "run_attempt": 1,
                    "caller_sha": self.caller,
                },
            },
        )
        identity = created.get("id")
        if type(identity) is not int or identity < 1:
            raise ValueError("Approval consumption outcome ambiguous; do not retry")
        self.receipt_id = identity
        self.verify()
        return identity
