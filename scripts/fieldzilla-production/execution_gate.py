"""Exact-manifest human authorization for the existing production release lane.

Read-only gate used before a deployment identity is assumed. It supplements,
never replaces, verify_release_promotion_gate.py. It grants no IAM permission.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

REPOSITORY = "Synergie-ITCI/programme-management-platform"
OWNER = {"login": "SaurabhVermaIN", "id": 52234089}
OPERATIONS = {"rehearsal", "prepare", "rollout", "recover"}


def manifest_digest(raw: bytes) -> str:
    # Bind exact artifact bytes, not a caller's normalized interpretation.
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise TypeError("Execution manifest must be an object")
    return hashlib.sha256(raw).hexdigest()


def approval_text(operation: str, digest: str, expires_at: str) -> str:
    if operation not in OPERATIONS:
        raise ValueError("Unsupported execution operation")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("Invalid manifest digest")
    return (
        f"FIELDZILLA EXECUTION APPROVED operation={operation} "
        f"manifest_sha256={digest} expires_at={expires_at}"
    )


def verify_comment(
    comment: dict[str, Any],
    *,
    operation: str,
    raw_manifest: bytes,
    promotion_pr: int,
    expires_at: str,
    now: datetime | None = None,
) -> str:
    """Validate a freshly fetched GitHub comment; never trusts a display name."""
    now = now or datetime.now(UTC)
    expiry = datetime.fromisoformat(expires_at)
    created = datetime.fromisoformat(str(comment.get("created_at", "")))
    if (
        now.utcoffset() is None
        or expiry.utcoffset() is None
        or created.utcoffset() is None
        or not created <= now < expiry
        or not timedelta(0) < expiry - created <= timedelta(hours=2)
    ):
        raise ValueError("Execution approval window invalid or expired")
    user = comment.get("user") or {}
    if (
        user.get("login") != OWNER["login"]
        or user.get("id") != OWNER["id"]
        or comment.get("issue_url")
        != f"https://api.github.com/repos/{REPOSITORY}/issues/{promotion_pr}"
        or comment.get("created_at") != comment.get("updated_at")
    ):
        raise ValueError("Execution approval identity, issue or edit state differs")
    digest = manifest_digest(raw_manifest)
    if comment.get("body") != approval_text(operation, digest, expires_at):
        raise ValueError("Execution approval operation or exact manifest differs")
    return digest
