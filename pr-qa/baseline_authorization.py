"""Strict, live GitHub binding for single-PR baseline authorizations.

No state supplied in a PR event can substitute for the read-only live lookup.
This module never persists credentials or logs API response content.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "one-time-baseline.schema.json"
)


def schema_errors(
    value: Any, schema: dict[str, Any], path: str = "authorization"
) -> list[str]:
    """Validate the deliberately small JSON Schema vocabulary used by this schema."""
    types = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "boolean": bool,
    }
    kind = schema["type"]
    if not isinstance(value, types[kind]) or (
        kind == "integer" and isinstance(value, bool)
    ):
        return [f"{path}: invalid type"]
    errors = []
    if kind == "object":
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required field {key}")
        for key, item in value.items():
            rule = props.get(key, schema.get("additionalProperties", False))
            if rule is False:
                errors.append(f"{path}: unknown field")
            else:
                errors.extend(
                    schema_errors(item, rule, f"{path}.{key}" if key in props else path)
                )
    elif kind == "array":
        if schema.get("uniqueItems") and len(
            {json.dumps(v, sort_keys=True) for v in value}
        ) != len(value):
            errors.append(f"{path}: duplicate items")
        for item in value:
            errors.extend(schema_errors(item, schema["items"], path))
    elif kind == "string":
        if len(value.strip()) < schema.get("minLength", 0):
            errors.append(f"{path}: empty value")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            errors.append(f"{path}: invalid format")
    elif kind == "integer" and value < schema.get("minimum", 0):
        errors.append(f"{path}: below minimum")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: unsupported value")
    return errors


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "Redirect rejected", headers, fp
        )


def read_live_pr(repository: str, number: int, token: str) -> dict[str, Any]:
    """Only fixed GitHub HTTPS endpoints; redirects and oversized responses fail closed."""
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        or type(number) is not int
        or number < 1
    ):
        raise ValueError("Invalid live PR lookup identity")
    url = f"https://api.github.com/repos/{repository}/pulls/{number}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "synergie-pr-qa",
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(
            request, timeout=20
        ) as response:
            if response.status != 200:
                raise ValueError("non-success status")
            data = response.read(2_000_001)
            if len(data) > 2_000_000:
                raise ValueError("oversized response")
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise TypeError("malformed response")
            return payload
    except (urllib.error.URLError, OSError, ValueError, TypeError):
        # Do not expose exception text: it may contain URLs, headers or response bodies.
        raise ValueError("Live GitHub PR verification unavailable") from None


def validate_authorization(ctx, git_context, policy, size) -> list[str]:
    try:
        errors = schema_errors(policy, json.loads(SCHEMA_PATH.read_text()))
    except (OSError, ValueError, KeyError, TypeError):
        return ["Baseline authorization schema unavailable or malformed"]
    if errors:
        return errors
    if policy["enabled"] is not True:
        return ["Central policy does not enable baseline alignment mode."]
    now = datetime.now(timezone.utc)
    try:
        issued = datetime.fromisoformat(policy["issued_at"].replace("Z", "+00:00"))
        expiry = datetime.fromisoformat(policy["expires_after"].replace("Z", "+00:00"))
        if issued.utcoffset() is None or expiry.utcoffset() is None:
            raise ValueError("timezone required")
        if not (issued <= now < expiry) or not (
            timedelta(0) < expiry - issued <= timedelta(hours=24)
        ):
            raise ValueError("invalid authorization window")
    except (ValueError, OverflowError):
        return [
            "baseline authorization expired, future-issued, or outside its maximum 24-hour window"
        ]
    if (
        len(ctx.changed_files) > policy["allowed_changed_files"]
        or size["effective_additions"] > policy["allowed_effective_additions"]
    ):
        return ["Baseline diff exceeds authorized limits"]
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    repository_id = os.environ.get("GITHUB_REPOSITORY_ID", "")
    ref = re.fullmatch(
        r"refs/pull/([1-9][0-9]*)/(?:merge|head)", os.environ.get("GITHUB_REF", "")
    )
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
        or not ref
        or not repository_id.isdecimal()
        or not token
        or Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve() != ctx.repo.resolve()
    ):
        return ["Trusted GitHub pull-request execution context or token unavailable"]
    if repository != policy["repository"]:
        return [f"repository `{repository}` is not authorized"]
    if int(ref.group(1)) != policy["pr_number"]:
        return ["Current GitHub PR number differs from authorization"]
    event_pr = ctx.event.get("pull_request") or {}
    event_repo = ctx.event.get("repository") or {}
    if not isinstance(event_pr, dict) or not isinstance(event_repo, dict):
        return ["Malformed GitHub event context"]
    if (
        type(event_pr.get("number")) is not int
        or event_pr.get("number") != policy["pr_number"]
        or event_repo.get("full_name", repository) != repository
    ):
        return ["Event repository or PR number differs from trusted GitHub context"]
    if ctx.head_ref != policy["head_ref"]:
        return [f"source branch `{ctx.head_ref}` is not authorized"]
    if ctx.base_ref != policy["base_ref"]:
        return [f"target branch `{ctx.base_ref}` is not authorized"]
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ctx.repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if head.returncode or head.stdout.strip() != policy["expected_head_sha"]:
        return ["Checked-out source SHA differs from authorization"]
    if git_context.get("head_sha") not in ("HEAD", policy["expected_head_sha"]):
        return ["Event source SHA differs from authorization"]
    if (
        policy.get("expected_base_sha")
        and git_context.get("base_sha") != policy["expected_base_sha"]
    ):
        return ["destination SHA differs from authorization"]
    if len(ctx.changed_files) < policy.get("minimum_changed_files", 0):
        return ["Baseline changed-file count is below its authorized minimum"]
    try:
        live = read_live_pr(repository, policy["pr_number"], token)
        live_head, live_base = live["head"], live["base"]
        matches = (
            type(live["number"]) is int
            and live["number"] == policy["pr_number"]
            and live["state"] == "open"
            and live["merged"] is False
            and live_head["sha"] == policy["expected_head_sha"]
            and live_head["ref"] == policy["head_ref"]
            and live_base["ref"] == policy["base_ref"]
            and live_base["sha"] == git_context.get("base_sha")
            and live_base["repo"]["full_name"] == repository
            and type(live_base["repo"]["id"]) is int
            and live_base["repo"]["id"] == int(repository_id)
            and live_head["repo"]["full_name"] == repository
            and type(live_head["repo"]["id"]) is int
            and live_head["repo"]["id"] == int(repository_id)
            and (
                not policy.get("expected_base_sha")
                or live_base["sha"] == policy["expected_base_sha"]
            )
        )
    except (ValueError, OSError, KeyError, TypeError):
        return ["Live GitHub PR verification unavailable or malformed"]
    if not matches:
        return ["Live GitHub PR is not the exact authorized open, unmerged PR"]
    marker = policy.get("required_pr_body_marker")
    if marker and (marker not in ctx.pr_body or marker not in (live.get("body") or "")):
        return ["PR body is missing required baseline marker"]
    return []
