"""Read-only caller/source checks before isolated application rehearsal.

Production rollout continues to require the existing promotion verifier. This
module cannot authorize production or substitute rehearsal for Gate C/Gate D.
The trusted reusable workflow must supply its actual checked-out central SHA.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from execution_gate import REPOSITORY

REQUIRED_CHECKS = {
    "Architecture Governance",
    "pr-qa / Pull Request Quality Assurance",
}


def verify_rehearsal_context(
    *,
    manifest: dict[str, Any],
    environment: dict[str, str],
    api: Callable,
    central_checkout_sha: str,
) -> dict[str, dict[str, Any]]:
    return _verify_context(
        manifest=manifest,
        environment=environment,
        api=api,
        central_checkout_sha=central_checkout_sha,
        scope="production-rehearsal",
        workflow="fieldzilla-production-application.yml",
    )


def verify_image_context(*, manifest, environment, api, central_checkout_sha):
    if manifest.get("operation") != "prepare":
        raise ValueError("Image publication requires its exact preparation approval")
    return _verify_context(
        manifest=manifest,
        environment=environment,
        api=api,
        central_checkout_sha=central_checkout_sha,
        scope="production-images",
        workflow="fieldzilla-production-images.yml",
    )


def verify_production_context(*, manifest, environment, api, central_checkout_sha):
    """Require a merged Gate C candidate at the current protected main caller."""
    if manifest.get("scope") != "production" or manifest.get("operation") != "rollout":
        raise ValueError("Production execution requires an exact rollout manifest")
    caller = manifest.get("caller_sha", "")
    source = manifest.get("application", {}).get("source_sha", "")
    central = manifest.get("central_sha", "")
    tag = manifest.get("central_tag", "")
    promotion = manifest.get("promotion_pr")
    if (
        any(not re.fullmatch(r"[0-9a-f]{40}", value) for value in (caller, source, central))
        or not re.fullmatch(r"pr-qa-v1-rc[1-9][0-9]*", str(tag))
        or type(promotion) is not int
        or promotion < 1
    ):
        raise ValueError("Production refs must bind exact commits and a release")
    expected_ref = (
        "Synergie-ITCI/.github/.github/workflows/fieldzilla-production-application.yml@refs/tags/"
        + tag
    )
    if (
        environment.get("GITHUB_REPOSITORY") != REPOSITORY
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_SHA") != caller
        or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environment.get("GITHUB_RUN_ATTEMPT") != "1"
        or environment.get("CENTRAL_WORKFLOW_REF") != expected_ref
        or central_checkout_sha != central
        or api(f"repos/{REPOSITORY}/git/ref/heads/main").get("object", {}).get("sha") != caller
    ):
        raise ValueError("Production caller or executing release changed")
    pr = api(f"repos/{REPOSITORY}/pulls/{promotion}")
    merge = pr.get("merge_commit_sha", "")
    if (
        pr.get("state") != "closed"
        or not pr.get("merged_at")
        or pr.get("head", {}).get("sha") != source
        or pr.get("head", {}).get("repo", {}).get("full_name") != REPOSITORY
        or pr.get("base", {}).get("ref") != "main"
        or not re.fullmatch(r"[0-9a-f]{40}", merge)
    ):
        raise ValueError("Exact candidate has not passed Gate C")
    lineage = api(f"repos/{REPOSITORY}/compare/{merge}...{caller}")
    if lineage.get("status") not in {"identical", "ahead"}:
        raise ValueError("Gate C merge is not in the executing main")
    ref = api(f"repos/Synergie-ITCI/.github/git/ref/tags/{tag}").get("object", {})
    if ref.get("type") != "tag" or not re.fullmatch(r"[0-9a-f]{40}", ref.get("sha", "")):
        raise ValueError("Production executor release is not annotated")
    release = api("repos/Synergie-ITCI/.github/git/tags/" + ref["sha"])
    if release.get("object", {}).get("type") != "commit" or release.get("object", {}).get("sha") != central:
        raise ValueError("Production executor release source differs")
    latest = {}
    for page in range(1, 101):
        rows = api(f"repos/{REPOSITORY}/commits/{source}/check-runs?per_page=100&page={page}").get("check_runs")
        if not isinstance(rows, list):
            raise TypeError("Gate C exact-head checks unavailable")
        for row in rows:
            if row.get("name") in REQUIRED_CHECKS and (
                row["name"] not in latest or row.get("id", 0) > latest[row["name"]].get("id", 0)
            ):
                latest[row["name"]] = row
        if len(rows) < 100:
            break
    else:
        raise ValueError("Gate C check history exceeds bounded readback")
    if set(latest) != REQUIRED_CHECKS or any(
        row.get("head_sha") != source
        or row.get("status") != "completed"
        or row.get("conclusion") != "success"
        or row.get("app", {}).get("slug") != "github-actions"
        for row in latest.values()
    ):
        raise ValueError("Gate C exact-head checks are not current successes")
    return latest


def _verify_context(
    *, manifest, environment, api, central_checkout_sha, scope, workflow
):
    if manifest.get("scope") != scope:
        raise ValueError("Execution purpose does not match the exact trusted workflow")
    caller = manifest.get("caller_sha", "")
    source = manifest.get("application", {}).get("source_sha", "")
    base = manifest.get("base_sha", "")
    central = manifest.get("central_sha", "")
    tag = manifest.get("central_tag", "")
    promotion = manifest.get("promotion_pr")
    if (
        any(
            not re.fullmatch(r"[0-9a-f]{40}", value)
            for value in (caller, source, base, central)
        )
        or not re.fullmatch(r"pr-qa-v1-rc[1-9][0-9]*", tag)
        or type(promotion) is not int
        or promotion < 1
    ):
        raise ValueError(
            "Rehearsal references must be exact commits and an immutable release"
        )
    expected_ref = (
        "Synergie-ITCI/.github/.github/workflows/" + workflow + "@refs/tags/" + tag
    )
    if (
        environment.get("GITHUB_REPOSITORY") != REPOSITORY
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_SHA") != caller
        or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environment.get("GITHUB_RUN_ATTEMPT") != "1"
        or environment.get("CENTRAL_WORKFLOW_REF") != expected_ref
        or central_checkout_sha != central
    ):
        raise ValueError(
            "Unexpected rehearsal caller, workflow or executing code identity"
        )
    main = api(f"repos/{REPOSITORY}/git/ref/heads/main")
    if main.get("object", {}).get("sha") != caller or caller != base:
        raise ValueError(
            "Protected caller/base advanced; reprepare the exact rehearsal"
        )
    pr = api(f"repos/{REPOSITORY}/pulls/{promotion}")
    if (
        pr.get("state") != "open"
        or pr.get("draft") is not False
        or pr.get("head", {}).get("sha") != source
        or pr.get("head", {}).get("repo", {}).get("full_name") != REPOSITORY
        or pr.get("base", {}).get("ref") != "main"
        or pr.get("base", {}).get("sha") != base
        or pr.get("base", {}).get("repo", {}).get("full_name") != REPOSITORY
    ):
        raise ValueError("Exact main-targeted rehearsal candidate changed")
    ref = api(f"repos/Synergie-ITCI/.github/git/ref/tags/{tag}")
    tagged = ref.get("object", {})
    if tagged.get("type") != "tag" or not re.fullmatch(
        r"[0-9a-f]{40}", tagged.get("sha", "")
    ):
        raise ValueError("Expected the governed annotated immutable release")
    release = api("repos/Synergie-ITCI/.github/git/tags/" + tagged["sha"])
    if (
        release.get("object", {}).get("type") != "commit"
        or release["object"].get("sha") != central
    ):
        raise ValueError("Central release source mismatch")
    latest: dict[str, dict[str, Any]] = {}
    for page in range(1, 101):
        reply = api(
            f"repos/{REPOSITORY}/commits/{source}/check-runs?per_page=100&page={page}"
        )
        rows = reply.get("check_runs")
        if not isinstance(rows, list):
            raise TypeError("Exact-head check readback unavailable")
        for row in rows:
            if row.get("name") in REQUIRED_CHECKS:
                if type(row.get("id")) is not int:
                    raise ValueError("Check identity unavailable")
                previous = latest.get(row["name"])
                if previous is None or previous["id"] < row["id"]:
                    latest[row["name"]] = row
        if len(rows) < 100:
            break
    else:
        raise ValueError("Check history exceeds bounded readback")
    if set(latest) != REQUIRED_CHECKS or any(
        row.get("head_sha") != source
        or row.get("status") != "completed"
        or row.get("conclusion") != "success"
        or row.get("app", {}).get("slug") != "github-actions"
        for row in latest.values()
    ):
        raise ValueError("Required exact-head governed checks are unresolved")
    return latest
