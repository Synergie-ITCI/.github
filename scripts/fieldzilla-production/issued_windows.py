"""Execution-time expiry/revocation check; never issues or relaxes QA policy.

QA remains authoritative for content, SQL fingerprints and dependencies. This
extra execution guard prevents a previously green run from extending the life
of its centrally issued, exact-PR review records.
"""

import base64
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from execution_gate import REPOSITORY

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pr-qa"))
from baseline_authorization import schema_errors


def verify_no_changed_sql(manifest, *, api):
    """Allow an image-only request to omit SQL review only for a SQL-free PR."""
    if manifest.get("scope") != "production-images":
        raise ValueError("Only image publication may omit SQL review")
    for page in range(1, 11):
        rows = api(
            f"repos/{REPOSITORY}/pulls/{manifest['promotion_pr']}/files"
            f"?per_page=100&page={page}"
        )
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValueError("Exact PR changed-file evidence is unavailable")
        if page == 1 and not rows:
            raise ValueError("Exact PR changed-file evidence is empty")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Exact PR changed-file evidence is malformed")
            for key in ("filename", "previous_filename"):
                path = row.get(key)
                if path is None and key == "previous_filename":
                    continue
                if not isinstance(path, str) or not path or len(path) > 1024:
                    raise ValueError("Exact PR changed-file path is malformed")
                if path.lower().endswith(".sql") or path.lower().startswith("apps/api/alembic/"):
                    raise ValueError("Changed SQL or migration requires exact SQL review")
        if len(rows) < 100:
            return
    raise ValueError("Exact PR changed-file evidence exceeds the bounded read")


def verify_issued_windows(manifest, *, api, activated_policies, now=None):
    expected = manifest.get("review_authorizations", {})
    if (
        not isinstance(expected, dict)
        or set(expected) != {"baseline", "sql"}
        or not isinstance(expected["baseline"], str)
        or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", expected["baseline"])
        or (expected["sql"] is not None and (
            not isinstance(expected["sql"], str)
            or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", expected["sql"])
        ))
    ):
        raise ValueError("Exact central review identities must be bound")
    if expected["sql"] is None:
        verify_no_changed_sql(manifest, api=api)
    main = (
        api("repos/Synergie-ITCI/.github/git/ref/heads/main")
        .get("object", {})
        .get("sha", "")
    )
    if not re.fullmatch(r"[0-9a-f]{40}", main):
        raise ValueError("Live central policy source unavailable")
    now = now or datetime.now(UTC)
    end = datetime.fromisoformat(manifest["expires_at"])
    if now.utcoffset() is None or end.utcoffset() is None:
        raise ValueError("Execution window must include a timezone")
    for kind, path, expiry_key in (
        ("baseline", "policy/pr-qa-policy.json", "expires_after"),
        ("sql", "policy/audited-migration-authorizations.json", "expires_at"),
    ):
        if kind == "sql" and expected["sql"] is None:
            continue
        content = api(f"repos/Synergie-ITCI/.github/contents/{path}?ref={main}")
        if content.get("type") != "file" or content.get("encoding") != "base64":
            raise ValueError("Live central review records unavailable")
        encoded = content.get("content", "")
        if not isinstance(encoded, str) or len(encoded) > 1_500_000:
            raise ValueError("Central review record size or encoding differs")
        payload = json.loads(base64.b64decode(encoded))
        if kind == "baseline" and (
            not isinstance(payload, dict) or payload.get("version") != 1
        ):
            raise TypeError("Central policy schema differs")
        rows = (
            payload.get("one_time_baseline_alignments")
            if kind == "baseline"
            else payload
        )
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise TypeError("Central review records are malformed")
        matches = [row for row in rows if row.get("authorization_id") == expected[kind]]
        if len(matches) != 1:
            raise ValueError("Central review identity is absent, revoked or ambiguous")
        row = matches[0]
        # These files come only from verify_qa_policy_evidence: the selected,
        # protected immutable QA release proved by the successful detector and
        # final report. Executor code is a separate immutable reference.
        bundled = activated_policies[path]
        bundled_rows = (
            bundled["one_time_baseline_alignments"] if kind == "baseline" else bundled
        )
        activated = [
            item
            for item in bundled_rows
            if item.get("authorization_id") == expected[kind]
        ]
        if activated != [row]:
            raise ValueError(
                "Live review differs from the activated immutable QA release"
            )
        schema_path = (
            "one-time-baseline.schema.json"
            if kind == "baseline"
            else "audited-migration-authorizations.schema.json"
        )
        schema = json.loads((ROOT / "schemas" / schema_path).read_text())
        if schema_errors(row if kind == "baseline" else [row], schema):
            raise ValueError(
                "Activated review schema is incompatible with this executor"
            )
        binding = {
            "repository": REPOSITORY,
            "repository_id": 1315697868,
            "pr_number": manifest["promotion_pr"],
            "base_ref": "main",
            "expected_head_sha": manifest["application"]["source_sha"],
            "expected_base_sha": manifest["base_sha"],
        }
        if any(row.get(key) != value for key, value in binding.items()) or (
            kind == "baseline" and row.get("enabled") is not True
        ):
            raise ValueError("Central review no longer binds this exact candidate")
        issued = datetime.fromisoformat(row["issued_at"])
        expiry = datetime.fromisoformat(row[expiry_key])
        if (
            issued.utcoffset() is None
            or expiry.utcoffset() is None
            or not issued <= now < end <= expiry
            or not timedelta(0) < expiry - issued <= timedelta(hours=24)
        ):
            raise ValueError("Execution exceeds the current central review window")
