"""Execution-time expiry/revocation check; never issues or relaxes QA policy.

QA remains authoritative for content, SQL fingerprints and dependencies. This
extra execution guard prevents a previously green run from extending the life
of its centrally issued, exact-PR review records.
"""

import base64
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from execution_gate import REPOSITORY


def verify_issued_windows(manifest, *, api, now=None, bundled_policies=None):
    expected = manifest.get("review_authorizations", {})
    if (
        not isinstance(expected, dict)
        or set(expected) != {"baseline", "sql"}
        or any(
            not isinstance(value, str)
            or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value)
            for value in expected.values()
        )
    ):
        raise ValueError("Both exact central review identities must be bound")
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
        bundled = (
            bundled_policies[path]
            if bundled_policies is not None
            else json.loads((Path(__file__).resolve().parents[2] / path).read_text())
        )
        bundled_rows = (
            bundled["one_time_baseline_alignments"] if kind == "baseline" else bundled
        )
        activated = [
            item
            for item in bundled_rows
            if item.get("authorization_id") == expected[kind]
        ]
        if activated != [row]:
            raise ValueError("Live review differs from the executing immutable release")
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
