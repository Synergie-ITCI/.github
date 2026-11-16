"""Execution-time expiry/revocation check; never issues or relaxes QA policy.

QA remains authoritative for content, SQL fingerprints and dependencies. This
extra execution guard prevents a previously green run from extending the life
of its centrally issued, exact-PR review records.
"""

import base64
import hashlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from execution_gate import REPOSITORY
from merge_metadata_recovery import verify_merge_metadata_recovery

ROOT = Path(__file__).resolve().parents[2]
SQL_FREE_PRODUCTION_SOURCE = "08026deb18c37ec3dcb845abca93209625a2fc88"
SQL_FREE_PRODUCTION_BASE = "0e6ab78dfeeb8348a9c3ab0c097e4989e4468fce"
SQL_FREE_PRODUCTION_MIGRATION = "apps/api/alembic/versions/20261113_0074_tenant_bootstrap_owner_rls.py"
SQL_FREE_PRODUCTION_MIGRATION_SHA256 = "3f3650808b57bedbe2f339278a98c03226a3af9c16af22cd4d612a9af7d6b3cf"
SQL_FREE_UPDATE_SOURCE = "7ab72476c96b853a6c18a5b91223622fbba9e173"
SQL_FREE_UPDATE_BASE = "52ae1bedaffe089f611048e13199dfaaa769d553"
SQL_FREE_PR783_SOURCE = "2817ab3ad079e7795ca723e9cd6fbbc705f2bc8f"
SQL_FREE_PR783_BASE = "79b9676aac733a9a78a6901af48e76fa93688828"
SQL_FREE_UPDATE_REVISIONS = ["20260909_0041", "20261113_0074"]
SQL_FREE_UPDATE_BINDINGS = {
    780: (SQL_FREE_UPDATE_SOURCE, SQL_FREE_UPDATE_BASE),
    783: (SQL_FREE_PR783_SOURCE, SQL_FREE_PR783_BASE),
}
PR787_SOURCE = "a6e35a7ad36fbc21417a8575bb723a7948a5e8c7"
PR787_BASE = "739fd2759b949e3228affb69cd090b64613b159a"
PR786_HEAD = "2b0753f08aaabdacb780d1abd35fc2d5e80bc181"
PR786_BASE = "576fba59c0d5958cb623351b29201b4d4aef589c"
PR786_TREE = "5af21a0fe5f9d89a7d96dd1d50230318e67a63d2"
PR787_MIGRATION = "apps/api/alembic/versions/20261116_0075_operational_role_permissions.py"
PR787_MIGRATION_SHA256 = "2432a1c42d5a8a65e4e5f67f1535450d77526edaa25c1bb2d96761daae967dc4"
PR787_FILES = {
    ".github/workflows/fieldzilla-production-hosting.yml",
    "deploy/production/hosting/prepare_application_manifest.py",
    "deploy/production/hosting/test_prepare_application_manifest.py",
}
sys.path.insert(0, str(ROOT / "pr-qa"))
from baseline_authorization import schema_errors


def is_sql_free_update(manifest):
    """Allow only exact reviewed hotfixes to keep the already-current DB."""
    source_and_base = SQL_FREE_UPDATE_BINDINGS.get(manifest.get("promotion_pr"))
    return (
        manifest.get("scope") == "production"
        and manifest.get("operation") == "rollout"
        and source_and_base is not None
        and manifest.get("base_sha") == source_and_base[1]
        and manifest.get("application", {}).get("source_sha") == source_and_base[0]
        and manifest.get("review_authorizations", {}).get("sql") is None
        and manifest.get("database") == {
            "name": "fieldzilla_production",
            "role": "pmp_fieldzilla_prod_migrator",
            "before": SQL_FREE_UPDATE_REVISIONS,
            "after": SQL_FREE_UPDATE_REVISIONS,
        }
    )


def verify_no_changed_sql(manifest, *, api):
    """Bind SQL-free publication or an exact reviewed production rollout."""
    scope = manifest.get("scope")
    if scope == "production" and not is_sql_free_update(manifest):
        # PR743's reviewed additive RLS migration is inherited by the exact
        # PR772 image. No other production source or DB transition may use this
        # exception to the existing exact-PR SQL-review requirement.
        database = manifest.get("database", {})
        if (
            not isinstance(database, dict)
            or manifest.get("promotion_pr") != 772
            or manifest.get("base_sha") != SQL_FREE_PRODUCTION_BASE
            or manifest.get("application", {}).get("source_sha") != SQL_FREE_PRODUCTION_SOURCE
            or database.get("before") != ["20260909_0041", "20261109_0073"]
            or database.get("after") != ["20260909_0041", "20261113_0074"]
        ):
            raise ValueError("SQL-free production rollout binding differs")
        content = api(
            f"repos/{REPOSITORY}/contents/{SQL_FREE_PRODUCTION_MIGRATION}"
            f"?ref={SQL_FREE_PRODUCTION_SOURCE}"
        )
        if content.get("type") != "file" or content.get("encoding") != "base64":
            raise ValueError("Reviewed production migration source is unavailable")
        encoded = content.get("content", "")
        if not isinstance(encoded, str) or len(encoded) > 65536:
            raise ValueError("Reviewed production migration source is oversized")
        migration = base64.b64decode(encoded.replace("\n", ""), validate=True)
        if hashlib.sha256(migration).hexdigest() != SQL_FREE_PRODUCTION_MIGRATION_SHA256:
            raise ValueError("Reviewed production migration bytes differ")
    elif scope not in {"production", "production-images"}:
        raise ValueError("Only image publication or the exact reviewed rollout may omit SQL review")
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


def verify_pr787_inherited_migration(manifest, *, api):
    """Prove the audited migration is inherited unchanged from the PR #786 merge."""
    if manifest.get("scope") != "production" or manifest.get("promotion_pr") != 787:
        return
    if (
        manifest.get("application", {}).get("source_sha") != PR787_SOURCE
        or manifest.get("base_sha") != PR787_BASE
        or manifest.get("review_authorizations", {}).get("sql")
        != "407d605f-815b-4516-b714-5b72bf6c1422"
        or manifest.get("database") != {
            "name": "fieldzilla_production",
            "role": "pmp_fieldzilla_prod_migrator",
            "before": ["20260909_0041", "20261113_0074"],
            "after": ["20260909_0041", "20261116_0075"],
        }
    ):
        raise ValueError("PR #787 inherited migration binding differs")
    base = api(f"repos/{REPOSITORY}/git/commits/{PR787_BASE}")
    original = api(f"repos/{REPOSITORY}/git/commits/{PR786_HEAD}")
    source = api(f"repos/{REPOSITORY}/git/commits/{PR787_SOURCE}")
    if (
        base.get("sha") != PR787_BASE
        or [row.get("sha") for row in base.get("parents", [])] != [PR786_BASE, PR786_HEAD]
        or base.get("tree", {}).get("sha") != PR786_TREE
        or base.get("verification", {}).get("verified") is not True
        or original.get("tree", {}).get("sha") != PR786_TREE
        or source.get("sha") != PR787_SOURCE
        or [row.get("sha") for row in source.get("parents", [])] != [PR787_BASE]
    ):
        raise ValueError("Reviewed PR #786 merge or PR #787 ancestry differs")
    reply = api(f"repos/{REPOSITORY}/contents/{PR787_MIGRATION}?ref={PR787_SOURCE}")
    encoded = reply.get("content", "")
    if (
        reply.get("type") != "file"
        or reply.get("encoding") != "base64"
        or not isinstance(encoded, str)
        or len(encoded) > 65536
        or hashlib.sha256(base64.b64decode(encoded.replace("\n", ""), validate=True)).hexdigest()
        != PR787_MIGRATION_SHA256
    ):
        raise ValueError("Inherited migration 0075 bytes differ")
    files = api(f"repos/{REPOSITORY}/pulls/787/files?per_page=100&page=1")
    if (
        not isinstance(files, list)
        or len(files) != len(PR787_FILES)
        or any(not isinstance(row, dict) or row.get("previous_filename") is not None for row in files)
        or {row.get("filename") for row in files} != PR787_FILES
    ):
        raise ValueError("PR #787 changed files differ from reviewed caller-only patch")


def verify_issued_windows(manifest, *, api, activated_policies, now=None):
    verify_pr787_inherited_migration(manifest, api=api)
    if activated_policies.get("__merge_metadata_recovery__") is True:
        verify_merge_metadata_recovery(
            manifest, api=api,
            activated_sha=manifest.get("qa_evidence", {}).get("policy_sha"),
            now=now,
        )
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
