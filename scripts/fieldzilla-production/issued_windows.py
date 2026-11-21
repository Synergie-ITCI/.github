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
SQL_FREE_PR802_SOURCE = "b55cf18a881c1722d307cac4c04114667e8379ea"
SQL_FREE_PR802_BASE = "cfbdc0e4d5ac2478ea33befff657e23570507e48"
SQL_FREE_PR804_SOURCE = "0d82540f4e2ca19a5edceea34d78728fea57fa46"
SQL_FREE_PR804_BASE = "254484811fe33ddcaa6c8bd5a105f76d8384d6eb"
SQL_FREE_PR806_SOURCE = "670b7482120cda2375fad491a270e0b00f833450"
SQL_FREE_PR806_BASE = "aa23b1b0bebbf4c5bf5dadc768e38a049e6b07d0"
SQL_FREE_PR808_SOURCE = "5d92dd585eda25391297bfd9d408c585f556a4d6"
SQL_FREE_PR808_BASE = "bd9b3bd3d6b0fa4d7e27448e09a674de3c601aa0"
SQL_FREE_PR811_SOURCE = "410badf52529ace7a7e05295f012c8ff6b50be3a"
SQL_FREE_PR811_BASE = "6a41100ee099ee7f0ed1d12ca222c4df7dcd704d"
SQL_FREE_PR814_SOURCE = "6b2b91e65452a705ae856678dfda1441f8377c6e"
SQL_FREE_PR814_BASE = "8ebd9e87912aa134d00462e08d9fdc757a3cb98b"
SQL_FREE_PR816_SOURCE = "d0760117e67cdff1c9b7aa9de7920533da4a35eb"
SQL_FREE_PR816_BASE = "85ee72c6e93a53411db87607dbb171aec638a149"
SQL_FREE_PR819_SOURCE = "59e520f20481ed2cc192d1c9a0ba569d480a5e90"
SQL_FREE_PR819_BASE = "ea29a5727ae4ac81b3c5aa6f2bad91eac1d546df"
SQL_FREE_UPDATE_REVISIONS = ["20260909_0041", "20261113_0074"]
SQL_FREE_PR802_REVISIONS = ["20260909_0041", "20261117_0077"]
SQL_FREE_UPDATE_BINDINGS = {
    780: (SQL_FREE_UPDATE_SOURCE, SQL_FREE_UPDATE_BASE, SQL_FREE_UPDATE_REVISIONS),
    783: (SQL_FREE_PR783_SOURCE, SQL_FREE_PR783_BASE, SQL_FREE_UPDATE_REVISIONS),
    802: (SQL_FREE_PR802_SOURCE, SQL_FREE_PR802_BASE, SQL_FREE_PR802_REVISIONS),
    804: (SQL_FREE_PR804_SOURCE, SQL_FREE_PR804_BASE, SQL_FREE_PR802_REVISIONS),
    806: (SQL_FREE_PR806_SOURCE, SQL_FREE_PR806_BASE, SQL_FREE_PR802_REVISIONS),
    808: (SQL_FREE_PR808_SOURCE, SQL_FREE_PR808_BASE, SQL_FREE_PR802_REVISIONS),
    811: (SQL_FREE_PR811_SOURCE, SQL_FREE_PR811_BASE, SQL_FREE_PR802_REVISIONS),
    814: (SQL_FREE_PR814_SOURCE, SQL_FREE_PR814_BASE, SQL_FREE_PR802_REVISIONS),
    816: (SQL_FREE_PR816_SOURCE, SQL_FREE_PR816_BASE, SQL_FREE_PR802_REVISIONS),
    819: (SQL_FREE_PR819_SOURCE, SQL_FREE_PR819_BASE, SQL_FREE_PR802_REVISIONS),
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
PR791_SOURCE = "8821f317a4316ec7bca639ac7b6d22e9f903cfd9"
PR791_BASE = "a1b883710bdd37ce915901dcfa86a837733a7b7b"
PR791_MIGRATION = "apps/api/alembic/versions/20261117_0076_tenant_owner_operational_delegation.py"
PR791_MIGRATION_SHA256 = "30bea9f387d9d9e50304a8e8f3dac1db7bb6e7adeda092d896b023c37c3b8681"
PR835_SOURCE = "54069e56d92bfc4546d924c7963e23db4a24e439"
PR835_BASE = "d63120d3a4664b163e5871aaf40eab6ad361af40"
PR835_MIGRATION = "apps/api/alembic/versions/20261121_0078_password_reset_tenant_lookup_rls.py"
PR835_MIGRATION_SHA256 = "e2e6991cc2f2807942b8e37d9d0f2ae65087f084f3694805426dfdb66b88cf35"
PR835_FILES = {
    PR835_MIGRATION,
    "apps/api/docs/password-reset-migration-0078.md",
    "apps/api/tests/architecture/test_password_management_contracts.py",
}
PR791_SQL_REVIEW = "50e42152-16ec-43c3-8bce-b8df5f4f10cf"
PR798_SOURCE = "ee2b975c9c5a4881d71c6cd46d17af4e2f33aeae"
PR798_BASE = "4c31546a984e3bda42d52b11a2ce268989991eab"
PR798_MERGE = "42566a33d50b9a0924b89e7603857446858703cb"
PR797_HEAD = "fd220a932b07a466ceb400d56ebcf22e6c06653c"
PR796_HEAD = "e080a80d6b1c6e3059d003a939e8c117134e7951"
PR794_HEAD = "0352baa1de50b44050e6061b028edc29995faa3f"
PR794_BASE = "35c22710266b12d595c83e37c4bd7249e94077ce"
PR794_MERGE = "2bb27d09cd8f9643ccc1fc75d3775753798e9dab"
PR796_MERGE = "4444cd46683eac6350e54336796610b82c5b6f82"
PR794_TREE = "828f27b5c1eee6862590adc22e751f3731274d6f"
PR796_TREE = "8d5087bf59c700e7f00ff88d6a70a778323596f4"
PR797_TREE = "7bd0d2cb95fb2c8a83265de8382e00d844b3fc6e"
PR798_TREE = "b2b70f169808e4d04a321049a3982c256caae995"
PR798_SQL_REVIEW = "b0f5dab9-3c63-4273-a8cb-4ca891f7c8ee"
PR798_REVIEWED_FILES = {
    "apps/api/alembic/versions/20261117_0077_mother_schema_bridge.py": "ce13743006d75236e47706abb27419388f85889d30a5bf94ae0bfd1c652ce5aa",
    "apps/api/alembic/versions/20261117_0076_tenant_owner_operational_delegation.py": PR791_MIGRATION_SHA256,
    "apps/api/alembic/production_bridge/otp_policy.py": "d996aab759d75bed5f93831f71163129a7deffdfd692dbc30f9cb8ad054bb71d",
    "apps/api/alembic/production_bridge/policy_correction_audit.py": "484242306a3ea50e7cc4015edd0b6a687f458a5558af82217cbdbedc053e20c5",
    "apps/api/alembic/production_bridge/production_baseline.py": "adebe0a50757125c18db47bebff23956ae85558a065151c77e94126908d0be0b",
    "apps/api/alembic/production_bridge/role_permissions.py": "376ac7a3d0cf0dc1dfe032739b4dc398f3e48e0c162908a408cca8093633d572",
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
            "before": source_and_base[2],
            "after": source_and_base[2],
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


def verify_pr791_migration(manifest, *, api):
    """Bind the forward role guard to the exact source and reviewed bytes."""
    if manifest.get("scope") != "production" or manifest.get("promotion_pr") != 791:
        return
    if (
        manifest.get("application", {}).get("source_sha") != PR791_SOURCE
        or manifest.get("base_sha") != PR791_BASE
        or manifest.get("review_authorizations", {}).get("sql") != PR791_SQL_REVIEW
        or manifest.get("database") != {
            "name": "fieldzilla_production",
            "role": "pmp_fieldzilla_prod_migrator",
            "before": ["20260909_0041", "20261116_0075"],
            "after": ["20260909_0041", "20261117_0076"],
        }
    ):
        raise ValueError("PR #791 role migration binding differs")
    reply = api(f"repos/{REPOSITORY}/contents/{PR791_MIGRATION}?ref={PR791_SOURCE}")
    encoded = reply.get("content", "")
    if (
        reply.get("type") != "file"
        or reply.get("encoding") != "base64"
        or not isinstance(encoded, str)
        or len(encoded) > 65536
        or hashlib.sha256(base64.b64decode(encoded.replace("\n", ""), validate=True)).hexdigest()
        != PR791_MIGRATION_SHA256
    ):
        raise ValueError("Reviewed migration 0076 bytes differ")


def verify_pr798_inherited_migration(manifest, *, api):
    """Bind the mother release to the reviewed production bridge and merge chain."""
    if manifest.get("scope") != "production" or manifest.get("promotion_pr") != 798:
        return
    if (
        manifest.get("application", {}).get("source_sha") != PR798_SOURCE
        or manifest.get("base_sha") != PR798_BASE
        or manifest.get("review_authorizations", {}).get("sql") != PR798_SQL_REVIEW
        or manifest.get("database") != {
            "name": "fieldzilla_production",
            "role": "pmp_fieldzilla_prod_migrator",
            "before": ["20260909_0041", "20261117_0076"],
            "after": ["20260909_0041", "20261117_0077"],
        }
    ):
        raise ValueError("PR #798 inherited bridge binding differs")
    chain = (
        (PR794_MERGE, [PR794_BASE, PR794_HEAD], PR794_TREE),
        (PR796_MERGE, [PR794_MERGE, PR796_HEAD], PR796_TREE),
        (PR798_BASE, [PR796_MERGE, PR797_HEAD], PR797_TREE),
        (PR798_MERGE, [PR798_BASE, PR798_SOURCE], PR798_TREE),
    )
    for sha, parents, tree in chain:
        commit = api(f"repos/{REPOSITORY}/git/commits/{sha}")
        if (
            commit.get("sha") != sha
            or [row.get("sha") for row in commit.get("parents", [])] != parents
            or commit.get("tree", {}).get("sha") != tree
            or commit.get("verification", {}).get("verified") is not True
        ):
            raise ValueError("Reviewed mother merge ancestry or tree differs")
    for sha, tree in (
        (PR794_HEAD, PR794_TREE),
        (PR796_HEAD, PR796_TREE),
        (PR797_HEAD, PR797_TREE),
        (PR798_SOURCE, PR798_TREE),
    ):
        commit = api(f"repos/{REPOSITORY}/git/commits/{sha}")
        if commit.get("sha") != sha or commit.get("tree", {}).get("sha") != tree:
            raise ValueError("Reviewed mother PR head tree differs")
    for path, expected in PR798_REVIEWED_FILES.items():
        content = api(f"repos/{REPOSITORY}/contents/{path}?ref={PR798_SOURCE}")
        encoded = content.get("content", "")
        if (
            content.get("type") != "file"
            or content.get("encoding") != "base64"
            or not isinstance(encoded, str)
            or len(encoded) > 131072
            or hashlib.sha256(base64.b64decode(encoded.replace("\n", ""), validate=True)).hexdigest()
            != expected
        ):
            raise ValueError(f"Reviewed mother production bridge bytes differ: {path}")
    files = api(f"repos/{REPOSITORY}/pulls/798/files?per_page=100&page=1")
    if (
        not isinstance(files, list)
        or len(files) != 37
        or any(
            not isinstance(row, dict)
            or row.get("previous_filename") is not None
            or not str(row.get("filename", "")).startswith("apps/mobile/")
            for row in files
        )
    ):
        raise ValueError("PR #798 changed files differ from reviewed mobile-only patch")


def verify_pr835_password_reset_migration(manifest, *, api):
    """Bind the restricted lookup migration to exact source and reviewed bytes."""
    if manifest.get("scope") != "production" or manifest.get("promotion_pr") != 835:
        return
    if (
        manifest.get("application", {}).get("source_sha") != PR835_SOURCE
        or manifest.get("base_sha") != PR835_BASE
        or not manifest.get("review_authorizations", {}).get("sql")
        or manifest.get("database") != {
            "name": "fieldzilla_production",
            "role": "pmp_fieldzilla_prod_migrator",
            "before": ["20260909_0041", "20261117_0077"],
            "after": ["20260909_0041", "20261121_0078"],
        }
    ):
        raise ValueError("PR #835 password reset migration binding differs")
    reply = api(f"repos/{REPOSITORY}/contents/{PR835_MIGRATION}?ref={PR835_SOURCE}")
    encoded = reply.get("content", "")
    if (
        reply.get("type") != "file"
        or reply.get("encoding") != "base64"
        or not isinstance(encoded, str)
        or len(encoded) > 65536
        or hashlib.sha256(base64.b64decode(encoded.replace("\n", ""), validate=True)).hexdigest()
        != PR835_MIGRATION_SHA256
    ):
        raise ValueError("Reviewed migration 0078 bytes differ")
    files = api(f"repos/{REPOSITORY}/pulls/835/files?per_page=100&page=1")
    if (
        not isinstance(files, list)
        or len(files) != len(PR835_FILES)
        or any(not isinstance(row, dict) or row.get("previous_filename") for row in files)
        or {row.get("filename") for row in files} != PR835_FILES
    ):
        raise ValueError("PR #835 changed files differ from reviewed patch")


def verify_issued_windows(manifest, *, api, activated_policies, now=None):
    verify_pr835_password_reset_migration(manifest, api=api)
    verify_pr787_inherited_migration(manifest, api=api)
    verify_pr791_migration(manifest, api=api)
    verify_pr798_inherited_migration(manifest, api=api)
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
