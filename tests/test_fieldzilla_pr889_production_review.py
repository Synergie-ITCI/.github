"""The exact clinical export review binds source and migration without deployment authority."""

import json
from datetime import datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Synergie-ITCI/programme-management-platform"
HEAD = "d5b7c1e6c7db19b60e8ba51cf1bdc99ddbe3ce58"
BASE = "798e14977606e4485552a290a7801048b3acbc04"
MIGRATION_SHA256 = "0a3f5bfb9e7d74b1f621b89f3cb7e16efacdac1f9a97e16c1fe8e0e79d6a2676"


def _window(row: dict[str, object], expiry_key: str) -> None:
    issued = datetime.fromisoformat(str(row["issued_at"]).replace("Z", "+00:00"))
    expiry = datetime.fromisoformat(str(row[expiry_key]).replace("Z", "+00:00"))
    assert issued < expiry <= issued + timedelta(hours=24)


def test_exact_pr889_baseline_review_has_no_relaxation() -> None:
    policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
    rows = [
        row for row in policy["one_time_baseline_alignments"]
        if row.get("repository") == REPOSITORY and row.get("pr_number") == 889
    ]
    assert len(rows) == 1
    row = rows[0]
    assert (row["expected_head_sha"], row["expected_base_sha"]) == (HEAD, BASE)
    assert (row["head_ref"], row["base_ref"]) == ("feat/clinical-question-exports", "main")
    assert (row["allowed_changed_files"], row["allowed_effective_additions"]) == (24, 1554)
    assert row["relaxations"] == []
    _window(row, "expires_after")


def test_exact_pr889_sql_review_binds_only_migration_0082() -> None:
    rows = json.loads((ROOT / "policy/audited-migration-authorizations.json").read_text())
    matches = [
        row for row in rows
        if row.get("repository") == REPOSITORY and row.get("pr_number") == 889
    ]
    assert len(matches) == 1
    row = matches[0]
    assert (row["expected_head_sha"], row["expected_base_sha"]) == (HEAD, BASE)
    assert row["migration_path"] == (
        "apps/api/alembic/versions/20261128_0082_clinical_question_exports.py"
    )
    assert row["migration_sha256"] == MIGRATION_SHA256
    assert row["delete_fingerprints"] == []
    assert row["approved_reviewer"] == {"login": "SaurabhVermaIN", "id": 52234089}
    _window(row, "expires_at")
