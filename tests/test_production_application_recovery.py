"""Journal assessment must fail closed without issuing an execution request."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "scripts/fieldzilla-production")
)
from application_recovery import assess


def journal(tmp_path, manifest, *events):
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    path = tmp_path / "journal.jsonl"
    rows = [{"event": "started", "scope": manifest["scope"], "manifest_sha256": digest}]
    rows.extend(events)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    return path


def test_unacknowledged_migration_is_never_retryable(tmp_path):
    manifest = {"scope": "production", "application": {"source_sha": "a"}}
    path = journal(
        tmp_path,
        manifest,
        {"event": "task_launch_requested", "kind": "migration", "phase": "migration"},
        {"event": "mutation_started", "action": "run-task"},
    )
    result = assess(manifest, path)
    assert result["phase"] == "migration_outcome_requires_live_reconciliation"
    assert result["unacknowledged_mutation"] == "run-task"
    assert result["automatic_retry_allowed"] is False


def test_attested_migration_remains_non_retryable(tmp_path):
    manifest = {"scope": "production"}
    path = journal(
        tmp_path,
        manifest,
        {"event": "task_launch_requested", "kind": "migration", "phase": "migration"},
        {"event": "database_attested", "phase": "after", "revisions": ["r1"]},
    )
    result = assess(manifest, path)
    assert result["phase"] == "migration_attested_after_execution"
    assert result["automatic_retry_allowed"] is False


def test_wrong_manifest_is_rejected(tmp_path):
    path = journal(tmp_path, {"scope": "production"})
    with pytest.raises(ValueError, match="exact manifest"):
        assess({"scope": "production", "changed": True}, path)
