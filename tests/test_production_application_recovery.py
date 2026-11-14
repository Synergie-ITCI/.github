"""Journal assessment must fail closed without issuing an execution request."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

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


class RecoveryAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def test_unacknowledged_migration_is_never_retryable(self):
        manifest = {"scope": "production", "application": {"source_sha": "a"}}
        path = journal(
            self.folder,
            manifest,
            {
                "event": "task_launch_requested",
                "kind": "migration",
                "phase": "migration",
            },
            {"event": "mutation_started", "action": "run-task"},
        )
        result = assess(manifest, path)
        self.assertEqual(
            result["phase"], "migration_outcome_requires_live_reconciliation"
        )
        self.assertEqual(result["unacknowledged_mutation"], "run-task")
        self.assertIs(result["automatic_retry_allowed"], False)

    def test_attested_migration_remains_non_retryable(self):
        manifest = {"scope": "production"}
        path = journal(
            self.folder,
            manifest,
            {
                "event": "task_launch_requested",
                "kind": "migration",
                "phase": "migration",
            },
            {"event": "database_attested", "phase": "after", "revisions": ["r1"]},
        )
        result = assess(manifest, path)
        self.assertEqual(result["phase"], "migration_attested_after_execution")
        self.assertIs(result["automatic_retry_allowed"], False)

    def test_wrong_manifest_is_rejected(self):
        path = journal(self.folder, {"scope": "production"})
        with self.assertRaisesRegex(ValueError, "exact manifest"):
            assess({"scope": "production", "changed": True}, path)
