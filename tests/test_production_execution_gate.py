import hashlib
import importlib.util
import unittest
from datetime import UTC, datetime
from pathlib import Path

path = (
    Path(__file__).resolve().parents[1]
    / "scripts/fieldzilla-production/execution_gate.py"
)
spec = importlib.util.spec_from_file_location("production_execution_gate", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ExecutionGateTests(unittest.TestCase):
    def setUp(self):
        self.raw = b'{"source_sha":"candidate","target":"rehearsal"}\n'
        self.expiry = "2026-11-10T12:00:00Z"
        self.now = datetime(2026, 11, 10, 11, 0, tzinfo=UTC)
        self.comment = {
            "user": {"login": "SaurabhVermaIN", "id": 52234089},
            "issue_url": "https://api.github.com/repos/Synergie-ITCI/programme-management-platform/issues/712",
            "created_at": "2026-11-10T10:30:00Z",
            "updated_at": "2026-11-10T10:30:00Z",
            "body": module.approval_text(
                "rehearsal", hashlib.sha256(self.raw).hexdigest(), self.expiry
            ),
        }

    def check(self, **changes):
        args = {
            "operation": "rehearsal",
            "raw_manifest": self.raw,
            "promotion_pr": 712,
            "expires_at": self.expiry,
            "now": self.now,
        }
        args.update(changes)
        return module.verify_comment(self.comment, **args)

    def test_exact_approval(self):
        self.assertEqual(self.check(), hashlib.sha256(self.raw).hexdigest())

    def test_changed_bytes_or_operation_rejected(self):
        for mutation in ({"raw_manifest": self.raw + b" "}, {"operation": "rollout"}):
            with self.assertRaises(ValueError):
                self.check(**mutation)

    def test_reviewer_identity_issue_and_edits(self):
        for key, value in (
            ("user", {"login": "SaurabhVermaIN", "id": 1}),
            ("issue_url", self.comment["issue_url"] + "0"),
            ("updated_at", "2026-11-10T10:31:00Z"),
        ):
            old = self.comment[key]
            self.comment[key] = value
            with self.assertRaises(ValueError):
                self.check()
            self.comment[key] = old

    def test_expired_future_or_unbounded_windows(self):
        for now in (
            datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
            datetime(2026, 11, 10, 10, 0, tzinfo=UTC),
        ):
            with self.assertRaises(ValueError):
                self.check(now=now)
        self.expiry = "2026-11-10T13:00:00Z"
        with self.assertRaises(ValueError):
            self.check()

    def test_unknown_operation_or_non_object_manifest(self):
        with self.assertRaises(ValueError):
            self.check(operation="cutover-staging")
        with self.assertRaises(TypeError):
            module.manifest_digest(b"[]")
