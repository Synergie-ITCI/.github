import json
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fieldzilla-production"))
from approval_receipts import ApprovalReceipt
from execution_gate import approval_text, manifest_digest


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.raw = b'{"target":"synthetic-rehearsal"}'
        now = datetime.now(UTC)
        self.expiry = (now + timedelta(minutes=30)).isoformat()
        created = (now - timedelta(minutes=1)).isoformat()
        self.comment = {
            "id": 123,
            "user": {"login": "SaurabhVermaIN", "id": 52234089},
            "author_association": "OWNER",
            "issue_url": "https://api.github.com/repos/Synergie-ITCI/programme-management-platform/issues/712",
            "created_at": created,
            "updated_at": created,
            "body": approval_text("rehearsal", manifest_digest(self.raw), self.expiry),
        }
        self.rows = []
        self.native = False
        self.posts = 0

    def api(self, path, method="GET", payload=None):
        if path.endswith("environments/synergie-app-production"):
            return {
                "protection_rules": [{"type": "required_reviewers"}]
                if self.native
                else []
            }
        if path.endswith("issues/comments/123"):
            return self.comment
        if "deployments?" in path:
            return self.rows
        if method == "POST" and path.endswith("/deployments"):
            self.posts += 1
            row = {"id": self.posts, **payload}
            self.rows.append(row)
            return row
        raise AssertionError(path)

    def receipt(self, **changes):
        args = {
            "api": self.api,
            "raw_manifest": self.raw,
            "operation": "rehearsal",
            "promotion_pr": 712,
            "comment_id": 123,
            "expires_at": self.expiry,
            "caller_sha": "a" * 40,
            "run_id": "456",
            "run_attempt": "1",
        }
        args.update(changes)
        return ApprovalReceipt(**args)

    def test_once_then_only_this_run_can_continue(self):
        owner = self.receipt()
        owner.verify()
        self.assertEqual(owner.consume(), 1)
        owner.verify()
        with self.assertRaises(ValueError):
            self.receipt().verify()
        with self.assertRaises(ValueError):
            owner.consume()
        self.assertEqual(self.posts, 1)

    def test_native_review_cannot_be_bypassed(self):
        self.native = True
        with self.assertRaises(ValueError):
            self.receipt().consume()
        self.assertEqual(self.posts, 0)

    def test_edited_comment_and_wrong_association_cannot_be_consumed(self):
        self.comment["updated_at"] = datetime.now(UTC).isoformat()
        with self.assertRaises(ValueError):
            self.receipt().consume()
        self.assertEqual(self.posts, 0)

    def test_changed_receipt_or_duplicate_cannot_continue(self):
        owner = self.receipt()
        owner.consume()
        self.rows[0]["payload"]["run_id"] = "other-run"
        with self.assertRaises(ValueError):
            owner.verify()

    def test_workflow_rerun_cannot_reuse_an_old_approval(self):
        with self.assertRaises(ValueError):
            self.receipt(run_attempt="2")

    def test_string_payload_history_is_still_consumed(self):
        owner = self.receipt()
        owner.consume()
        self.rows[0]["payload"] = json.dumps(self.rows[0]["payload"])
        with self.assertRaises(ValueError):
            self.receipt().verify()

    def test_receipt_cannot_change_operation_or_attempt_within_this_run(self):
        owner = self.receipt()
        owner.consume()
        payload = self.rows[0]["payload"]
        for key, wrong in (("operation", "rollout"), ("run_attempt", 2)):
            with self.subTest(key=key):
                original = payload[key]
                payload[key] = wrong
                with self.assertRaises(ValueError):
                    owner.verify()
                payload[key] = original

    def test_malformed_remote_history_fails_before_consumption(self):
        self.rows = {}
        with self.assertRaises(TypeError):
            self.receipt().consume()
        self.assertEqual(self.posts, 0)
