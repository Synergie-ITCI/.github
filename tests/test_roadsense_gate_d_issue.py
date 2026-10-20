"""Manual release-intent and approval issuance must be exact and fail closed."""

import datetime as dt
import hashlib
import io
import json
import sys
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import roadsense_gate_d as gate  # noqa: E402
import roadsense_gate_d_issue as issue  # noqa: E402
from tests.test_roadsense_gate_d import fixture, NOW, SHA, zipped


class IssuanceTests(unittest.TestCase):
    def test_issue_intent_binds_authenticated_requester(self):
        expected = fixture()[1]
        record = issue.issue_intent(expected, ("Developer", 123, 10, SHA))
        self.assertEqual(record["requester_login"], "Developer")
        self.assertEqual(record["requester_id"], 123)
        self.assertEqual(record["intent_run_id"], 10)
        self.assertEqual({k: record[k] for k in gate.TUPLE}, expected)

    def test_issue_intent_rejects_mismatched_sha_and_policy(self):
        expected = fixture()[1]
        with self.assertRaises(gate.Rejected):
            issue.issue_intent(expected, ("Developer", 123, 10, "f" * 40))
        expected["environment"] = "staging"
        with self.assertRaises(gate.Rejected):
            issue.issue_intent(expected, ("Developer", 123, 10, SHA))

    def test_issue_approval_binds_intent_and_authority(self):
        approval, expected, intent_run, _, _, _, intent_artifact, intent_blob, _, _ = fixture()
        intent_record = {key: approval[key] for key in gate.INTENT_FIELDS}
        raw = json.dumps(intent_record, sort_keys=True).encode()
        digest = hashlib.sha256(raw).hexdigest()
        with patch.object(gate, "gh_json", return_value=intent_run), patch.object(gate, "get_artifact", return_value=(intent_artifact, intent_blob)):
            # Fixture zip uses default json.dumps(..., sort_keys=True), matching raw above.
            issued = issue.issue_approval(10, digest, ("SaurabhVermaIN", 52234089, 11, SHA), NOW)
        self.assertEqual(issued["approver_id"], 52234089)
        self.assertEqual(issued["requester_id"], 52234089)
        self.assertEqual(issued["expires_at"], "2026-10-20T13:00:00Z")
        self.assertEqual({k: issued[k] for k in gate.TUPLE}, expected)

    def test_wrong_approver_and_intent_hash_rejected(self):
        approval, _, intent_run, _, _, _, intent_artifact, intent_blob, _, _ = fixture()
        with patch.object(gate, "gh_json", return_value=intent_run), patch.object(gate, "get_artifact", return_value=(intent_artifact, intent_blob)):
            with self.assertRaises(gate.Rejected):
                issue.issue_approval(10, "0" * 64, ("Other", 999, 11, SHA), NOW)
            with self.assertRaises(gate.Rejected):
                issue.issue_approval(10, "0" * 64, ("SaurabhVermaIN", 52234089, 11, SHA), NOW)

    def test_context_rejects_nonmain_or_rerun(self):
        base = {
            "GITHUB_REPOSITORY": gate.REPO, "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_ACTOR": "SaurabhVermaIN", "GITHUB_ACTOR_ID": "52234089",
            "GITHUB_RUN_ID": "11", "GITHUB_SHA": SHA,
        }
        with patch.dict("os.environ", {**base, "GITHUB_REF": "refs/heads/feature"}, clear=True):
            with self.assertRaises(gate.Rejected):
                issue.context()
        with patch.dict("os.environ", {**base, "GITHUB_RUN_ATTEMPT": "2"}, clear=True):
            with self.assertRaises(gate.Rejected):
                issue.context()


if __name__ == "__main__":
    unittest.main()
