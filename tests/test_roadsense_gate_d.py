"""Negative tests for the proposed, inactive RoadSense Gate D verifier."""

import copy
import datetime as dt
import hashlib
import io
import json
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import roadsense_gate_d as gate  # noqa: E402

NOW = dt.datetime(2026, 10, 20, 12, 0, tzinfo=dt.UTC)
SHA = "a" * 40


def run(run_id, path, actor):
    return {
        "id": run_id,
        "head_repository": {"full_name": gate.REPO, "id": gate.REPO_ID},
        "path": path, "event": "workflow_dispatch", "head_branch": "main",
        "head_sha": SHA, "status": "completed", "conclusion": "success",
        "run_attempt": 1, "actor": {"login": actor[0], "id": actor[1]},
        "triggering_actor": {"login": actor[0], "id": actor[1]},
        "created_at": "2026-10-20T11:00:00Z" if run_id == 10 else "2026-10-20T11:05:00Z",
    }


def zipped(record):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("approval.json", json.dumps(record, sort_keys=True).encode())
    return stream.getvalue()


def fixture():
    record = {
        "repository": gate.REPO, "repository_id": gate.REPO_ID,
        "requester_login": "SaurabhVermaIN", "requester_id": 52234089,
        "approver_login": "SaurabhVermaIN", "approver_id": 52234089,
        "intent_run_id": 10, "approval_run_id": 11, "release_id": "roadsense-20261020-01",
        "source_sha": SHA, "image_digest": "sha256:" + "b" * 64,
        "database_sha256": "c" * 64, "database_s3_version": "v1xyz",
        "policy_version": "2026-10-16-release-candidate-hold-v1",
        "environment": gate.ENVIRONMENT, "ssm_target": gate.SSM_TARGET,
        "rollback_image_digest": "sha256:" + "d" * 64,
        "rollback_database_sha256": "e" * 64,
        "issued_at": "2026-10-20T11:06:00Z", "expires_at": "2026-10-20T12:06:00Z",
    }
    intent = run(10, gate.INTENT_PATH, gate.AUTHORITY)
    approval = run(11, gate.APPROVAL_PATH, gate.AUTHORITY)
    blob = zipped(record)
    artifact = {
        "id": 12, "name": gate.ARTIFACT_NAME, "workflow_run": {"id": 11},
        "expired": False, "size_in_bytes": len(blob),
        "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
    }
    return record, {key: record[key] for key in gate.TUPLE}, intent, approval, artifact, blob, SHA, []


class GateDTests(unittest.TestCase):
    def assert_rejected(self, index, mutate):
        args = list(copy.deepcopy(fixture()))
        mutate(args[index], args)
        with self.assertRaises(gate.Rejected):
            gate.validate(*args, NOW, gate.AUTHORITY)

    def test_authorized_saurabh_self_approval(self):
        gate.validate(*fixture(), NOW, gate.AUTHORITY)

    def test_approval_for_other_requester(self):
        args = list(fixture())
        args[0]["requester_login"], args[0]["requester_id"] = "Developer", 123
        args[2] = run(10, gate.INTENT_PATH, ("Developer", 123))
        args[5] = zipped(args[0])
        args[4]["digest"] = "sha256:" + hashlib.sha256(args[5]).hexdigest()
        gate.validate(*args, NOW, ("Developer", 123))

    def test_different_deployment_actor_rejected(self):
        with self.assertRaises(gate.Rejected):
            gate.validate(*fixture(), NOW, ("OtherUser", 777))

    def test_missing_approval(self):
        self.assert_rejected(0, lambda record, _: record.clear())

    def test_forged_artifact(self):
        self.assert_rejected(5, lambda blob, args: args.__setitem__(5, blob + b"forged"))

    def test_stale_approval(self):
        self.assert_rejected(0, lambda record, _: record.__setitem__("expires_at", "2026-10-20T11:59:00Z"))

    def test_replayed_approval(self):
        self.assert_rejected(7, lambda deployments, _: deployments.append({"environment": gate.MARKER_ENVIRONMENT, "payload": {"approval_run_id": 11}}))

    def test_reused_release_id(self):
        self.assert_rejected(7, lambda deployments, _: deployments.append({"environment": gate.MARKER_ENVIRONMENT, "payload": {"release_id": "roadsense-20261020-01"}}))

    def test_every_release_binding_mismatch(self):
        for key in gate.TUPLE:
            with self.subTest(key=key):
                self.assert_rejected(1, lambda expected, _, key=key: expected.__setitem__(key, "wrong"))

    def test_malformed_release_tuple_fails_closed(self):
        self.assert_rejected(0, lambda record, _: record.__setitem__("image_digest", 123))
        self.assert_rejected(1, lambda expected, _: expected.__setitem__("database_sha256", None))

    def test_artifact_without_provenance_fails_closed(self):
        self.assert_rejected(4, lambda artifact, _: artifact.__setitem__("workflow_run", None))

    def test_unauthorized_approver(self):
        self.assert_rejected(3, lambda approval, _: approval["actor"].update(login="Attacker", id=999))

    def test_forged_record_identity(self):
        self.assert_rejected(0, lambda record, _: record.__setitem__("approver_id", 999))

    def test_wrong_workflow_or_branch(self):
        self.assert_rejected(3, lambda approval, _: approval.__setitem__("path", ".github/workflows/other.yml"))
        self.assert_rejected(3, lambda approval, _: approval.__setitem__("head_branch", "feature"))

    def test_rerun_and_changed_actor(self):
        self.assert_rejected(3, lambda approval, _: approval.__setitem__("run_attempt", 2))
        self.assert_rejected(3, lambda approval, _: approval["triggering_actor"].update(id=999))

    def test_main_moved(self):
        self.assert_rejected(6, lambda sha, args: args.__setitem__(6, "f" * 40))

    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(gate.Rejected):
            gate.strict_json(b'{"repository":"one","repository":"two"}')

    def test_expected_tuple_unknown_field_rejected(self):
        data = {key: "x" for key in gate.TUPLE}
        data["skip_approval"] = True
        with self.assertRaises(gate.Rejected):
            gate.strict_expected(json.dumps(data).encode())

    def test_composite_gate_precedes_any_production_permission(self):
        action = (Path(__file__).resolve().parents[1] / "actions/roadsense-gate-d/action.yml").read_text()
        self.assertIn("--mark-used", action)
        self.assertNotIn("id-token: write", action)
        self.assertNotIn("configure-aws-credentials", action)
        self.assertNotIn("ssm send-command", action)

    def test_no_credential_or_ssm_operation_in_verifier(self):
        source = Path(gate.__file__).read_text()
        self.assertNotIn("configure-aws-credentials", source)
        self.assertNotIn("ssm send-command", source)
        self.assertNotIn("id-token: write", source)


if __name__ == "__main__":
    unittest.main()
