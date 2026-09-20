import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "actions" / "ssm-artifact-promoter" / "promote.py"
spec = importlib.util.spec_from_file_location("ssm_artifact_promoter", MODULE_PATH)
promote = importlib.util.module_from_spec(spec)
sys.modules["ssm_artifact_promoter"] = promote
spec.loader.exec_module(promote)


class SsmArtifactPromoterTests(unittest.TestCase):
    def config(self, **overrides):
        values = {
            "expected_repository": "Synergie-ITCI/telepathy-operations-web",
            "expected_repository_id": "1303926139",
            "expected_environment": "uat",
            "aws_region": "ap-south-1",
            "ssm_instance_id": "mi-0dc488c7be58166a4",
            "artifact_bucket": "synergie-hub-release-artifacts-918870682888-ap-south-1",
            "artifact_key": "telepathy-operations-web/123/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/release.tgz",
            "artifact_sha256": "b" * 64,
            "remote_script_key": "telepathy-operations-web/123/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/remote-deploy.sh",
            "remote_script_sha256": "c" * 64,
            "allowed_artifact_prefix": "telepathy-operations-web/123/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
            "deploy_ref": "a" * 40,
            "rollback_ref": "d" * 40,
            "app_root": "/var/www/telepathy-operations-web",
            "app_user": "ubuntu",
            "validation_url": "https://uat.synergieinsights.in/",
            "api_health_url": "https://uat.synergieinsights.in/api/operations/health",
            "command_timeout_seconds": 480,
            "poll_interval_seconds": 1,
            "poll_attempts": 2,
            "presign_expires_seconds": 900,
            "evidence_path": "evidence.json",
        }
        values.update(overrides)
        return promote.PromotionConfig(**values)

    def env(self):
        return {
            "GITHUB_REPOSITORY": "Synergie-ITCI/telepathy-operations-web",
            "GITHUB_REPOSITORY_ID": "1303926139",
        }

    def test_valid_telepathy_uat_inputs_are_accepted(self):
        with patch.dict(os.environ, self.env(), clear=False):
            promote.validate_config(self.config())

    def test_rejects_wrong_repository_environment_and_instance(self):
        cases = [
            {"expected_repository": "Synergie-ITCI/other"},
            {"expected_repository_id": "999"},
            {"expected_environment": "production"},
            {"ssm_instance_id": "mi-not-valid"},
        ]
        for change in cases:
            with self.subTest(change=change), patch.dict(os.environ, self.env(), clear=False):
                with self.assertRaises(ValueError):
                    promote.validate_config(self.config(**change))

    def test_rejects_malformed_hashes_and_mutable_refs(self):
        cases = [
            {"deploy_ref": "main"},
            {"rollback_ref": "release"},
            {"deploy_ref": "a" * 40, "rollback_ref": "a" * 40},
            {"artifact_sha256": "abc"},
            {"remote_script_sha256": "abc"},
        ]
        for change in cases:
            with self.subTest(change=change), patch.dict(os.environ, self.env(), clear=False):
                with self.assertRaises(ValueError):
                    promote.validate_config(self.config(**change))

    def test_rejects_path_traversal_and_cross_prefix_artifacts(self):
        cases = [
            {"artifact_key": "/telepathy-operations-web/123/release.tgz"},
            {"artifact_key": "telepathy-operations-web/123/../release.tgz"},
            {"artifact_key": "other/123/release.tgz"},
            {"remote_script_key": "telepathy-operations-web/123/script;bad.sh"},
            {"app_root": "../tmp/app"},
            {"app_user": "ubuntu;bad"},
        ]
        for change in cases:
            with self.subTest(change=change), patch.dict(os.environ, self.env(), clear=False):
                with self.assertRaises(ValueError):
                    promote.validate_config(self.config(**change))

    def test_builds_structured_ssm_command_with_quoted_values(self):
        config = self.config()
        params = promote.build_ssm_parameters(config, "https://artifact.example/release.tgz", "https://artifact.example/script.sh")
        commands = params["commands"]
        self.assertEqual(params["executionTimeout"], ["540"])
        self.assertIn("curl --fail --silent --show-error --location --max-time 120", commands[4])
        self.assertIn("sha256sum -c -", commands[5])
        self.assertIn("sudo -u ubuntu -H env", commands[7])
        self.assertIn("DEPLOY_REF=" + config.deploy_ref, commands[7])
        self.assertIn("ROLLBACK_REF=" + config.rollback_ref, commands[7])
        self.assertNotIn(";", commands[7].split("env ", 1)[1].split(" timeout ", 1)[0])

    def test_promote_writes_evidence_and_cancels_on_timeout(self):
        config = self.config(poll_attempts=1)
        calls = []

        def fake_json(args, check=True):
            calls.append(args)
            if args[:3] == ["aws", "ssm", "send-command"]:
                return {"CommandId": "abc-123"}
            if args[:3] == ["aws", "ssm", "get-command-invocation"]:
                return {"Status": "InProgress", "ResponseCode": -1}
            raise AssertionError(args)

        def fake_text(args, check=True):
            calls.append(args)
            if args[:3] == ["aws", "s3", "presign"]:
                return "https://signed.example/object"
            if args[:3] == ["aws", "ssm", "cancel-command"]:
                return ""
            raise AssertionError(args)

        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.env(), clear=False), \
                patch.object(promote, "run_json", side_effect=fake_json), \
                patch.object(promote, "run_text", side_effect=fake_text), \
                patch.object(promote.time, "sleep", return_value=None):
            config = self.config(poll_attempts=1, evidence_path=str(Path(tmp) / "evidence.json"))
            self.assertEqual(promote.promote(config), 1)
            evidence = Path(config.evidence_path).read_text()
            self.assertIn('"command_id": "abc-123"', evidence)
            self.assertTrue(any(call[:3] == ["aws", "ssm", "cancel-command"] for call in calls))


if __name__ == "__main__":
    unittest.main()
