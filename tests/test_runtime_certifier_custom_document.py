import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "tools" / "runtime_certifier.py"
spec = importlib.util.spec_from_file_location("runtime_certifier_custom_document", MODULE)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

DEPLOY = "a" * 40
ROLLBACK = "b" * 40


def config(**overrides):
    values = dict(
        instance_id="i-0123456789abcdef0",
        region="ap-south-1",
        app_path="/srv/production-app",
        app_user="deploy",
        validation_url="https://example.invalid/health",
        deploy_ref=DEPLOY,
        rollback_ref=ROLLBACK,
        runtime_kind="php-fpm",
        runtime_version="8.2",
        web_server="apache",
    )
    values.update(overrides)
    return mod.Config(**values)


class RuntimeCertifierCustomDocumentTests(unittest.TestCase):
    def invoke(self, cfg, output):
        calls = []

        def aws(args, **kwargs):
            calls.append(args)
            if "send-command" in args:
                payload_path = args[args.index("--parameters") + 1].removeprefix("file://")
                calls.append(json.loads(Path(payload_path).read_text(encoding="utf-8")))
                return subprocess.CompletedProcess(args, 0, "command-id")
            if "wait" in args:
                return subprocess.CompletedProcess(args, 0, "")
            result = {"Status": "Success", "StandardOutputContent": output, "StandardErrorContent": ""}
            return subprocess.CompletedProcess(args, 0, json.dumps(result))

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            mod, "run_command", side_effect=aws
        ), mock.patch.dict("os.environ", {"GITHUB_OUTPUT": f"{directory}/output"}):
            result = mod.certify(cfg)
            github_output = Path(directory, "output").read_text(encoding="utf-8")
        return result, calls, github_output

    def test_legacy_mode_preserves_run_shell_script_payload(self):
        result, calls, _ = self.invoke(config(), "DEPLOY_STATE=ALREADY_DEPLOYED\n")
        self.assertEqual(result, 0)
        send = next(call for call in calls if isinstance(call, list) and "send-command" in call)
        self.assertEqual(send[send.index("--document-name") + 1], "AWS-RunShellScript")
        payload = next(call for call in calls if isinstance(call, dict))
        self.assertEqual(list(payload), ["commands"])

    def test_restricted_document_receives_only_exact_refs(self):
        evidence = (
            "RUNTIME_CERTIFIER=PASS\nREADY_TO_DEPLOY=YES\n"
            "DEPLOY_STATE=READY_FROM_ROLLBACK\nDEPLOYMENT_REQUIRED=YES\n"
            "PRODUCTION_MUTATED=NO\n"
        )
        cfg = config(ssm_document_name="Synergie-Example-Production-Certify")
        result, calls, github_output = self.invoke(cfg, evidence)
        self.assertEqual(result, 0)
        send = next(call for call in calls if isinstance(call, list) and "send-command" in call)
        self.assertEqual(send[send.index("--document-name") + 1], cfg.ssm_document_name)
        payload = next(call for call in calls if isinstance(call, dict))
        self.assertEqual(payload, {"DeployRef": [DEPLOY], "RollbackRef": [ROLLBACK]})
        self.assertNotIn("commands", payload)
        self.assertIn("deployment_required=true", github_output)

    def test_restricted_document_evidence_fails_closed(self):
        cfg = config(ssm_document_name="Synergie-Example-Production-Certify")
        with self.assertRaises(mod.CertifierError):
            self.invoke(cfg, "DEPLOY_STATE=READY_FROM_ROLLBACK\n")
        duplicate = (
            "RUNTIME_CERTIFIER=PASS\nREADY_TO_DEPLOY=YES\n"
            "DEPLOY_STATE=READY_FROM_ROLLBACK\nDEPLOY_STATE=ALREADY_DEPLOYED\n"
            "DEPLOYMENT_REQUIRED=YES\nPRODUCTION_MUTATED=NO\n"
        )
        with self.assertRaises(mod.CertifierError):
            self.invoke(cfg, duplicate)

    def test_custom_document_name_and_host_profile_are_restricted(self):
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(config(ssm_document_name="AWS-RunShellScript"))
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(config(
                ssm_document_name="Synergie-Example-Production-Certify",
                host_profile="shared-host",
            ))
        with self.assertRaises(mod.CertifierError):
            mod.validate_config(config(
                ssm_document_name="Synergie-Example-Production-Certify",
                rollback_kind="legacy-baseline",
            ))


if __name__ == "__main__":
    unittest.main()
