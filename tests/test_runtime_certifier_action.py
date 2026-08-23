import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "actions" / "runtime-certifier" / "action.yml"


class RuntimeCertifierActionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = ACTION.read_text(encoding="utf-8")

    def test_action_is_composite(self):
        self.assertIn("using: composite", self.text)

    def test_action_invokes_central_certifier(self):
        self.assertIn(
            '${{ github.action_path }}/../../tools/runtime_certifier.py',
            self.text,
        )

    def test_required_runtime_inputs_exist(self):
        for value in (
            "instance-id:",
            "app-path:",
            "app-user:",
            "validation-url:",
            "deploy-ref:",
            "rollback-ref:",
            "runtime-version:",
        ):
            self.assertIn(value, self.text)

    def test_outputs_expose_deploy_decision(self):
        self.assertIn("deploy-state:", self.text)
        self.assertIn("deployment-required:", self.text)
        self.assertIn(
            "steps.certify.outputs.deploy_state",
            self.text,
        )
        self.assertIn(
            "steps.certify.outputs.deployment_required",
            self.text,
        )

    def test_no_application_specific_values(self):
        lowered = self.text.lower()

        for forbidden in (
            "dhansamvaad",
            "jiobp-staging",
            "saksham-staging",
            "/var/www/",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_action_contains_no_deployment_mutation(self):
        lowered = self.text.lower()

        for forbidden in (
            "artisan migrate",
            "git reset --hard",
            "systemctl restart",
            "systemctl reload",
            "rm -rf",
            "deploy-via-ssm",
        ):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()
