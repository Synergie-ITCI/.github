from __future__ import annotations

import importlib.util
import sys
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "consumer-compatibility-preflight"


def load_module():
    loader = SourceFileLoader("consumer_compatibility_preflight", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ConsumerCompatibilityPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def assert_violation(self, text: str, needle: str) -> None:
        violations = self.module.validate_consumer_workflow(ROOT, text)
        self.assertTrue(any(needle in item for item in violations), violations)

    def test_positive_telepathy_compatible_fixture_passes(self) -> None:
        self.assertEqual(self.module.run(ROOT), [])

    def test_missing_required_input_fails(self) -> None:
        self.assert_violation(
            self.module.telepathy_uat_fixture(include_required_input=False),
            "missing required input `api-health-url`",
        )

    def test_unknown_input_fails(self) -> None:
        self.assert_violation(
            self.module.telepathy_uat_fixture(unknown_input=True),
            "undeclared input `surprise-input`",
        )

    def test_unauthorized_central_action_fails(self) -> None:
        self.assert_violation(
            self.module.telepathy_uat_fixture(action_name="opentofu-plan-authorizer"),
            "central action is not approved",
        )

    def test_mutable_ref_fails(self) -> None:
        self.assert_violation(
            self.module.telepathy_uat_fixture(ssm_ref="main"),
            "central action reference must be immutable",
        )

    def test_gate_d_rejection_fails(self) -> None:
        self.assert_violation(
            self.module.telepathy_uat_fixture(guarded=False),
            "does not satisfy controlled Gate D authorization",
        )

    def test_positive_programme_management_fieldzilla_runtime_fixture_passes(self) -> None:
        self.assertEqual(
            self.module.validate_consumer_workflow(
                ROOT,
                self.module.programme_management_fieldzilla_runtime_fixture(),
                require_controlled_gate_d=False,
            ),
            [],
        )

    def test_programme_management_missing_required_input_fails(self) -> None:
        self.assert_violation(
            self.module.programme_management_fieldzilla_runtime_fixture(include_required_input=False),
            "missing required input `expected-sha`",
        )

    def test_programme_management_unknown_input_fails(self) -> None:
        self.assert_violation(
            self.module.programme_management_fieldzilla_runtime_fixture(unknown_input=True),
            "undeclared input `surprise-input`",
        )

    def test_programme_management_mutable_workflow_ref_fails(self) -> None:
        self.assert_violation(
            self.module.programme_management_fieldzilla_runtime_fixture(workflow_ref="main"),
            "central reusable workflow reference must be immutable",
        )

    def test_programme_management_unapproved_tofu_root_fails(self) -> None:
        self.assert_violation(
            self.module.programme_management_fieldzilla_runtime_fixture(tofu_root="deploy/production"),
            "tofu-root is not in the central allowlist",
        )


if __name__ == "__main__":
    unittest.main()
