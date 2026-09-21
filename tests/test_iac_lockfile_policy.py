from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGRESSION_TESTS = ROOT / "tests" / "test_pr_qa_regressions.py"
spec = importlib.util.spec_from_file_location("test_pr_qa_regressions_harness", REGRESSION_TESTS)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class IacLockfilePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = module.PrQaRegressionTests(methodName="run")
        self.harness.setUp()

    def tearDown(self) -> None:
        self.harness.tearDown()

    def test_terraform_lockfile_is_allowed_inside_approved_iac_root(self) -> None:
        repo, base = self.harness.init_repo("approved-runtime-lockfile")
        self.harness.write(
            repo / "deploy" / "staging" / "fieldzilla-runtime" / ".terraform.lock.hcl",
            '# This file is maintained automatically by "tofu init".\n',
        )
        self.harness.commit(repo, "ci: add opentofu lockfile")

        code, report, report_json, _ = self.harness.run_engine_with_artifacts(
            repo,
            base,
            static_only=True,
            base_ref="development",
            head_ref="chore/approved-iac-lockfile",
            repository="Synergie-ITCI/programme-management-platform",
        )

        self.assertEqual(code, 0, report)
        self.assertNotIn("unexpected hidden file or directory `.terraform.lock.hcl`", report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Protected Resources"], "WARNING")
        self.assertIn("GOVERNED_CRITICAL_INFRASTRUCTURE", report)


if __name__ == "__main__":
    unittest.main()
