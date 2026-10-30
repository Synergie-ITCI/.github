from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pr-qa"))
from risk_contract import assess_risk_contracts
from adapters.base import CheckResult
from pr_qa import gate_application_risk_contract


class ApplicationRiskContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        (self.repo / "tests").mkdir()
        (self.repo / "tests" / "test_auth.py").write_text("def test_auth(): pass\n")
        self.contract = [{"risk": "session", "source_paths": ["app/auth.py"],
                          "evidence_paths": ["tests/test_auth.py"],
                          "test_command": ["pytest", "-q", "tests/test_auth.py"]}]

    def test_unrelated_change_does_not_trigger_test_contract(self):
        self.assertEqual(assess_risk_contracts(self.contract, ["README.md"], self.repo, False), [])

    def test_changed_auth_requires_passing_existing_test_gate(self):
        self.assertEqual(assess_risk_contracts(self.contract, ["app/auth.py"], self.repo, False),
                         [("session", "TESTS_NOT_PASSED")])
        self.assertEqual(assess_risk_contracts(self.contract, ["app/auth.py"], self.repo, True),
                         [("session", "PASS")])

    def test_missing_or_unsafe_evidence_fails_closed(self):
        (self.repo / "tests" / "test_auth.py").unlink()
        self.assertEqual(assess_risk_contracts(self.contract, ["app/auth.py"], self.repo, True),
                         [("session", "MISSING_EVIDENCE_FILE")])
        unsafe = [{**self.contract[0], "evidence_paths": ["../outside.py"]}]
        self.assertEqual(assess_risk_contracts(unsafe, ["app/auth.py"], self.repo, True),
                         [("session", "INVALID_CONTRACT")])

    def test_central_gate_blocks_failed_existing_tests(self):
        context = SimpleNamespace(
            event={"repository": {"full_name": "Synergie-ITCI/pilot"}},
            policy={"application_risk_contracts": {"Synergie-ITCI/pilot": self.contract}},
            changed_files=["app/auth.py"], repo=self.repo,
            run=lambda command, timeout: SimpleNamespace(ok=True, skipped=False),
        )
        failed_tests = [CheckResult("Tests", "FAIL", "synthetic test failure")]
        result = gate_application_risk_contract(context, failed_tests)
        self.assertEqual([(item.gate, item.status) for item in result],
                         [("Application Risk Contract", "FAIL")])
        passing_tests = [CheckResult("Tests", "PASS", "synthetic test pass")]
        result = gate_application_risk_contract(context, passing_tests)
        self.assertEqual(result[0].status, "PASS")

        context.run = lambda command, timeout: SimpleNamespace(
            ok=False, skipped=False, concise_output=lambda: "synthetic focused failure"
        )
        result = gate_application_risk_contract(context, passing_tests)
        self.assertEqual(result[0].status, "FAIL")

    def test_unrelated_test_skips_do_not_hide_pass_or_failure(self):
        commands = []
        context = SimpleNamespace(
            event={"repository": {"full_name": "Synergie-ITCI/pilot"}},
            policy={"application_risk_contracts": {"Synergie-ITCI/pilot": self.contract}},
            changed_files=["app/auth.py"], repo=self.repo,
            run=lambda command, timeout: (commands.append(command) or SimpleNamespace(ok=True, skipped=False)),
        )
        python_pass = CheckResult("Tests", "PASS", "Python tests passed", technology="Python")
        unrelated_skips = [CheckResult("Tests", "SKIP", f"No {name} files changed",
                                       technology=name, blocking=False)
                           for name in ("Shell", "Docker", "GitHub Actions")]
        result = gate_application_risk_contract(context, [python_pass, *unrelated_skips])
        self.assertEqual(result[0].status, "PASS")
        self.assertEqual(commands, [self.contract[0]["test_command"]])

        result = gate_application_risk_contract(context, [python_pass, *unrelated_skips,
                                                         CheckResult("Tests", "FAIL", "Selected test failed")])
        self.assertEqual(result[0].status, "FAIL")
        self.assertEqual(len(commands), 1)

        context.run = lambda command, timeout: SimpleNamespace(
            ok=False, skipped=False, concise_output=lambda: "selected test failed"
        )
        result = gate_application_risk_contract(context, [python_pass, *unrelated_skips])
        self.assertEqual(result[0].status, "FAIL")


if __name__ == "__main__":
    unittest.main()
