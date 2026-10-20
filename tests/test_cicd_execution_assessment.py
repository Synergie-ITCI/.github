"""Regression cases for the advisory CI/CD execution assessment."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "assess-cicd-execution"
from importlib.machinery import SourceFileLoader

assessment = SourceFileLoader("cicd_assessment", str(SCRIPT)).load_module()


CALLER = """name: PR Quality Assurance
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
concurrency:
  group: pr-qa-${{ github.repository }}-${{ github.event.pull_request.number }}
  cancel-in-progress: true
jobs:
  pr-qa:
    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@main
"""


class ExecutionAssessmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Assessment Test")
        self.write("README.md", "# Test\n")
        self.commit()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def write(self, path: str, text: str) -> None:
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")

    def commit(self) -> None:
        self.git("add", ".")
        self.git("commit", "-qm", "fixture", "--allow-empty")

    def item(self, key: str) -> dict:
        return next(item for item in assessment.assess(self.repo)["standards"] if item["key"] == key)

    def test_corrected_pmp_caller_and_intentional_draft_validation(self) -> None:
        self.write(".github/workflows/pr-qa.yml", CALLER)
        self.commit()
        item = self.item("pr_execution")
        self.assertEqual(item["status"], "COMPLIANT")
        self.assertEqual(item["evidence"], [{"file": ".github/workflows/pr-qa.yml", "line": 7}])

    def test_historical_edited_trigger_is_advisory_not_security_failure(self) -> None:
        self.write(".github/workflows/pr-qa.yml", CALLER.replace("ready_for_review]", "ready_for_review, edited]"))
        self.commit()
        item = self.item("pr_execution")
        self.assertEqual(item["status"], "ADVISORY DEVIATION")
        self.assertEqual(item["kind"], "efficiency")
        self.assertIn("metadata-sensitive", item["why"])
        self.assertEqual(item["evidence"][0]["line"], 4)

    def test_telepathy_default_pr_trigger_is_valid_but_cancellation_advised(self) -> None:
        self.write(".github/workflows/pr-qa.yml", """name: PR Quality Assurance
on:
  pull_request:
    branches:
      - main
jobs:
  pr-qa:
    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@main
""")
        self.commit()
        item = self.item("pr_execution")
        self.assertEqual(item["status"], "ADVISORY DEVIATION")
        self.assertIn("cancellation", item["summary"])
        self.assertNotIn("trigger configuration", item["summary"])

    def test_changed_caller_job_identity_is_advisory(self) -> None:
        self.write(".github/workflows/pr-qa.yml", CALLER.replace("  pr-qa:\n", "  renamed-qa:\n"))
        self.commit()
        item = self.item("pr_execution")
        self.assertEqual(item["status"], "ADVISORY DEVIATION")
        self.assertIn("required-check identity", item["why"])

    def test_reusable_workflow_call_is_not_consumer_pr_caller(self) -> None:
        self.write(".github/workflows/quality-gate.yml", CALLER.replace("  pull_request:", "  workflow_call:"))
        self.commit()
        self.assertEqual(self.item("pr_execution")["status"], "NOT VERIFIED")

    def test_default_pr_triggers_with_concurrency_are_accepted(self) -> None:
        self.write(".github/workflows/pr-qa.yml", CALLER.replace("  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review]", "  pull_request:"))
        self.commit()
        self.assertEqual(self.item("pr_execution")["status"], "COMPLIANT")
        self.write(".github/workflows/pr-qa.yml", CALLER.replace("on:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review]", "on: [pull_request]"))
        self.commit()
        self.assertEqual(self.item("pr_execution")["status"], "COMPLIANT")

    def test_missing_and_ambiguous_caller_evidence(self) -> None:
        self.assertEqual(self.item("pr_execution")["status"], "NOT VERIFIED")
        self.write(".github/workflows/pr-qa.yml", CALLER.replace("  pull_request:", "  workflow_dispatch:"))
        self.commit()
        self.assertEqual(self.item("pr_execution")["status"], "NOT VERIFIED")

    def test_preflight_size_and_platform_specific_audit(self) -> None:
        self.write("scripts/local_ci_preflight.py", "MAX_ADDITIONS = 5000\n")
        self.write("apps/web/package-lock.json", "{}\n")
        self.write(".github/workflows/audit.yml", "name: Audit\non: push\njobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm audit\n")
        self.commit()
        self.assertEqual(self.item("preflight")["status"], "COMPLIANT")
        self.assertEqual(self.item("pr_size")["status"], "COMPLIANT")
        self.assertEqual(self.item("dependency_audit")["status"], "COMPLIANT")

    def test_different_stack_and_missing_audit_evidence(self) -> None:
        self.assertEqual(self.item("dependency_audit")["status"], "NOT APPLICABLE")
        self.write("apps/api/poetry.lock", "# lock\n")
        self.commit()
        self.assertEqual(self.item("dependency_audit")["status"], "NOT VERIFIED")

    def test_release_preflight_dependency_and_missing_provenance(self) -> None:
        self.write(".github/workflows/staging-deploy.yml", """name: Deploy
on: workflow_dispatch
jobs:
  controlled-release-preflight:
    runs-on: ubuntu-latest
    steps:
      - run: echo preflight
  deploy:
    needs: controlled-release-preflight
    runs-on: ubuntu-latest
""")
        self.commit()
        self.assertEqual(self.item("release_sequence")["status"], "COMPLIANT")
        self.assertEqual(self.item("qa_reuse")["status"], "NOT VERIFIED")
        self.write(".github/workflows/staging-deploy.yml", "name: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n")
        self.commit()
        self.assertEqual(self.item("release_sequence")["status"], "NOT VERIFIED")

    def test_expired_security_approval_is_advisory(self) -> None:
        self.assertEqual(self.item("security_review")["status"], "NOT APPLICABLE")
        self.write("policy/exceptions/dependency.json", '{"expires_at": "2020-01-01T00:00:00Z"}\n')
        self.commit()
        item = self.item("security_review")
        self.assertEqual(item["status"], "ADVISORY DEVIATION")
        self.assertEqual(item["kind"], "security")
        self.assertEqual(item["evidence"][0]["line"], 1)

    def test_unavailable_repository_data(self) -> None:
        result = assessment.assess(self.repo / "missing")
        self.assertEqual(len(result["standards"]), 7)
        self.assertTrue(all(item["status"] == "NOT VERIFIED" for item in result["standards"]))


if __name__ == "__main__":
    unittest.main()
