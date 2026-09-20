from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "actions/central-framework-guard/action.yml"
ACTIONLINT_CONFIG = ROOT / ".github/actionlint.yaml"
WORKFLOWS = [
    ROOT / ".github/workflows/fieldzilla-staging-opentofu-apply.yml",
    ROOT / ".github/workflows/fieldzilla-staging-opentofu-bootstrap.yml",
]


class CentralFrameworkGuardTests(unittest.TestCase):
    def test_guard_is_generic_and_fail_closed_for_release_workflows(self) -> None:
        text = GUARD.read_text(encoding="utf-8")
        self.assertIn("workflow-ref:", text)
        self.assertIn("workflow-sha:", text)
        self.assertIn("workflow-repository:", text)
        self.assertIn("workflow-file-path:", text)
        self.assertIn("expected-workflow-file:", text)
        self.assertIn("require-release-tag:", text)
        self.assertIn("refs/tags/pr-qa-v1-rc*", text)
        self.assertIn('actual="$(git -C "${framework_root}" rev-parse HEAD)"', text)
        self.assertIn('[ "${actual}" = "${WORKFLOW_SHA}" ]', text)
        self.assertNotIn("fieldzilla", text.lower())

    def test_central_workflows_use_same_guarded_checkout_pattern(self) -> None:
        for workflow in WORKFLOWS:
            text = workflow.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow.name):
                self.assertIn("Checkout central framework at workflow SHA", text)
                self.assertIn("repository: ${{ job.workflow_repository || 'Synergie-ITCI/.github' }}", text)
                self.assertIn("ref: ${{ job.workflow_sha || github.workflow_sha }}", text)
                self.assertIn("path: .central-framework", text)
                self.assertIn("uses: ./.central-framework/actions/central-framework-guard", text)
                self.assertIn(f"expected-workflow-file: .github/workflows/{workflow.name}", text)

    def test_central_workflows_do_not_self_pin_internal_actions(self) -> None:
        for workflow in WORKFLOWS:
            text = workflow.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow.name):
                self.assertNotRegex(
                    text,
                    r"uses:\s+Synergie-ITCI/\.github/actions/[A-Za-z0-9_.-]+@",
                )
                local_uses = re.findall(r"uses:\s+\./\.central-framework/actions/[A-Za-z0-9_.-]+", text)
                self.assertTrue(local_uses)

    def test_actionlint_ignore_is_limited_to_reusable_workflow_identity_fields(self) -> None:
        text = ACTIONLINT_CONFIG.read_text(encoding="utf-8")
        self.assertIn(".github/workflows/fieldzilla-staging-opentofu-*.yml", text)
        self.assertIn('property "workflow_(ref|sha|repository|file_path)" is not defined', text)
        self.assertNotIn("shellcheck", text.lower())
        self.assertNotIn("syntax", text.lower())


if __name__ == "__main__":
    unittest.main()
