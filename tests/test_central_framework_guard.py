from __future__ import annotations

import re
import os
import subprocess
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
    def guard_script(self) -> str:
        text = GUARD.read_text(encoding="utf-8")
        marker = "      run: |\n"
        start = text.index(marker) + len(marker)
        lines = []
        for line in text[start:].splitlines():
            if line.startswith("        "):
                lines.append(line[8:])
            elif line:
                break
        return "\n".join(lines) + "\n"

    def run_guard(self, workflow_ref: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "GITHUB_ACTION_PATH": str(ROOT / "actions/central-framework-guard"),
                "GITHUB_OUTPUT": os.devnull,
                "WORKFLOW_REF": workflow_ref,
                "WORKFLOW_SHA": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
                ).strip(),
                "WORKFLOW_REPOSITORY": "Synergie-ITCI/.github",
                "WORKFLOW_FILE_PATH": ".github/workflows/fieldzilla-staging-opentofu-apply.yml",
                "EXPECTED_REPOSITORY": "Synergie-ITCI/.github",
                "EXPECTED_WORKFLOW_FILE": ".github/workflows/fieldzilla-staging-opentofu-apply.yml",
                "REQUIRE_RELEASE_TAG": "true",
            }
        )
        return subprocess.run(
            ["bash", "-c", self.guard_script()],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_guard_is_generic_and_fail_closed_for_release_workflows(self) -> None:
        text = GUARD.read_text(encoding="utf-8")
        self.assertIn("workflow-ref:", text)
        self.assertIn("workflow-sha:", text)
        self.assertIn("workflow-repository:", text)
        self.assertIn("workflow-file-path:", text)
        self.assertIn("expected-workflow-file:", text)
        self.assertIn("require-release-tag:", text)
        self.assertIn("refs/tags/*", text)
        self.assertIn('normalized_ref="${ref#refs/tags/}"', text)
        self.assertIn('actual="$(git -C "${framework_root}" rev-parse HEAD)"', text)
        self.assertIn('[ "${actual}" = "${WORKFLOW_SHA}" ]', text)
        self.assertNotIn("fieldzilla", text.lower())

    def test_guard_accepts_github_reusable_workflow_tag_shorthand(self) -> None:
        proc = self.run_guard(
            "Synergie-ITCI/.github/.github/workflows/"
            "fieldzilla-staging-opentofu-apply.yml@pr-qa-v1-rc163"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_guard_accepts_expanded_tag_ref_representation(self) -> None:
        proc = self.run_guard(
            "Synergie-ITCI/.github/.github/workflows/"
            "fieldzilla-staging-opentofu-apply.yml@refs/tags/pr-qa-v1-rc163"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_guard_rejects_mutable_or_malformed_refs(self) -> None:
        refs = [
            "Synergie-ITCI/.github/.github/workflows/"
            "fieldzilla-staging-opentofu-apply.yml@refs/heads/main",
            "Synergie-ITCI/.github/.github/workflows/"
            "fieldzilla-staging-opentofu-apply.yml@main",
            "Synergie-ITCI/.github/.github/workflows/"
            "fieldzilla-staging-opentofu-apply.yml@pr-qa-v1-rc163-extra",
            "Synergie-ITCI/.github/.github/workflows/"
            "fieldzilla-staging-opentofu-apply.yml@refs/tags/pr-qa-v1-rc163-extra",
        ]
        for ref in refs:
            with self.subTest(ref=ref):
                proc = self.run_guard(ref)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("workflow ref must be an immutable pr-qa release tag", proc.stderr)

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
