"""Keep the image identity diagnostic unable to reach source or AWS operations."""

import re
import unittest
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github/workflows/fieldzilla-production-images.yml"
)


class ImageIdentityDiagnosticTests(unittest.TestCase):
    def test_diagnostic_stops_after_identity_check(self):
        workflow = WORKFLOW.read_text()
        build, publish = workflow.split("\n  publish:\n", 1)
        steps = re.findall(r"(?ms)^      - name: (.+?)\n(.*?)(?=^      - name: |\Z)", build)
        self.assertEqual(steps[0][0], "Verify actual build identity without a production environment")
        self.assertEqual(len(steps), 9)
        identity = steps[0][1]
        self.assertNotIn("image_runner.py", identity)
        self.assertNotIn("aws ", identity)
        self.assertNotIn("docker ", identity)
        for name, body in steps[1:]:
            with self.subTest(step=name):
                self.assertIn("        if: ${{ !inputs.diagnostic-only }}\n", body)
        self.assertIn("    if: ${{ !inputs.diagnostic-only }}\n", publish.split("\n    steps:\n", 1)[0])
        self.assertIn("      diagnostic-only:\n        type: boolean\n", build)
        self.assertIn("default: false", build)

    def test_identity_error_reports_names_without_values(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("mismatched = [k for k, v in expected.items() if str(claims.get(k)) != v]", workflow)
        self.assertNotIn("print(claims)", workflow)
        self.assertNotIn("print(token)", workflow)


if __name__ == "__main__":
    unittest.main()
