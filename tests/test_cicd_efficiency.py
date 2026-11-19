"""Regression coverage for the central PR-QA service boundary."""

from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/pr-qa.yml"


class CentralPostgresServiceTests(unittest.TestCase):
    def test_central_self_qa_skips_postgres_and_consumers_keep_it(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "image: ${{ github.repository != 'Synergie-ITCI/.github' && 'postgres:16' || '' }}",
            workflow,
        )
        self.assertIn("POSTGRES_DB: telepathy_test", workflow)
        self.assertIn("POSTGRES_HOST_AUTH_METHOD: trust", workflow)


if __name__ == "__main__":
    unittest.main()
