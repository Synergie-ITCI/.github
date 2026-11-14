"""Protected consumer selector changes require exact owner authorization."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
from pr_qa import gate_review_policy, selector_owner_approval_text


class SelectorApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / ".github").mkdir()
        (self.repo / ".github/synergie-pr-qa-release.json").write_text(
            json.dumps({
                "version": 1,
                "repository": "Synergie-ITCI/programme-management-platform",
                "release": "pr-qa-v1-rc296",
                "commit": "b" * 40,
            })
        )
        self.context = SimpleNamespace(
            repo=self.repo,
            changed_files=[".github/synergie-pr-qa-release.json"],
            base_ref="main",
            head_ref="feature/release",
            policy={},
            event={"number": 768, "pull_request": {
                "number": 768,
                "user": {"login": "SaurabhVermaIN"},
                "head": {"sha": "a" * 40},
            }},
        )

    def result(self, comments):
        evidence = {"source": "github_api", "mergeable": True, "reviews": [], "comments": comments}
        with (
            patch("pr_qa.resolve_repository_name", return_value="Synergie-ITCI/programme-management-platform"),
            patch("pr_qa.load_review_policy_evidence", return_value=evidence),
        ):
            return gate_review_policy(self.context)[0]

    def test_exact_unedited_owner_comment_is_required_even_for_owner_authored_pr(self):
        expected = selector_owner_approval_text(self.context)
        self.assertIn("head=" + "a" * 40, expected)
        self.assertEqual(self.result([]).status, "FAIL")
        comment = {
            "user": {"login": "SaurabhVermaIN", "id": 52234089},
            "body": expected,
            "created_at": "2026-11-14T18:00:00Z",
            "updated_at": "2026-11-14T18:00:00Z",
        }
        self.assertEqual(self.result([comment]).status, "PASS")
        self.assertEqual(self.result([{**comment, "updated_at": "2026-11-14T18:01:00Z"}]).status, "FAIL")
        self.assertEqual(self.result([{**comment, "body": expected.replace("a" * 40, "c" * 40)}]).status, "FAIL")
