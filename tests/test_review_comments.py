from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REVIEW_COMMENTS = ROOT / "pr-qa" / "review_comments.py"
SPEC = importlib.util.spec_from_file_location("review_comments", REVIEW_COMMENTS)
review_comments = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules["review_comments"] = review_comments
SPEC.loader.exec_module(review_comments)


class FakeGitHubClient:
    def __init__(self, files: list[dict], comments: list[dict] | None = None) -> None:
        self.files = files
        self.comments = comments or []
        self.created_reviews: list[dict] = []
        self.updated_comments: list[tuple[int, str]] = []
        self.deleted_comments: list[int] = []

    def list_pull_files(self, pr_number: int) -> list[dict]:
        return self.files

    def list_review_comments(self, pr_number: int) -> list[dict]:
        return self.comments

    def create_review(self, pr_number: int, comments: list[dict]) -> dict:
        self.created_reviews.append({"pr_number": pr_number, "comments": comments})
        return {"id": 1}

    def update_comment(self, comment_id: int, body: str) -> dict:
        self.updated_comments.append((comment_id, body))
        return {"id": comment_id}

    def delete_comment(self, comment_id: int) -> dict:
        self.deleted_comments.append(comment_id)
        return {}


class ReviewCommentServiceTests(unittest.TestCase):
    def test_diff_position_parser_supports_added_modified_deleted_and_renamed_lines(self) -> None:
        positions = review_comments.build_diff_positions(
            [
                {
                    "filename": "src/app.py",
                    "patch": "@@ -1,2 +1,3 @@\n unchanged\n-old\n+new\n+extra",
                },
                {
                    "filename": "renamed/new.py",
                    "previous_filename": "renamed/old.py",
                    "status": "renamed",
                    "patch": "@@ -3,2 +3,2 @@\n-old_name\n+new_name",
                },
            ]
        )

        self.assertIn(2, positions["src/app.py"]["RIGHT"])
        self.assertIn(3, positions["src/app.py"]["RIGHT"])
        self.assertIn(2, positions["src/app.py"]["LEFT"])
        self.assertIn(3, positions["renamed/new.py"]["RIGHT"])
        self.assertIn(3, positions["renamed/old.py"]["LEFT"])

    def test_synchronization_creates_one_batched_review_without_duplicates(self) -> None:
        client = FakeGitHubClient(files=[{"filename": "app.py", "patch": "@@ -0,0 +1,1 @@\n+TOKEN='x'"}])
        finding = self.finding("abc123abc123abc123abc123", "app.py", 1)
        duplicate = dict(finding)

        outcome = review_comments.synchronize_inline_review_comments(client, 6, [finding, duplicate])

        self.assertEqual(outcome["created"], 1)
        self.assertEqual(len(client.created_reviews), 1)
        self.assertEqual(len(client.created_reviews[0]["comments"]), 1)
        self.assertEqual(client.created_reviews[0]["comments"][0]["path"], "app.py")

    def test_synchronization_updates_existing_comment_body(self) -> None:
        fingerprint = "def456def456def456def456"
        client = FakeGitHubClient(
            files=[{"filename": "app.py", "patch": "@@ -0,0 +1,1 @@\n+TOKEN='x'"}],
            comments=[
                {
                    "id": 42,
                    "path": "app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": f"<!-- synergie-pr-qa:inline-review fingerprint={fingerprint} -->\nold body",
                }
            ],
        )

        outcome = review_comments.synchronize_inline_review_comments(client, 6, [self.finding(fingerprint, "app.py", 1)])

        self.assertEqual(outcome["updated"], 1)
        self.assertEqual(client.updated_comments[0][0], 42)
        self.assertIn("Recommendation:", client.updated_comments[0][1])
        self.assertFalse(client.created_reviews)

    def test_synchronization_removes_obsolete_comments_after_fix(self) -> None:
        fingerprint = "feedfeedfeedfeedfeedfeed"
        client = FakeGitHubClient(
            files=[{"filename": "app.py", "patch": "@@ -0,0 +1,1 @@\n+clean=True"}],
            comments=[
                {
                    "id": 77,
                    "path": "app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": f"<!-- synergie-pr-qa:inline-review fingerprint={fingerprint} -->\nstale",
                }
            ],
        )

        outcome = review_comments.synchronize_inline_review_comments(client, 6, [])

        self.assertEqual(outcome["removed"], 1)
        self.assertEqual(client.deleted_comments, [77])

    def test_non_diff_findings_are_not_published(self) -> None:
        client = FakeGitHubClient(files=[{"filename": "app.py", "patch": "@@ -0,0 +1,1 @@\n+clean=True"}])

        outcome = review_comments.synchronize_inline_review_comments(client, 6, [self.finding("0123456789abcdef01234567", "app.py", 3)])

        self.assertEqual(outcome["diff_mappable_findings"], 0)
        self.assertFalse(client.created_reviews)

    def test_comment_body_redacts_secret_values(self) -> None:
        body = review_comments.render_comment_body(
            self.finding(
                "111111111111111111111111",
                "app.py",
                1,
                explanation="Possible token='ghp_abcdefghijklmnopqrstuvwxyz123456' detected.",
            )
        )

        self.assertIn("[REDACTED]", body)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", body)

    def finding(self, fingerprint: str, path: str, line: int, *, explanation: str = "QA finding.") -> dict:
        return {
            "fingerprint": fingerprint,
            "path": path,
            "line": line,
            "side": "RIGHT",
            "gate": "Secrets",
            "severity": "BLOCKING",
            "title": "SECRET DETECTED",
            "explanation": explanation,
            "recommendation": "Use approved secrets management.",
        }


if __name__ == "__main__":
    unittest.main()
