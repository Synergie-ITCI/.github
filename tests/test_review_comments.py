from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REVIEW_COMMENTS = ROOT / "pr-qa" / "review_comments.py"
sys.path.insert(0, str(ROOT / "pr-qa"))
SPEC = importlib.util.spec_from_file_location("review_comments", REVIEW_COMMENTS)
review_comments = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules["review_comments"] = review_comments
SPEC.loader.exec_module(review_comments)


class FakeGitHubClient:
    def __init__(
        self,
        files: list[dict],
        comments: list[dict] | None = None,
        *,
        head_sha: str = "head",
        head_sequence: list[str] | None = None,
        create_response: dict | None = None,
        create_error: Exception | None = None,
        update_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.files = files
        self.comments = comments or []
        self.head_sha = head_sha
        self.head_sequence = head_sequence or []
        self.create_response = create_response
        self.create_error = create_error
        self.update_error = update_error
        self.delete_error = delete_error
        self.created_reviews: list[dict] = []
        self.updated_comments: list[tuple[int, str]] = []
        self.deleted_comments: list[int] = []

    def list_pull_files(self, pr_number: int) -> list[dict]:
        return self.files

    def list_review_comments(self, pr_number: int) -> list[dict]:
        return self.comments

    def get_pull(self, pr_number: int) -> dict:
        head_sha = self.head_sequence.pop(0) if self.head_sequence else self.head_sha
        return {"head": {"sha": head_sha}}

    def create_review(self, pr_number: int, comments: list[dict], body: str = "") -> dict:
        if self.create_error:
            raise self.create_error
        self.created_reviews.append({"pr_number": pr_number, "comments": comments, "body": body})
        return self.create_response if self.create_response is not None else {"id": 1}

    def update_comment(self, comment_id: int, body: str) -> dict:
        if self.update_error:
            raise self.update_error
        self.updated_comments.append((comment_id, body))
        return {"id": comment_id}

    def delete_comment(self, comment_id: int) -> dict:
        if self.delete_error:
            raise self.delete_error
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

    def test_create_review_failure_preserves_existing_comments(self) -> None:
        fingerprint = "feedfeedfeedfeedfeedfeed"
        client = FakeGitHubClient(
            files=[{"filename": "app.py", "patch": "@@ -0,0 +1,2 @@\n+line1\n+line2"}],
            comments=[
                {
                    "id": 77,
                    "path": "app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": f"<!-- synergie-pr-qa:inline-review fingerprint={fingerprint} -->\nold location",
                    "user": {"login": "github-actions[bot]"},
                }
            ],
            create_error=RuntimeError("GitHub API rate limit"),
        )

        with self.assertRaises(RuntimeError):
            review_comments.synchronize_inline_review_comments(
                client,
                6,
                [self.finding(fingerprint, "app.py", 2)],
                expected_head_sha="head",
                trusted_author_logins={"github-actions[bot]"},
            )

        self.assertFalse(client.deleted_comments)
        self.assertFalse(client.updated_comments)

    def test_partial_create_review_response_preserves_existing_comments(self) -> None:
        fingerprint = "cccccccccccccccccccccccc"
        client = FakeGitHubClient(
            files=[{"filename": "app.py", "patch": "@@ -0,0 +1,2 @@\n+line1\n+line2"}],
            comments=[
                {
                    "id": 77,
                    "path": "app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": f"<!-- synergie-pr-qa:inline-review fingerprint={fingerprint} -->\nold location",
                    "user": {"login": "github-actions[bot]"},
                }
            ],
            create_response={},
        )

        with self.assertRaises(RuntimeError):
            review_comments.synchronize_inline_review_comments(
                client,
                6,
                [self.finding(fingerprint, "app.py", 2)],
                expected_head_sha="head",
                trusted_author_logins={"github-actions[bot]"},
            )

        self.assertEqual(len(client.created_reviews), 1)
        self.assertFalse(client.deleted_comments)

    def test_patch_failure_does_not_delete_existing_comments(self) -> None:
        fingerprint = "dddddddddddddddddddddddd"
        client = FakeGitHubClient(
            files=[{"filename": "app.py", "patch": "@@ -0,0 +1,1 @@\n+TOKEN='x'"}],
            comments=[
                {
                    "id": 42,
                    "path": "app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": f"<!-- synergie-pr-qa:inline-review fingerprint={fingerprint} -->\nold body",
                    "user": {"login": "github-actions[bot]"},
                }
            ],
            update_error=RuntimeError("timeout"),
        )

        with self.assertRaises(RuntimeError):
            review_comments.synchronize_inline_review_comments(
                client,
                6,
                [self.finding(fingerprint, "app.py", 1)],
                expected_head_sha="head",
                trusted_author_logins={"github-actions[bot]"},
            )

        self.assertFalse(client.deleted_comments)

    def test_delete_failure_does_not_hide_existing_comment(self) -> None:
        fingerprint = "eeeeeeeeeeeeeeeeeeeeeeee"
        client = FakeGitHubClient(
            files=[{"filename": "app.py", "patch": "@@ -0,0 +1,1 @@\n+clean=True"}],
            comments=[
                {
                    "id": 77,
                    "path": "app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": f"<!-- synergie-pr-qa:inline-review fingerprint={fingerprint} -->\nstale",
                    "user": {"login": "github-actions[bot]"},
                }
            ],
            delete_error=RuntimeError("timeout"),
        )

        with self.assertRaises(RuntimeError):
            review_comments.synchronize_inline_review_comments(
                client,
                6,
                [],
                expected_head_sha="head",
                trusted_author_logins={"github-actions[bot]"},
            )

        self.assertFalse(client.deleted_comments)

    def test_stale_head_skips_publication_without_modifying_comments(self) -> None:
        client = FakeGitHubClient(
            files=[{"filename": "app.py", "patch": "@@ -0,0 +1,1 @@\n+TOKEN='x'"}],
            head_sha="new-head",
        )

        outcome = review_comments.synchronize_inline_review_comments(
            client,
            6,
            [self.finding("0123456789abcdef01234567", "app.py", 1)],
            expected_head_sha="old-head",
        )

        self.assertTrue(outcome["publication_skipped"])
        self.assertFalse(client.created_reviews)
        self.assertFalse(client.deleted_comments)
        self.assertFalse(client.updated_comments)

    def test_head_change_after_publication_preserves_existing_cleanup_targets(self) -> None:
        fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbb"
        client = FakeGitHubClient(
            files=[{"filename": "app.py", "patch": "@@ -0,0 +1,2 @@\n+line1\n+line2"}],
            comments=[
                {
                    "id": 88,
                    "path": "app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": f"<!-- synergie-pr-qa:inline-review fingerprint={fingerprint} -->\nold location",
                    "user": {"login": "github-actions[bot]"},
                }
            ],
            head_sequence=["head", "new-head"],
        )

        outcome = review_comments.synchronize_inline_review_comments(
            client,
            6,
            [self.finding(fingerprint, "app.py", 2)],
            expected_head_sha="head",
            trusted_author_logins={"github-actions[bot]"},
        )

        self.assertTrue(outcome["publication_skipped"])
        self.assertEqual(len(client.created_reviews), 1)
        self.assertFalse(client.deleted_comments)

    def test_copied_namespace_marker_from_user_is_not_managed(self) -> None:
        client = FakeGitHubClient(
            files=[{"filename": "app.py", "patch": "@@ -0,0 +1,1 @@\n+clean=True"}],
            comments=[
                {
                    "id": 99,
                    "path": "app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": "<!-- synergie-pr-qa:inline-review fingerprint=feedfeedfeedfeedfeedfeed -->\nuser copied marker",
                    "user": {"login": "SaurabhVermaIN"},
                }
            ],
        )

        outcome = review_comments.synchronize_inline_review_comments(
            client,
            6,
            [],
            trusted_author_logins={"github-actions[bot]"},
        )

        self.assertEqual(outcome["removed"], 0)
        self.assertFalse(client.deleted_comments)

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

    def test_ai_comments_use_separate_namespace_and_staff_review_format(self) -> None:
        body = review_comments.render_comment_body(
            {
                "review_type": "ai",
                "fingerprint": "222222222222222222222222",
                "title": "AI REVIEW: POSSIBLE BUG",
                "severity": "HIGH",
                "category": "Possible Bug",
                "observation": "Value may be None before dereference.",
                "why_it_matters": "This can fail at runtime.",
                "recommendation": "Guard the value or return early.",
            },
            review_comments.AI_MARKER_NAMESPACE,
        )

        self.assertIn("synergie-ai-review:inline-review", body)
        self.assertIn("Category: Possible Bug", body)
        self.assertIn("Why it matters: This can fail at runtime.", body)
        self.assertIn("Recommended improvement: Guard the value or return early.", body)

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
