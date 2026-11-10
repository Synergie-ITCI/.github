import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fieldzilla-production"))
from rehearsal_context import REQUIRED_CHECKS, verify_rehearsal_context

REPO = "Synergie-ITCI/programme-management-platform"


class RehearsalContextTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "scope": "production-rehearsal",
            "caller_sha": "a" * 40,
            "base_sha": "a" * 40,
            "application": {"source_sha": "b" * 40},
            "central_sha": "c" * 40,
            "central_tag": "pr-qa-v1-rc999",
            "promotion_pr": 712,
        }
        self.environment = {
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ATTEMPT": "1",
            "CENTRAL_WORKFLOW_REF": "Synergie-ITCI/.github/.github/workflows/fieldzilla-production-application.yml@refs/tags/pr-qa-v1-rc999",
        }
        identity = {"full_name": REPO}
        self.pr = {
            "state": "open",
            "draft": False,
            "head": {"sha": "b" * 40, "repo": identity},
            "base": {"sha": "a" * 40, "ref": "main", "repo": identity},
        }
        self.checks = [
            {
                "id": index,
                "name": name,
                "head_sha": "b" * 40,
                "status": "completed",
                "conclusion": "success",
                "app": {"slug": "github-actions"},
            }
            for index, name in enumerate(sorted(REQUIRED_CHECKS), 1)
        ]
        self.main = "a" * 40
        self.release = "c" * 40

    def api(self, path):
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": self.main}}
        if path.endswith("/pulls/712"):
            return self.pr
        if "/git/ref/tags/" in path:
            return {"object": {"type": "tag", "sha": "d" * 40}}
        if "/git/tags/" in path:
            return {"object": {"type": "commit", "sha": self.release}}
        if "/check-runs?" in path:
            return {"check_runs": self.checks}
        raise AssertionError(path)

    def verify(self):
        verify_rehearsal_context(
            manifest=self.manifest,
            environment=self.environment,
            api=self.api,
            central_checkout_sha="c" * 40,
        )

    def test_exact_immutable_source_and_current_head_checks(self):
        self.verify()

    def test_staging_production_or_non_main_dispatch_cannot_enter(self):
        for scope in ("staging", "production"):
            self.manifest["scope"] = scope
            with self.assertRaises(ValueError):
                self.verify()
        self.manifest["scope"] = "production-rehearsal"
        for key, value in (
            ("GITHUB_REF", "refs/heads/staging"),
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_RUN_ATTEMPT", "2"),
        ):
            original = self.environment[key]
            self.environment[key] = value
            with self.assertRaises(ValueError):
                self.verify()
            self.environment[key] = original

    def test_changed_source_base_or_fork_rejected(self):
        for part, key, value in (
            ("head", "sha", "e" * 40),
            ("base", "sha", "e" * 40),
            ("head", "repo", {"full_name": "other/fork"}),
        ):
            original = copy.deepcopy(self.pr[part][key])
            self.pr[part][key] = value
            with self.assertRaises(ValueError):
                self.verify()
            self.pr[part][key] = original
        self.main = "e" * 40
        with self.assertRaises(ValueError):
            self.verify()

    def test_old_success_cannot_override_new_pending_or_failed_check(self):
        row = copy.deepcopy(self.checks[0])
        row["id"] = 99
        row["status"] = "in_progress"
        row["conclusion"] = None
        self.checks.append(row)
        with self.assertRaises(ValueError):
            self.verify()
        row["status"] = "completed"
        row["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            self.verify()

    def test_wrong_head_or_non_actions_result_rejected(self):
        for key, value in (("head_sha", "e" * 40), ("app", {"slug": "custom-app"})):
            original = self.checks[0][key]
            self.checks[0][key] = value
            with self.assertRaises(ValueError):
                self.verify()
            self.checks[0][key] = original

    def test_moved_central_tag_cannot_execute_different_code(self):
        self.release = "e" * 40
        with self.assertRaises(ValueError):
            self.verify()

    def test_malformed_remote_check_history_cannot_pass(self):
        self.checks = {}
        with self.assertRaises(TypeError):
            self.verify()
