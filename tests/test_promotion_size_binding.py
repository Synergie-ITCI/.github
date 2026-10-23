"""A size review can follow an identical patch, but never expanded content or scope."""

import copy
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
import baseline_authorization as binding
import pr_qa as qa
from adapters.base import PRContext


class PromotionSizeBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)

        def git(*args):
            return subprocess.run(["git", *args], cwd=self.repo, check=True,
                                  capture_output=True, text=True).stdout.strip()

        self.git = git
        git("init", "-q")
        git("config", "user.name", "Test")
        git("config", "user.email", "test@example.invalid")
        (self.repo / "app.txt").write_text("before\n")
        git("add", ".")
        git("commit", "-qm", "base")
        self.base = git("rev-parse", "HEAD")
        (self.repo / "app.txt").write_text("after\n")
        git("add", ".")
        git("commit", "-qm", "reviewed change")
        self.head = git("rev-parse", "HEAD")
        patch = subprocess.run(["git", "diff", "--raw", "-z", "--no-renames", "--abbrev=40",
                                f"{self.base}...HEAD"], cwd=self.repo, check=True,
                               capture_output=True).stdout
        now = datetime.now(timezone.utc)
        self.marker = "REVIEWED-PROMOTION-ID"
        self.policy = {
            "enabled": True, "repository": "Synergie-ITCI/example", "repository_id": 77,
            "pr_number": 41, "expected_head_sha": self.head, "expected_base_sha": self.base,
            "head_ref": "feature/reviewed", "base_ref": "development",
            "allowed_effective_additions": 6000, "allowed_changed_files": 1,
            "purpose": "Reviewed content only", "issued_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_after": (now + timedelta(hours=1)).isoformat(),
            "authorization_id": "00000000-0000-4000-8000-000000000001",
            "relaxations": ["diff_size"],
            "promotion_scope": {
                "reviewed_patch_sha256": hashlib.sha256(patch).hexdigest(),
                "issued_at": (now - timedelta(minutes=1)).isoformat(),
                "expires_after": (now + timedelta(days=20)).isoformat(),
                "required_pr_body_marker": self.marker,
                "branches": [
                    {"head_ref": "promotion/reviewed-staging", "base_ref": "staging"},
                    {"head_ref": "promotion/reviewed-main", "base_ref": "main"},
                ],
            },
        }
        self.ctx = PRContext(repo=self.repo, config={}, policy={}, changed_files=["app.txt"],
                             head_ref="promotion/reviewed-main", base_ref="main", pr_body=self.marker,
                             event={"repository": {"full_name": "Synergie-ITCI/example"},
                                    "pull_request": {"number": 43}})
        self.gc = {"head_sha": self.head, "base_sha": self.base}
        self.live = {
            "number": 43, "state": "open", "merged": False, "draft": False, "body": self.marker,
            "head": {"sha": self.head, "ref": self.ctx.head_ref,
                     "repo": {"id": 77, "full_name": self.policy["repository"]}},
            "base": {"sha": self.base, "ref": self.ctx.base_ref,
                     "repo": {"id": 77, "full_name": self.policy["repository"]}},
        }
        env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
               "GITHUB_REPOSITORY": self.policy["repository"], "GITHUB_REPOSITORY_ID": "77",
               "GITHUB_REF": "refs/pull/43/merge", "GITHUB_WORKSPACE": str(self.repo),
               "GH_TOKEN": "fixture"}
        self.patch_env = mock.patch.dict(os.environ, env, clear=True)
        self.patch_env.start()
        self.addCleanup(self.patch_env.stop)
        self.lookup = mock.patch.object(binding, "read_live_pr", return_value=self.live)
        self.lookup.start()
        self.addCleanup(self.lookup.stop)

    def validate(self):
        return binding.validate_authorization(self.ctx, self.gc, self.policy,
                                              {"effective_additions": 5500})

    def test_identical_staging_and_main_promotions_pass(self):
        self.assertEqual(self.validate(), [])
        self.ctx.head_ref = "promotion/reviewed-staging"
        self.ctx.base_ref = "staging"
        self.live["head"]["ref"] = self.ctx.head_ref
        self.live["base"]["ref"] = self.ctx.base_ref
        self.assertEqual(self.validate(), [])

    def test_changed_or_expanded_patch_requires_new_review(self):
        (self.repo / "app.txt").write_text("different\n")
        self.git("add", ".")
        self.git("commit", "-qm", "different content")
        self.head = self.git("rev-parse", "HEAD")
        self.gc["head_sha"] = self.head
        self.live["head"]["sha"] = self.head
        self.assertIn("Promotion patch differs", self.validate()[0])
        (self.repo / "extra.txt").write_text("extra\n")
        self.git("add", ".")
        self.git("commit", "-qm", "expanded content")
        self.head = self.git("rev-parse", "HEAD")
        self.gc["head_sha"] = self.head
        self.live["head"]["sha"] = self.head
        self.assertIn("Promotion patch differs", self.validate()[0])

    def test_scope_expiry_and_live_identity_fail_closed(self):
        self.ctx.head_ref = "promotion/unreviewed"
        self.assertIn("not authorized", self.validate()[0])
        self.ctx.head_ref = "promotion/reviewed-main"
        self.policy["promotion_scope"]["expires_after"] = "2000-01-01T00:00:00Z"
        self.assertIn("expired", self.validate()[0])
        self.policy["promotion_scope"]["expires_after"] = (datetime.now(timezone.utc) + timedelta(days=20)).isoformat()
        self.live["head"]["sha"] = "f" * 40
        self.assertIn("not the exact authorized", self.validate()[0])

    def test_marker_and_size_limits_fail_closed(self):
        self.ctx.pr_body = ""
        self.assertIn("marker", self.validate()[0])
        self.ctx.pr_body = self.marker
        self.policy["allowed_effective_additions"] = 5000
        self.assertIn("exceeds authorized limits", self.validate()[0])

    def test_local_release_preflight_uses_exact_active_release_base(self):
        event = {"release_preflight": {"technical_validation_only": True,
                                       "base_sha": self.base, "head_sha": self.head}}
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
            context = qa.gather_git_context(self.repo, event, "main", "release-candidate")
        self.assertEqual(context["base_sha"], self.base)
        self.assertEqual(context["changed_files"], ["app.txt"])
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            context = qa.gather_git_context(self.repo, event, "main", "release-candidate")
        self.assertNotEqual(context["base_sha"], self.base)
