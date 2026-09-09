"""Exact PR 132 authorization and rejection cases, with no live mutation."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

_spec = importlib.util.spec_from_file_location(
    "pr132_binding_fixture", Path(__file__).with_name("test_baseline_live_binding.py")
)
existing = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(existing)


class ExactPr132AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.central = json.loads((existing.ROOT / "policy/pr-qa-policy.json").read_text())
        authorization = self.central.get("one_time_baseline_alignment")
        if authorization is None or authorization.get("pr_number") != 132:
            archived = subprocess.check_output(
                ["git", "show", "pr-qa-v1-rc105:policy/pr-qa-policy.json"],
                cwd=existing.ROOT, text=True,
            )
            authorization = json.loads(archived)["one_time_baseline_alignment"]
        existing.BaselineLiveBindingTests.setUp(self)
        self.policy = copy.deepcopy(authorization)
        self.sha = self.policy["expected_head_sha"]
        self.base = self.policy["expected_base_sha"]
        self.repository = self.policy["repository"]
        self.now = datetime.fromisoformat(self.policy["issued_at"]) + timedelta(minutes=1)
        mock.patch.object(existing.binding, "datetime", wraps=datetime).start().now.return_value = self.now
        self.ctx.head_ref = self.policy["head_ref"]
        self.ctx.base_ref = self.policy["base_ref"]
        self.ctx.pr_body = self.policy["required_pr_body_marker"]
        self.ctx.changed_files = [f"file-{i}.py" for i in range(182)]
        self.ctx.additions = 25489
        self.ctx.event["repository"]["full_name"] = self.repository
        self.ctx.event["pull_request"].update(number=132, body=self.ctx.pr_body)
        self.gc = {"head_sha": self.sha, "base_sha": self.base}
        self.size = {"effective_additions": 25489}
        self.git.return_value.stdout = self.sha + "\n"
        self.live.update(number=132, body=self.ctx.pr_body)
        self.live["head"].update(sha=self.sha, ref=self.ctx.head_ref)
        self.live["base"].update(sha=self.base, ref=self.ctx.base_ref)
        for side in ("head", "base"):
            self.live[side]["repo"].update(full_name=self.repository, id=1315697868)
        os.environ.update(GITHUB_REPOSITORY=self.repository,
                          GITHUB_REPOSITORY_ID="1315697868", GITHUB_REF="refs/pull/132/merge")
        spec = importlib.util.spec_from_file_location("pr132_engine", existing.ROOT / "pr-qa/pr_qa.py")
        self.engine = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.engine
        spec.loader.exec_module(self.engine)

    def validate(self):
        return existing.binding.validate_authorization(self.ctx, self.gc, self.policy, self.size)

    def test_exact_binding_and_only_two_relaxations(self):
        self.assertEqual(self.validate(), [])
        self.assertEqual(self.validate(), [])
        self.assertEqual(self.http.call_count, 2)
        self.assertEqual(self.policy["repository_id"], 1315697868)
        self.assertEqual(self.sha, "28f56cc00b941f5ba791323acffc6fe483f95879")
        self.assertEqual(self.base, "0c3185b2ec1846e193e71b2a3b54d2bea6d11e56")
        self.assertEqual(self.policy["allowed_effective_additions"], 25489)
        self.assertEqual(self.policy["allowed_changed_files"], 182)
        self.assertEqual(self.policy["relaxations"], ["diff_size", "exact_gitleaks_fingerprint_allowlist"])
        self.assertEqual(len(self.policy["gitleaks_allowlist"]), 2)

    def test_live_repository_pr_refs_shas_and_state_changes_rejected(self):
        for field, value in [("number", 133), ("state", "closed"), ("merged", True),
                             ("head.sha", "c" * 40), ("base.sha", "d" * 40),
                             ("head.ref", "other"), ("base.ref", "main"),
                             ("head.repo.id", 77), ("base.repo.id", 77),
                             ("head.repo.full_name", "other/repo"),
                             ("base.repo.full_name", "other/repo")]:
            with self.subTest(field=field):
                live = copy.deepcopy(self.live)
                parts = field.split(".")
                target = live
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
                self.http.return_value = live
                self.assertTrue(self.validate())

    def test_coherent_other_repository_id_cannot_reuse_named_authorization(self):
        for side in ("head", "base"):
            self.live[side]["repo"]["id"] = 77
        with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY_ID": "77"}):
            self.assertEqual(self.validate(), ["Trusted GitHub repository ID differs from authorization"])
        self.http.assert_not_called()

    def test_expired_closed_merged_and_other_consumer_replay_rejected(self):
        self.policy["expires_after"] = (self.now - timedelta(seconds=1)).isoformat()
        self.assertTrue(self.validate())
        self.policy["expires_after"] = (self.now + timedelta(hours=1)).isoformat()
        for changes in ({"state": "closed"}, {"merged": True}):
            self.http.return_value = {**self.live, **changes}
            self.assertTrue(self.validate())
        self.http.return_value = self.live
        with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "Synergie-ITCI/other"}):
            self.assertTrue(self.validate())
        with mock.patch.dict(os.environ, {"GITHUB_REF": "refs/pull/133/merge"}):
            self.assertTrue(self.validate())

    def test_checksum_line_and_fingerprint_matching_is_exact(self):
        lines = ["React-cxxstableapi: 06f491a41595d7e71e9a1783781913e0b2291d57",
                 "RNKeychain: 551d42b0ef53426f82551a0cc961cfa10ad33afa"]
        for allowance, line in zip(self.policy["gitleaks_allowlist"], lines):
            item = {"RuleID": allowance["rule_id"], "File": allowance["path"],
                    "StartLine": allowance["line"], "Fingerprint": allowance["fingerprint"]}
            with (mock.patch.object(self.engine, "baseline_inherited_path", return_value=True),
                  mock.patch.object(self.engine, "baseline_inherited_gitleaks_false_positive", return_value=False),
                  mock.patch.object(self.engine, "baseline_allowance_expired", return_value=False),
                  mock.patch.object(self.engine, "source_line", return_value=line) as source):
                self.assertEqual(self.engine.matching_gitleaks_allowance(self.ctx, item, [allowance]), allowance)
                source.return_value = line + "changed"
                self.assertIsNone(self.engine.matching_gitleaks_allowance(self.ctx, item, [allowance]))
                source.return_value = line
                for key, value in [("Fingerprint", "another:finding:generic-api-key:1"),
                                   ("File", "other/Podfile.lock"), ("StartLine", 1),
                                   ("RuleID", "other-rule")]:
                    self.assertIsNone(self.engine.matching_gitleaks_allowance(self.ctx, {**item, key: value}, [allowance]))

    def test_unmatched_consumers_keep_default_limits_without_lookup(self):
        for repository in (self.repository, "Synergie-ITCI/.github", "Synergie-ITCI/other", "outside/repo"):
            ctx = existing.PRContext(repo=existing.ROOT, config=copy.deepcopy(self.central["defaults"]),
                policy={**self.central, "one_time_baseline_alignment": self.policy},
                changed_files=[f"file-{i}.py" for i in range(201)], additions=5001,
                head_ref="feature/unmatched", base_ref="development",
                event={"repository": {"full_name": repository}, "pull_request": {"number": 999}})
            with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": repository}):
                self.assertEqual(self.engine.gate_baseline_alignment(ctx, self.gc)[0].status, "PASS")
                self.assertFalse(self.engine.baseline_active(ctx))
                findings = self.engine.risk_threshold_findings(ctx)
                self.assertTrue(any("max_additions=5000" in finding for finding in findings))
                self.assertTrue(any("max_changed_files=200" in finding for finding in findings))
                ctx.event["pull_request"]["labels"] = [{"name": "one-time-baseline-alignment"}]
                self.assertEqual(self.engine.gate_baseline_alignment(ctx, self.gc)[0].status, "FAIL")
        self.http.assert_not_called()
