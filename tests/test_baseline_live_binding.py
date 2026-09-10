from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
import baseline_authorization as binding
from adapters.base import PRContext


class BaselineLiveBindingTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.base = "b" * 40
        self.repository = "Synergie-ITCI/example"
        self.now = datetime.now(timezone.utc)
        self.policy = {
            "enabled": True,
            "repository": self.repository,
            "pr_number": 125,
            "expected_head_sha": self.sha,
            "expected_base_sha": self.base,
            "head_ref": "chore/baseline",
            "base_ref": "integration/example",
            "allowed_effective_additions": 10857,
            "allowed_changed_files": 107,
            "purpose": "One exact mechanical baseline",
            "issued_at": (self.now - timedelta(minutes=1)).isoformat(),
            "expires_after": (self.now + timedelta(hours=1)).isoformat(),
            "authorization_id": "00000000-0000-4000-8000-000000000001",
            "relaxations": ["diff_size"],
        }
        self.ctx = PRContext(
            repo=ROOT,
            config={},
            policy={},
            changed_files=["a.py"],
            head_ref="chore/baseline",
            base_ref="integration/example",
            event={
                "repository": {"full_name": self.repository},
                "pull_request": {"number": 125, "state": "open", "merged": False},
            },
        )
        self.gc = {"head_sha": self.sha, "base_sha": self.base}
        self.size = {"effective_additions": 10857}
        self.live = {
            "number": 125,
            "state": "open",
            "merged": False, "draft": False,
            "head": {
                "sha": self.sha,
                "ref": "chore/baseline",
                "repo": {"id": 77, "full_name": self.repository},
            },
            "base": {
                "sha": self.base,
                "ref": "integration/example",
                "repo": {"id": 77, "full_name": self.repository},
            },
        }
        self.env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REPOSITORY": self.repository,
            "GITHUB_REPOSITORY_ID": "77",
            "GITHUB_REF": "refs/pull/125/merge",
            "GITHUB_WORKSPACE": str(ROOT),
            "GH_TOKEN": "fixture",
        }
        self.environment = mock.patch.dict(os.environ, self.env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.http = mock.patch.object(
            binding, "read_live_pr", return_value=self.live
        ).start()
        self.addCleanup(mock.patch.stopall)
        self.git = mock.patch.object(
            binding.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, self.sha + "\n", ""),
        ).start()

    def validate(self):
        return binding.validate_authorization(self.ctx, self.gc, self.policy, self.size)

    def test_exact_open_pr_and_reruns_allowed_with_fresh_lookup(self):
        self.assertEqual(self.validate(), [])
        self.assertEqual(self.validate(), [])
        self.assertEqual(self.http.call_count, 2)
        self.http.assert_called_with(self.repository, 125, "fixture")

    def test_live_identity_and_state_mismatches_fail(self):
        cases = [
            ("number", 126),
            ("state", "closed"),
            ("merged", True),
            ("merged", None),
            ("head.sha", "c" * 40),
            ("head.ref", "other/source"),
            ("base.ref", "other/base"),
            ("base.repo.full_name", "other/repo"),
            ("base.repo.id", 78),
            ("head.repo.full_name", "fork/repo"),
            ("head.repo.id", 78),
            ("base.sha", "d" * 40),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                live = copy.deepcopy(self.live)
                target = live
                parts = field.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
                self.http.return_value = live
                self.assertTrue(self.validate())

    def test_trusted_context_cannot_be_overridden_by_event_or_policy(self):
        cases = {
            "GITHUB_REPOSITORY": "other/repo",
            "GITHUB_REPOSITORY_ID": "88",
            "GITHUB_REF": "refs/pull/126/merge",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_ACTIONS": "false",
            "GITHUB_WORKSPACE": "/not-the-checkout",
            "GH_TOKEN": "",
        }
        for key, value in cases.items():
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: value}):
                self.assertTrue(self.validate())
        self.ctx.event["pull_request"]["number"] = 126
        self.assertTrue(self.validate())
        self.ctx.event["pull_request"]["number"] = 125
        self.ctx.event["repository"]["full_name"] = "forged/repo"
        self.assertTrue(self.validate())

    def test_old_open_event_cannot_override_live_closed_or_changed_head(self):
        self.http.return_value = {**self.live, "state": "closed", "merged": True}
        self.assertTrue(self.validate())
        self.http.return_value = copy.deepcopy(self.live)
        self.http.return_value["head"]["sha"] = "f" * 40
        self.assertTrue(self.validate())
        self.assertEqual(self.ctx.event["pull_request"]["state"], "open")

    def test_authorization_scope_and_checkout_must_match(self):
        for field, value in [
            ("repository", "other/repo"),
            ("pr_number", 126),
            ("head_ref", "wrong"),
            ("base_ref", "wrong"),
            ("expected_head_sha", "c" * 40),
        ]:
            with self.subTest(field=field):
                old = self.policy[field]
                self.policy[field] = value
                self.assertTrue(self.validate())
                self.policy[field] = old
        self.git.return_value.stdout = "f" * 40
        self.assertTrue(self.validate())

    def test_authorized_limits_are_hard_caps(self):
        self.policy["allowed_effective_additions"] = 10856
        self.assertTrue(self.validate())
        self.policy["allowed_effective_additions"] = 10857
        self.policy["allowed_changed_files"] = 0
        self.assertTrue(self.validate())

    def test_time_window_requires_timezone_and_maximum_24_hours(self):
        cases = [
            {"expires_after": (self.now - timedelta(seconds=1)).isoformat()},
            {"issued_at": (self.now + timedelta(minutes=1)).isoformat()},
            {"expires_after": (self.now + timedelta(hours=25)).isoformat()},
            {"issued_at": "2026-09-09T00:00:00"},
            {"expires_after": "not-a-date"},
        ]
        original = self.policy.copy()
        for values in cases:
            with self.subTest(values=values):
                self.policy = {**original, **values}
                self.assertTrue(self.validate())
        self.policy = original
        self.policy["expires_after"] = (
            datetime.fromisoformat(original["issued_at"]) + timedelta(hours=24)
        ).isoformat()
        self.assertEqual(self.validate(), [])

    def test_strict_schema_rejects_missing_unknown_and_malformed_fields(self):
        schema = json.loads(binding.SCHEMA_PATH.read_text())
        original = self.policy.copy()
        for field in schema["required"]:
            with self.subTest(missing=field):
                self.policy = {k: v for k, v in original.items() if k != field}
                self.assertTrue(self.validate())
        for values in [
            {"unexpected": True},
            {"pr_number": True},
            {"allowed_changed_files": -1},
            {"relaxations": ["disable_secrets"]},
            {"authorization_id": ""},
            {"expected_head_sha": "bad"},
            {"purpose": " "},
            {"binary_assets": {"unknown": True}},
        ]:
            with self.subTest(values=values):
                self.policy = {**original, **values}
                self.assertTrue(self.validate())
        for malformed in [None, [], "invalid"]:
            self.policy = malformed
            self.assertTrue(self.validate())

    def test_missing_malformed_or_unavailable_live_pr_fails_closed(self):
        for value in [None, [], {}, {"number": 125}, {**self.live, "head": None}]:
            with self.subTest(value=value):
                self.http.return_value = value
                self.assertTrue(self.validate())
        for error in [ValueError("malformed"), OSError("unavailable")]:
            self.http.side_effect = error
            self.assertTrue(self.validate())

    def test_final_governance_rechecks_live_state(self):
        import argparse

        spec = importlib.util.spec_from_file_location(
            "final_binding_engine", ROOT / "pr-qa/pr_qa.py"
        )
        engine = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = engine
        spec.loader.exec_module(engine)
        self.ctx.policy = {"one_time_baseline_alignment": self.policy}
        self.ctx.pr_body = ""
        self.ctx.event["pull_request"]["labels"] = [
            {"name": "one-time-baseline-alignment"}
        ]
        self.ctx.additions = 10857
        engine.context_cache(self.ctx).update(
            baseline_authorized=True, baseline_mode="baseline"
        )
        self.http.return_value = {**self.live, "state": "closed", "merged": True}
        with (
            mock.patch.object(engine, "gather_git_context", return_value=self.gc),
            mock.patch.object(engine, "run_if_enabled", return_value=[]),
            mock.patch.object(engine, "gate_release_drift", return_value=[]),
        ):
            results = engine.run_governance(
                self.ctx, [], argparse.Namespace(review_policy_input="")
            )
        self.assertEqual(results[0].status, "FAIL")
        self.assertFalse(engine.baseline_active(self.ctx))

    def test_transport_errors_are_redacted_and_never_authorize(self):
        # Exercise real transport helper; only the HTTP opener is mocked.
        spec = importlib.util.spec_from_file_location(
            "transport_binding", ROOT / "pr-qa/baseline_authorization.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for status in [301, 401, 403, 404, 429, 500]:
            with (
                self.subTest(status=status),
                mock.patch.object(module.urllib.request, "build_opener") as opener,
            ):
                opener.return_value.open.side_effect = urllib.error.HTTPError(
                    "https://api.github.com", status, "sensitive-response", {}, None
                )
                with self.assertRaisesRegex(
                    ValueError, "^Live GitHub PR verification unavailable$"
                ):
                    module.read_live_pr(self.repository, 125, "fixture")
        for body in [b"invalid-json", b"[]", b"x" * 2_000_001]:
            with mock.patch.object(module.urllib.request, "build_opener") as opener:
                response = opener.return_value.open.return_value.__enter__.return_value
                response.status = 200
                response.read.return_value = body
                with self.assertRaises(ValueError):
                    module.read_live_pr(self.repository, 125, "fixture")
        with self.assertRaises(urllib.error.HTTPError) as redirect:
            module.NoRedirect().redirect_request(
                mock.Mock(full_url="https://api.github.com"),
                None,
                302,
                "",
                {},
                "https://untrusted.invalid",
            )
        redirect.exception.close()

    def test_omitted_authorization_preserves_default_limits_and_makes_no_lookup(self):
        spec = importlib.util.spec_from_file_location(
            "baseline_engine_test", ROOT / "pr-qa/pr_qa.py"
        )
        engine = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = engine
        spec.loader.exec_module(engine)
        self.ctx.policy = json.loads((ROOT / "policy/pr-qa-policy.json").read_text())
        self.ctx.policy.pop("one_time_baseline_alignment", None)
        self.assertEqual(
            engine.gate_baseline_alignment(self.ctx, self.gc)[0].status, "PASS"
        )
        self.http.assert_not_called()
        self.assertEqual(
            self.ctx.policy["defaults"]["thresholds"]["max_additions"], 5000
        )
        self.assertEqual(
            self.ctx.policy["defaults"]["thresholds"]["max_changed_files"], 200
        )
