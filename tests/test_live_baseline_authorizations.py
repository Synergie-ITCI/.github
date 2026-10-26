"""Live PR decisions change without changing the immutable QA framework."""

import base64
import copy
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))

import baseline_authorization as binding
import pr_qa as qa
from adapters.base import PRContext


class Response:
    status = 200

    def __init__(self, value):
        self.body = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit):
        return self.body[:limit]


class LiveBaselineAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.entry = {
            "enabled": True,
            "repository": "Synergie-ITCI/roadsense-production-dashboard",
            "pr_number": 105,
            "head_ref": "promote/roadsense-pr98-staging",
            "base_ref": "staging",
            "relaxations": ["diff_size"],
        }
        self.context = PRContext(
            repo=ROOT, config={}, policy={"one_time_baseline_alignments": []},
            changed_files=[], head_ref=self.entry["head_ref"], base_ref="staging",
            event={"repository": {"full_name": self.entry["repository"]},
                   "pull_request": {"number": 105}},
        )
        self.env = patch.dict(os.environ, {
            "PR_QA_LIVE_AUTHORIZATIONS": "true",
            "GITHUB_REPOSITORY": self.entry["repository"],
            "GH_TOKEN": "fixture",
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_protected_main_decision_selected_without_immutable_policy_edit(self):
        with patch.object(binding, "read_live_central_alignments",
                          return_value=("a" * 40, [self.entry])) as lookup:
            self.assertEqual(qa.baseline_policy(self.context), self.entry)
            self.assertEqual(qa.baseline_policy(self.context), self.entry)
            lookup.assert_called_once_with("fixture")
        self.assertEqual(self.context.policy["one_time_baseline_alignments"], [])

    def test_lookup_failure_or_duplicate_scope_fails_closed(self):
        with patch.object(binding, "read_live_central_alignments", side_effect=ValueError):
            self.assertEqual(qa.baseline_policy(self.context), {"enabled": False})
        delattr(self.context, "_stack_cache")
        with patch.object(binding, "read_live_central_alignments",
                          return_value=("a" * 40, [self.entry, copy.deepcopy(self.entry)])):
            self.assertEqual(qa.baseline_policy(self.context), {"enabled": False})

    def test_live_non_size_relaxation_is_not_activated(self):
        other = {**self.entry, "relaxations": ["historical_commit_volume"]}
        with patch.object(binding, "read_live_central_alignments",
                          return_value=("a" * 40, [other])):
            self.assertEqual(qa.baseline_policy(self.context), {})

    def test_synthetic_repository_cannot_use_live_decisions(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "Synergie-ITCI/.github"}):
            with patch.object(binding, "read_live_central_alignments") as read:
                self.assertEqual(qa.baseline_policy(self.context), {})
                read.assert_not_called()

    def test_application_test_command_does_not_inherit_engine_switch(self):
        outcome = self.context.run([
            sys.executable, "-c",
            "import os; print(os.environ.get('PR_QA_LIVE_AUTHORIZATIONS', 'absent'))",
        ])
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.stdout.strip(), "absent")

    def test_live_read_pins_contents_to_main_sha(self):
        main = "b" * 40
        policy = {"version": 1, "one_time_baseline_alignments": [self.entry]}
        payload = {"type": "file", "encoding": "base64",
                   "content": base64.b64encode(json.dumps(policy).encode()).decode()}
        urls = []

        class Opener:
            def open(self, request, timeout):
                urls.append(request.full_url)
                return Response({"object": {"sha": main}} if len(urls) == 1 else payload)

        with patch.object(binding.urllib.request, "build_opener", return_value=Opener()):
            self.assertEqual(binding.read_live_central_alignments("fixture"), (main, [self.entry]))
        self.assertEqual(urls[0], "https://api.github.com/repos/Synergie-ITCI/.github/git/ref/heads/main")
        self.assertEqual(urls[1], f"https://api.github.com/repos/Synergie-ITCI/.github/contents/policy/pr-qa-policy.json?ref={main}")

    def test_only_authorization_entries_are_release_neutral(self):
        pinned = {"version": 1, "defaults": {"thresholds": {"max_additions": 5000}},
                  "one_time_baseline_alignments": []}
        changed = copy.deepcopy(pinned)
        changed["one_time_baseline_alignments"] = [self.entry]
        encode = lambda value: json.dumps(value).encode()
        self.assertTrue(qa.release_sensitive_policy_matches(encode(changed), encode(pinned)))
        changed["defaults"]["thresholds"]["max_additions"] = 9000
        self.assertFalse(qa.release_sensitive_policy_matches(encode(changed), encode(pinned)))
        changed["defaults"]["thresholds"]["max_additions"] = 5000
        changed["one_time_baseline_alignments"].append({"relaxations": ["historical_commit_volume"]})
        self.assertFalse(qa.release_sensitive_policy_matches(encode(changed), encode(pinned)))
        self.assertFalse(qa.release_sensitive_policy_matches(b"broken", encode(pinned)))


if __name__ == "__main__":
    unittest.main()
