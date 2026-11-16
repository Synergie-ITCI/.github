import base64
import copy
import json
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/fieldzilla-production"))
from merge_metadata_recovery import verify_merge_metadata_recovery

REPO = "Synergie-ITCI/programme-management-platform"
HEAD = "2" * 40
BASE = "5" * 40
MERGE = "7" * 40
TREE = "8" * 40
CALLER = "9" * 40
CENTRAL = "a" * 40


class MergeMetadataRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "scope": "production-images", "merge_metadata_recovery": True,
            "promotion_pr": 786, "application": {"source_sha": HEAD},
            "base_sha": BASE, "caller_sha": CALLER,
        }
        self.record = {
            "repository": REPO, "pr_number": 786, "head_sha": HEAD,
            "base_sha": BASE, "merge_sha": MERGE, "tree_sha": TREE,
            "owner_comment_id": 123, "issued_at": "2026-11-16T15:00:00Z",
            "expires_at": "2026-11-17T14:00:00Z",
            "support_ticket": "https://help.github.com/ticket/personal/0/5012738",
            "enabled": True,
        }
        identity = {"full_name": REPO}
        self.pr = {
            "number": 786, "state": "open", "merged": False,
            "merged_at": None, "draft": False,
            "head": {"sha": HEAD, "repo": identity},
            "base": {"sha": BASE, "ref": "main", "repo": identity},
        }
        self.merge = {
            "sha": MERGE, "parents": [{"sha": BASE}, {"sha": HEAD}],
            "tree": {"sha": TREE}, "verification": {"verified": True},
            "message": "Merge pull request #786 from Synergie-ITCI/feature/fieldzilla-role-management-promotion",
            "committer": {"date": "2026-11-16T14:00:00Z"},
        }
        self.rulesets = {
            19620452: {
                "id": 19620452, "updated_at": "2026-10-31T00:00:00Z",
                "enforcement": "active", "bypass_actors": [],
                "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
                "rules": [
                    {"type": "pull_request"},
                    {"type": "required_status_checks", "parameters": {
                        "required_status_checks": [{"context": "pr-qa / Pull Request Quality Assurance"}]}}
                ],
            },
            20796933: {
                "id": 20796933, "updated_at": "2026-08-20T00:00:00Z",
                "enforcement": "active", "bypass_actors": [],
                "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
                "rules": [{"type": "required_status_checks", "parameters": {
                    "required_status_checks": [
                        {"context": "Architecture Governance"},
                        {"context": "pr-qa / Pull Request Quality Assurance"},
                    ]}}],
            },
        }
        self.comment = {
            "body": (
                f"FIELDZILLA MERGE METADATA RECOVERY V1 repo={REPO} pr=786 "
                f"head={HEAD} base={BASE} merge={MERGE} tree={TREE} "
                "expires_at=2026-11-17T14:00:00Z"
            ),
            "user": {"login": "SaurabhVermaIN", "id": 52234089},
            "issue_url": f"https://api.github.com/repos/{REPO}/issues/786",
            "created_at": "2026-11-16T15:01:00Z",
            "updated_at": "2026-11-16T15:01:00Z",
        }

    def api(self, path):
        if path.startswith("repos/Synergie-ITCI/.github/contents/"):
            payload = {"version": 1, "recoveries": [self.record]}
            return {"type": "file", "encoding": "base64", "content": base64.b64encode(json.dumps(payload).encode()).decode()}
        if path == "repos/Synergie-ITCI/.github/git/ref/heads/main":
            return {"object": {"sha": CENTRAL}}
        if path == f"repos/{REPO}/pulls/786":
            return self.pr
        if path == f"repos/{REPO}/git/ref/heads/main":
            return {"object": {"sha": CALLER}}
        if path == f"repos/{REPO}/compare/{MERGE}...{CALLER}":
            return {"status": "ahead"}
        if path == f"repos/{REPO}/git/commits/{MERGE}":
            return self.merge
        if path == f"repos/{REPO}/git/commits/{HEAD}":
            return {"tree": {"sha": TREE}}
        for identifier, value in self.rulesets.items():
            if path == f"repos/{REPO}/rulesets/{identifier}":
                return value
        if path == f"repos/{REPO}/issues/comments/123":
            return self.comment
        raise AssertionError(path)

    def verify(self):
        return verify_merge_metadata_recovery(
            self.manifest, api=self.api, activated_sha=CENTRAL,
            now=datetime(2026, 11, 16, 16, tzinfo=UTC),
        )

    def test_exact_incident_passes_only_with_explicit_opt_in(self):
        self.assertEqual(self.verify(), self.record)
        self.manifest["merge_metadata_recovery"] = False
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_identity_ancestry_tree_or_approval_fails(self):
        mutations = [
            (self.manifest, "base_sha", "1" * 40),
            (self.pr, "state", "closed"),
            (self.merge, "parents", [{"sha": HEAD}, {"sha": BASE}]),
            (self.merge["tree"], "sha", "1" * 40),
            (self.comment, "updated_at", "2026-11-16T15:02:00Z"),
            (self.rulesets[19620452], "bypass_actors", [{"actor_id": 1}]),
        ]
        for target, key, changed in mutations:
            original = copy.deepcopy(target[key])
            target[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()
            target[key] = original

    def test_expired_window_fails(self):
        with self.assertRaises(ValueError):
            verify_merge_metadata_recovery(
                self.manifest, api=self.api, activated_sha=CENTRAL,
                now=datetime(2026, 11, 17, 14, tzinfo=UTC),
            )


if __name__ == "__main__":
    unittest.main()
