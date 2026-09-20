"""Adversarial coverage for the governed release registry and tag protections."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
from release_pin import EVIDENCE_HEADER, resolve_active_release, same_timestamp, validate_workflow, verify_live_release


class ReleasePinTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/pr-qa.yml").read_text()
        self.manifest = json.loads((ROOT / "policy/framework-releases.json").read_text())
        self.release, self.entry = validate_workflow(self.workflow, self.manifest)
        self.ref = {"ref": f"refs/tags/{self.release}",
                    "object": {"type": "tag", "sha": "a" * 40}}
        self.tag = {"object": {"type": "commit", "sha": self.entry["commit"]}}
        self.ruleset = {
            "updated_at": self.entry["ruleset_updated_at"],
            "id": self.entry["ruleset_id"], "target": "tag", "enforcement": "active",
            "bypass_actors": [], "conditions": {"ref_name": {
                "include": [f"refs/tags/{self.release}"], "exclude": []}},
            "rules": [{"type": "update"}, {"type": "deletion"}],
        }

    def lookup(self, path):
        if path.startswith("git/ref/"):
            return self.ref
        if path.startswith("git/tags/"):
            return self.tag
        return self.ruleset

    def test_ruleset_timestamp_offsets_preserve_exact_instant(self):
        self.assertTrue(same_timestamp("2026-09-09T10:08:30.583Z", "2026-09-09T15:38:30.583+05:30"))
        for value in (None, "", "2026-09-09T10:08:30.583", "2026-09-09T10:08:30.584Z",
                      "2026-09-09T10:08:30Z", "2026-09-09T10:08:30.583001Z"):
            self.assertFalse(same_timestamp(value, "2026-09-09T15:38:30.583+05:30"))

    def test_registered_protected_annotated_tag(self):
        verify_live_release(self.release, self.entry, self.lookup)

    def test_read_only_response_requires_exact_reviewed_ruleset_timestamp(self):
        del self.ruleset["bypass_actors"]
        verify_live_release(self.release, self.entry, self.lookup)
        self.ruleset["updated_at"] = "2026-09-10T00:00:00Z"
        with self.assertRaises(ValueError):
            verify_live_release(self.release, self.entry, self.lookup)
        del self.ruleset["updated_at"]
        with self.assertRaises(ValueError):
            verify_live_release(self.release, self.entry, self.lookup)

    def test_manifest_requires_explicit_no_bypass_evidence(self):
        for change in ({"bypass_actors": [{"actor_id": 1}]}, {"ruleset_updated_at": ""}):
            manifest = copy.deepcopy(self.manifest)
            manifest["releases"][self.release].update(change)
            with self.assertRaises(ValueError):
                validate_workflow(self.workflow, manifest)

    def test_unregistered_branches_shas_mutable_and_arbitrary_tags_rejected(self):
        for ref in ("main", "development", "a" * 40, "latest", "${{ inputs.framework-ref }}"):
            workflow = self.workflow.replace("ref: ${{ steps.active-framework.outputs.release }}", f"ref: {ref}", 1)
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                validate_workflow(workflow, self.manifest)

    def test_even_registered_branch_or_sha_is_rejected(self):
        for ref in ("main", "a" * 40, "latest"):
            manifest = copy.deepcopy(self.manifest)
            manifest["releases"][ref] = self.entry
            workflow = self.workflow.replace("ref: ${{ needs.detect.outputs.framework_release }}", f"ref: {ref}", 1)
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                validate_workflow(workflow, manifest)

    def test_credentials_overrides_and_checkout_bypasses_rejected(self):
        mutations = [
            self.workflow.replace("persist-credentials: false", "persist-credentials: true", 1),
            self.workflow.replace("persist-credentials: false", "token: ${{ secrets.OTHER }}\n          persist-credentials: false", 1),
            self.workflow.replace("persist-credentials: false", "ssh-key: private\n          persist-credentials: false", 1),
            self.workflow.replace("persist-credentials: false", "", 1),
            self.workflow.replace("ref: ${{ steps.active-framework.outputs.release }}", "ref: main", 1),
            self.workflow.replace("ref: ${{ needs.detect.outputs.framework_release }}", "ref: ${{ inputs.framework-ref }}", 1),
            self.workflow.replace("      - name: Checkout pull request", '      - name: Checkout pull request\n        env:\n          PR_QA_FRAMEWORK_RELEASE: "main"', 1),
            self.workflow.replace("    name: Detect repository technologies", '    env:\n      PR_QA_FRAMEWORK_RELEASE: "main"\n    name: Detect repository technologies'),
            self.workflow.replace("          python3 .pr-qa-framework/pr-qa/pr_qa.py", '          echo "PR_QA_FRAMEWORK_RELEASE=main" >> "$GITHUB_ENV"\n          python3 .pr-qa-framework/pr-qa/pr_qa.py', 1),
        ]
        for workflow in mutations:
            with self.subTest(workflow=mutations.index(workflow)), self.assertRaises(ValueError):
                validate_workflow(workflow, self.manifest)

    def test_moved_tag_and_unprotected_or_bypassable_tags_rejected(self):
        self.tag["object"]["sha"] = "b" * 40
        with self.assertRaises(ValueError):
            verify_live_release(self.release, self.entry, self.lookup)
        self.tag["object"]["sha"] = self.entry["commit"]
        valid = copy.deepcopy(self.ruleset)
        for change in (
            {"enforcement": "disabled"}, {"enforcement": "evaluate"},
            {"bypass_actors": [{"actor_id": 1}]}, {"target": "branch"},
            {"rules": [{"type": "update"}]}, {"rules": [{"type": "deletion"}]},
            {"conditions": {"ref_name": {"include": ["refs/tags/*"], "exclude": []}}},
            {"conditions": {"ref_name": {"include": [f"refs/tags/{self.release}"], "exclude": [f"refs/tags/{self.release}"]}}},
        ):
            self.ruleset = {**valid, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_live_release(self.release, self.entry, self.lookup)

    def test_future_annotated_release_evidence_activates_without_registry_edit(self):
        future_release = "pr-qa-v1-rc160"
        future_commit = "f" * 40
        future_entry = {
            "release": future_release,
            "commit": future_commit,
            "ruleset_id": 999160,
            "ruleset_updated_at": "2026-09-20T12:00:00.000+05:30",
            "bypass_actors": [],
        }
        tag_sha = "1" * 40
        refs = [
            {"ref": f"refs/tags/{self.release}", "object": {"type": "commit", "sha": self.entry["commit"]}},
            {"ref": f"refs/tags/{future_release}", "object": {"type": "tag", "sha": tag_sha}},
        ]
        future_tag = {
            "tag": future_release,
            "message": EVIDENCE_HEADER + "\n" + json.dumps(future_entry, sort_keys=True),
            "object": {"type": "commit", "sha": future_commit},
        }
        legacy_ruleset = copy.deepcopy(self.ruleset)
        future_ruleset = {
            "updated_at": future_entry["ruleset_updated_at"],
            "id": future_entry["ruleset_id"], "target": "tag", "enforcement": "active",
            "bypass_actors": [], "conditions": {"ref_name": {
                "include": [f"refs/tags/{future_release}"], "exclude": []}},
            "rules": [{"type": "update"}, {"type": "deletion"}, {"type": "non_fast_forward"}],
        }

        def lookup(path):
            if path == f"git/ref/tags/{self.release}":
                return refs[0]
            if path == f"git/ref/tags/{future_release}":
                return refs[1]
            if path == "git/tags/" + tag_sha:
                return future_tag
            if path == f"rulesets/{self.entry['ruleset_id']}":
                return legacy_ruleset
            if path == f"rulesets/{future_entry['ruleset_id']}":
                return future_ruleset
            raise AssertionError(path)

        release, entry = resolve_active_release(self.manifest, lookup=lookup, list_refs=lambda path: refs)
        self.assertEqual(release, future_release)
        self.assertEqual(entry["commit"], future_commit)
        self.assertNotIn(future_release, self.manifest["releases"])
