"""The deployment-risk exception accepts only the reviewed RoadSense caller shape."""

import importlib.util
import copy
import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "pr-qa" / "pr_qa.py"
spec = importlib.util.spec_from_file_location("roadsense_pr_qa_engine", ENGINE)
engine = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(ENGINE.parent))
sys.modules[spec.name] = engine
spec.loader.exec_module(engine)


def caller(path):
    job_id, central_file, permissions, inputs, approver_only = engine.ROADSENSE_GATE_D_CALLERS[path]
    source = ["name: RoadSense review", "", "on:", "  workflow_dispatch:", "    inputs:"]
    for name in inputs:
        source += [f"      {name}:", "        description: Reviewed exact value", "        required: true", "        type: string"]
    source += ["", "permissions:"]
    source += [f"  {key}: {value}" for key, value in permissions.items()]
    condition = "github.ref == 'refs/heads/main'"
    if approver_only:
        condition += " && github.actor == 'SaurabhVermaIN' && github.actor_id == '52234089'"
    release = "roadsense-gate-d-v3" if job_id == "deploy" else "roadsense-gate-d-v1"
    source += ["", "jobs:", f"  {job_id}:", f"    if: {condition}",
               f"    uses: Synergie-ITCI/.github/.github/workflows/{central_file}@{release}",
               "    with:"]
    source += [f"      {target}: ${{{{ inputs.{name} }}}}" for name, target in inputs.items()]
    return "\n".join(source) + "\n"


class CallerClassifierTests(unittest.TestCase):
    def setUp(self):
        self.ctx = SimpleNamespace(event={"repository": {"full_name": "Synergie-ITCI/roadsense-production-dashboard"}})
        self.approval_patch = patch.object(engine, "approved_roadsense_gate_d_release", return_value=True)
        self.approved = self.approval_patch.start()
        self.addCleanup(self.approval_patch.stop)

    def test_all_four_exact_callers_are_reviewable(self):
        for path in engine.ROADSENSE_GATE_D_CALLERS:
            with self.subTest(path=path):
                self.assertTrue(engine.roadsense_gate_d_caller_details(self.ctx, path, caller(path)))

    def test_identity_probe_exception_requires_exact_bytes_repository_and_release(self):
        path = engine.ROADSENSE_OIDC_PROBE_PATH
        source = (ROOT / "tests/fixtures/roadsense-oidc-identity-probe.yml").read_text()
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), engine.ROADSENSE_OIDC_PROBE_SHA256)
        self.assertTrue(engine.roadsense_oidc_identity_probe_details(self.ctx, path, source))
        for altered in (
            source.replace("roadsense-gate-d-v4", "roadsense-gate-d-v3"),
            source.replace('"Effect":"Deny"', '"Effect":"Allow"'),
            source + "\n# unexpected change\n",
        ):
            self.assertFalse(engine.roadsense_oidc_identity_probe_details(self.ctx, path, altered))
        self.assertFalse(engine.roadsense_oidc_identity_probe_details(self.ctx, "other.yml", source))
        self.ctx.event["repository"]["full_name"] = "Synergie-ITCI/other"
        self.assertFalse(engine.roadsense_oidc_identity_probe_details(self.ctx, path, source))
        self.ctx.event["repository"]["full_name"] = "Synergie-ITCI/roadsense-production-dashboard"
        self.approved.return_value = False
        self.assertFalse(engine.roadsense_oidc_identity_probe_details(self.ctx, path, source))

    def test_pyyaml_boolean_on_key_is_accepted(self):
        path = ".github/workflows/roadsense-controlled-release.yml"
        text = caller(path)
        parsed = engine.parse_workflow_yaml(text)
        parsed[True] = parsed.pop("on", parsed.get(True))
        parsed.pop("on", None)
        with patch.object(engine, "parse_workflow_yaml", return_value=parsed):
            self.assertTrue(engine.roadsense_gate_d_caller_details(self.ctx, path, text))

    def test_future_protected_compatible_deploy_version_needs_no_classifier_change(self):
        path = ".github/workflows/roadsense-controlled-release.yml"
        self.assertTrue(engine.roadsense_gate_d_caller_details(
            self.ctx, path, caller(path).replace("@roadsense-gate-d-v3", "@roadsense-gate-d-v4")))
        self.approved.return_value = False
        self.assertFalse(engine.roadsense_gate_d_caller_details(
            self.ctx, path, caller(path).replace("@roadsense-gate-d-v3", "@roadsense-gate-d-v4")))

    def test_changed_pin_trigger_permission_and_actor_are_rejected(self):
        path = ".github/workflows/roadsense-controlled-release.yml"
        clean = caller(path)
        for bad in (
            clean.replace("@roadsense-gate-d-v3", "@main"),
            clean.replace("@roadsense-gate-d-v3", "@roadsense-gate-d-v1"),
            clean.replace("@roadsense-gate-d-v3", "@roadsense-gate-d-v2"),
            clean.replace("workflow_dispatch:", "push:"),
            clean.replace("  id-token: write", "  id-token: read"),
            clean.replace("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/development'"),
            clean + "    steps:\n      - run: aws ssm send-command\n",
        ):
            with self.subTest(bad=bad[-80:]):
                self.assertFalse(engine.roadsense_gate_d_caller_details(self.ctx, path, bad))
        approval = ".github/workflows/roadsense-gate-d-approve.yml"
        self.assertFalse(engine.roadsense_gate_d_caller_details(
            self.ctx, approval, caller(approval).replace("52234089", "999")))

    def test_exception_does_not_apply_to_other_repositories(self):
        self.ctx.event["repository"]["full_name"] = "Synergie-ITCI/other"
        path = ".github/workflows/roadsense-controlled-release.yml"
        self.assertFalse(engine.roadsense_gate_d_caller_details(self.ctx, path, caller(path)))

    def test_release_identity_requires_governed_commit_and_exact_protection(self):
        self.approval_patch.stop()
        release = "roadsense-gate-d-v4"
        workflow = "roadsense-controlled-release.yml"
        commit = "a" * 40
        tag_object = "b" * 40
        main = "c" * 40
        rules = {"id": 42, "target": "tag", "enforcement": "active",
                 "updated_at": "2026-10-20T00:00:00Z", "bypass_actors": [],
                 "conditions": {"ref_name": {"include": [f"refs/tags/{release}"], "exclude": []},
                                "repository_name": {"include": [".github"], "exclude": [], "protected": False}},
                 "rules": [{"type": "update"}, {"type": "deletion"}]}
        repo_rules = copy.deepcopy(rules)
        repo_rules["conditions"].pop("repository_name")
        prefix = "repos/Synergie-ITCI/.github"
        policy = {"repository": "Synergie-ITCI/.github", "gate_d_workflow_releases": {
            release: {"commit": commit, "tag_object": tag_object, "ruleset_id": 42,
                      "ruleset_updated_at": rules["updated_at"], "bypass_actors": [],
                      "workflows": [workflow]}}}
        responses = {
            f"{prefix}/git/ref/heads/main": {"object": {"sha": main}},
            f"{prefix}/contents/policy/framework-releases.json?ref={main}": {
                "type": "file", "encoding": "base64", "content": base64.b64encode(json.dumps(policy).encode()).decode()},
            f"{prefix}/git/ref/tags/{release}": {"ref": f"refs/tags/{release}",
                                                    "object": {"type": "tag", "sha": tag_object}},
            f"{prefix}/git/tags/{tag_object}": {"tag": release, "object": {"type": "commit", "sha": commit}},
            f"{prefix}/compare/{commit}...{main}": {"status": "ahead"},
            f"{prefix}/commits/{commit}/pulls": [{"merged_at": "2026-10-20T00:00:00Z",
                                                   "merge_commit_sha": commit,
                                                   "base": {"ref": "main", "repo": {"full_name": "Synergie-ITCI/.github"}}}],
            f"{prefix}/rulesets/42": repo_rules,
        }
        def verify(data):
            return engine.approved_roadsense_gate_d_release(release, workflow, lambda path: data[path])
        self.assertTrue(verify(responses))
        self.assertFalse(engine.approved_roadsense_gate_d_release(
            release, "unauthorized.yml", lambda path: responses[path]))
        for path, change in (
            (f"{prefix}/compare/{commit}...{main}", {"status": "diverged"}),
            (f"{prefix}/rulesets/42", {**repo_rules, "enforcement": "disabled"}),
            (f"{prefix}/rulesets/42", {**repo_rules, "updated_at": "2026-10-21T00:00:00Z"}),
        ):
            with self.subTest(path=path):
                bad = {**responses, path: change}
                self.assertFalse(verify(bad))


if __name__ == "__main__":
    unittest.main()
