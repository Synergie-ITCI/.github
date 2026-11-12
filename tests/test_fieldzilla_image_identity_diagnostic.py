"""Keep the image identity diagnostic unable to reach source or AWS operations."""

import re
import base64
import io
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github/workflows/fieldzilla-production-images.yml"
)


class ImageIdentityDiagnosticTests(unittest.TestCase):
    def build_identity_script(self):
        workflow = WORKFLOW.read_text()
        block = re.findall(r"python3 - <<'PY'\n(.*?)\n\s+PY", workflow, re.S)[0]
        lines = block.splitlines()
        indent = len(lines[0]) - len(lines[0].lstrip())
        return "\n".join(line[indent:] for line in lines)

    def test_diagnostic_stops_after_identity_check(self):
        workflow = WORKFLOW.read_text()
        build, publish = workflow.split("\n  publish:\n", 1)
        steps = re.findall(r"(?ms)^      - name: (.+?)\n(.*?)(?=^      - name: |\Z)", build)
        self.assertEqual(steps[0][0], "Verify actual build identity without a production environment")
        self.assertEqual(len(steps), 9)
        identity = steps[0][1]
        self.assertNotIn("image_runner.py", identity)
        self.assertNotIn("aws ", identity)
        self.assertNotIn("docker ", identity)
        for name, body in steps[1:]:
            with self.subTest(step=name):
                self.assertIn("        if: ${{ !inputs.diagnostic-only }}\n", body)
        self.assertIn("    if: ${{ !inputs.diagnostic-only }}\n", publish.split("\n    steps:\n", 1)[0])
        self.assertIn("      diagnostic-only:\n        type: boolean\n", build)
        self.assertIn("default: false", build)

    def test_identity_error_reports_names_without_values(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("mismatched = [k for k, v in expected.items() if str(claims.get(k)) != v]", workflow)
        self.assertNotIn("print(claims)", workflow)
        self.assertNotIn("print(token)", workflow)

    def test_tag_object_claim_is_checked_against_pinned_release_source(self):
        central, tag_object, caller = "a" * 40, "b" * 40, "c" * 40
        tag = "pr-qa-v1-rc999"
        workflow_ref = (
            "Synergie-ITCI/.github/.github/workflows/"
            f"fieldzilla-production-images.yml@refs/tags/{tag}"
        )
        claims = {
            "aud": "fieldzilla-production-image-build",
            "repository_id": "1315697868",
            "repository_owner_id": "209829096",
            "ref": "refs/heads/main",
            "sha": caller,
            "job_workflow_ref": workflow_ref,
            "job_workflow_sha": tag_object,
        }
        env = {
            "GITHUB_REPOSITORY": "Synergie-ITCI/programme-management-platform",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": caller,
            "CALLER_SHA": caller,
            "WORKFLOW_TAG": tag,
            "CENTRAL_SHA": central,
            "CENTRAL_WORKFLOW_REF": workflow_ref,
            "GH_TOKEN": "test-token",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/test?x=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-token",
        }
        tag_source = central

        def urlopen(request, timeout):
            url = request.full_url
            if "/git/ref/tags/" in url:
                reply = {"object": {"type": "tag", "sha": tag_object}}
            elif "/git/tags/" in url:
                reply = {"tag": tag, "object": {"type": "commit", "sha": tag_source}}
            else:
                payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
                reply = {"value": f"header.{payload}.signature"}
            return io.BytesIO(json.dumps(reply).encode())

        with patch.dict(os.environ, env), patch("urllib.request.urlopen", side_effect=urlopen):
            exec(compile(self.build_identity_script(), "identity-gate", "exec"), {})
            claims["job_workflow_sha"] = central
            with self.assertRaisesRegex(SystemExit, "job_workflow_sha"):
                exec(compile(self.build_identity_script(), "identity-gate", "exec"), {})
            claims["job_workflow_sha"] = tag_object
            tag_source = "d" * 40
            with self.assertRaisesRegex(SystemExit, "release tag source differs"):
                exec(compile(self.build_identity_script(), "identity-gate", "exec"), {})


if __name__ == "__main__":
    unittest.main()
