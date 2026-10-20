"""Keep the RoadSense SSM command fixed to the reviewed remote script."""

import base64
import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "iam/roadsense-production-remote-v1.sh"
DOCUMENT = ROOT / "iam/roadsense-production-command-v1.json"
EXPECTED_SHA = "459f0aa8a0eb95a9f459ad0fa042db7abfefc33a648b51d66889bde45b898e0a"


class RoadSenseRestrictedSsmDocumentTests(unittest.TestCase):
    def test_fixed_script_and_bounded_parameter(self):
        document = json.loads(DOCUMENT.read_text())
        source = SCRIPT.read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), EXPECTED_SHA)
        self.assertEqual(document["schemaVersion"], "2.2")
        self.assertEqual(set(document["parameters"]), {"ReleaseJsonBase64"})
        parameter = document["parameters"]["ReleaseJsonBase64"]
        self.assertEqual(parameter["interpolationType"], "ENV_VAR")
        self.assertIsNone(re.fullmatch(parameter["allowedPattern"], "$(touch /tmp/unsafe)"))
        self.assertIsNone(re.fullmatch(parameter["allowedPattern"], "echo unsafe;"))
        self.assertIsNotNone(re.fullmatch(parameter["allowedPattern"], base64.b64encode(b"x" * 100).decode()))

        self.assertEqual(len(document["mainSteps"]), 1)
        step = document["mainSteps"][0]
        self.assertEqual(step["action"], "aws:runShellScript")
        self.assertEqual(step["precondition"], {"StringEquals": ["platformType", "Linux"]})
        (command,) = step["inputs"]["runCommand"]
        encoded = re.search(r"printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d", command)
        self.assertIsNotNone(encoded)
        self.assertEqual(base64.b64decode(encoded.group(1), validate=True), source)
        self.assertIn(f"'{EXPECTED_SHA}'", command)
        self.assertIn('RELEASE_JSON_B64="$SSM_ReleaseJsonBase64" bash "$script"', command)
        self.assertIn('AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_CONFIG_FILE=/dev/null', command)
        self.assertIn('AWS_EC2_METADATA_DISABLED=false HOME="$clean_home"', command)
        self.assertIn('-u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN', command)
        self.assertNotIn("{{", command)

    def test_workflow_and_policy_use_only_fixed_document(self):
        workflow = (ROOT / ".github/workflows/roadsense-controlled-release.yml").read_text()
        policy = json.loads((ROOT / "iam/roadsense-deploy-policy.json").read_text())
        self.assertIn(f"'{EXPECTED_SHA}'", workflow)
        self.assertIn("--document-version 1", workflow)
        self.assertIn("--document-name RoadSense-GateD-Production-Command-v1", workflow)
        self.assertNotIn("AWS-RunShellScript", workflow)
        self.assertNotIn("AWS-RunShellScript", json.dumps(policy))
        send = next(item for item in policy["Statement"] if item["Sid"] == "SendCommandOnlyToRoadSenseManagedNode")
        self.assertEqual(set(send["Resource"]), {
            "arn:aws:ssm:ap-south-1:918870682888:document/RoadSense-GateD-Production-Command-v1",
            "arn:aws:ssm:ap-south-1:918870682888:managed-instance/mi-0dade13fd68d1b435",
        })


if __name__ == "__main__":
    unittest.main()
