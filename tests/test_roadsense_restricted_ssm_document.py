"""Keep the RoadSense SSM command fixed to the reviewed remote script."""

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
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
        self.assertEqual(parameter["allowedPattern"], "^[A-Za-z0-9+/=]+$")
        self.assertEqual((parameter["minChars"], parameter["maxChars"]), (100, 8192))
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
        self.assertIn('[[ -n "${AWS_SHARED_CREDENTIALS_FILE:-}" && -r "$AWS_SHARED_CREDENTIALS_FILE" ]]', command)
        self.assertIn('AWS_SHARED_CREDENTIALS_FILE="$AWS_SHARED_CREDENTIALS_FILE" AWS_CONFIG_FILE=/dev/null', command)
        self.assertIn('AWS_EC2_METADATA_DISABLED=true HOME="$clean_home"', command)
        self.assertNotIn('AWS_SHARED_CREDENTIALS_FILE=/dev/null', command)
        self.assertIn('-u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN', command)
        self.assertIn(
            'arn:aws:sts::918870682888:assumed-role/SynergieSSMHybridManagedInstanceCore/mi-0dade13fd68d1b435',
            command,
        )
        self.assertLess(command.index('aws sts get-caller-identity'), command.index('RELEASE_JSON_B64='))
        self.assertIn('aws sts get-caller-identity --query Arn --output text)" = ' + '\\' + '\n', command)
        self.assertNotIn("{{", command)

    def test_workflow_and_policy_use_only_fixed_document(self):
        workflow = (ROOT / ".github/workflows/roadsense-controlled-release.yml").read_text()
        policy = json.loads((ROOT / "iam/roadsense-deploy-policy.json").read_text())
        trust = json.loads((ROOT / "iam/roadsense-deploy-trust.json").read_text())
        self.assertIn(f"'{EXPECTED_SHA}'", workflow)
        self.assertIn("--document-version 2", workflow)
        self.assertIn("--document-name RoadSense-GateD-Production-Command-v1", workflow)
        self.assertNotIn("AWS-RunShellScript", workflow)
        self.assertNotIn("AWS-RunShellScript", json.dumps(policy))
        send = next(item for item in policy["Statement"] if item["Sid"] == "SendCommandOnlyToRoadSenseManagedNode")
        self.assertEqual(set(send["Resource"]), {
            "arn:aws:ssm:ap-south-1:918870682888:document/RoadSense-GateD-Production-Command-v1",
            "arn:aws:ssm:ap-south-1:918870682888:managed-instance/mi-0dade13fd68d1b435",
        })
        claims = trust["Statement"][0]["Condition"]["StringEquals"]
        self.assertEqual(
            claims["token.actions.githubusercontent.com:job_workflow_ref"],
            "Synergie-ITCI/.github/.github/workflows/roadsense-controlled-release.yml@refs/tags/roadsense-gate-d-v5",
        )
        self.assertEqual(
            claims["token.actions.githubusercontent.com:sub"],
            "repo:Synergie-ITCI@209829096/roadsense-production-dashboard@1426678649:ref:refs/heads/main",
        )

    def test_identity_probe_is_separate_and_has_no_deploy_permissions(self):
        workflow = (ROOT / ".github/workflows/roadsense-controlled-release.yml").read_text()
        self.assertIn("&& !inputs.identity-probe", workflow)
        probe = workflow.split("\n  identity-probe:\n", 1)[1].split("\n  deploy:\n", 1)[0]
        self.assertIn("&& inputs.identity-probe", probe)
        self.assertIn("id-token: write", probe)
        self.assertIn("aws-actions/configure-aws-credentials@v4", probe)
        self.assertIn('"Effect":"Deny","Action":"*","Resource":"*"', probe)
        self.assertIn("aws sts get-caller-identity", probe)
        self.assertIn("grep -Eq 'AccessDenied|UnauthorizedOperation'", probe)
        self.assertNotIn("send-command", probe)
        self.assertNotIn("AWS-RunShellScript", probe)
        self.assertNotIn("approval-run-id:", probe)
        deploy = workflow.split("\n  deploy:\n", 1)[1]
        self.assertIn("needs: authorize", deploy)
        self.assertIn("if: needs.authorize.outputs.approved == 'true'", deploy)
        permissions = deploy.split("\n    permissions:\n", 1)[1].split("\n    steps:\n", 1)[0]
        self.assertIn("      deployments: read\n", permissions)
        self.assertNotIn("      deployments: write\n", permissions)

    def test_hybrid_bucket_grant_and_probe_are_read_only_and_node_bound(self):
        grant = json.loads((ROOT / "iam/roadsense-hybrid-image-read-statement.json").read_text())
        self.assertEqual(grant["Action"], "s3:GetObjectVersion")
        self.assertEqual(
            grant["Principal"]["AWS"],
            "arn:aws:iam::918870682888:role/SynergieSSMHybridManagedInstanceCore",
        )
        self.assertEqual(
            grant["Condition"]["StringEquals"]["aws:userid"],
            "AROA5L4HV5UECXEPEC3FY:mi-0dade13fd68d1b435",
        )
        self.assertEqual(
            grant["Resource"],
            "arn:aws:s3:::synergie-production-app-backups-918870682888-ap-south-1/"
            "applications/roadsense/images/*/roadsense-image.tar",
        )
        probe = json.loads((ROOT / "iam/roadsense-artifact-probe-v1.json").read_text())
        self.assertEqual(set(probe["parameters"]), {"ArchiveSha256", "ImageVersion"})
        self.assertEqual(probe["mainSteps"][0]["action"], "aws:runShellScript")
        (command,) = probe["mainSteps"][0]["inputs"]["runCommand"]
        self.assertIn("ROAD_SENSE_PROBE_UNRELATED_READ=DENIED", command)
        self.assertIn('test "$version" = "$SSM_ImageVersion"', command)
        self.assertNotIn("docker ", command)
        self.assertNotIn("put-object", command)
        self.assertNotIn("{{", command)

    def test_wrong_hybrid_identity_stops_before_release_script(self):
        document = json.loads(DOCUMENT.read_text())
        (command,) = document["mainSteps"][0]["inputs"]["runCommand"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credentials = root / "credentials"
            credentials.write_text("[default]\naws_access_key_id=placeholder\naws_secret_access_key=placeholder\n")
            fake_aws = root / "aws"
            fake_aws.write_text("#!/bin/sh\nprintf '%s\\n' 'arn:aws:sts::918870682888:assumed-role/OtherRole/other-node'\n")
            fake_aws.chmod(0o700)
            fake_docker = root / "docker"
            fake_docker.write_text("#!/bin/sh\ntouch '" + str(root / "docker-ran") + "'\n")
            fake_docker.chmod(0o700)
            env = os.environ.copy()
            env.update({
                "PATH": f"{root}:{env['PATH']}",
                "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
                "SSM_ReleaseJsonBase64": base64.b64encode(b"{}" ).decode(),
            })
            result = subprocess.run(["bash", "-c", command], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "docker-ran").exists())

    def test_correct_hybrid_identity_invokes_only_the_fixed_remote_script(self):
        document = json.loads(DOCUMENT.read_text())
        (command,) = document["mainSteps"][0]["inputs"]["runCommand"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credentials = root / "credentials"
            credentials.write_text("")
            fake_aws = root / "aws"
            fake_aws.write_text(
                "#!/bin/sh\n"
                "test \"$1 $2\" = 'sts get-caller-identity' || exit 2\n"
                "printf '%s\\n' 'arn:aws:sts::918870682888:assumed-role/"
                "SynergieSSMHybridManagedInstanceCore/mi-0dade13fd68d1b435'\n"
            )
            fake_aws.chmod(0o700)
            fake_bash = root / "bash"
            fake_bash.write_text(
                "#!/bin/sh\n"
                "sha256sum \"$1\" | cut -d' ' -f1 > \"$MOCK_REMOTE_SHA_FILE\"\n"
                "printf '%s' \"$RELEASE_JSON_B64\" > \"$MOCK_RELEASE_FILE\"\n"
            )
            fake_bash.chmod(0o700)
            release = base64.b64encode(b'{"release_id":"isolated","padding":"' + b"x" * 100 + b'"}').decode()
            env = os.environ.copy()
            env.update({
                "PATH": f"{root}:{env['PATH']}",
                "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
                "SSM_ReleaseJsonBase64": release,
                "MOCK_REMOTE_SHA_FILE": str(root / "remote-sha"),
                "MOCK_RELEASE_FILE": str(root / "release"),
            })
            result = subprocess.run(["/bin/bash", "-c", command], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "remote-sha").read_text().strip(), EXPECTED_SHA)
            self.assertEqual((root / "release").read_text(), release)


if __name__ == "__main__":
    unittest.main()
