"""Positive and fail-closed fixtures for the exact Scholarships security contract."""

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pr-qa"))
import scholarships_gate_d_contract as contract
import pr_qa as engine
from adapters.base import PRContext


HEAD = "a" * 40
REVIEWER = "ravisynergie"


class ScholarshipsGateDContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scholarships-gate-d-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = {}
        self.write("deploy/gate-d-approval.py", "# synthetic reviewed verifier\n")
        approval_digest = self.files["deploy/gate-d-approval.py"]
        workflow = "\n".join([
            "environment: production", "refs/heads/main",
            "python3 deploy/gate-d-approval.py",
            f"{approval_digest} deploy/gate-d-approval.py | sha256sum -c",
            contract.CERTIFIER_ROLE,
            "id: runtime_certifier",
            "Synergie-ITCI/.github/actions/runtime-certifier@runtime-certifier-action-v1.10",
            contract.RELEASE_ROLE,
            "aws-actions/configure-aws-credentials",
            'Document.DefaultVersion --output text)" = 1',
            'Document.LatestVersion --output text)" = 1',
            "if: steps.runtime_certifier.outputs.deployment-required == 'true'",
            "if: steps.runtime_certifier.outputs.deployment-required == 'true'",
            "if: steps.runtime_certifier.outputs.deployment-required == 'true'",
            "aws ssm send-command",
        ])
        self.write(".github/workflows/scholarships-gate-d-release.yml", workflow)
        cert_script = "\n".join([
            "php8.3-fpm.sock", "apache2ctl -S", "proxy_fcgi_module",
            "PRODUCTION_MUTATED=NO", "DEPLOY_STATE=READY_FROM_ROLLBACK",
        ])
        self.write("deploy/ssm-runtime-certifier.sh", cert_script)
        release_script = "--backup-only\ngzip -t\nsha256sum\nprivate_paths=\npublic_html\n"
        bootstrap_script = "set -euo pipefail\n"
        self.write("deploy/production-release.sh", release_script)
        self.write("deploy/ssm-bootstrap.sh", bootstrap_script)
        arn = f"arn:aws:ssm:ap-south-1:{contract.ACCOUNT}:"
        host = arn + f"managed-instance/{contract.HOST}"
        for prefix, document in (("certifier-", contract.CERTIFIER_DOCUMENT), ("", contract.RELEASE_DOCUMENT)):
            policy = {"Statement": [
                {"Effect": "Deny", "Action": "ssm:SendCommand", "Resource": "arn:aws:ssm:ap-south-1:*:document/AWS-RunShellScript"},
                {"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": [host, arn + f"document/{document}"]},
            ]}
            self.write(f"deploy/scholarships-gate-d-{prefix}role-policy-v1.json", json.dumps(policy))
        trust = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {"Federated": "arn:aws:iam::918870682888:oidc-provider/token.actions.githubusercontent.com"},
            "Condition": {"StringEquals": {
            "token.actions.githubusercontent.com:" + key: value for key, value in {
                "aud": "sts.amazonaws.com", "sub": "repo:Synergie-ITCI/scholarships:environment:production",
                "environment": "production", "ref": "refs/heads/main",
                "repository_id": "1132519991", "repository_owner_id": "209829096",
            }.items()
        }}}]}
        for name in ("certifier-trust", "trust"):
            self.write(f"deploy/scholarships-gate-d-{name}-v1.json", json.dumps(trust))
        self.write("deploy/github-production-environment-v1.json", json.dumps({
            "reviewers": [{"type": "User", "id": 52234089}],
            "deployment_branch_policy": {"protected_branches": True},
        }))
        self.write("deploy/scholarships-gate-d-runtime-certifier-v1.json", json.dumps({
            "schemaVersion": "2.2",
            "parameters": {name: {"type": "String", "interpolationType": "ENV_VAR", "allowedPattern": "^[0-9a-f]{40}$"}
                           for name in ("DeployRef", "RollbackRef")},
            "mainSteps": [{"action": "aws:runShellScript", "inputs": {"runCommand": [
                "printf '%s' '" + base64.b64encode(cert_script.encode()).decode() + "' | base64 -d | bash"
            ]}}],
        }))
        release_command = (
            "set -euo pipefail\n"
            "export REVIEWED_RELEASE_SCRIPT_SHA256=" + hashlib.sha256(release_script.encode()).hexdigest() + "\n"
            "export REVIEWED_RELEASE_SCRIPT_B64=" + base64.b64encode(release_script.encode()).decode() + "\n"
            "printf '%s' '" + base64.b64encode(bootstrap_script.encode()).decode() + "' | base64 -d | bash\n"
        )
        self.write("deploy/scholarships-gate-d-production-command-v1.json", json.dumps({
            "schemaVersion": "2.2",
            "parameters": {
                "SourceSha": {"type": "String", "interpolationType": "ENV_VAR", "allowedPattern": "^[0-9a-f]{40}$"},
                "ArtifactSha256": {"type": "String", "interpolationType": "ENV_VAR", "allowedPattern": "^[0-9a-f]{64}$"},
                "ExpectedCurrentIdentity": {"type": "String", "interpolationType": "ENV_VAR", "allowedPattern": "^[0-9a-f]{40}$"},
                "ArtifactUrl": {"type": "String", "interpolationType": "ENV_VAR", "allowedPattern":
                    "^https://synergie-scholarships-release-artifacts-918870682888-ap-south-1"
                    "[.]s3[.]ap-south-1[.]amazonaws[.]com/scholarships/releases/"
                    "[0-9a-f]{40}/[0-9a-f]{64}[.]tar[.]gz[?][A-Za-z0-9%_=&.-]+$", "maxChars": 4096},
            },
            "mainSteps": [{"action": "aws:runShellScript", "inputs": {"runCommand": [release_command]}}],
        }))
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({
            "repository": "Synergie-ITCI/scholarships", "pr_number": 15,
            "head_sha": HEAD, "required_security_reviewer": REVIEWER,
            "files": self.files,
        }))
        self.reviews = [{"state": "APPROVED", "user": {"login": REVIEWER}, "commit_id": HEAD,
                         "body": f"SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED={HEAD}"}]

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

    def check(self, *, head=HEAD, pr_number=15, reviews=None, controlled=True, changed=None):
        with patch.object(contract, "MANIFEST", self.manifest):
            return contract.verify(self.root, changed if changed is not None else list(self.files),
                                   head, pr_number, self.reviews if reviews is None else reviews, controlled)

    def test_positive_exact_head_reviewed_contract(self):
        self.assertEqual(self.check(), [])

    def test_head_scope_hash_and_review_invalidation(self):
        self.assertIn("exact PR head changed", " ".join(self.check(head="b" * 40)))
        self.assertIn("PR identity changed", " ".join(self.check(pr_number=14)))
        self.assertIn("changed-file scope changed", " ".join(self.check(changed=list(self.files)[:-1])))
        self.assertIn("security review", " ".join(self.check(reviews=[])))
        self.assertIn("security review", " ".join(self.check(reviews=[{
            "state": "APPROVED", "user": {"login": REVIEWER}, "commit_id": HEAD,
        }])))
        self.assertIn("security review", " ".join(self.check(reviews=[{
            "state": "APPROVED", "user": {"login": REVIEWER}, "commit_id": "b" * 40,
        }])))
        self.assertIn("controlled Gate D", " ".join(self.check(controlled=False)))
        (self.root / "deploy/production-release.sh").write_text("echo changed\n")
        self.assertIn("certified file changed", " ".join(self.check()))

    def test_semantic_weakening_rejected_even_with_updated_hash(self):
        mutations = {
            ".github/workflows/scholarships-gate-d-release.yml": (
                "if: steps.runtime_certifier.outputs.deployment-required == 'true'", "if: always()"),
            "deploy/scholarships-gate-d-certifier-role-policy-v1.json": (
                contract.CERTIFIER_DOCUMENT, "AWS-RunShellScript"),
            "deploy/ssm-runtime-certifier.sh": ("proxy_fcgi_module", "php7_module"),
            "deploy/production-release.sh": ("--backup-only", "--no-backup"),
        }
        for relative, (old, new) in mutations.items():
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_text()
                path.write_text(original.replace(old, new))
                data = json.loads(self.manifest.read_text())
                data["files"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                self.manifest.write_text(json.dumps(data))
                self.assertTrue(self.check())
                path.write_text(original)
                data["files"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                self.manifest.write_text(json.dumps(data))

    def test_deployment_gate_requires_live_exact_head_independent_review(self):
        context = PRContext(
            repo=self.root, config={}, policy={}, changed_files=list(self.files),
            base_ref="fix/scholarships-pr7-qa-assets", head_ref="security/pr15",
            event={"repository": {"full_name": "Synergie-ITCI/scholarships"},
                   "pull_request": {"number": 15, "head": {"sha": HEAD}}},
        )
        with patch.object(contract, "MANIFEST", self.manifest), \
             patch.object(engine, "SCHOLARSHIPS_GATE_D_MANIFEST", self.manifest), \
             patch.object(engine, "controlled_gate_d_workflow_details", return_value=["controlled"]), \
             patch.object(engine, "fetch_github_review_policy_evidence",
                          return_value={"source": "github_api", "reviews": self.reviews}):
            self.assertEqual(engine.gate_deployment_safety(context, {})[0].status, "WARNING")
        with patch.object(contract, "MANIFEST", self.manifest), \
             patch.object(engine, "SCHOLARSHIPS_GATE_D_MANIFEST", self.manifest), \
             patch.object(engine, "controlled_gate_d_workflow_details", return_value=["controlled"]), \
             patch.object(engine, "fetch_github_review_policy_evidence", return_value=None):
            self.assertEqual(engine.gate_deployment_safety(context, {})[0].status, "FAIL")


if __name__ == "__main__":
    unittest.main()
