"""Fail-closed fixtures for Scholarships PR #55 public asset certification."""

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pr-qa'))
import scholarships_gate_d_contract as contract


HEAD = 'a' * 40


class PublicAssetsContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='scholarships-public-assets-contract-')
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.names = [
            'deploy/compile-first-recovery-public-assets-document.py',
            'deploy/first-recovery-public-assets.py',
            'deploy/public-assets-manifest.json',
            'deploy/scholarships-first-recovery-public-assets-v1.json',
            'tests/test_first_recovery_public_assets.py',
        ]
        assets = {f'assets/home/images/test-{i}.png': 'b' * 64 for i in range(36)}
        self.write(self.names[2], json.dumps(assets))
        script = (
            'ASSETS = __ASSET_MAP__\n'
            'BACKUP_VERSION = "1uloEZmYt8h91r6zPAKA01ygteb_yCqx"\n'
            'BACKUP_SHA = "54121df892ad8103e4f2c62c1577e1c07083f82a88e9eb84b8eb4e2e644d195c"\n'
            'HOSTNAME = "ip-172-26-10-203.ap-south-1.compute.internal"\n'
            'RELEASE_SHA = "b1ccf807b3b3d2812f1b0958c513866c85691b64"\n'
        )
        self.write(self.names[1], script)
        self.write(self.names[0], 'fixed compiler\n')
        key = 'applications/scholarships/first-cutover/43713023653/application.tar.gz.part-0000'
        pattern = ('^https://synergie-production-app-backups-918870682888-ap-south-1'
                   '[.]s3[.]ap-south-1[.]amazonaws[.]com/' + key.replace('.', '[.]')
                   + '[?][A-Za-z0-9%_=&.~-]+$')
        command = ("set -eu\nprintf '%s' '" + base64.b64encode(
            script.replace('__ASSET_MAP__', repr(assets)).encode()).decode()
                   + "' | base64 -d | python3\n")
        self.write(self.names[3], json.dumps({'parameters': {'BackupUrl': {
            'interpolationType': 'ENV_VAR', 'allowedPattern': pattern}},
            'mainSteps': [{'action': 'aws:runShellScript', 'inputs': {'runCommand': [command]}}]}))
        self.write(self.names[4], 'test_installation_and_partial_failure_cleanup\n')
        self.manifest = self.repo / 'manifest.json'
        self.manifest.write_text(json.dumps({
            'repository': 'Synergie-ITCI/scholarships', 'pr_number': 55,
            'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: hashlib.sha256((self.repo / name).read_bytes()).hexdigest()
                      for name in self.names},
        }))
        digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.comment = {'user': {'login': 'SaurabhVermaIN'},
                        'created_at': '2026-11-16T00:00:00Z',
                        'updated_at': '2026-11-16T00:00:00Z',
                        'body': '\n'.join([
                            'SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED=' + HEAD,
                            'CERTIFIED_MANIFEST_SHA256=' + digest,
                            'REVIEWED=IAM,SSM,APPROVAL,ARTIFACT,HOST,RUNTIME,BACKUP,RESTORE,PRIVATE_DOCUMENTS,ROLLBACK',
                            'OWNER_ACCEPTS_TECHNICAL_REVIEW_RESPONSIBILITY=YES',
                        ])}

    def write(self, name, value):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def verify(self, names=None, comments=None):
        with patch.object(contract, 'FIRST_CUTOVER_PUBLIC_ASSETS_MANIFEST', self.manifest):
            return contract.verify_first_cutover_public_assets(
                self.repo, self.names if names is None else names, HEAD,
                [self.comment] if comments is None else comments)

    def test_exact_scope_and_owner_comment_pass(self):
        self.assertEqual(self.verify(), [])

    def test_missing_owner_or_scope_fails(self):
        self.assertIn('owner-led', ' '.join(self.verify(comments=[])))
        self.assertIn('scope', ' '.join(self.verify(names=self.names[:-1])))

    def test_file_or_backup_version_drift_fails(self):
        self.write(self.names[1], 'altered')
        self.assertIn('certified file changed', ' '.join(self.verify()))
        self.write(self.names[1], 'BACKUP_VERSION = "other"')
        self.assertIn('certified file changed', ' '.join(self.verify()))


if __name__ == '__main__':
    unittest.main()
