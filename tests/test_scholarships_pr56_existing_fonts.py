"""Exact-head certification for the verified existing-font correction."""

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


class ExistingFontsContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.names = [
            'deploy/first-recovery-public-assets.py',
            'deploy/scholarships-first-recovery-public-assets-v1.json',
            'tests/test_first_recovery_public_assets.py',
        ]
        script = ("ASSETS = __ASSET_MAP__\n"
                  "if directory == 'assets/home/fonts':\n"
                  "    raise RuntimeError('existing public font differs from verified backup')\n"
                  "if not file.is_symlink(): installed.append(target)\n")
        self.write(self.names[0], script)
        assets = {'assets/home/fonts/test.woff2': 'a' * 64}
        self.write('deploy/public-assets-manifest.json', json.dumps(assets))
        command = ("set -eu\nprintf '%s' '" + base64.b64encode(
            script.replace('__ASSET_MAP__', repr(assets)).encode()).decode()
                   + "' | base64 -d | python3\n")
        self.write(self.names[1], json.dumps({'mainSteps': [
            {'inputs': {'runCommand': [command]}}]}))
        self.write(self.names[2],
                   'test_exact_existing_fonts_are_preserved_and_changed_fonts_rejected\n')
        self.manifest = self.repo / 'manifest.json'
        self.manifest.write_text(json.dumps({
            'repository': 'Synergie-ITCI/scholarships', 'pr_number': 56,
            'head_sha': 'a' * 40, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: hashlib.sha256((self.repo / name).read_bytes()).hexdigest()
                      for name in self.names},
        }))
        digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.comment = {'user': {'login': 'SaurabhVermaIN'},
                        'created_at': '2026-11-16T00:00:00Z',
                        'updated_at': '2026-11-16T00:00:00Z',
                        'body': '\n'.join([
                            'SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED=' + 'a' * 40,
                            'CERTIFIED_MANIFEST_SHA256=' + digest,
                            'REVIEWED=IAM,SSM,APPROVAL,ARTIFACT,HOST,RUNTIME,BACKUP,RESTORE,PRIVATE_DOCUMENTS,ROLLBACK',
                            'OWNER_ACCEPTS_TECHNICAL_REVIEW_RESPONSIBILITY=YES',
                        ])}

    def write(self, name, value):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def verify(self, changed=None, comments=None):
        with patch.object(contract, 'FIRST_CUTOVER_EXISTING_FONTS_MANIFEST', self.manifest):
            return contract.verify_first_cutover_existing_fonts(
                self.repo, self.names if changed is None else changed, 'a' * 40,
                [self.comment] if comments is None else comments)

    def test_exact_certification(self):
        self.assertEqual(self.verify(), [])

    def test_missing_owner_and_changed_scope_fail(self):
        self.assertIn('owner-led', ' '.join(self.verify(comments=[])))
        self.assertIn('scope', ' '.join(self.verify(changed=self.names[:-1])))

    def test_changed_script_fails(self):
        self.write(self.names[0], 'altered')
        self.assertIn('certified file changed', ' '.join(self.verify()))


if __name__ == '__main__':
    unittest.main()
