"""The exact Gate D SSM shell repair and protected promotions fail closed."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pr-qa'))
import pr_qa
import scholarships_gate_d_contract as contract
from adapters.base import PRContext

HEAD = '304390448cef6383341de9da5977f802b58bde10'


class GateDSSMShellFixTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        paths = json.loads(contract.GATE_D_SSM_SHELL_FIX_MANIFEST.read_text())['files']
        for rel in paths:
            file = self.root / rel
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('reviewed\n')
        (self.root / '.github/workflows/scholarships-gate-d-release.yml').write_text('\n'.join((
            'environment: production', 'deployments: write',
            'gate-d-owner-receipt.py consume', 'Assume restricted runtime-certification role',
            'Certify actual production PHP-FPM serving runtime',
            'Assume repository and environment bound production role',
            'Scholarships-GateD-Production-Command-v1 --document-version 3',
            'scholarships-gate-d-production-command-v3.json', 'aws ssm send-command',
        )))
        (self.root / 'deploy/gate-d-owner-receipt.py').write_text('\n'.join((
            "ROOT / 'scholarships-gate-d-production-command-v3.json'",
            "ROLLBACK_SOURCE = 'e853573a7d426a5b8e3dd2cece7e816d41045d24'",
            'receipt.consume()',
        )))
        (self.root / 'deploy/compile-ssm-document-v3.py').write_text('"set -eu\\n"\ndocument-version 3\n')
        (self.root / 'deploy/scholarships-gate-d-production-command-v3.json').write_text(
            json.dumps({'mainSteps': [{'inputs': {'runCommand': [
                'set -eu\nbase64 -d > "$bootstrap"\nbash "$bootstrap"\n']}}]}))
        self.files = {rel: hashlib.sha256((self.root / rel).read_bytes()).hexdigest()
                      for rel in paths}
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({
            'repository': 'Synergie-ITCI/scholarships', 'pr_number': 90,
            'head_sha': HEAD, 'technical_certification_owner': 'SaurabhVermaIN',
            'removed_paths': [], 'files': self.files,
        }))
        digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.comment = {'user': {'login': 'SaurabhVermaIN'},
                        'created_at': '2026-11-18T04:00:00Z',
                        'updated_at': '2026-11-18T04:00:00Z',
                        'body': '\n'.join((f'SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED={HEAD}',
                            f'CERTIFIED_MANIFEST_SHA256={digest}',
                            'REVIEWED=IAM,SSM,APPROVAL,ARTIFACT,HOST,RUNTIME,BACKUP,RESTORE,PRIVATE_DOCUMENTS,ROLLBACK',
                            'OWNER_ACCEPTS_TECHNICAL_REVIEW_RESPONSIBILITY=YES'))}

    def verify(self, *, comments=None, head=HEAD, controlled=True):
        with patch.object(contract, 'GATE_D_SSM_SHELL_FIX_MANIFEST', self.manifest):
            return contract.verify_gate_d_ssm_shell_fix(
                self.root, list(self.files), head,
                [self.comment] if comments is None else comments, controlled)

    def test_exact_owner_scope_and_posix_wrapper(self):
        self.assertEqual(self.verify(), [])
        self.assertTrue(self.verify(head='b' * 40))
        self.assertIn('owner-led', ' '.join(self.verify(comments=[])))
        self.assertIn('protected Gate D', ' '.join(self.verify(controlled=False)))
        file = self.root / 'deploy/compile-ssm-document-v3.py'
        file.write_text('set -euo pipefail\n')
        self.assertIn('certified file changed', ' '.join(self.verify()))


class GateDSSMShellFixPromotionTests(unittest.TestCase):
    def setUp(self):
        self.files = json.loads(pr_qa.SCHOLARSHIPS_GATE_D_SSM_SHELL_FIX_MANIFEST.read_text())['files']

    def verify(self, number, head_ref, base_ref, *, altered=False):
        head, base = 'a' * 40, 'b' * 40
        ctx = PRContext(repo=Path('/unused'), config={}, policy={},
                        changed_files=list(self.files), head_ref=head_ref, base_ref=base_ref,
                        event={'pull_request': {'number': number,
                            'head': {'sha': head}, 'base': {'sha': base}}})
        with (patch.object(pr_qa, 'resolve_repository_name', return_value='Synergie-ITCI/scholarships'),
              patch.object(pr_qa, 'run_git', return_value=head),
              patch.object(pr_qa, 'git_lines', return_value=list(self.files)),
              patch.object(pr_qa, 'commit_is_ancestor', return_value=True),
              patch.object(pr_qa, 'resolve_fresh_origin_development_tip', return_value=head),
              patch.object(pr_qa, 'resolve_fresh_origin_staging_tip', return_value=(head if head_ref == 'staging' else base)),
              patch.object(pr_qa, 'resolve_fresh_origin_main_tip', return_value=base),
              patch.object(pr_qa, 'tree_file_sha256', side_effect=lambda repo, sha, rel:
                  '0' * 64 if altered and rel == next(iter(self.files)) else self.files[rel])):
            return pr_qa.exact_scholarships_gate_d_ssm_shell_fix_promotion(ctx)

    def test_only_two_exact_protected_promotions(self):
        self.assertTrue(self.verify(91, 'development', 'staging'))
        self.assertTrue(self.verify(92, 'staging', 'main'))
        self.assertFalse(self.verify(90, 'development', 'staging'))
        self.assertFalse(self.verify(92, 'staging', 'main', altered=True))


if __name__ == '__main__':
    unittest.main()
