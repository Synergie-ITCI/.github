"""PR #87 certification and its protected promotions fail closed on drift."""

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


HEAD = '4e3d0c8b40107da6f53e29f584094542889c5aaa'


class GateDOwnerReceiptCertificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        reviewed = json.loads(contract.GATE_D_OWNER_RECEIPT_MANIFEST.read_text())
        self.files = {}
        for rel in reviewed['files']:
            file = self.root / rel
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('reviewed\n')
            self.files[rel] = hashlib.sha256(file.read_bytes()).hexdigest()
        workflow = self.root / '.github/workflows/scholarships-gate-d-release.yml'
        workflow.write_text('\n'.join((
            'environment: production', 'refs/heads/main', 'deployments: write',
            'pull-requests: read', 'Checkout exact approved source',
            'python3 deploy/gate-d-owner-receipt.py consume',
            'Assume restricted runtime-certification role',
            'Certify actual production PHP-FPM serving runtime',
            'Assume repository and environment bound production role',
            'aws ssm send-command', '--document-version 2',
        )))
        (self.root / 'deploy/gate-d-owner-receipt.py').write_text('\n'.join((
            "ROLLBACK_SOURCE = 'e853573a7d426a5b8e3dd2cece7e816d41045d24'",
            "BACKUP_RUN = '44171193048'", 'ApprovalReceipt(api=api',
            "'receipt_marker_prefix': 'scholarships-gate-d'", 'receipt.consume()',
        )))
        (self.root / 'deploy/first_cutover_approval.py').write_text('\n'.join((
            "contract.get('receipt_marker_prefix', 'scholarships-first-cutover')",
            'created_at', 'updated_at', 'timedelta(hours=2)',
        )))
        self.files = {rel: hashlib.sha256((self.root / rel).read_bytes()).hexdigest()
                      for rel in self.files}
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({
            'repository': 'Synergie-ITCI/scholarships', 'pr_number': 87,
            'head_sha': HEAD, 'technical_certification_owner': 'SaurabhVermaIN',
            'removed_paths': [], 'files': self.files,
        }))
        digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.comment = {
            'user': {'login': 'SaurabhVermaIN'},
            'created_at': '2026-11-18T03:00:00Z',
            'updated_at': '2026-11-18T03:00:00Z',
            'body': '\n'.join((
                f'SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED={HEAD}',
                f'CERTIFIED_MANIFEST_SHA256={digest}',
                'REVIEWED=IAM,SSM,APPROVAL,ARTIFACT,HOST,RUNTIME,BACKUP,RESTORE,PRIVATE_DOCUMENTS,ROLLBACK',
                'OWNER_ACCEPTS_TECHNICAL_REVIEW_RESPONSIBILITY=YES',
            )),
        }

    def verify(self, *, comments=None, head=HEAD, files=None, controlled=True):
        with patch.object(contract, 'GATE_D_OWNER_RECEIPT_MANIFEST', self.manifest):
            return contract.verify_gate_d_owner_receipt(
                self.root, list(self.files) if files is None else files, head,
                [self.comment] if comments is None else comments, controlled)

    def test_exact_scope_owner_and_control_sequence(self):
        self.assertEqual(self.verify(), [])
        self.assertTrue(self.verify(head='b' * 40))
        self.assertTrue(self.verify(files=list(self.files)[:-1]))
        self.assertIn('owner-led', ' '.join(self.verify(comments=[])))
        self.assertIn('protected approval', ' '.join(self.verify(controlled=False)))

    def test_changed_byte_and_removed_certifier_fail(self):
        (self.root / 'deploy/gate-d-owner-receipt.py').write_text('changed\n')
        self.assertIn('certified file changed', ' '.join(self.verify()))
        (self.root / 'deploy/gate-d-owner-receipt.py').write_text('\n'.join((
            "ROLLBACK_SOURCE = 'e853573a7d426a5b8e3dd2cece7e816d41045d24'",
            "BACKUP_RUN = '44171193048'", 'ApprovalReceipt(api=api',
            "'receipt_marker_prefix': 'scholarships-gate-d'", 'receipt.consume()',
        )))
        workflow = self.root / '.github/workflows/scholarships-gate-d-release.yml'
        workflow.write_text(workflow.read_text().replace(
            'Certify actual production PHP-FPM serving runtime', 'runtime skipped'))
        self.assertIn('certified file changed', ' '.join(self.verify()))


class GateDOwnerReceiptPromotionTests(unittest.TestCase):
    def setUp(self):
        self.files = json.loads(pr_qa.SCHOLARSHIPS_GATE_D_OWNER_RECEIPT_MANIFEST.read_text())['files']

    def context(self, number, head, base, head_ref, base_ref):
        return PRContext(repo=Path('/unused'), config={}, policy={},
                         changed_files=list(self.files), head_ref=head_ref,
                         base_ref=base_ref,
                         event={'pull_request': {'number': number,
                             'head': {'sha': head}, 'base': {'sha': base}}})

    def verify(self, ctx, *, ancestor=True, altered=False):
        head = ctx.event['pull_request']['head']['sha']
        base = ctx.event['pull_request']['base']['sha']
        with (patch.object(pr_qa, 'resolve_repository_name', return_value='Synergie-ITCI/scholarships'),
              patch.object(pr_qa, 'run_git', return_value=head),
              patch.object(pr_qa, 'git_lines', return_value=list(self.files)),
              patch.object(pr_qa, 'commit_is_ancestor', return_value=ancestor),
              patch.object(pr_qa, 'resolve_fresh_origin_development_tip', return_value=head),
              patch.object(pr_qa, 'resolve_fresh_origin_staging_tip', return_value=(
                  head if ctx.head_ref == 'staging' else base)),
              patch.object(pr_qa, 'resolve_fresh_origin_main_tip', return_value=base),
              patch.object(pr_qa, 'tree_file_sha256', side_effect=lambda repo, sha, rel:
                  '0' * 64 if altered and rel == next(iter(self.files)) else self.files[rel])):
            return pr_qa.exact_scholarships_gate_d_owner_receipt_promotion(ctx)

    def test_only_protected_exact_bytes_and_certified_ancestry(self):
        staging = self.context(88, 'a' * 40, 'b' * 40, 'development', 'staging')
        main = self.context(89, 'c' * 40, 'd' * 40, 'staging', 'main')
        self.assertTrue(self.verify(staging))
        self.assertTrue(self.verify(main))
        self.assertFalse(self.verify(staging, ancestor=False))
        self.assertFalse(self.verify(main, altered=True))
        self.assertFalse(self.verify(self.context(90, 'a' * 40, 'b' * 40,
                                                 'development', 'staging')))
