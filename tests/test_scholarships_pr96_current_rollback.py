"""PR #96 certification binds the current rollback and only two protected promotions."""

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

HEAD = '2db0c1209dda360259c21d278063ba7666540581'
CURRENT = 'f4c685021a600871457db83034d7d663d1317f40'
ARTIFACT = 'f4c883c4852a1b80dae6d8e43ded919b529555798677a786533a211102ba0f25'


class CurrentRollbackCertificationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        paths = json.loads(contract.GATE_D_CURRENT_ROLLBACK_MANIFEST.read_text())['files']
        for rel in paths:
            file = self.root / rel
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('reviewed\n')
        (self.root / '.github/workflows/scholarships-gate-d-release.yml').write_text('\n'.join((
            'gate-d-owner-receipt.py consume', 'aws-actions/configure-aws-credentials',
            f'test "$EXPECTED_CURRENT" = {CURRENT}',
            'Scholarships-GateD-Production-Command-v1 --document-version 3',
        )))
        (self.root / 'deploy/gate-d-owner-receipt.py').write_text('\n'.join((
            f"ROLLBACK_SOURCE = '{CURRENT}'", f"ROLLBACK_ARTIFACT = '{ARTIFACT}'",
            "OPERATION = 'gate-d-application-csrf-fallback'",
            "APPROVAL_PREFIX = 'SCHOLARSHIPS GATE D APPLICATION CSRF APPROVED'",
            "'deployment_task': 'scholarships-gate-d-application-csrf-fallback'",
            "ROOT / 'scholarships-gate-d-production-command-v3.json'",
            'receipt.consume()',
        )))
        self.files = {rel: hashlib.sha256((self.root / rel).read_bytes()).hexdigest()
                      for rel in paths}
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({
            'repository': 'Synergie-ITCI/scholarships', 'pr_number': 96,
            'head_sha': HEAD, 'technical_certification_owner': 'SaurabhVermaIN',
            'removed_paths': [], 'files': self.files,
        }))

    def verify(self, *, head=HEAD, controlled=True, certified=True):
        with (patch.object(contract, 'GATE_D_CURRENT_ROLLBACK_MANIFEST', self.manifest),
              patch.object(contract, '_owner_certified', return_value=certified)):
            return contract.verify_gate_d_current_rollback(
                self.root, list(self.files), head, [], controlled)

    def test_exact_scope_and_controls(self):
        self.assertEqual(self.verify(), [])
        self.assertIn('identity changed', ' '.join(self.verify(head='a' * 40)))
        self.assertIn('owner-led', ' '.join(self.verify(certified=False)))
        self.assertIn('protected Gate D', ' '.join(self.verify(controlled=False)))
        receipt = self.root / 'deploy/gate-d-owner-receipt.py'
        receipt.write_text(receipt.read_text().replace(CURRENT, 'a' * 40))
        self.assertIn('certified file changed', ' '.join(self.verify()))


class CurrentRollbackPromotionTests(unittest.TestCase):
    def setUp(self):
        self.files = json.loads(pr_qa.SCHOLARSHIPS_GATE_D_CURRENT_ROLLBACK_MANIFEST.read_text())['files']

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
            return pr_qa.exact_scholarships_gate_d_current_rollback_promotion(ctx)

    def test_only_two_exact_protected_promotions(self):
        self.assertTrue(self.verify(97, 'development', 'staging'))
        self.assertTrue(self.verify(98, 'staging', 'main'))
        self.assertFalse(self.verify(96, 'development', 'staging'))
        self.assertFalse(self.verify(98, 'staging', 'main', altered=True))


if __name__ == '__main__':
    unittest.main()
