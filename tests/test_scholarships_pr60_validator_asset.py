"""Exact-head certification of the fixed validator asset recovery."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pr-qa'))
import scholarships_gate_d_contract as contract


class ValidatorAssetContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.names = sorted({
            'deploy/VALIDATOR_ASSET_RESTORE.md',
            'deploy/compile-first-recovery-validator-document.py',
            'deploy/first-recovery-validator-asset.py',
            'deploy/scholarships-first-recovery-validator-v1.json',
            'tests/test_first_recovery_validator_asset.py',
        })
        for name in self.names:
            file = self.repo / name
            file.parent.mkdir(parents=True, exist_ok=True)
            if name.endswith('v1.json'):
                file.write_text(json.dumps({
                    'parameters': {'BackupUrl': {'interpolationType': 'ENV_VAR'}},
                    'mainSteps': [{'action': 'aws:runShellScript'}],
                }))
            elif name.endswith('first-recovery-validator-asset.py'):
                file.write_text("BACKUP_VERSION = '1uloEZmYt8h91r6zPAKA01ygteb_yCqx'\n"
                                "MEMBER = 'public_html/' + ASSET\n"
                                "DATABASE_MIGRATIONS=NOT_RUN\n"
                                "def public_health(expected):\n    pass\n")
            else:
                file.write_text('fixed validator control\n')
        self.manifest = self.repo / 'manifest.json'
        self.manifest.write_text(json.dumps({
            'repository': 'Synergie-ITCI/scholarships', 'pr_number': 60,
            'head_sha': 'a' * 40, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: hashlib.sha256((self.repo / name).read_bytes()).hexdigest()
                      for name in self.names},
        }))

    def verify(self, changed=None, certified=True):
        output = (self.repo / 'deploy/scholarships-first-recovery-validator-v1.json').read_bytes()
        result = type('Result', (), {'returncode': 0, 'stdout': output})()
        with patch.object(contract, 'VALIDATOR_ASSET_MANIFEST', self.manifest), \
             patch.object(contract, '_owner_certified', return_value=certified), \
             patch.object(contract.subprocess, 'run', return_value=result):
            return contract.verify_validator_asset(
                self.repo, self.names if changed is None else changed, 'a' * 40, [])

    def test_exact_scope_and_owner_certification(self):
        self.assertEqual(self.verify(), [])
        self.assertIn('owner-led', ' '.join(self.verify(certified=False)))
        self.assertIn('scope', ' '.join(self.verify(changed=self.names[:-1])))

    def test_changed_file_fails(self):
        file = self.repo / 'deploy/first-recovery-validator-asset.py'
        file.write_text(file.read_text() + 'run_migrations\n')
        self.assertIn('certified file changed', ' '.join(self.verify()))


if __name__ == '__main__':
    unittest.main()
