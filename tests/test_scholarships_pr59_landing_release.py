"""Exact-head certification of the fixed landing UI release and rollback."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pr-qa'))
import scholarships_gate_d_contract as contract


class LandingReleaseContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.names = sorted({
            'deploy/LANDING_UI_RELEASE.md',
            'deploy/compile-first-landing-release-document.py',
            'deploy/compile-first-landing-rollback-document.py',
            'deploy/first-landing-release.py',
            'deploy/first-landing-rollback.py',
            'deploy/scholarships-first-landing-release-v1.json',
            'deploy/scholarships-first-landing-rollback-v1.json',
            'tests/test_first_landing_release.py',
        })
        for name in self.names:
            file = self.repo / name
            file.parent.mkdir(parents=True, exist_ok=True)
            if name.endswith('v1.json'):
                file.write_text(json.dumps({'parameters': {}}))
            elif name.endswith('first-landing-release.py'):
                file.write_text('NEW_FILES = json.loads\nLANDING_UI_REVERTED=yes\n'
                                'DATABASE_MIGRATIONS=NOT_RUN\n')
            elif name.endswith('first-landing-rollback.py'):
                file.write_text('LANDING_UI_ROLLED_BACK=yes\nDATABASE_MIGRATIONS=NOT_RUN\n')
            else:
                file.write_text('fixed landing control\n')
        self.manifest = self.repo / 'manifest.json'
        self.manifest.write_text(json.dumps({
            'repository': 'Synergie-ITCI/scholarships', 'pr_number': 59,
            'head_sha': 'a' * 40, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: hashlib.sha256((self.repo / name).read_bytes()).hexdigest()
                      for name in self.names},
        }))

    def verify(self, changed=None, certified=True):
        def compile_document(command, **kwargs):
            kind = 'rollback' if 'rollback' in command[1] else 'release'
            output = (self.repo / f'deploy/scholarships-first-landing-{kind}-v1.json').read_bytes()
            return type('Result', (), {'returncode': 0, 'stdout': output})()

        with patch.object(contract, 'LANDING_RELEASE_MANIFEST', self.manifest), \
             patch.object(contract, '_owner_certified', return_value=certified), \
             patch.object(contract.subprocess, 'run', side_effect=compile_document):
            return contract.verify_landing_release(
                self.repo, self.names if changed is None else changed, 'a' * 40, [])

    def test_exact_scope_and_owner_certification(self):
        self.assertEqual(self.verify(), [])
        self.assertIn('owner-led', ' '.join(self.verify(certified=False)))
        self.assertIn('scope', ' '.join(self.verify(changed=self.names[:-1])))

    def test_changed_file_and_database_command_fail(self):
        file = self.repo / 'deploy/first-landing-release.py'
        file.write_text(file.read_text() + 'run_migrations\n')
        self.assertIn('certified file changed', ' '.join(self.verify()))


if __name__ == '__main__':
    unittest.main()
