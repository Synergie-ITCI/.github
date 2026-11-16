"""Fail-closed fixtures for the exact Scholarships first-cutover contract."""

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


class FirstCutoverContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='scholarships-first-cutover-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.files = {}
        self.write('.github/workflows/scholarships-first-cutover-prepare.yml',
                   'refs/heads/main\nenvironment: production\n'
                   'git merge-base --is-ancestor\n'
                   'scholarships-first-cutover\naws ssm send-command\nverified-receipt.json\n')
        self.write('.github/workflows/scholarships-first-cutover.yml',
                   'refs/heads/main\nenvironment: production\n'
                   'python3 deploy/first-cutover-approval-cli.py consume\n'
                   'aws-actions/configure-aws-credentials\n'
                   'aws ssm send-command --document-name Scholarships-First-Cutover-v1\n')
        self.write('deploy/first_cutover_approval.py',
                   'APPROVAL_ISSUE = 18\nrun_attempt == "1"\n'
                   'native reviewer protection exists\napproval already consumed\n'
                   'receipt no longer uniquely belongs to this run\n')
        arn = f'arn:aws:ssm:ap-south-1:{contract.ACCOUNT}:'
        host = arn + f'managed-instance/{contract.HOST}'
        for name, documents in {
            'backup': ('Backup', 'Upload', 'Restore'),
            'cutover': ('Cutover',),
        }.items():
            policy = {'Statement': [
                {'Effect': 'Deny', 'Action': 'ssm:SendCommand',
                 'Resource': 'arn:aws:ssm:ap-south-1:*:document/AWS-RunShellScript'},
                {'Effect': 'Allow', 'Action': 'ssm:SendCommand',
                 'Resource': [host] + [arn + f'document/Scholarships-First-{item}-v1' for item in documents]},
            ]}
            self.write(f'deploy/scholarships-first-{name}-role-policy-v1.json', json.dumps(policy))
            trust = {'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithWebIdentity',
                'Principal': {'Federated': f'arn:aws:iam::{contract.ACCOUNT}:oidc-provider/token.actions.githubusercontent.com'},
                'Condition': {'StringEquals': {'token.actions.githubusercontent.com:' + key: value
                    for key, value in {'aud': 'sts.amazonaws.com',
                        'sub': 'repo:Synergie-ITCI/scholarships:environment:production',
                        'environment': 'production', 'ref': 'refs/heads/main',
                        'repository_id': '1132519991', 'repository_owner_id': '209829096'}.items()}}}]}
            self.write(f'deploy/scholarships-first-{name}-trust-v1.json', json.dumps(trust))
        for name in ('backup', 'upload', 'restore', 'cutover'):
            self.write(f'deploy/scholarships-first-{name}-command-v1.json',
                       json.dumps({'schemaVersion': '2.2', 'mainSteps': [{'action': 'aws:runShellScript'}]}))
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 19, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN', 'files': self.files}))
        digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.comment = {'user': {'login': 'SaurabhVermaIN'},
            'created_at': '2026-11-15T00:00:00Z', 'updated_at': '2026-11-15T00:00:00Z',
            'body': '\n'.join((f'SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED={HEAD}',
                f'CERTIFIED_MANIFEST_SHA256={digest}',
                'REVIEWED=IAM,SSM,APPROVAL,ARTIFACT,HOST,RUNTIME,BACKUP,RESTORE,PRIVATE_DOCUMENTS,ROLLBACK',
                'OWNER_ACCEPTS_TECHNICAL_REVIEW_RESPONSIBILITY=YES'))}

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

    def check(self, *, head=HEAD, comments=None, changed=None):
        with patch.object(contract, 'FIRST_CUTOVER_MANIFEST', self.manifest):
            return contract.verify_first_cutover(self.root,
                list(self.files) if changed is None else changed, head,
                [self.comment] if comments is None else comments)

    def test_exact_fixture_passes(self):
        self.assertEqual(self.check(), [])

    def test_owner_evidence_is_required_and_unedited(self):
        self.assertIn('owner-led', ' '.join(self.check(comments=[])))
        edited = dict(self.comment, updated_at='2026-11-15T00:01:00Z')
        self.assertIn('owner-led', ' '.join(self.check(comments=[edited])))

    def test_head_scope_and_bytes_are_bound(self):
        self.assertTrue(self.check(head='b' * 40))
        self.assertTrue(self.check(changed=list(self.files)[:-1]))
        path = self.root / 'deploy/first_cutover_approval.py'
        path.write_text(path.read_text() + 'extra\n')
        self.assertIn('certified file changed', ' '.join(self.check()))

    def test_generic_shell_allow_is_rejected(self):
        path = self.root / 'deploy/scholarships-first-cutover-role-policy-v1.json'
        policy = json.loads(path.read_text())
        policy['Statement'][1]['Resource'].append('arn:aws:ssm:ap-south-1:*:document/AWS-RunShellScript')
        path.write_text(json.dumps(policy))
        self.assertIn('certified file changed', ' '.join(self.check()))

    def test_exact_followup_requires_owner_and_unchanged_bytes(self):
        changed = ['.github/workflows/scholarships-first-cutover-prepare.yml',
                   'deploy/first_cutover_approval.py', 'tests/test_first_cutover_approval.py']
        self.write(changed[2], 'receipt tests\n')
        followup = self.root / 'followup.json'
        followup.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 20, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(followup.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_FOLLOWUP_MANIFEST', followup):
            verify = lambda comments: contract.verify_first_cutover_followup(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[0]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_mysql_restore_repair_requires_exact_bytes_and_owner(self):
        changed = ['deploy/first-restore-test.py',
                   'deploy/scholarships-first-restore-command-v1.json']
        self.write(changed[0], "runuser', '-u', 'mysql'\n"
                   "datadir = workdir / 'data'\nshutil.rmtree(workdir\n")
        self.write(changed[1], json.dumps({'mainSteps': [
            {'action': 'aws:runShellScript'}], 'parameters': {}}))
        manifest = self.root / 'mysql-restore.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 23, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_MYSQL_RESTORE_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_mysql_restore(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[0]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_restore_version_pin_requires_exact_bytes_and_owner(self):
        changed = ['.github/workflows/scholarships-first-cutover-prepare.yml',
                   'deploy/FIRST_CUTOVER_ACTIVATION.md',
                   'tests/test_first_cutover_approval.py']
        self.write(changed[0], 'environment: production\nrefs/heads/main\n'
                   'Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:3\n'
                   'Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3\n'
                   'Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:4\n'
                   '--document-name Scholarships-First-Restore-v1 --document-version 4\n')
        self.write(changed[1], 'Restore version 4\n')
        self.write(changed[2], 'version pin test\n')
        manifest = self.root / 'restore-pin.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 24, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_RESTORE_PIN_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_restore_pin(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[0]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_spent_backup_cleanup_removal_requires_exact_bytes_and_owner(self):
        changed = ['.github/workflows/scholarships-first-cutover-prepare.yml',
                   'deploy/FIRST_CUTOVER_ACTIVATION.md', 'deploy/first-backup.sh',
                   'deploy/scholarships-first-backup-command-v1.json',
                   'tests/test_first_cutover_approval.py']
        self.write(changed[0], 'environment: production\nrefs/heads/main\n'
                   'Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:4\n'
                   'Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3\n'
                   'Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:4\n'
                   '--document-name Scholarships-First-Backup-v1 --document-version 4\n')
        for rel in changed[1:]:
            self.write(rel, 'reviewed content\n')
        manifest = self.root / 'backup-cleanup.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 25, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_BACKUP_CLEANUP_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_backup_cleanup(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[2]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_restore_diagnostic_requires_exact_bytes_and_owner(self):
        changed = ['.github/workflows/scholarships-first-cutover-prepare.yml',
                   'deploy/FIRST_CUTOVER_ACTIVATION.md', 'deploy/first-restore-test.py',
                   'deploy/scholarships-first-restore-command-v1.json',
                   'tests/test_first_cutover_approval.py']
        self.write(changed[0], 'environment: production\nrefs/heads/main\n'
                   'Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:4\n'
                   'Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3\n'
                   'Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:5\n'
                   '--document-name Scholarships-First-Restore-v1 --document-version 5\n')
        self.write(changed[2], "runuser', '-u', 'mysql'\ntraceback.print_exc(limit=8)\n")
        for rel in (changed[1], changed[3], changed[4]):
            self.write(rel, 'reviewed content\n')
        manifest = self.root / 'restore-diagnostic.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 26, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_RESTORE_DIAGNOSTIC_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_restore_diagnostic(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[2]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_unique_mysql_workspace_requires_exact_bytes_and_owner(self):
        changed = ['.github/workflows/scholarships-first-cutover-prepare.yml',
                   'deploy/FIRST_CUTOVER_ACTIVATION.md', 'deploy/first-restore-test.py',
                   'deploy/scholarships-first-restore-command-v1.json',
                   'tests/test_first_cutover_approval.py']
        self.write(changed[0], 'environment: production\nrefs/heads/main\n'
                   'Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:4\n'
                   'Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3\n'
                   'Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:6\n'
                   '--document-name Scholarships-First-Restore-v1 --document-version 6\n')
        self.write(changed[2], "tempfile.mkdtemp(prefix=f'scholarships-restore-mysql-{run}-'\n"
                   "shutil.chown(workdir, user='mysql', group='mysql')\n"
                   'shutil.rmtree(workdir, ignore_errors=True)\ntraceback.print_exc(limit=8)\n')
        for rel in (changed[1], changed[3], changed[4]):
            self.write(rel, 'reviewed content\n')
        manifest = self.root / 'mysql-workspace.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 27, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_MYSQL_WORKSPACE_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_mysql_workspace(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[2]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_mysql_shutdown_requires_exact_bytes_and_owner(self):
        changed = ['.github/workflows/scholarships-first-cutover-prepare.yml',
                   'deploy/FIRST_CUTOVER_ACTIVATION.md', 'deploy/first-restore-test.py',
                   'deploy/scholarships-first-restore-command-v1.json',
                   'tests/test_first_cutover_approval.py', 'tests/test_first_restore_mysql.py']
        self.write(changed[0], 'environment: production\nrefs/heads/main\n'
                   'Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:4\n'
                   'Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3\n'
                   'Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:7\n'
                   '--document-name Scholarships-First-Restore-v1 --document-version 7\n')
        self.write(changed[2], "'--skip-networking'\n'--user=mysql'\n"
                   "'mysqladmin', f'--socket={socket}', '--user=root', 'shutdown'\n"
                   "['runuser', '-u', 'mysql', '--', '/bin/kill'\n"
                   'signal.signal(signal.SIGTERM, interrupt_restore)\n'
                   'shutil.rmtree(workdir)\ntraceback.print_exc(limit=8)\n')
        for rel in (changed[1], changed[3], changed[4], changed[5]):
            self.write(rel, 'reviewed content\n')
        manifest = self.root / 'mysql-shutdown.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 28, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_MYSQL_SHUTDOWN_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_mysql_shutdown(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[2]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_receipt_resume_requires_exact_bytes_and_owner(self):
        changed = ['.github/workflows/scholarships-first-cutover-prepare.yml',
                   'deploy/FIRST_CUTOVER_ACTIVATION.md', 'deploy/first-receipt-resume.py',
                   'tests/test_first_receipt_resume.py']
        self.write(changed[0], "!inputs.resume_verified_receipt\ninputs.resume_verified_receipt\n"
                   "github.actor == 'SaurabhVermaIN'\ngithub.ref == 'refs/heads/main'\n"
                   'github.run_attempt == 1\nenvironment: production\n'
                   'python3 deploy/first-receipt-resume.py\n')
        self.write(changed[2], "PREFIX = 'applications/scholarships/first-cutover/43713023653'\n"
                   "'restore': ('1d45ad9e-13e3-4c06-851c-205df77403a2'\n"
                   "'DocumentVersion'\nChecksumMode='ENABLED'\nIfNoneMatch='*'\n"
                   'get_command_invocation\n')
        for rel in (changed[1], changed[3]):
            self.write(rel, 'reviewed content\n')
        manifest = self.root / 'receipt-resume.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 29, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_RECEIPT_RESUME_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_receipt_resume(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[2]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_rehearsal_preflight_requires_exact_bytes_and_owner(self):
        changed = ['deploy/FIRST_CUTOVER_ACTIVATION.md',
                   'deploy/compile-first-rehearsal-preflight-document.py',
                   'deploy/first-rehearsal-preflight.py',
                   'deploy/scholarships-first-rehearsal-preflight-command-v1.json',
                   'tests/test_first_rehearsal_preflight.py']
        for rel in (changed[0], changed[1], changed[4]):
            self.write(rel, 'reviewed content\n')
        self.write(changed[2], 'i-060e4ec1fd5345c30\n'
                   'ip-172-31-34-212.ap-south-1.compute.internal\n'
                   'rehearsal node identity mismatch\n')
        self.write(changed[3], json.dumps({'parameters': {}, 'mainSteps': [
            {'action': 'aws:runShellScript', 'inputs': {'runCommand': ['fixed']}}]}))
        manifest = self.root / 'rehearsal-preflight.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 30, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_REHEARSAL_PREFLIGHT_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_rehearsal_preflight(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[2]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_rehearsal_identity_diagnostic_requires_exact_bytes_and_owner(self):
        changed = ['deploy/first-rehearsal-preflight.py',
                   'deploy/scholarships-first-rehearsal-preflight-command-v1.json',
                   'tests/test_first_rehearsal_preflight.py']
        self.write(changed[0], 'i-060e4ec1fd5345c30\n'
                   'SCHOLARSHIPS_REHEARSAL_IDENTITY=\nrehearsal node identity mismatch\n')
        self.write(changed[1], json.dumps({'parameters': {}, 'mainSteps': [
            {'action': 'aws:runShellScript', 'inputs': {'runCommand': ['fixed']}}]}))
        self.write(changed[2], 'reviewed tests\n')
        manifest = self.root / 'rehearsal-identity.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 31, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_REHEARSAL_IDENTITY_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_rehearsal_identity(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[0]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_rehearsal_node_serial_requires_exact_bytes_and_owner(self):
        changed = ['deploy/first-rehearsal-preflight.py',
                   'deploy/scholarships-first-rehearsal-preflight-command-v1.json',
                   'tests/test_first_rehearsal_preflight.py']
        self.write(changed[0], 'i-060e4ec1fd5345c30\n'
                   'EXPECTED_DMI_SERIAL\n'
                   'ec265fe7-70f0-ff7a-3d00-df5b7e29a614\n'
                   'rehearsal node identity mismatch\n')
        self.write(changed[1], json.dumps({'parameters': {}, 'mainSteps': [
            {'action': 'aws:runShellScript', 'inputs': {'runCommand': ['fixed']}}]}))
        self.write(changed[2], 'reviewed tests\n')
        manifest = self.root / 'rehearsal-node.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 32, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_REHEARSAL_NODE_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_rehearsal_node(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[0]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_synthetic_rehearsal_requires_exact_scope_and_owner(self):
        changed = ['.github/workflows/scholarships-first-cutover.yml',
                   'deploy/FIRST_CUTOVER_ACTIVATION.md',
                   'deploy/compile-first-synthetic-rehearsal-document.py',
                   'deploy/first-synthetic-rehearsal.py', 'deploy/private-storage.sh',
                   'deploy/production-release.sh', 'deploy/rollback.sh',
                   'deploy/scholarships-first-cutover-command-v1.json',
                   'deploy/scholarships-first-synthetic-rehearsal-command-v1.json',
                   'deploy/scholarships-gate-d-production-command-v1.json',
                   'tests/test_first_cutover_approval.py',
                   'tests/test_first_synthetic_rehearsal.py']
        for rel in changed:
            self.write(rel, 'reviewed content\n')
        self.write(changed[0], '--document-version 3\n'
                   'Document.DefaultVersion --output text)" = 3\n'
                   'Document.LatestVersion --output text)" = 3\n')
        self.write(changed[3], 'i-060e4ec1fd5345c30\n'
                   'ec265fe7-70f0-ff7a-3d00-df5b7e29a614\n'
                   '127.0.0.1:18083\nDROP DATABASE IF EXISTS\n'
                   'APACHE_CONF.unlink()\nshutil.rmtree\n')
        self.write(changed[5], 'SCHOLARSHIPS_TEST_MODE\n'
                   'scholarships-first-rehearsal-????????\n')
        self.write(changed[8], json.dumps({'parameters': {
            'ArtifactUrl': {'interpolationType': 'ENV_VAR', 'allowedPattern':
                '2449283b4b70f4cc00698540c88ff8dbbc939c4ae99f496d3aaf72f1a4a1bc2c'},
            'RollbackArtifactUrl': {'interpolationType': 'ENV_VAR', 'allowedPattern':
                'e6e752d9d8aef0aa7342390e1900a8ed8c17c74f963811d3f292d63b4079114e'}},
            'mainSteps': [{'action': 'aws:runShellScript',
                           'inputs': {'runCommand': ['fixed']}}]}))
        manifest = self.root / 'synthetic-rehearsal.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 33, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_SYNTHETIC_REHEARSAL_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_synthetic_rehearsal(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            (self.root / changed[3]).write_text('changed\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_exact_ssm_repair_requires_posix_wrapper_and_owner(self):
        names = ('backup', 'upload', 'restore', 'cutover')
        changed = ['.github/workflows/scholarships-first-cutover-prepare.yml',
                   '.github/workflows/scholarships-first-cutover.yml',
                   'deploy/FIRST_CUTOVER_ACTIVATION.md', 'tests/test_first_cutover_approval.py']
        for workflow in changed[:2]:
            self.write(workflow, (self.root / workflow).read_text() + '--document-version 2\n')
        self.write(changed[2], 'version 2\n')
        self.write(changed[3], 'shell regression\n')
        for name in names:
            compiler = f'deploy/compile-first-{name}-document.py'
            document = f'deploy/scholarships-first-{name}-command-v1.json'
            self.write(compiler, 'command = "set -eu\\n"\n')
            self.write(document, json.dumps({'parameters': {}, 'mainSteps': [{
                'action': 'aws:runShellScript', 'inputs': {'runCommand': ['set -eu\ntrue\n']}}]}))
            changed.extend((compiler, document))
        manifest = self.root / 'ssm-repair.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 21, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_SSM_REPAIR_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_ssm_repair(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            self.write('deploy/compile-first-backup-document.py', 'set -euo pipefail\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))

    def test_exact_host_compatibility_and_cleanup_require_owner(self):
        changed = ['.github/workflows/scholarships-first-cutover-prepare.yml',
                   'deploy/FIRST_CUTOVER_ACTIVATION.md', 'deploy/first-backup.sh',
                   'deploy/first-upload.py', 'deploy/first-restore-test.py',
                   'tests/test_first_backup_transfer.py', 'tests/test_first_cutover_approval.py']
        self.write(changed[0], 'refs/heads/main\nenvironment: production\n--document-version 3\n')
        self.write(changed[1], 'Python 3.8 backup recovery\n')
        self.write(changed[2], 'backups/first-cutover/43694560855\n'
                   '! -e $incomplete/manifest.json\n! -e $incomplete/verified.json\n'
                   'rm -rf --one-file-system -- "$incomplete"\n')
        for name in changed[3:]:
            self.write(name, 'streaming checksum\n')
        for name in ('backup', 'upload', 'restore'):
            path = f'deploy/scholarships-first-{name}-command-v1.json'
            self.write(path, json.dumps({'schemaVersion': '2.2'}))
            changed.append(path)
        manifest = self.root / 'host-compat.json'
        manifest.write_text(json.dumps({'repository': 'Synergie-ITCI/scholarships',
            'pr_number': 22, 'head_sha': HEAD, 'removed_paths': [],
            'technical_certification_owner': 'SaurabhVermaIN',
            'files': {name: self.files[name] for name in changed}}))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        comment = dict(self.comment, body=self.comment['body'].replace(
            self.comment['body'].splitlines()[1], f'CERTIFIED_MANIFEST_SHA256={digest}'))
        with patch.object(contract, 'FIRST_CUTOVER_HOST_COMPAT_MANIFEST', manifest):
            verify = lambda comments: contract.verify_first_cutover_host_compat(
                self.root, changed, HEAD, comments)
            self.assertEqual(verify([comment]), [])
            self.assertIn('owner-led', ' '.join(verify([])))
            self.write(changed[2], 'unrelated cleanup\n')
            self.assertIn('certified file changed', ' '.join(verify([comment])))


if __name__ == '__main__':
    unittest.main()
