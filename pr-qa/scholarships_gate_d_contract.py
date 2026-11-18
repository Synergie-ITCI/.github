"""Reviewed Scholarships Gate D release contracts for exact PR heads.

This does not approve deployment. Any changed file, missing owner-led
technical certification, or weakened execution boundary invalidates certification.
"""

import base64
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr15-gate-d.json"
PROMOTION_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr13-gate-d.json"
MAIN_PROMOTION_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr7-gate-d.json"
FIRST_CUTOVER_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr19-first-cutover.json"
FIRST_CUTOVER_FOLLOWUP_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr20-first-cutover.json"
FIRST_CUTOVER_SSM_REPAIR_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr21-first-cutover.json"
FIRST_CUTOVER_HOST_COMPAT_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr22-first-cutover.json"
FIRST_CUTOVER_MYSQL_RESTORE_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr23-first-cutover.json"
FIRST_CUTOVER_RESTORE_PIN_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr24-first-cutover.json"
FIRST_CUTOVER_BACKUP_CLEANUP_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr25-first-cutover.json"
FIRST_CUTOVER_RESTORE_DIAGNOSTIC_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr26-first-cutover.json"
FIRST_CUTOVER_MYSQL_WORKSPACE_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr27-first-cutover.json"
FIRST_CUTOVER_MYSQL_SHUTDOWN_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr28-first-cutover.json"
FIRST_CUTOVER_RECEIPT_RESUME_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr29-first-cutover.json"
FIRST_CUTOVER_REHEARSAL_PREFLIGHT_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr30-first-cutover.json"
FIRST_CUTOVER_REHEARSAL_IDENTITY_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr31-first-cutover.json"
FIRST_CUTOVER_REHEARSAL_NODE_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr32-first-cutover.json"
FIRST_CUTOVER_SYNTHETIC_REHEARSAL_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr33-first-cutover.json"
FIRST_CUTOVER_REHEARSAL_PERMISSIONS_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr34-first-cutover.json"
FIRST_CUTOVER_REHEARSAL_DIAGNOSTIC_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr35-first-cutover.json"
FIRST_CUTOVER_REHEARSAL_WEBROOT_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr36-first-cutover.json"
FIRST_CUTOVER_REHEARSAL_READINESS_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr37-first-cutover.json"
FIRST_CUTOVER_DIRECT_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr38-first-cutover.json"
FIRST_CUTOVER_APPROVAL_DIAGNOSTIC_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr39-first-cutover.json"
FIRST_CUTOVER_COMMENT_SCOPE_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr40-first-cutover.json"
FIRST_CUTOVER_OWNER_ID_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr41-first-cutover.json"
FIRST_CUTOVER_RECOVERY_INSPECT_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr42-first-cutover.json"
FIRST_CUTOVER_RECOVERY_ROOT_CAUSE_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr43-first-cutover.json"
FIRST_CUTOVER_RECOVERY_FPM_PROBE_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr44-first-cutover.json"
FIRST_CUTOVER_RECOVERY_FPM_TRACE_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr45-first-cutover.json"
FIRST_CUTOVER_PUBLIC_ASSETS_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr55-first-cutover.json"
FIRST_CUTOVER_EXISTING_FONTS_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr56-first-cutover.json"
LANDING_RELEASE_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr59-landing-release.json"
VALIDATOR_ASSET_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr60-validator-asset.json"
CURRENT_RECOVERY_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr78-current-recovery.json"
GATE_D_OWNER_RECEIPT_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr87-gate-d-owner-receipt.json"
GATE_D_SSM_SHELL_FIX_MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr90-ssm-shell-fix.json"
HOST = "mi-04a256fa549e372a8"
ACCOUNT = "918870682888"
RELEASE_DOCUMENT = "Scholarships-GateD-Production-Command-v1"
CERTIFIER_DOCUMENT = "Synergie-Scholarships-Runtime-Certifier-v1"
RELEASE_ROLE = "SynergieScholarshipsGithubOidcProductionDeploy"
CERTIFIER_ROLE = "SynergieScholarshipsGithubOidcRuntimeCertifier"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _send_resources(policy: dict[str, Any]) -> set[str]:
    statements = policy.get("Statement", [])
    allowed = [s for s in statements if s.get("Effect") == "Allow"
               and s.get("Action") == "ssm:SendCommand"]
    if len(allowed) != 1:
        return set()
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        if any(action in {"*", "ssm:*", "iam:*", "sts:*"} for action in actions):
            return set()
        if statement is not allowed[0] and "ssm:SendCommand" in actions:
            return set()
    return set(allowed[0].get("Resource", []))


def _has_generic_deny(policy: dict[str, Any]) -> bool:
    return any(s.get("Effect") == "Deny"
               and s.get("Action") == "ssm:SendCommand"
               and s.get("Resource") == "arn:aws:ssm:ap-south-1:*:document/AWS-RunShellScript"
               for s in policy.get("Statement", []))


def _role_trust_is_bound(trust: dict[str, Any]) -> bool:
    try:
        if len(trust["Statement"]) != 1:
            return False
        statement = trust["Statement"][0]
        if (statement.get("Effect") != "Allow"
                or statement.get("Action") != "sts:AssumeRoleWithWebIdentity"
                or statement.get("Principal") != {"Federated": "arn:aws:iam::918870682888:oidc-provider/token.actions.githubusercontent.com"}):
            return False
        condition = trust["Statement"][0]["Condition"]["StringEquals"]
    except (KeyError, IndexError, TypeError):
        return False
    prefix = "token.actions.githubusercontent.com:"
    return all(condition.get(prefix + key) == value for key, value in {
        "aud": "sts.amazonaws.com",
        "sub": "repo:Synergie-ITCI/scholarships:environment:production",
        "environment": "production",
        "ref": "refs/heads/main",
        "repository_id": "1132519991",
        "repository_owner_id": "209829096",
    }.items())


def _document_is_fixed(document: dict[str, Any], params: set[str], script: bytes) -> bool:
    if document.get("schemaVersion") != "2.2":
        return False
    actual_params = document.get("parameters", {})
    if set(actual_params) != params or not all(
        p.get("type") == "String" and p.get("interpolationType") == "ENV_VAR"
        and p.get("allowedPattern") == "^[0-9a-f]{40}$" for p in actual_params.values()
    ):
        return False
    steps = document.get("mainSteps", [])
    if len(steps) != 1 or steps[0].get("action") != "aws:runShellScript":
        return False
    commands = steps[0].get("inputs", {}).get("runCommand", [])
    if len(commands) != 1:
        return False
    encoded = base64.b64encode(script).decode("ascii")
    return commands[0] == f"printf '%s' '{encoded}' | base64 -d | bash"


def _release_document_matches(document: dict[str, Any], release: bytes, bootstrap: bytes) -> bool:
    if document.get("schemaVersion") != "2.2":
        return False
    parameters = document.get("parameters", {})
    if set(parameters) != {"SourceSha", "ArtifactSha256", "ExpectedCurrentIdentity", "ArtifactUrl"}:
        return False
    if not all(item.get("type") == "String" and item.get("interpolationType") == "ENV_VAR"
               for item in parameters.values()):
        return False
    if parameters["ExpectedCurrentIdentity"].get("allowedPattern") != "^[0-9a-f]{40}$":
        return False
    if parameters["SourceSha"].get("allowedPattern") != "^[0-9a-f]{40}$":
        return False
    if parameters["ArtifactSha256"].get("allowedPattern") != "^[0-9a-f]{64}$":
        return False
    url_pattern = parameters["ArtifactUrl"].get("allowedPattern", "")
    if url_pattern != (
        "^https://synergie-scholarships-release-artifacts-918870682888-ap-south-1"
        "[.]s3[.]ap-south-1[.]amazonaws[.]com/scholarships/releases/"
        "[0-9a-f]{40}/[0-9a-f]{64}[.]tar[.]gz[?][A-Za-z0-9%_=&.-]+$"
    ) or parameters["ArtifactUrl"].get("maxChars") != 4096:
        return False
    steps = document.get("mainSteps", [])
    if len(steps) != 1 or steps[0].get("action") != "aws:runShellScript":
        return False
    command = (
        "set -euo pipefail\n"
        "export REVIEWED_RELEASE_SCRIPT_SHA256=" + hashlib.sha256(release).hexdigest() + "\n"
        "export REVIEWED_RELEASE_SCRIPT_B64=" + base64.b64encode(release).decode("ascii") + "\n"
        "printf '%s' '" + base64.b64encode(bootstrap).decode("ascii") + "' | base64 -d | bash\n"
    )
    return steps[0].get("inputs", {}).get("runCommand") == [command]


def _owner_certified(comments: list[dict[str, Any]], owner: str, head: str,
                     manifest_digest: str) -> bool:
    required = {
        f"SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED={head}",
        f"CERTIFIED_MANIFEST_SHA256={manifest_digest}",
        "REVIEWED=IAM,SSM,APPROVAL,ARTIFACT,HOST,RUNTIME,BACKUP,RESTORE,PRIVATE_DOCUMENTS,ROLLBACK",
        "OWNER_ACCEPTS_TECHNICAL_REVIEW_RESPONSIBILITY=YES",
    }
    for comment in comments:
        if not isinstance(comment, dict) or (comment.get("user") or {}).get("login") != owner:
            continue
        if not comment.get("created_at") or comment.get("updated_at") != comment.get("created_at"):
            continue
        if required.issubset(set(str(comment.get("body") or "").splitlines())):
            return True
    return False


def verify_current_recovery(repo: Path, changed: list[str], head: str,
                            comments: list[dict[str, Any]]) -> list[str]:
    """Certify only PR #78's exact current-landing recovery control changes."""
    path = CURRENT_RECOVERY_MANIFEST
    manifest = _read_json(path)
    files = manifest.get("files")
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 78 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("current recovery certification identity changed")
    if not isinstance(files, dict) or len(files) != 27 or set(changed) != set(files):
        errors.append("current recovery changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts
                or not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"current recovery certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led current recovery technical certification is absent")
    workflow = (repo / ".github/workflows/scholarships-first-cutover.yml").read_text()
    prepare = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    release = (repo / "deploy/production-release.sh").read_text()
    backup = (repo / "deploy/first-current-backup.sh").read_text()
    cutover = (repo / "deploy/first-current-cutover.sh").read_text()
    positions = [workflow.find(token) for token in (
        "python3 deploy/first-cutover-approval-cli.py consume",
        "aws-actions/configure-aws-credentials", "aws ssm send-command")]
    if ("environment: production" not in workflow or "refs/heads/main" not in workflow
            or -1 in positions or positions != sorted(positions)
            or "AWS-RunShellScript" in workflow + prepare):
        errors.append("protected cutover approval/OIDC/fixed-SSM boundary changed")
    if ("environment: production" not in prepare or "refs/heads/main" not in prepare
            or "Scholarships-First-Backup-v1" not in prepare
            or "Scholarships-First-Restore-v1" not in prepare):
        errors.append("protected backup and isolated restore boundary changed")
    if ("--backup-only" not in backup or "database.sql.gz" not in backup
            or "documents.tar.gz" not in backup or "shared/private-documents" not in backup
            or "off_host_verified" not in cutover or "isolated_restore_pass" not in cutover
            or "rollback.sh" not in cutover or "--check" not in cutover):
        errors.append("fresh backup, private document or rollback verification changed")
    if ("c44cef5ac0490aa0c356c6c1d441ab521197a77fc212e4f10613687cb3be150b"
            not in release or "RECOVERY_BACKUP_RUN_ID" not in release
            or "RECOVERY_ROLLBACK_SHA256" not in release):
        errors.append("one-use current landing release identity changed")
    role = _read_json(repo / "deploy/scholarships-first-cutover-role-policy-v1.json")
    host = f"arn:aws:ssm:ap-south-1:{ACCOUNT}:managed-instance/{HOST}"
    if (_send_resources(role) != {host, f"arn:aws:ssm:ap-south-1:{ACCOUNT}:document/Scholarships-First-Cutover-v1"}
            or not _has_generic_deny(role)):
        errors.append("fixed SSM host/document or generic-shell denial changed")
    for name in ("scholarships-first-current-backup-command-v1.json",
                 "scholarships-first-current-cutover-command-v1.json",
                 "scholarships-gate-d-production-command-v2.json",
                 "scholarships-gate-d-runtime-certifier-v2.json"):
        document = _read_json(repo / "deploy" / name)
        if document.get("schemaVersion") != "2.2" or len(document.get("mainSteps", [])) != 1:
            errors.append(f"fixed SSM document structure changed: {name}")
    return errors


def verify_gate_d_owner_receipt(repo: Path, changed: list[str], head: str,
                                comments: list[dict[str, Any]],
                                controlled_workflow: bool) -> list[str]:
    """Certify only PR #87's exact owner-receipt control and preserved Gate D."""
    path = GATE_D_OWNER_RECEIPT_MANIFEST
    manifest = _read_json(path)
    files = manifest.get('files')
    errors: list[str] = []
    if (manifest.get('repository') != 'Synergie-ITCI/scholarships'
            or manifest.get('pr_number') != 87 or manifest.get('head_sha') != head
            or manifest.get('technical_certification_owner') != 'SaurabhVermaIN'
            or manifest.get('removed_paths') != []):
        errors.append('Gate D owner receipt certification identity changed')
    if not isinstance(files, dict) or len(files) != 7 or set(changed) != set(files):
        errors.append('Gate D owner receipt changed-file scope changed')
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not isinstance(rel, str) or Path(rel).is_absolute() or '..' in Path(rel).parts
                or not re.fullmatch(r'[0-9a-f]{64}', str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f'Gate D owner receipt certified file changed: {rel}')
    if errors:
        return errors
    if not _owner_certified(comments, 'SaurabhVermaIN', head,
                            hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append('owner-led Gate D technical certification is absent')
    workflow = (repo / '.github/workflows/scholarships-gate-d-release.yml').read_text()
    owner_receipt = (repo / 'deploy/gate-d-owner-receipt.py').read_text()
    approval = (repo / 'deploy/first_cutover_approval.py').read_text()
    sequence = [workflow.find(token) for token in (
        'Checkout exact approved source',
        'python3 deploy/gate-d-owner-receipt.py consume',
        'Assume restricted runtime-certification role',
        'Certify actual production PHP-FPM serving runtime',
        'Assume repository and environment bound production role',
        'aws ssm send-command',
    )]
    if (not controlled_workflow or -1 in sequence or sequence != sorted(sequence)
            or 'environment: production' not in workflow
            or "refs/heads/main" not in workflow
            or 'deployments: write' not in workflow
            or 'pull-requests: read' not in workflow
            or '--document-version 2' not in workflow
            or 'AWS-RunShellScript' in workflow):
        errors.append('protected approval, runtime certifier or fixed SSM order changed')
    if ("ROLLBACK_SOURCE = 'e853573a7d426a5b8e3dd2cece7e816d41045d24'" not in owner_receipt
            or 'BACKUP_RUN = \'44171193048\'' not in owner_receipt
            or 'ApprovalReceipt(api=api' not in owner_receipt
            or "'receipt_marker_prefix': 'scholarships-gate-d'" not in owner_receipt
            or 'receipt.consume()' not in owner_receipt
            or "contract.get('receipt_marker_prefix', 'scholarships-first-cutover')" not in approval
            or 'created_at' not in approval or 'updated_at' not in approval
            or 'timedelta(hours=2)' not in approval):
        errors.append('one-use exact owner comment and rollback binding changed')
    return errors


def verify_gate_d_ssm_shell_fix(repo: Path, changed: list[str], head: str,
                                comments: list[dict[str, Any]],
                                controlled_workflow: bool) -> list[str]:
    """Certify the exact POSIX wrapper repair after the v2 SSM command failed closed."""
    path = GATE_D_SSM_SHELL_FIX_MANIFEST
    manifest = _read_json(path)
    files = manifest.get('files')
    errors: list[str] = []
    if (manifest.get('repository') != 'Synergie-ITCI/scholarships'
            or manifest.get('pr_number') != 90 or manifest.get('head_sha') != head
            or manifest.get('technical_certification_owner') != 'SaurabhVermaIN'
            or manifest.get('removed_paths') != []):
        errors.append('Gate D SSM shell fix certification identity changed')
    if not isinstance(files, dict) or len(files) != 8 or set(changed) != set(files):
        errors.append('Gate D SSM shell fix changed-file scope changed')
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not isinstance(rel, str) or Path(rel).is_absolute() or '..' in Path(rel).parts
                or not re.fullmatch(r'[0-9a-f]{64}', str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f'Gate D SSM shell fix certified file changed: {rel}')
    if errors:
        return errors
    if not _owner_certified(comments, 'SaurabhVermaIN', head,
                            hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append('owner-led Gate D SSM shell fix technical certification is absent')
    workflow = (repo / '.github/workflows/scholarships-gate-d-release.yml').read_text()
    owner_receipt = (repo / 'deploy/gate-d-owner-receipt.py').read_text()
    command = _read_json(repo / 'deploy/scholarships-gate-d-production-command-v3.json')
    wrapper = command['mainSteps'][0]['inputs']['runCommand'][0]
    compiler = (repo / 'deploy/compile-ssm-document-v3.py').read_text()
    sequence = [workflow.find(token) for token in (
        'gate-d-owner-receipt.py consume',
        'Assume restricted runtime-certification role',
        'Certify actual production PHP-FPM serving runtime',
        'Assume repository and environment bound production role',
        'aws ssm send-command',
    )]
    if (not controlled_workflow or -1 in sequence or sequence != sorted(sequence)
            or 'environment: production' not in workflow
            or 'Scholarships-GateD-Production-Command-v1 --document-version 3' not in workflow
            or 'scholarships-gate-d-production-command-v3.json' not in workflow
            or 'deployments: write' not in workflow
            or 'AWS-RunShellScript' in workflow):
        errors.append('protected Gate D workflow or fixed version 3 document binding changed')
    if (not wrapper.startswith('set -eu\n')
            or 'base64 -d > "$bootstrap"\n' not in wrapper
            or 'bash "$bootstrap"\n' not in wrapper
            or wrapper.index('base64 -d > "$bootstrap"') > wrapper.index('bash "$bootstrap"')
            or '"set -eu\\n"' not in compiler
            or "document-version 3" not in workflow):
        errors.append('POSIX SSM wrapper or checked bootstrap execution changed')
    if ("ROOT / 'scholarships-gate-d-production-command-v3.json'" not in owner_receipt
            or "ROLLBACK_SOURCE = 'e853573a7d426a5b8e3dd2cece7e816d41045d24'" not in owner_receipt
            or 'receipt.consume()' not in owner_receipt):
        errors.append('one-use owner manifest or rollback binding changed')
    return errors


def verify_first_cutover_host_compat(repo: Path, changed: list[str], head: str,
                                     comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact Python 3.8 and incomplete-backup recovery in PR #22."""
    manifest = _read_json(FIRST_CUTOVER_HOST_COMPAT_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 22
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover host compatibility identity changed")
    expected = {".github/workflows/scholarships-first-cutover-prepare.yml",
                "deploy/FIRST_CUTOVER_ACTIVATION.md", "deploy/first-backup.sh",
                "deploy/first-upload.py", "deploy/first-restore-test.py",
                "tests/test_first_backup_transfer.py", "tests/test_first_cutover_approval.py"}
    expected |= {f"deploy/scholarships-first-{name}-command-v1.json"
                 for name in ("backup", "upload", "restore")}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover host compatibility changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover host compatibility certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_HOST_COMPAT_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover host compatibility certification is absent")
    prepare = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    if ("environment: production" not in prepare or "refs/heads/main" not in prepare
            or "--document-version 3" not in prepare):
        errors.append("first-cutover version-3 preparation boundary changed")
    backup = (repo / "deploy/first-backup.sh").read_text()
    if ("backups/first-cutover/43694560855" not in backup
            or "! -e $incomplete/manifest.json" not in backup
            or "! -e $incomplete/verified.json" not in backup
            or "rm -rf --one-file-system -- \"$incomplete\"" not in backup):
        errors.append("exact incomplete-backup cleanup boundary changed")
    for rel in ("deploy/first-backup.sh", "deploy/first-upload.py", "deploy/first-restore-test.py"):
        script = (repo / rel).read_text()
        if "hashlib.file_digest" in script or ".is_relative_to(" in script:
            errors.append(f"host Python 3.8 compatibility changed: {rel}")
    return errors


def verify_first_cutover_mysql_restore(repo: Path, changed: list[str], head: str,
                                       comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact MySQL 5.7 isolated-restore repair in PR #23."""
    manifest = _read_json(FIRST_CUTOVER_MYSQL_RESTORE_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 23
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover MySQL restore identity changed")
    expected = {"deploy/first-restore-test.py",
                "deploy/scholarships-first-restore-command-v1.json"}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover MySQL restore changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover MySQL restore certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_MYSQL_RESTORE_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover MySQL restore certification is absent")
    restore = (repo / "deploy/first-restore-test.py").read_text()
    if ("runuser', '-u', 'mysql'" not in restore
            or "datadir = workdir / 'data'" not in restore
            or "shutil.rmtree(workdir" not in restore):
        errors.append("isolated MySQL restore boundary changed")
    document = _read_json(repo / "deploy/scholarships-first-restore-command-v1.json")
    steps = document.get("mainSteps", [])
    if (len(steps) != 1 or steps[0].get("action") != "aws:runShellScript"
            or "Commands" in document.get("parameters", {})):
        errors.append("fixed restore SSM document boundary changed")
    return errors


def verify_first_cutover_restore_pin(repo: Path, changed: list[str], head: str,
                                     comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact fixed-document version pin in PR #24."""
    manifest = _read_json(FIRST_CUTOVER_RESTORE_PIN_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 24
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover restore pin identity changed")
    expected = {".github/workflows/scholarships-first-cutover-prepare.yml",
                "deploy/FIRST_CUTOVER_ACTIVATION.md",
                "tests/test_first_cutover_approval.py"}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover restore pin changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover restore pin certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_RESTORE_PIN_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover restore pin certification is absent")
    workflow = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    for token in ("environment: production", "refs/heads/main",
                  "Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:3",
                  "Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3",
                  "Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:4",
                  "--document-name Scholarships-First-Restore-v1 --document-version 4"):
        if token not in workflow:
            errors.append(f"first-cutover restore version boundary changed: {token}")
    if "AWS-RunShellScript" in workflow:
        errors.append("generic SSM shell used in restore preparation workflow")
    return errors


def verify_first_cutover_backup_cleanup(repo: Path, changed: list[str], head: str,
                                        comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact spent one-time backup cleanup removal in PR #25."""
    manifest = _read_json(FIRST_CUTOVER_BACKUP_CLEANUP_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 25
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover backup cleanup identity changed")
    expected = {".github/workflows/scholarships-first-cutover-prepare.yml",
                "deploy/FIRST_CUTOVER_ACTIVATION.md", "deploy/first-backup.sh",
                "deploy/scholarships-first-backup-command-v1.json",
                "tests/test_first_cutover_approval.py"}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover backup cleanup changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover backup cleanup certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_BACKUP_CLEANUP_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover backup cleanup certification is absent")
    workflow = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    backup = (repo / "deploy/first-backup.sh").read_text()
    if ("Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:4" not in workflow
            or "--document-name Scholarships-First-Backup-v1 --document-version 4" not in workflow
            or "Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3" not in workflow
            or "Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:4" not in workflow
            or "environment: production" not in workflow or "refs/heads/main" not in workflow
            or "AWS-RunShellScript" in workflow):
        errors.append("fixed backup version boundary changed")
    if "43694560855" in backup or "rm -rf --one-file-system" in backup:
        errors.append("spent cleanup remains in fixed backup payload")
    return errors


def verify_first_cutover_restore_diagnostic(repo: Path, changed: list[str], head: str,
                                            comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact fixed-document restore diagnostics in PR #26."""
    manifest = _read_json(FIRST_CUTOVER_RESTORE_DIAGNOSTIC_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 26
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover restore diagnostic identity changed")
    expected = {".github/workflows/scholarships-first-cutover-prepare.yml",
                "deploy/FIRST_CUTOVER_ACTIVATION.md", "deploy/first-restore-test.py",
                "deploy/scholarships-first-restore-command-v1.json",
                "tests/test_first_cutover_approval.py"}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover restore diagnostic changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover restore diagnostic certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_RESTORE_DIAGNOSTIC_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover restore diagnostic certification is absent")
    workflow = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    restore = (repo / "deploy/first-restore-test.py").read_text()
    if ("Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:5" not in workflow
            or "--document-name Scholarships-First-Restore-v1 --document-version 5" not in workflow
            or "Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:4" not in workflow
            or "Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3" not in workflow
            or "environment: production" not in workflow or "refs/heads/main" not in workflow
            or "AWS-RunShellScript" in workflow):
        errors.append("fixed restore diagnostic version boundary changed")
    if "traceback.print_exc(limit=8)" not in restore or "runuser', '-u', 'mysql'" not in restore:
        errors.append("bounded restore diagnostics or MySQL isolation changed")
    return errors


def verify_first_cutover_mysql_workspace(repo: Path, changed: list[str], head: str,
                                         comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact isolated MySQL workspace repair in PR #27."""
    manifest = _read_json(FIRST_CUTOVER_MYSQL_WORKSPACE_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 27
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover MySQL workspace identity changed")
    expected = {".github/workflows/scholarships-first-cutover-prepare.yml",
                "deploy/FIRST_CUTOVER_ACTIVATION.md", "deploy/first-restore-test.py",
                "deploy/scholarships-first-restore-command-v1.json",
                "tests/test_first_cutover_approval.py"}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover MySQL workspace changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover MySQL workspace certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_MYSQL_WORKSPACE_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover MySQL workspace certification is absent")
    workflow = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    restore = (repo / "deploy/first-restore-test.py").read_text()
    if ("Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:6" not in workflow
            or "--document-name Scholarships-First-Restore-v1 --document-version 6" not in workflow
            or "Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:4" not in workflow
            or "Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3" not in workflow
            or "environment: production" not in workflow or "refs/heads/main" not in workflow
            or "AWS-RunShellScript" in workflow):
        errors.append("fixed restore workspace version boundary changed")
    if ("tempfile.mkdtemp(prefix=f'scholarships-restore-mysql-{run}-'" not in restore
            or "shutil.chown(workdir, user='mysql', group='mysql')" not in restore
            or "shutil.rmtree(workdir, ignore_errors=True)" not in restore
            or "traceback.print_exc(limit=8)" not in restore):
        errors.append("isolated MySQL workspace or diagnostics changed")
    return errors


def verify_first_cutover_mysql_shutdown(repo: Path, changed: list[str], head: str,
                                        comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact process-ownership and cleanup repair in PR #28."""
    manifest = _read_json(FIRST_CUTOVER_MYSQL_SHUTDOWN_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 28
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover MySQL shutdown identity changed")
    expected = {".github/workflows/scholarships-first-cutover-prepare.yml",
                "deploy/FIRST_CUTOVER_ACTIVATION.md", "deploy/first-restore-test.py",
                "deploy/scholarships-first-restore-command-v1.json",
                "tests/test_first_cutover_approval.py", "tests/test_first_restore_mysql.py"}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover MySQL shutdown changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover MySQL shutdown certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_MYSQL_SHUTDOWN_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover MySQL shutdown certification is absent")
    workflow = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    restore = (repo / "deploy/first-restore-test.py").read_text()
    if ("Scholarships-First-Restore-v1:scholarships-first-restore-command-v1.json:7" not in workflow
            or "--document-name Scholarships-First-Restore-v1 --document-version 7" not in workflow
            or "Scholarships-First-Backup-v1:scholarships-first-backup-command-v1.json:4" not in workflow
            or "Scholarships-First-Upload-v1:scholarships-first-upload-command-v1.json:3" not in workflow
            or "environment: production" not in workflow or "refs/heads/main" not in workflow
            or "AWS-RunShellScript" in workflow):
        errors.append("fixed restore shutdown version boundary changed")
    if ("'--skip-networking'" not in restore
            or "'--user=mysql'" not in restore
            or "'mysqladmin', f'--socket={socket}', '--user=root', 'shutdown'" not in restore
            or "['runuser', '-u', 'mysql', '--', '/bin/kill'" not in restore
            or "signal.signal(signal.SIGTERM, interrupt_restore)" not in restore
            or "shutil.rmtree(workdir)" not in restore
            or "server.terminate()" in restore
            or "traceback.print_exc(limit=8)" not in restore):
        errors.append("least-privilege MySQL shutdown or cleanup changed")
    return errors


def verify_first_cutover_receipt_resume(repo: Path, changed: list[str], head: str,
                                        comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact one-use receipt continuation in PR #29."""
    manifest = _read_json(FIRST_CUTOVER_RECEIPT_RESUME_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 29
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover receipt continuation identity changed")
    expected = {".github/workflows/scholarships-first-cutover-prepare.yml",
                "deploy/FIRST_CUTOVER_ACTIVATION.md", "deploy/first-receipt-resume.py",
                "tests/test_first_receipt_resume.py"}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover receipt continuation scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover receipt continuation certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_RECEIPT_RESUME_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover receipt continuation certification is absent")
    workflow = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    resume = (repo / "deploy/first-receipt-resume.py").read_text()
    if ("!inputs.resume_verified_receipt" not in workflow
            or "inputs.resume_verified_receipt" not in workflow
            or "github.actor == 'SaurabhVermaIN'" not in workflow
            or "github.ref == 'refs/heads/main'" not in workflow
            or "github.run_attempt == 1" not in workflow
            or "environment: production" not in workflow
            or "python3 deploy/first-receipt-resume.py" not in workflow
            or "AWS-RunShellScript" in workflow):
        errors.append("bounded receipt workflow gate changed")
    if ("PREFIX = 'applications/scholarships/first-cutover/43713023653'" not in resume
            or "'restore': ('1d45ad9e-13e3-4c06-851c-205df77403a2'" not in resume
            or "'DocumentVersion'" not in resume
            or "ChecksumMode='ENABLED'" not in resume
            or "IfNoneMatch='*'" not in resume
            or "get_command_invocation" not in resume
            or "send_command" in resume):
        errors.append("fixed receipt evidence or one-use boundary changed")
    return errors


def verify_first_cutover_rehearsal_preflight(repo: Path, changed: list[str], head: str,
                                              comments: list[dict[str, Any]]) -> list[str]:
    """Certify the parameter-free, read-only rehearsal probe in PR #30."""
    manifest = _read_json(FIRST_CUTOVER_REHEARSAL_PREFLIGHT_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 30
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("rehearsal preflight identity changed")
    expected = {"deploy/FIRST_CUTOVER_ACTIVATION.md",
                "deploy/compile-first-rehearsal-preflight-document.py",
                "deploy/first-rehearsal-preflight.py",
                "deploy/scholarships-first-rehearsal-preflight-command-v1.json",
                "tests/test_first_rehearsal_preflight.py"}
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("rehearsal preflight changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"rehearsal preflight certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_REHEARSAL_PREFLIGHT_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led rehearsal preflight certification is absent")
    source = (repo / "deploy/first-rehearsal-preflight.py").read_text()
    document = _read_json(repo / "deploy/scholarships-first-rehearsal-preflight-command-v1.json")
    if (document.get("parameters") != {}
            or len(document.get("mainSteps", [])) != 1
            or document["mainSteps"][0].get("action") != "aws:runShellScript"
            or "{{" in str(document["mainSteps"][0])
            or "i-060e4ec1fd5345c30" not in source
            or "ip-172-31-34-212.ap-south-1.compute.internal" not in source
            or "rehearsal node identity mismatch" not in source
            or any(token in source for token in ("os.system", "subprocess.Popen", "shutil.rmtree", "write_text("))):
        errors.append("fixed read-only rehearsal preflight boundary changed")
    return errors


def verify_first_cutover_rehearsal_identity(repo: Path, changed: list[str], head: str,
                                             comments: list[dict[str, Any]]) -> list[str]:
    """Certify PR #31's bounded, fail-closed rehearsal identity diagnostic."""
    manifest = _read_json(FIRST_CUTOVER_REHEARSAL_IDENTITY_MANIFEST)
    expected = {"deploy/first-rehearsal-preflight.py",
                "deploy/scholarships-first-rehearsal-preflight-command-v1.json",
                "tests/test_first_rehearsal_preflight.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 31 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("rehearsal identity certification changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("rehearsal identity changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"rehearsal identity certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_REHEARSAL_IDENTITY_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led rehearsal identity certification is absent")
    source = (repo / "deploy/first-rehearsal-preflight.py").read_text()
    document = _read_json(repo / "deploy/scholarships-first-rehearsal-preflight-command-v1.json")
    if (document.get("parameters") != {} or len(document.get("mainSteps", [])) != 1
            or document["mainSteps"][0].get("action") != "aws:runShellScript"
            or "{{" in str(document["mainSteps"][0])
            or "SCHOLARSHIPS_REHEARSAL_IDENTITY=" not in source
            or "rehearsal node identity mismatch" not in source
            or "i-060e4ec1fd5345c30" not in source
            or any(token in source for token in ("os.system", "subprocess.Popen", "shutil.rmtree", "write_text("))):
        errors.append("fixed read-only rehearsal diagnostic boundary changed")
    return errors


def verify_first_cutover_rehearsal_node(repo: Path, changed: list[str], head: str,
                                         comments: list[dict[str, Any]]) -> list[str]:
    """Certify PR #32's observed DMI identity guard for the rehearsal node."""
    manifest = _read_json(FIRST_CUTOVER_REHEARSAL_NODE_MANIFEST)
    expected = {"deploy/first-rehearsal-preflight.py",
                "deploy/scholarships-first-rehearsal-preflight-command-v1.json",
                "tests/test_first_rehearsal_preflight.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 32 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("rehearsal node certification changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("rehearsal node changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"rehearsal node certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_REHEARSAL_NODE_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led rehearsal node certification is absent")
    source = (repo / "deploy/first-rehearsal-preflight.py").read_text()
    document = _read_json(repo / "deploy/scholarships-first-rehearsal-preflight-command-v1.json")
    if (document.get("parameters") != {} or len(document.get("mainSteps", [])) != 1
            or document["mainSteps"][0].get("action") != "aws:runShellScript"
            or "{{" in str(document["mainSteps"][0])
            or "EXPECTED_DMI_SERIAL" not in source
            or "ec265fe7-70f0-ff7a-3d00-df5b7e29a614" not in source
            or "rehearsal node identity mismatch" not in source
            or "i-060e4ec1fd5345c30" not in source
            or any(token in source for token in ("os.system", "subprocess.Popen", "shutil.rmtree", "write_text("))):
        errors.append("fixed read-only rehearsal node boundary changed")
    return errors


def verify_first_cutover_synthetic_rehearsal(repo: Path, changed: list[str], head: str,
                                              comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact PR #33 fixed SSM synthetic cutover and rollback scope."""
    manifest = _read_json(FIRST_CUTOVER_SYNTHETIC_REHEARSAL_MANIFEST)
    expected = {".github/workflows/scholarships-first-cutover.yml",
                "deploy/FIRST_CUTOVER_ACTIVATION.md",
                "deploy/compile-first-synthetic-rehearsal-document.py",
                "deploy/first-synthetic-rehearsal.py",
                "deploy/private-storage.sh", "deploy/production-release.sh",
                "deploy/rollback.sh", "deploy/scholarships-first-cutover-command-v1.json",
                "deploy/scholarships-first-synthetic-rehearsal-command-v1.json",
                "deploy/scholarships-gate-d-production-command-v1.json",
                "tests/test_first_cutover_approval.py",
                "tests/test_first_synthetic_rehearsal.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 33 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("synthetic rehearsal certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("synthetic rehearsal changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"synthetic rehearsal certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_SYNTHETIC_REHEARSAL_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led synthetic rehearsal certification is absent")
    runner = (repo / "deploy/first-synthetic-rehearsal.py").read_text()
    release = (repo / "deploy/production-release.sh").read_text()
    workflow = (repo / ".github/workflows/scholarships-first-cutover.yml").read_text()
    document = _read_json(repo / "deploy/scholarships-first-synthetic-rehearsal-command-v1.json")
    params = document.get("parameters", {})
    steps = document.get("mainSteps", [])
    if (set(params) != {"ArtifactUrl", "RollbackArtifactUrl"}
            or not all(p.get("interpolationType") == "ENV_VAR" for p in params.values())
            or "2449283b4b70f4cc00698540c88ff8dbbc939c4ae99f496d3aaf72f1a4a1bc2c" not in params["ArtifactUrl"].get("allowedPattern", "")
            or "e6e752d9d8aef0aa7342390e1900a8ed8c17c74f963811d3f292d63b4079114e" not in params["RollbackArtifactUrl"].get("allowedPattern", "")
            or len(steps) != 1 or steps[0].get("action") != "aws:runShellScript"
            or "{{" in str(steps)
            or "i-060e4ec1fd5345c30" not in runner
            or "ec265fe7-70f0-ff7a-3d00-df5b7e29a614" not in runner
            or "127.0.0.1:18083" not in runner
            or "DROP DATABASE IF EXISTS" not in runner
            or "APACHE_CONF.unlink()" not in runner
            or "shutil.rmtree" not in runner
            or "SCHOLARSHIPS_TEST_MODE" not in release
            or "scholarships-first-rehearsal-????????" not in release
            or "--document-version 3" not in workflow
            or workflow.count('Document.DefaultVersion --output text)" = 3') != 1
            or workflow.count('Document.LatestVersion --output text)" = 3') != 1
            or "AWS-RunShellScript" in workflow):
        errors.append("fixed synthetic SSM or production boundary changed")
    return errors


def verify_first_cutover_rehearsal_permissions(repo: Path, changed: list[str], head: str,
                                                comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact PR #34 synthetic fixture permissions and fixed SSM v2."""
    manifest = _read_json(FIRST_CUTOVER_REHEARSAL_PERMISSIONS_MANIFEST)
    expected = {"deploy/FIRST_CUTOVER_ACTIVATION.md",
                "deploy/first-synthetic-rehearsal.py",
                "deploy/scholarships-first-synthetic-rehearsal-command-v1.json",
                "tests/test_first_synthetic_rehearsal.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 34 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("rehearsal permission certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("rehearsal permission changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"rehearsal permission certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_REHEARSAL_PERMISSIONS_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led rehearsal permission certification is absent")
    runner = (repo / "deploy/first-synthetic-rehearsal.py").read_text()
    document = _read_json(repo / "deploy/scholarships-first-synthetic-rehearsal-command-v1.json")
    params = document.get("parameters", {})
    steps = document.get("mainSteps", [])
    if ("current.chmod(0o755)" not in runner
            or "(current / '.htaccess').chmod(0o644)" not in runner
            or "(current / '.scholarships-rehearsal-health.php').chmod(0o644)" not in runner
            or "prior rehearsal workspace remains" not in runner
            or "prior rehearsal database remains" not in runner
            or "SCHOLARSHIPS_SYNTHETIC_REHEARSAL_PASS=" not in runner
            or set(params) != {"ArtifactUrl", "RollbackArtifactUrl"}
            or not all(p.get("interpolationType") == "ENV_VAR" for p in params.values())
            or len(steps) != 1 or steps[0].get("action") != "aws:runShellScript"
            or "{{" in str(steps)
            or "i-060e4ec1fd5345c30" not in runner):
        errors.append("fixed synthetic SSM v2 or Apache permission boundary changed")
    return errors


def verify_first_cutover_rehearsal_diagnostic(repo: Path, changed: list[str], head: str,
                                               comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact PR #35 synthetic-vhost-only health diagnostics and fixed SSM v3."""
    manifest = _read_json(FIRST_CUTOVER_REHEARSAL_DIAGNOSTIC_MANIFEST)
    expected = {"deploy/FIRST_CUTOVER_ACTIVATION.md",
                "deploy/first-synthetic-rehearsal.py",
                "deploy/scholarships-first-synthetic-rehearsal-command-v1.json",
                "tests/test_first_synthetic_rehearsal.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 35 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("rehearsal diagnostic certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("rehearsal diagnostic changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"rehearsal diagnostic certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_REHEARSAL_DIAGNOSTIC_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led rehearsal diagnostic certification is absent")
    runner = (repo / "deploy/first-synthetic-rehearsal.py").read_text()
    document = _read_json(repo / "deploy/scholarships-first-synthetic-rehearsal-command-v1.json")
    params = document.get("parameters", {})
    steps = document.get("mainSteps", [])
    if ("root / 'apache-error.log'" not in runner
            or "LogLevel warn authz_core:debug" not in runner
            or "def health_check(root, stage):" not in runner
            or "body[:200]" not in runner or "splitlines()[-8:]" not in runner
            or "health_check(root, 'synthetic legacy')" not in runner
            or "SCHOLARSHIPS_SYNTHETIC_REHEARSAL_PASS=" not in runner
            or set(params) != {"ArtifactUrl", "RollbackArtifactUrl"}
            or not all(p.get("interpolationType") == "ENV_VAR" for p in params.values())
            or len(steps) != 1 or steps[0].get("action") != "aws:runShellScript"
            or "{{" in str(steps)
            or "i-060e4ec1fd5345c30" not in runner):
        errors.append("fixed synthetic SSM v3 or vhost-only diagnostic boundary changed")
    return errors


def verify_first_cutover_rehearsal_webroot(repo: Path, changed: list[str], head: str,
                                           comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact PR #36 Apache-visible synthetic workspace and fixed SSM v4."""
    path = FIRST_CUTOVER_REHEARSAL_WEBROOT_MANIFEST
    manifest = _read_json(path)
    expected = {"deploy/FIRST_CUTOVER_ACTIVATION.md", "deploy/first-synthetic-rehearsal.py",
                "deploy/private-storage.sh", "deploy/production-release.sh", "deploy/rollback.sh",
                "deploy/scholarships-first-cutover-command-v1.json",
                "deploy/scholarships-first-synthetic-rehearsal-command-v1.json",
                "deploy/scholarships-gate-d-production-command-v1.json",
                "tests/test_first_synthetic_rehearsal.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 36 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("rehearsal webroot certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("rehearsal webroot changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"rehearsal webroot certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led rehearsal webroot certification is absent")
    runner = (repo / "deploy/first-synthetic-rehearsal.py").read_text()
    production = (repo / "deploy/production-release.sh").read_text()
    private = (repo / "deploy/private-storage.sh").read_text()
    rollback = (repo / "deploy/rollback.sh").read_text()
    document = _read_json(repo / "deploy/scholarships-first-synthetic-rehearsal-command-v1.json")
    params = document.get("parameters", {})
    steps = document.get("mainSteps", [])
    if ("WORKSPACE_PARENT = Path('/var/www')" not in runner
            or "Path('/var/tmp'), WORKSPACE_PARENT" not in runner
            or "tempfile.mkdtemp(prefix='scholarships-first-rehearsal-'" not in runner
            or "dir=str(WORKSPACE_PARENT))" not in runner
            or "i-060e4ec1fd5345c30" not in runner
            or "SCHOLARSHIPS_SYNTHETIC_REHEARSAL_PASS=" not in runner
            or "/var/www/scholarships-first-rehearsal-????????" not in production
            or "/var/www/scholarships-first-rehearsal-????????" not in private
            or "/var/www/scholarships-first-rehearsal-????????" not in rollback
            or "/var/www/scholarships.synergieinsights.in" not in production
            or set(params) != {"ArtifactUrl", "RollbackArtifactUrl"}
            or not all(p.get("interpolationType") == "ENV_VAR" for p in params.values())
            or len(steps) != 1 or steps[0].get("action") != "aws:runShellScript"
            or "{{" in str(steps)):
        errors.append("fixed synthetic SSM v4 or Apache-visible workspace boundary changed")
    return errors


def verify_first_cutover_rehearsal_readiness(repo: Path, changed: list[str], head: str,
                                             comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact PR #37 bounded listener readiness after Apache reload."""
    path = FIRST_CUTOVER_REHEARSAL_READINESS_MANIFEST
    manifest = _read_json(path)
    expected = {"deploy/FIRST_CUTOVER_ACTIVATION.md",
                "deploy/first-synthetic-rehearsal.py",
                "deploy/scholarships-first-synthetic-rehearsal-command-v1.json",
                "tests/test_first_synthetic_rehearsal.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 37 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("rehearsal readiness certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("rehearsal readiness changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"rehearsal readiness certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led rehearsal readiness certification is absent")
    runner = (repo / "deploy/first-synthetic-rehearsal.py").read_text()
    tests = (repo / "tests/test_first_synthetic_rehearsal.py").read_text()
    document = _read_json(repo / "deploy/scholarships-first-synthetic-rehearsal-command-v1.json")
    params = document.get("parameters", {})
    steps = document.get("mainSteps", [])
    if ("WORKSPACE_PARENT = Path('/var/www')" not in runner
            or "deadline = time.monotonic() + 10" not in runner
            or "probe.returncode != 7 or time.monotonic() >= deadline" not in runner
            or "time.sleep(0.25)" not in runner
            or "test_health_waits_for_graceful_apache_listener_only" not in tests
            or "test_health_connection_refusal_is_bounded" not in tests
            or "SCHOLARSHIPS_SYNTHETIC_REHEARSAL_PASS=" not in runner
            or "i-060e4ec1fd5345c30" not in runner
            or set(params) != {"ArtifactUrl", "RollbackArtifactUrl"}
            or not all(p.get("interpolationType") == "ENV_VAR" for p in params.values())
            or len(steps) != 1 or steps[0].get("action") != "aws:runShellScript"
            or "{{" in str(steps)):
        errors.append("fixed synthetic SSM v5 or bounded readiness retry changed")
    return errors


def verify_first_cutover_direct(repo: Path, changed: list[str], head: str,
                                 comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact PR #38 reuse of immutable artifacts in the governed cutover."""
    path = FIRST_CUTOVER_DIRECT_MANIFEST
    manifest = _read_json(path)
    expected = {".github/workflows/scholarships-first-cutover.yml",
                "deploy/FIRST_CUTOVER_ACTIVATION.md", "tests/test_first_cutover_approval.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 38 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("direct cutover certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("direct cutover changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"direct cutover certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led direct cutover certification is absent")
    workflow = (repo / ".github/workflows/scholarships-first-cutover.yml").read_text()
    if ("environment: production" not in workflow
            or "github.ref == 'refs/heads/main'" not in workflow
            or "github.run_attempt == 1" not in workflow
            or "Consume one-use exact owner receipt before AWS OIDC" not in workflow
            or workflow.find("Consume one-use exact owner receipt before AWS OIDC")
               >= workflow.find("Assume cutover-only OIDC role after consumed owner receipt")
            or "--document-name Scholarships-First-Cutover-v1" not in workflow
            or "--document-version 3" not in workflow
            or "mi-04a256fa549e372a8" not in workflow
            or "s3api put-object" in workflow
            or "version=DtMN77Ft2om6nPPs5kAoUNDAiab96qo_" not in workflow
            or "rollback_version=N.kuwn9yxmaw9.smxP3FSrmnEczpryTJ" not in workflow
            or workflow.count("s3api head-object --bucket") < 4
            or workflow.count("s3api get-object --bucket") < 4
            or ".ServerSideEncryption==\"AES256\"" not in workflow
            or ".Metadata.sha256==$sha" not in workflow
            or "DefaultVersion --output text)\" = 1" not in workflow
            or "LatestVersion --output text)\" = 1" not in workflow
            or "Synergie-Scholarships-Runtime-Certifier-v1" not in workflow):
        errors.append("one-use approval, fixed SSM or immutable artifact boundary changed")
    return errors


def verify_first_cutover_approval_diagnostic(repo: Path, changed: list[str], head: str,
                                              comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact bounded approval API failure diagnostic on PR #39."""
    path = FIRST_CUTOVER_APPROVAL_DIAGNOSTIC_MANIFEST
    manifest = _read_json(path)
    expected = {"deploy/first-cutover-approval-cli.py", "tests/test_first_cutover_approval.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 39 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("approval diagnostic certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("approval diagnostic changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"approval diagnostic certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led approval diagnostic certification is absent")
    cli = (repo / "deploy/first-cutover-approval-cli.py").read_text()
    tests = (repo / "tests/test_first_cutover_approval.py").read_text()
    if ("capture_output=True" not in cli or "GitHub approval API request failed at" not in cli
            or "owner-comment-read" not in cli or "deployment-receipt-read" not in cli
            or "deployment-receipt-create" not in cli
            or "test_api_failure_reports_bounded_endpoint_and_status" not in tests):
        errors.append("bounded approval API diagnostic changed")
    return errors


def verify_first_cutover_comment_scope(repo: Path, changed: list[str], head: str,
                                        comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact PR #40 read scope for the PR #18 owner comment."""
    path = FIRST_CUTOVER_COMMENT_SCOPE_MANIFEST
    manifest = _read_json(path)
    expected = {".github/workflows/scholarships-first-cutover.yml",
                "tests/test_first_cutover_approval.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 40 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("owner-comment scope certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("owner-comment scope changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"owner-comment scope certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led owner-comment scope certification is absent")
    workflow = (repo / ".github/workflows/scholarships-first-cutover.yml").read_text()
    tests = (repo / "tests/test_first_cutover_approval.py").read_text()
    if ("      pull-requests: read\n" not in workflow
            or "      issues: read\n" in workflow
            or "      deployments: write\n" not in workflow
            or "Consume one-use exact owner receipt before AWS OIDC" not in workflow
            or "test_workflow_uses_pull_request_read_for_owner_comment" not in tests):
        errors.append("fixed PR comment read permission boundary changed")
    return errors


def verify_first_cutover_owner_id(repo: Path, changed: list[str], head: str,
                                  comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact PR #41 owner identity binding for the one-use receipt."""
    path = FIRST_CUTOVER_OWNER_ID_MANIFEST
    manifest = _read_json(path)
    expected = {"deploy/first_cutover_approval.py", "tests/test_first_cutover_approval.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 41 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("owner ID certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("owner ID changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"owner ID certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led owner ID certification is absent")
    approval = (repo / "deploy/first_cutover_approval.py").read_text()
    tests = (repo / "tests/test_first_cutover_approval.py").read_text()
    if ("OWNER = {\"login\": \"SaurabhVermaIN\", \"id\": 52234089}" not in approval
            or "owner identity mismatch" not in approval
            or 'comment.get("author_association")' in approval
            or "approval issue mismatch" not in approval
            or "edited approval rejected" not in approval
            or "approval manifest differs" not in approval
            or "approval already consumed" not in approval
            or "test_exact_owner_id_is_authoritative_when_association_varies" not in tests):
        errors.append("fixed one-use owner identity boundary changed")
    return errors


def verify_first_cutover_recovery_inspect(repo: Path, changed: list[str], head: str,
                                           comments: list[dict[str, Any]]) -> list[str]:
    """Certify exact read-only inspection after the failed first cutover."""
    path = FIRST_CUTOVER_RECOVERY_INSPECT_MANIFEST
    manifest = _read_json(path)
    expected = {"deploy/first-recovery-inspect.sh",
                "deploy/compile-first-recovery-inspect-document.py",
                "deploy/scholarships-first-recovery-inspect-v1.json",
                "tests/test_first_recovery_inspect.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 42 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("recovery inspection certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("recovery inspection changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"recovery inspection certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led recovery inspection certification is absent")
    script = (repo / "deploy/first-recovery-inspect.sh").read_text()
    document = _read_json(repo / "deploy/scholarships-first-recovery-inspect-v1.json")
    steps = document.get("mainSteps", [])
    if (document.get("parameters") != {} or len(steps) != 1
            or steps[0].get("action") != "aws:runShellScript"
            or "ip-172-26-10-203.ap-south-1.compute.internal" not in script
            or "20261116T085246Z-355f465e4813" not in script
            or "rollback.sh\" --check" not in script
            or "rollback.sh\" --execute" in script
            or "RESTORE_APPROVAL=" in script
            or "test_read_only_host_and_release_boundary" not in
               (repo / "tests/test_first_recovery_inspect.py").read_text()):
        errors.append("fixed read-only recovery inspection boundary changed")
    return errors


def verify_first_cutover_recovery_root_cause(repo: Path, changed: list[str], head: str,
                                             comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact bounded second inspection of the failed health check."""
    path = FIRST_CUTOVER_RECOVERY_ROOT_CAUSE_MANIFEST
    manifest = _read_json(path)
    expected = {"deploy/first-recovery-inspect-v2.sh",
                "deploy/compile-first-recovery-inspect-document-v2.py",
                "deploy/scholarships-first-recovery-inspect-v2.json",
                "tests/test_first_recovery_inspect_v2.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 43 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("recovery root-cause certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("recovery root-cause changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"recovery root-cause certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led recovery root-cause certification is absent")
    script = (repo / "deploy/first-recovery-inspect-v2.sh").read_text()
    document = _read_json(repo / "deploy/scholarships-first-recovery-inspect-v2.json")
    steps = document.get("mainSteps", [])
    if (document.get("parameters") != {} or len(steps) != 1
            or steps[0].get("action") != "aws:runShellScript"
            or "ip-172-26-10-203.ap-south-1.compute.internal" not in script
            or "20261116T085246Z-355f465e4813" not in script
            or "rollback.sh\" --check" not in script
            or "rollback.sh\" --execute" in script
            or "run_migrations.php" in script
            or "runuser -u www-data -- test -r" not in script
            or "test_bounded_failure_window_and_worker_access" not in
               (repo / "tests/test_first_recovery_inspect_v2.py").read_text()):
        errors.append("fixed read-only root-cause inspection boundary changed")
    return errors


def verify_first_cutover_recovery_fpm_probe(repo: Path, changed: list[str], head: str,
                                            comments: list[dict[str, Any]]) -> list[str]:
    """Certify one fail-closed internal FPM GET while public maintenance stays active."""
    path = FIRST_CUTOVER_RECOVERY_FPM_PROBE_MANIFEST
    manifest = _read_json(path)
    expected = {"deploy/first-recovery-fastcgi-probe.py",
                "deploy/compile-first-recovery-fastcgi-document.py",
                "deploy/scholarships-first-recovery-inspect-v3.json",
                "tests/test_first_recovery_fastcgi_probe.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 44 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("internal FPM probe certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("internal FPM probe changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"internal FPM probe certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led internal FPM probe certification is absent")
    script = (repo / "deploy/first-recovery-fastcgi-probe.py").read_text()
    document = _read_json(repo / "deploy/scholarships-first-recovery-inspect-v3.json")
    steps = document.get("mainSteps", [])
    if (document.get("parameters") != {} or len(steps) != 1
            or steps[0].get("action") != "aws:runShellScript"
            or "ip-172-26-10-203.ap-south-1.compute.internal" not in script
            or "RewriteRule ^ - [R=503,L]" not in script
            or "database-backed sessions are enabled" not in script
            or "'REQUEST_METHOD': 'GET'" not in script
            or "'HTTP_COOKIE':" in script
            or "run_migrations.php" in script
            or "rollback.sh" in script
            or "test_fixed_request_has_no_cookie_or_input_and_captures_failure" not in
               (repo / "tests/test_first_recovery_fastcgi_probe.py").read_text()):
        errors.append("fixed internal FPM probe boundary changed")
    return errors


def verify_first_cutover_recovery_fpm_trace(repo: Path, changed: list[str], head: str,
                                            comments: list[dict[str, Any]]) -> list[str]:
    """Certify one private temporary trace of an internal FPM request."""
    path = FIRST_CUTOVER_RECOVERY_FPM_TRACE_MANIFEST
    manifest = _read_json(path)
    expected = {"deploy/first-recovery-fastcgi-probe-v4.py",
                "deploy/compile-first-recovery-fastcgi-document-v4.py",
                "deploy/scholarships-first-recovery-inspect-v4.json",
                "tests/test_first_recovery_fastcgi_probe_v4.py"}
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 45 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("internal FPM trace certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("internal FPM trace changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"internal FPM trace certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head, hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led internal FPM trace certification is absent")
    script = (repo / "deploy/first-recovery-fastcgi-probe-v4.py").read_text()
    document = _read_json(repo / "deploy/scholarships-first-recovery-inspect-v4.json")
    steps = document.get("mainSteps", [])
    if (document.get("parameters") != {} or len(steps) != 1
            or steps[0].get("action") != "aws:runShellScript"
            or "ip-172-26-10-203.ap-south-1.compute.internal" not in script
            or "RewriteRule ^ - [R=503,L]" not in script
            or "database-backed sessions are enabled" not in script
            or "TemporaryDirectory(" not in script
            or "debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 12)" not in script
            or "set_exception_handler" not in script
            or "FCGI_APP_STATUS=" not in script
            or "'REQUEST_METHOD': 'GET'" not in script
            or "'HTTP_COOKIE':" in script
            or "run_migrations.php" in script
            or "rollback.sh" in script
            or "test_one_request_cleans_temporary_tracer" not in
               (repo / "tests/test_first_recovery_fastcgi_probe_v4.py").read_text()):
        errors.append("fixed internal FPM trace boundary changed")
    return errors


def verify_first_cutover_public_assets(repo: Path, changed: list[str], head: str,
                                       comments: list[dict[str, Any]]) -> list[str]:
    """Certify only the exact backup-sourced public asset repair in PR #55."""
    path = FIRST_CUTOVER_PUBLIC_ASSETS_MANIFEST
    manifest = _read_json(path)
    expected = {
        "deploy/compile-first-recovery-public-assets-document.py",
        "deploy/first-recovery-public-assets.py",
        "deploy/public-assets-manifest.json",
        "deploy/scholarships-first-recovery-public-assets-v1.json",
        "tests/test_first_recovery_public_assets.py",
    }
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 55 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("public asset repair certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("public asset repair changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"public asset repair certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led public asset repair certification is absent")
    assets = _read_json(repo / "deploy/public-assets-manifest.json")
    prefixes = ("assets/ujjwal/images/", "assets/ujjwal/css/images/",
                "assets/home/images/", "assets/home/fonts/",
                "assets/plugins/fontawesome-free/", "assets/plugins/icheck-bootstrap/")
    if (not isinstance(assets, dict) or len(assets) != 36
            or any(not name.startswith(prefixes) or not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                   for name, digest in assets.items())):
        errors.append("public-only asset manifest boundary changed")
        return errors
    script = (repo / "deploy/first-recovery-public-assets.py").read_text()
    document = _read_json(repo / "deploy/scholarships-first-recovery-public-assets-v1.json")
    compiled = script.replace("__ASSET_MAP__", repr(assets))
    command = "set -eu\nprintf '%s' '" + base64.b64encode(compiled.encode()).decode() + "' | base64 -d | python3\n"
    key = "applications/scholarships/first-cutover/43713023653/application.tar.gz.part-0000"
    pattern = ("^https://synergie-production-app-backups-918870682888-ap-south-1"
               "[.]s3[.]ap-south-1[.]amazonaws[.]com/" + key.replace(".", "[.]")
               + "[?][A-Za-z0-9%_=&.~-]+$")
    params = document.get("parameters", {})
    steps = document.get("mainSteps", [])
    if (script.count("__ASSET_MAP__") != 1
            or "1uloEZmYt8h91r6zPAKA01ygteb_yCqx" not in script
            or "54121df892ad8103e4f2c62c1577e1c07083f82a88e9eb84b8eb4e2e644d195c" not in script
            or "ip-172-26-10-203.ap-south-1.compute.internal" not in script
            or "b1ccf807b3b3d2812f1b0958c513866c85691b64" not in script
            or "run_migrations.php" in script or "database.sql.gz" in script
            or not isinstance(params, dict) or set(params) != {"BackupUrl"}
            or params["BackupUrl"].get("interpolationType") != "ENV_VAR"
            or params["BackupUrl"].get("allowedPattern") != pattern
            or len(steps) != 1 or steps[0].get("action") != "aws:runShellScript"
            or steps[0].get("inputs", {}).get("runCommand") != [command]
            or "test_installation_and_partial_failure_cleanup" not in
               (repo / "tests/test_first_recovery_public_assets.py").read_text()):
        errors.append("fixed public asset restore execution boundary changed")
    return errors


def verify_landing_release(repo: Path, changed: list[str], head: str,
                           comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact fixed PHP 8.3 landing switch and rollback controls."""
    path = LANDING_RELEASE_MANIFEST
    manifest = _read_json(path)
    expected = {
        "deploy/LANDING_UI_RELEASE.md",
        "deploy/compile-first-landing-release-document.py",
        "deploy/compile-first-landing-rollback-document.py",
        "deploy/first-landing-release.py",
        "deploy/first-landing-rollback.py",
        "deploy/scholarships-first-landing-release-v1.json",
        "deploy/scholarships-first-landing-rollback-v1.json",
        "tests/test_first_landing_release.py",
    }
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 59 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("landing release certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("landing release changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"landing release certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led landing release certification is absent")
    for kind in ("release", "rollback"):
        compiler = repo / f"deploy/compile-first-landing-{kind}-document.py"
        document = repo / f"deploy/scholarships-first-landing-{kind}-v1.json"
        result = subprocess.run(["python3", str(compiler)], cwd=repo,
                                capture_output=True, check=False)
        if (result.returncode != 0 or result.stdout != document.read_bytes()
                or _read_json(document).get("parameters") != {}):
            errors.append(f"fixed landing {kind} document differs from compiler")
    release = (repo / "deploy/first-landing-release.py").read_text()
    rollback = (repo / "deploy/first-landing-rollback.py").read_text()
    if ("DATABASE_MIGRATIONS=NOT_RUN" not in release
            or "DATABASE_MIGRATIONS=NOT_RUN" not in rollback
            or "run_migrations" in release + rollback
            or "mysql" in release.lower() + rollback.lower()
            or "NEW_FILES = json.loads" not in release
            or "LANDING_UI_REVERTED=yes" not in release
            or "LANDING_UI_ROLLED_BACK=yes" not in rollback):
        errors.append("fixed landing UI-only or rollback boundary changed")
    return errors


def verify_validator_asset(repo: Path, changed: list[str], head: str,
                           comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact, single-file validator recovery from a verified backup."""
    path = VALIDATOR_ASSET_MANIFEST
    manifest = _read_json(path)
    expected = {
        "deploy/VALIDATOR_ASSET_RESTORE.md",
        "deploy/compile-first-recovery-validator-document.py",
        "deploy/first-recovery-validator-asset.py",
        "deploy/scholarships-first-recovery-validator-v1.json",
        "tests/test_first_recovery_validator_asset.py",
    }
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 60 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("validator recovery certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("validator recovery changed-file scope changed")
        return errors
    for rel, file_hash in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(file_hash))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != file_hash):
            errors.append(f"validator recovery certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led validator recovery certification is absent")
    compiler = repo / "deploy/compile-first-recovery-validator-document.py"
    document = repo / "deploy/scholarships-first-recovery-validator-v1.json"
    result = subprocess.run(["python3", str(compiler)], cwd=repo,
                            capture_output=True, check=False)
    parsed = _read_json(document)
    steps = parsed.get("mainSteps", [])
    params = parsed.get("parameters", {})
    source = (repo / "deploy/first-recovery-validator-asset.py").read_text()
    if (result.returncode != 0 or result.stdout != document.read_bytes()
            or set(params) != {"BackupUrl"}
            or params["BackupUrl"].get("interpolationType") != "ENV_VAR"
            or len(steps) != 1 or steps[0].get("action") != "aws:runShellScript"
            or "BACKUP_VERSION = '1uloEZmYt8h91r6zPAKA01ygteb_yCqx'" not in source
            or "MEMBER = 'public_html/' + ASSET" not in source
            or "OLD_INDEX_SHA = '4c0b7d52e5206827c772ac531b4aaf073921e66dd24b0eaecf644a14a99a78f5'" not in source
            or "NEW_INDEX_SHA = '9f360d8b694f63b3f986eeefb089d968ff504ccdfda96593cc80d480ca127b01'" not in source
            or "CSS_SHA = 'f24ccfb5e3ae910e1b72f64dbbac993dbc2e3bbfc0c4d8d179e60e96374504dd'" not in source
            or "def patch_stylesheet_reference(release):" not in source
            or "DATABASE_MIGRATIONS=NOT_RUN" not in source
            or "def public_health(expected):" not in source
            or "run_migrations" in source or "mysql" in source.lower()):
        errors.append("fixed validator backup or execution boundary changed")
    return errors


def verify_first_cutover_existing_fonts(repo: Path, changed: list[str], head: str,
                                       comments: list[dict[str, Any]]) -> list[str]:
    """Certify only PR #56's correction for exact existing public fonts."""
    path = FIRST_CUTOVER_EXISTING_FONTS_MANIFEST
    manifest = _read_json(path)
    expected = {
        "deploy/first-recovery-public-assets.py",
        "deploy/scholarships-first-recovery-public-assets-v1.json",
        "tests/test_first_recovery_public_assets.py",
    }
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 56 or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("existing-font correction certification identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("existing-font correction changed-file scope changed")
        return errors
    for rel, digest in files.items():
        file = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not file.is_file() or file.is_symlink() or file.stat().st_size > 1_000_000
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            errors.append(f"existing-font correction certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(path.read_bytes()).hexdigest()):
        errors.append("owner-led existing-font correction certification is absent")
    script = (repo / "deploy/first-recovery-public-assets.py").read_text()
    assets = _read_json(repo / "deploy/public-assets-manifest.json")
    document = _read_json(repo / "deploy/scholarships-first-recovery-public-assets-v1.json")
    compiled = script.replace("__ASSET_MAP__", repr(assets))
    command = "set -eu\nprintf '%s' '" + base64.b64encode(compiled.encode()).decode() + "' | base64 -d | python3\n"
    if (script.count("__ASSET_MAP__") != 1
            or "directory == 'assets/home/fonts'" not in script
            or "existing public font differs from verified backup" not in script
            or "not file.is_symlink()" not in script
            or "installed.append(target)" not in script
            or "run_migrations.php" in script or "database.sql.gz" in script
            or document.get("mainSteps", [{}])[0].get("inputs", {}).get("runCommand") != [command]
            or "test_exact_existing_fonts_are_preserved_and_changed_fonts_rejected" not in
               (repo / "tests/test_first_recovery_public_assets.py").read_text()):
        errors.append("fixed existing-font correction boundary changed")
    return errors


def verify_first_cutover_ssm_repair(repo: Path, changed: list[str], head: str,
                                    comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact POSIX wrapper and version-2 document repair in PR #21."""
    manifest = _read_json(FIRST_CUTOVER_SSM_REPAIR_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 21
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover SSM repair identity changed")
    names = ("backup", "upload", "restore", "cutover")
    expected = ({f"deploy/compile-first-{name}-document.py" for name in names}
                | {f"deploy/scholarships-first-{name}-command-v1.json" for name in names}
                | {".github/workflows/scholarships-first-cutover-prepare.yml",
                   ".github/workflows/scholarships-first-cutover.yml",
                   "deploy/FIRST_CUTOVER_ACTIVATION.md", "tests/test_first_cutover_approval.py"})
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover SSM repair changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover SSM repair certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_SSM_REPAIR_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover SSM repair certification is absent")
    for name in names:
        compiler = (repo / f"deploy/compile-first-{name}-document.py").read_text()
        document = _read_json(repo / f"deploy/scholarships-first-{name}-command-v1.json")
        steps = document.get("mainSteps", [])
        command = (steps[0].get("inputs", {}).get("runCommand", [""])[0]
                   if len(steps) == 1 else "")
        if ("set -eu" not in compiler or "set -euo pipefail" in compiler
                or not command.startswith("set -eu\n")
                or steps[0].get("action") != "aws:runShellScript"
                or "Commands" in document.get("parameters", {})):
            errors.append(f"first-cutover {name} wrapper is not fixed and POSIX compatible")
    for name in ("scholarships-first-cutover-prepare.yml", "scholarships-first-cutover.yml"):
        workflow = (repo / ".github/workflows" / name).read_text()
        if ("environment: production" not in workflow or "refs/heads/main" not in workflow
                or "--document-version 2" not in workflow):
            errors.append(f"first-cutover version-2 workflow boundary changed: {name}")
    return errors


def verify_first_cutover_followup(repo: Path, changed: list[str], head: str,
                                  comments: list[dict[str, Any]]) -> list[str]:
    """Certify the exact three-file PR #20 repair to the first cutover."""
    manifest = _read_json(FIRST_CUTOVER_FOLLOWUP_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 20
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover follow-up identity changed")
    files = manifest.get("files")
    expected = {".github/workflows/scholarships-first-cutover-prepare.yml",
                "deploy/first_cutover_approval.py", "tests/test_first_cutover_approval.py"}
    if not isinstance(files, dict) or set(files) != expected or set(changed) != expected:
        errors.append("first-cutover follow-up changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover follow-up certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_FOLLOWUP_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover follow-up certification is absent")
    prepare = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    approval = (repo / "deploy/first_cutover_approval.py").read_text()
    if ("environment: production" not in prepare or "refs/heads/main" not in prepare
            or "git merge-base --is-ancestor" not in prepare
            or "environments/production" in prepare):
        errors.append("backup preparation execution boundary changed")
    if ("approval already consumed" not in approval
            or "receipt no longer uniquely belongs to this run" not in approval
            or "APPROVAL_ISSUE = 18" not in approval
            or "environments/production" in approval):
        errors.append("one-use owner receipt boundary changed")
    return errors


def verify_first_cutover(repo: Path, changed: list[str], head: str,
                         comments: list[dict[str, Any]]) -> list[str]:
    """Certify one exact PR #19 byte set without changing recurring Gate D."""
    manifest = _read_json(FIRST_CUTOVER_MANIFEST)
    errors: list[str] = []
    if (manifest.get("repository") != "Synergie-ITCI/scholarships"
            or manifest.get("pr_number") != 19
            or manifest.get("head_sha") != head
            or manifest.get("technical_certification_owner") != "SaurabhVermaIN"
            or manifest.get("removed_paths") != []):
        errors.append("first-cutover identity or removed-path inventory changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(changed) != set(files):
        errors.append("first-cutover changed-file scope changed")
        return errors
    for rel, digest in files.items():
        path = repo / rel
        if (not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts
                or not re.fullmatch(r"[0-9a-f]{64}", str(digest))
                or not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"first-cutover certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, "SaurabhVermaIN", head,
                            hashlib.sha256(FIRST_CUTOVER_MANIFEST.read_bytes()).hexdigest()):
        errors.append("owner-led first-cutover technical certification is absent")

    prepare = (repo / ".github/workflows/scholarships-first-cutover-prepare.yml").read_text()
    cutover = (repo / ".github/workflows/scholarships-first-cutover.yml").read_text()
    approval = (repo / "deploy/first_cutover_approval.py").read_text()
    if not all(token in prepare for token in (
            "refs/heads/main", "environment: production", "aws ssm send-command",
            "scholarships-first-cutover", "verified-receipt.json")):
        errors.append("first-cutover backup preparation workflow boundary changed")
    approval_at = cutover.find("python3 deploy/first-cutover-approval-cli.py consume")
    oidc_at = cutover.find("aws-actions/configure-aws-credentials")
    send_at = cutover.find("aws ssm send-command")
    if (min(approval_at, oidc_at, send_at) < 0 or not approval_at < oidc_at < send_at
            or "refs/heads/main" not in cutover or "environment: production" not in cutover
            or "Scholarships-First-Cutover-v1" not in cutover):
        errors.append("first-cutover approval, OIDC or fixed SSM execution order changed")
    if not all(token in approval for token in (
            "APPROVAL_ISSUE = 18", "run_attempt == \"1\"", "native reviewer protection exists",
            "approval already consumed", "receipt no longer uniquely belongs to this run")):
        errors.append("first-cutover one-use owner approval boundary changed")
    expected = {
        "scholarships-first-backup-role-policy-v1.json": {
            "Scholarships-First-Backup-v1", "Scholarships-First-Upload-v1",
            "Scholarships-First-Restore-v1"},
        "scholarships-first-cutover-role-policy-v1.json": {"Scholarships-First-Cutover-v1"},
    }
    host = f"arn:aws:ssm:ap-south-1:{ACCOUNT}:managed-instance/{HOST}"
    for name, documents in expected.items():
        policy = _read_json(repo / "deploy" / name)
        resources = _send_resources(policy)
        if (resources != {host} | {f"arn:aws:ssm:ap-south-1:{ACCOUNT}:document/{item}"
                                     for item in documents} or not _has_generic_deny(policy)):
            errors.append(f"first-cutover IAM SendCommand scope changed: {name}")
    for name in ("backup", "cutover"):
        if not _role_trust_is_bound(_read_json(repo / f"deploy/scholarships-first-{name}-trust-v1.json")):
            errors.append(f"first-cutover OIDC binding changed: {name}")
    for name in ("backup", "upload", "restore", "cutover"):
        document = _read_json(repo / f"deploy/scholarships-first-{name}-command-v1.json")
        if document.get("schemaVersion") != "2.2" or len(document.get("mainSteps", [])) != 1:
            errors.append(f"first-cutover fixed SSM document changed: {name}")
    if "AWS-RunShellScript" in prepare + cutover:
        errors.append("generic SSM shell used in first-cutover workflows")
    return errors


def verify(repo: Path, changed: list[str], head: str, pr_number: int,
           comments: list[dict[str, Any]], controlled_workflow: bool) -> list[str]:
    errors: list[str] = []
    manifest_path = {7: MAIN_PROMOTION_MANIFEST, 13: PROMOTION_MANIFEST}.get(pr_number, MANIFEST)
    manifest = _read_json(manifest_path)
    files = manifest["files"]
    if manifest.get("repository") != "Synergie-ITCI/scholarships" or manifest.get("pr_number") != pr_number or pr_number not in (7, 13, 15):
        errors.append("certified repository or PR identity changed")
    if head != manifest["head_sha"]:
        errors.append("certified exact PR head changed")
    if set(changed) != set(files):
        errors.append("certified changed-file scope changed")
    removed = manifest.get("removed_paths", [])
    if (not isinstance(removed, list) or (pr_number in (7, 13) and "removed_paths" not in manifest)
            or (pr_number == 13 and not removed) or (pr_number == 7 and removed)):
        errors.append("certified removed-file inventory is absent")
        removed = []
    for rel in removed:
        if (not isinstance(rel, str) or Path(rel).is_absolute()
                or ".." in Path(rel).parts or rel in files or (repo / rel).exists()
                or (repo / rel).is_symlink()):
            errors.append(f"certified removed file changed: {rel}")
    for rel, digest in files.items():
        path = repo / rel
        if (not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"certified file changed: {rel}")
    if errors:
        return errors
    if not _owner_certified(comments, manifest["technical_certification_owner"], head,
                            hashlib.sha256(manifest_path.read_bytes()).hexdigest()):
        errors.append("owner-led technical certification of exact PR head is absent")
    if not controlled_workflow:
        errors.append("approved controlled Gate D workflow shape is absent")

    workflow = (repo / ".github/workflows/scholarships-gate-d-release.yml").read_text()
    required_order = [
        "python3 deploy/gate-d-approval.py", CERTIFIER_ROLE,
        "id: runtime_certifier", RELEASE_ROLE, "aws ssm send-command",
    ]
    positions = [workflow.find(item) for item in required_order]
    if -1 in positions or positions != sorted(positions):
        errors.append("approval, certifier, credentials and release execution order changed")
    if workflow.count("if: steps.runtime_certifier.outputs.deployment-required == 'true'") < 3:
        errors.append("runtime deployment guard missing")
    if workflow.find("aws-actions/configure-aws-credentials") < workflow.find("python3 deploy/gate-d-approval.py"):
        errors.append("AWS credentials precede run-bound approval")
    approval_digest = hashlib.sha256((repo / "deploy/gate-d-approval.py").read_bytes()).hexdigest()
    if f"{approval_digest} deploy/gate-d-approval.py | sha256sum -c" not in workflow:
        errors.append("reviewed approval verifier digest is not pinned")
    if "runtime-certifier@runtime-certifier-action-v1.10" not in workflow:
        errors.append("immutable Runtime Certifier action changed")
    if "environment: production" not in workflow or "refs/heads/main" not in workflow:
        errors.append("production environment or protected-main binding changed")
    if "AWS-RunShellScript" in workflow:
        errors.append("generic SSM shell used by release workflow")
    if "Document.DefaultVersion --output text)\" = 1" not in workflow or "Document.LatestVersion --output text)\" = 1" not in workflow:
        errors.append("runtime certifier SSM document version is not fixed")

    arn = f"arn:aws:ssm:ap-south-1:{ACCOUNT}:"
    host = arn + f"managed-instance/{HOST}"
    for name, document in (("certifier", CERTIFIER_DOCUMENT), ("role", RELEASE_DOCUMENT)):
        policy = _read_json(repo / f"deploy/scholarships-gate-d-{name}-role-policy-v1.json") if name == "certifier" else _read_json(repo / "deploy/scholarships-gate-d-role-policy-v1.json")
        if _send_resources(policy) != {host, arn + f"document/{document}"} or not _has_generic_deny(policy):
            errors.append(f"{name} IAM SendCommand scope changed")
    for rel in ("certifier-trust", "trust"):
        if not _role_trust_is_bound(_read_json(repo / f"deploy/scholarships-gate-d-{rel}-v1.json")):
            errors.append(f"{rel} OIDC binding changed")
    environment = _read_json(repo / "deploy/github-production-environment-v1.json")
    if environment.get("reviewers") != [{"type": "User", "id": 52234089}]:
        errors.append("owner production reviewer changed")
    if not environment.get("deployment_branch_policy", {}).get("protected_branches"):
        errors.append("protected branch environment restriction changed")

    release_doc = _read_json(repo / "deploy/scholarships-gate-d-production-command-v1.json")
    cert_doc = _read_json(repo / "deploy/scholarships-gate-d-runtime-certifier-v1.json")
    if not _document_is_fixed(cert_doc, {"DeployRef", "RollbackRef"},
                              (repo / "deploy/ssm-runtime-certifier.sh").read_bytes()):
        errors.append("read-only certifier document or parameters changed")
    # The release document embeds both fixed scripts; its compiler and output
    # are independently reviewed and immutable-hashed above. It must expose
    # only the approved typed parameters, never an arbitrary command.
    if not _release_document_matches(
        release_doc, (repo / "deploy/production-release.sh").read_bytes(),
        (repo / "deploy/ssm-bootstrap.sh").read_bytes(),
    ):
        errors.append("release document command, checksum or parameter boundary changed")
    release_script = (repo / "deploy/production-release.sh").read_text()
    if not all(marker in release_script for marker in (
        "--backup-only", "gzip -t", "sha256sum", "private_paths=", "public_html",
    )):
        errors.append("release backup or private-document preconditions changed")
    cert_script = (repo / "deploy/ssm-runtime-certifier.sh").read_text()
    if not all(marker in cert_script for marker in (
        "php8.3-fpm.sock", "apache2ctl -S", "proxy_fcgi_module",
        "PRODUCTION_MUTATED=NO", "DEPLOY_STATE=READY_FROM_ROLLBACK",
    )):
        errors.append("read-only serving-runtime certification changed")
    if re.search(r"(?m)^\s*(?:aws ssm send-command|ssh )", cert_script):
        errors.append("runtime certification contains remote execution")
    return errors
