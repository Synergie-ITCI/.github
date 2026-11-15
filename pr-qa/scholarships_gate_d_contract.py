"""Reviewed Scholarships Gate D release contracts for exact PR heads.

This does not approve deployment. Any changed file, missing owner-led
technical certification, or weakened execution boundary invalidates certification.
"""

import base64
import hashlib
import json
import re
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
