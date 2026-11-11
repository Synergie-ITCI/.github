"""One reviewed Scholarships Gate D release contract for an exact PR head.

This does not approve deployment. Any changed file, missing independent
security review, or weakened execution boundary invalidates certification.
"""

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any


MANIFEST = Path(__file__).resolve().parents[1] / "policy/scholarships-pr15-gate-d.json"
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


def _latest_exact_head_security_review(reviews: list[dict[str, Any]], reviewer: str, head: str) -> bool:
    own = [r for r in reviews if isinstance(r, dict)
           and (r.get("user") or {}).get("login") == reviewer]
    marker = f"SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED={head}"
    return bool(own and own[-1].get("state") == "APPROVED"
                and own[-1].get("commit_id") == head
                and marker in str(own[-1].get("body") or "").splitlines())


def verify(repo: Path, changed: list[str], head: str, pr_number: int,
           reviews: list[dict[str, Any]], controlled_workflow: bool) -> list[str]:
    errors: list[str] = []
    manifest = _read_json(MANIFEST)
    files = manifest["files"]
    if manifest.get("repository") != "Synergie-ITCI/scholarships" or manifest.get("pr_number") != pr_number or pr_number != 15:
        errors.append("certified repository or PR identity changed")
    if head != manifest["head_sha"]:
        errors.append("certified exact PR head changed")
    if set(changed) != set(files):
        errors.append("certified changed-file scope changed")
    for rel, digest in files.items():
        path = repo / rel
        if (not path.is_file() or path.is_symlink() or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            errors.append(f"certified file changed: {rel}")
    if errors:
        return errors
    if not _latest_exact_head_security_review(reviews, manifest["required_security_reviewer"], head):
        errors.append("independent security review of exact PR head is absent")
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
