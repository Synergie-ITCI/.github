"""Fail-closed staging audit decision from the active central governance release."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from mobile_bundle_evidence import collect

REPOSITORY = "Synergie-ITCI/programme-management-platform"
MANIFEST = "fieldzilla-otp-staging-mobile-audit.json"
DEPENDENCIES = {"apps/mobile/package.json", "apps/mobile/package-lock.json"}
ADVISORY = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
SEVERITY = {"low": 1, "moderate": 2, "high": 3, "critical": 4}


def command(
    *args: str, cwd: Path | None = None, allow_audit_failure: bool = False
) -> str:
    result = subprocess.run(args, cwd=cwd, check=False, capture_output=True, text=True)
    if result.returncode != 0 and not (
        allow_audit_failure
        and args == ("npm", "audit", "--json")
        and result.returncode == 1
    ):
        raise subprocess.CalledProcessError(result.returncode, args)
    return result.stdout


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def script_digest(script: str) -> str:
    return hashlib.sha256(script.encode("utf-8")).hexdigest()


def advisories(report: dict) -> list[dict[str, str]]:
    vulnerabilities = report["vulnerabilities"]
    if not isinstance(vulnerabilities, dict) or not vulnerabilities:
        raise ValueError("Audit vulnerability set is empty or invalid")
    findings: list[dict[str, str]] = []
    for package, vulnerability in vulnerabilities.items():
        for via in vulnerability["via"]:
            if not isinstance(via, dict):
                continue
            identifier = via["url"].rsplit("/", 1)[-1]
            if not ADVISORY.fullmatch(identifier):
                raise ValueError("Invalid advisory identity")
            findings.append(
                {
                    "package": package,
                    "id": identifier,
                    "severity": via["severity"],
                    "range": via["range"],
                }
            )
    return sorted(findings, key=lambda item: (item["package"], item["id"]))


def github_names(endpoint: str, key: str) -> set[str]:
    data = json.loads(
        command("gh", "api", f"repos/{REPOSITORY}/{endpoint}?per_page=100")
    )
    if not isinstance(data, list) or len(data) >= 100:
        raise ValueError("Release state is incomplete")
    names = {item[key] for item in data}
    if not all(isinstance(name, str) and name for name in names):
        raise ValueError("Release state is invalid")
    return names


def check_advisory_subset(
    observed: list[dict[str, str]], approved: list[dict[str, str]]
) -> None:
    allowed = {(item["package"], item["id"]): item for item in approved}
    if len(allowed) != len(approved) or not allowed:
        raise ValueError("Approved advisory set is invalid")
    for item in observed:
        reference = allowed.get((item["package"], item["id"]))
        if reference is None:
            raise ValueError("New mobile advisory is outside exception")
        if (
            item["severity"] not in SEVERITY
            or reference["severity"] not in SEVERITY
            or SEVERITY[item["severity"]] > SEVERITY[reference["severity"]]
            or item["range"] != reference["range"]
        ):
            raise ValueError("Mobile advisory severity or affected range increased")


def validate(repo: Path, central: Path, head: str) -> dict:
    if central.resolve() != (repo / ".pr-qa-framework").resolve():
        raise ValueError("Exception must come from the central governance checkout")
    release = os.environ.get("ACTIVE_CENTRAL_RELEASE", "")
    if not re.fullmatch(r"pr-qa-v1-rc[1-9][0-9]*", release):
        raise ValueError("Active central governance release is unavailable")
    if (
        command("git", "remote", "get-url", "origin", cwd=central).strip()
        not in {
            "https://github.com/Synergie-ITCI/.github",
            "https://github.com/Synergie-ITCI/.github.git",
        }
        or command("git", "rev-parse", "HEAD", cwd=central).strip()
        != command(
            "git", "rev-parse", f"refs/tags/{release}^{{commit}}", cwd=central
        ).strip()
    ):
        raise ValueError("Central checkout does not match the immutable release")
    manifest_file = central / "policy/exceptions" / MANIFEST
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    evidence = manifest_file.parent / manifest["evidence_file"]
    if not evidence.is_file() or digest(evidence) != manifest["evidence_sha256"]:
        raise ValueError("Governance evidence missing or changed")
    if (
        os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_REF") != "refs/heads/staging"
        or os.environ.get("GITHUB_SHA") != head
        or os.environ.get("FIELDZILLA_RELEASE_ENVIRONMENT") != "staging"
        or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
        or manifest["repository"] != REPOSITORY
        or manifest["environment"] != "staging"
        or manifest["workflow"] != "staging-deploy.yml"
        or "head_sha" in manifest
        or command("git", "rev-parse", "HEAD", cwd=repo).strip() != head
        or command("git", "ls-files", "--", "policy/exceptions", cwd=repo).strip()
        or command("git", "ls-files", "--", ".pr-qa-framework", cwd=repo).strip()
    ):
        raise ValueError("Staging scope, exact head, or central ownership mismatch")
    if not all(
        manifest.get(key)
        for key in (
            "exception_id",
            "approver",
            "approved_at",
            "reason",
            "residual_risk",
            "remediation_owner",
        )
    ):
        raise ValueError("Governance approval is incomplete")
    expiry = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) >= expiry:
        raise ValueError("Governance exception expired")
    if set(manifest["dependency_sha256"]) != DEPENDENCIES or any(
        digest(repo / name) != expected
        for name, expected in manifest["dependency_sha256"].items()
    ):
        raise ValueError("Mobile dependency files changed")
    package = json.loads(
        (repo / "apps/mobile/package.json").read_text(encoding="utf-8")
    )
    audit_script = package.get("scripts", {}).get("audit:ci")
    if (
        audit_script != "npm audit --audit-level=high"
        or script_digest(audit_script) != manifest["audit_script_sha256"]
    ):
        raise ValueError("Mobile audit command changed")
    if github_names("tags", "name") != set(manifest["baseline_tags"]) or github_names(
        "releases", "tag_name"
    ) != set(manifest["baseline_releases"]):
        raise ValueError("New release or tag voids exception")
    audit = json.loads(
        command(
            "npm", "audit", "--json", cwd=repo / "apps/mobile", allow_audit_failure=True
        )
    )
    observed = advisories(audit)
    check_advisory_subset(observed, manifest["advisories"])
    covered = {item["package"] for item in manifest["advisories"]}
    expected_bundle_evidence = collect(repo, head, covered)
    bundle_file = repo / "staging-mobile-bundle-evidence/bundle-evidence.json"
    recorded_bundle_evidence = json.loads(bundle_file.read_text(encoding="utf-8"))
    if recorded_bundle_evidence != expected_bundle_evidence:
        raise ValueError("Per-SHA release bundle evidence is missing or changed")
    if any(
        item["covered_present"]
        for item in expected_bundle_evidence["platforms"].values()
    ):
        raise ValueError("Exception-covered package appears in a release JS bundle")
    return {
        "decision": "time-boxed exception; audit remains vulnerable",
        "exception_id": manifest["exception_id"],
        "repository": REPOSITORY,
        "environment": "staging",
        "staging_sha": head,
        "workflow_run_id": os.environ["GITHUB_RUN_ID"],
        "approver": manifest["approver"],
        "remediation_owner": manifest["remediation_owner"],
        "expires_at": manifest["expires_at"],
        "advisories": observed,
        "bundle_check": {
            platform: {
                "bundle_sha256": item["bundle_sha256"],
                "source_map_sha256": item["source_map_sha256"],
                "module_count": item["module_count"],
                "covered_present": item["covered_present"],
            }
            for platform, item in expected_bundle_evidence["platforms"].items()
        },
        "audit_metadata": audit.get("metadata", {}).get("vulnerabilities", {}),
    }


def main() -> int:
    if len(sys.argv) != 4:
        return 1
    try:
        result = validate(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
        Path("staging-mobile-audit-exception.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        print(
            "Mobile audit failed; exact-scope central exception accepted with residual build risk"
        )
        return 0
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"Mobile audit remains blocking: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
