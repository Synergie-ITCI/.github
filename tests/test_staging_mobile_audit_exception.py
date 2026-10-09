"""Exercise the staging mobile exception's dependency and per-SHA bundle gates."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
import mobile_bundle_evidence as bundles
import staging_mobile_audit_exception as exception

FINDING = {
    "package": "braces",
    "id": "GHSA-aaaa-bbbb-cccc",
    "severity": "high",
    "range": "<2",
}
SECOND = {
    "package": "shell-quote",
    "id": "GHSA-dddd-eeee-ffff",
    "severity": "critical",
    "range": "<3",
}


@pytest.fixture
def case(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    head = "a" * 40
    repo = tmp_path / "repo"
    central = repo / ".pr-qa-framework"
    mobile = repo / "apps/mobile"
    mobile.mkdir(parents=True)
    exceptions = central / "policy/exceptions"
    exceptions.mkdir(parents=True)
    script = "npm audit --audit-level=high"
    (mobile / "package.json").write_text(json.dumps({"scripts": {"audit:ci": script}}))
    (mobile / "package-lock.json").write_text("lock")
    evidence = exceptions / "evidence.md"
    evidence.write_text("approved dependency evidence")
    manifest = {
        "repository": exception.REPOSITORY,
        "environment": "staging",
        "workflow": "staging-deploy.yml",
        "exception_id": "test-staging-tooling",
        "approver": "Approver",
        "approved_at": "2026-10-09T00:00:00Z",
        "reason": "Reviewed dependency evidence",
        "residual_risk": "Build tools remain vulnerable",
        "remediation_owner": "Mobile Platform Lead",
        "expires_at": "2099-01-01T00:00:00Z",
        "evidence_file": evidence.name,
        "evidence_sha256": exception.digest(evidence),
        "dependency_sha256": {
            name: exception.digest(repo / name) for name in exception.DEPENDENCIES
        },
        "audit_script_sha256": exception.script_digest(script),
        "baseline_tags": ["baseline"],
        "baseline_releases": [],
        "advisories": [FINDING.copy(), SECOND.copy()],
    }
    manifest_file = exceptions / exception.MANIFEST

    def save() -> None:
        manifest_file.write_text(json.dumps(manifest))

    def bundle(head_sha: str, *, sources: list[str] | None = None) -> None:
        directory = repo / "staging-mobile-bundle-evidence"
        directory.mkdir(exist_ok=True)
        modules = sources or ["../node_modules/safe-package/index.js", "src/App.tsx"]
        for platform in bundles.PLATFORMS:
            (directory / f"{platform}.bundle").write_text("release bundle")
            (directory / f"{platform}.map").write_text(
                json.dumps({"version": 3, "sources": modules})
            )
        recorded = bundles.collect(repo, head_sha, {"braces", "shell-quote"})
        (directory / "bundle-evidence.json").write_text(json.dumps(recorded))

    audit = {"findings": [FINDING.copy(), SECOND.copy()]}
    tracked = {"paths": ""}

    def report() -> dict:
        return {
            "vulnerabilities": {
                item["package"]: {
                    "via": [
                        {
                            "url": "https://github.com/advisories/" + item["id"],
                            "severity": item["severity"],
                            "range": item["range"],
                        }
                    ]
                }
                for item in audit["findings"]
            }
        }

    def command(*args: str, cwd: Path | None = None, **kwargs: object) -> str:
        if args[:3] == ("npm", "audit", "--json"):
            return json.dumps(report())
        if args[:3] == ("git", "remote", "get-url") and cwd == central:
            return "https://github.com/Synergie-ITCI/.github"
        if args[:2] == ("git", "rev-parse") and cwd == central:
            return "c" * 40
        if args[:3] == ("git", "rev-parse", "HEAD") and cwd == repo:
            return os.environ["GITHUB_SHA"]
        if args[:2] == ("git", "ls-files") and cwd == repo:
            return tracked["paths"]
        raise AssertionError((args, cwd))

    release_state = {"tags": {"baseline"}, "releases": set()}
    monkeypatch.setattr(exception, "command", command)
    monkeypatch.setattr(
        exception, "github_names", lambda endpoint, key: release_state[endpoint]
    )
    monkeypatch.setenv("GITHUB_REPOSITORY", exception.REPOSITORY)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/staging")
    monkeypatch.setenv("GITHUB_SHA", head)
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("FIELDZILLA_RELEASE_ENVIRONMENT", "staging")
    monkeypatch.setenv("ACTIVE_CENTRAL_RELEASE", "pr-qa-v1-rc175")
    save()
    bundle(head)
    return SimpleNamespace(
        repo=repo,
        central=central,
        mobile=mobile,
        manifest=manifest,
        save=save,
        bundle=bundle,
        audit=audit,
        evidence=evidence,
        release_state=release_state,
        tracked=tracked,
        head=head,
    )


def test_one_dependency_approval_covers_two_verified_shas_and_reduced_findings(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = exception.validate(case.repo, case.central, case.head)
    assert first["staging_sha"] == case.head
    assert first["workflow_run_id"] == "12345"
    assert first["exception_id"] == "test-staging-tooling"
    assert set(first["bundle_check"]) == {"android", "ios"}
    next_head = "b" * 40
    monkeypatch.setenv("GITHUB_SHA", next_head)
    case.bundle(next_head)
    case.audit["findings"] = [FINDING.copy()]
    second = exception.validate(case.repo, case.central, next_head)
    assert second["advisories"] == [FINDING]
    assert second["staging_sha"] == next_head


def test_changed_lockfile_or_audit_script_fails(case: SimpleNamespace) -> None:
    (case.mobile / "package-lock.json").write_text("changed")
    with pytest.raises(ValueError, match="dependency files changed"):
        exception.validate(case.repo, case.central, case.head)
    (case.mobile / "package-lock.json").write_text("lock")
    (case.mobile / "package.json").write_text(
        json.dumps({"scripts": {"audit:ci": "echo audit"}})
    )
    case.manifest["dependency_sha256"]["apps/mobile/package.json"] = exception.digest(
        case.mobile / "package.json"
    )
    case.save()
    with pytest.raises(ValueError, match="audit command changed"):
        exception.validate(case.repo, case.central, case.head)


@pytest.mark.parametrize("change", ["new", "upgrade"])
def test_new_or_severity_upgraded_advisory_fails(
    case: SimpleNamespace, change: str
) -> None:
    if change == "new":
        case.audit["findings"].append(
            {
                "package": "another",
                "id": "GHSA-gggg-hhhh-iiii",
                "severity": "high",
                "range": "<4",
            }
        )
    else:
        case.audit["findings"][0]["severity"] = "critical"
    with pytest.raises(ValueError, match="advisory"):
        exception.validate(case.repo, case.central, case.head)


def test_missing_or_vulnerable_bundle_fails(case: SimpleNamespace) -> None:
    (case.repo / "staging-mobile-bundle-evidence/bundle-evidence.json").unlink()
    with pytest.raises(FileNotFoundError):
        exception.validate(case.repo, case.central, case.head)
    case.bundle(case.head)
    (case.repo / "staging-mobile-bundle-evidence/ios.map").unlink()
    with pytest.raises(ValueError, match="source map is missing"):
        exception.validate(case.repo, case.central, case.head)
    case.bundle(case.head, sources=["../node_modules/braces/index.js"])
    with pytest.raises(ValueError, match="appears in a release JS bundle"):
        exception.validate(case.repo, case.central, case.head)


def test_non_fieldzilla_or_production_scope_fails(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "another/repository")
    with pytest.raises(ValueError, match="scope"):
        exception.validate(case.repo, case.central, case.head)
    monkeypatch.setenv("GITHUB_REPOSITORY", exception.REPOSITORY)
    monkeypatch.setenv("FIELDZILLA_RELEASE_ENVIRONMENT", "production")
    with pytest.raises(ValueError, match="scope"):
        exception.validate(case.repo, case.central, case.head)


def test_expiry_release_unavailable_and_missing_evidence_fail(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    case.manifest["expires_at"] = "2000-01-01T00:00:00Z"
    case.save()
    with pytest.raises(ValueError, match="expired"):
        exception.validate(case.repo, case.central, case.head)
    case.manifest["expires_at"] = "2099-01-01T00:00:00Z"
    case.save()
    monkeypatch.setattr(
        exception,
        "github_names",
        lambda endpoint, key: (_ for _ in ()).throw(ValueError("unavailable")),
    )
    with pytest.raises(ValueError, match="unavailable"):
        exception.validate(case.repo, case.central, case.head)
    monkeypatch.setattr(
        exception, "github_names", lambda endpoint, key: case.release_state[endpoint]
    )
    case.evidence.unlink()
    with pytest.raises(ValueError, match="evidence missing"):
        exception.validate(case.repo, case.central, case.head)


def test_feature_repo_cannot_supply_its_own_exception(case: SimpleNamespace) -> None:
    local = case.repo / "policy/exceptions"
    local.mkdir(parents=True)
    (local / exception.MANIFEST).write_text(json.dumps(case.manifest))
    with pytest.raises(ValueError, match="central governance checkout"):
        exception.validate(case.repo, local.parent, case.head)
    case.tracked["paths"] = "policy/exceptions/fieldzilla-otp-staging-mobile-audit.json"
    with pytest.raises(ValueError, match="central ownership"):
        exception.validate(case.repo, case.central, case.head)
