"""Keep the staging mobile exception a protected dependency approval."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "policy/exceptions/fieldzilla-otp-staging-mobile-audit.json"


def test_staging_exception_record_is_approved_and_dependency_scoped() -> None:
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    assert record["repository"] == "Synergie-ITCI/programme-management-platform"
    assert record["environment"] == "staging"
    assert record["workflow"] == "staging-deploy.yml"
    assert record["exception_id"] == "fieldzilla-staging-mobile-tooling-2026-10"
    assert "head_sha" not in record
    assert record["approver"] == "Saurabh Verma"
    assert record["approved_at"]
    assert record["remediation_owner"] == "Mobile Platform Lead"
    assert record["reason"] and record["residual_risk"]
    approved = datetime.fromisoformat(record["approved_at"].replace("Z", "+00:00"))
    expiry = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
    assert approved < expiry <= approved + timedelta(days=30)
    assert set(record["dependency_sha256"]) == {
        "apps/mobile/package.json",
        "apps/mobile/package-lock.json",
    }
    assert (
        record["audit_script_sha256"]
        == hashlib.sha256(b"npm audit --audit-level=high").hexdigest()
    )
    evidence = RECORD.parent / record["evidence_file"]
    assert (
        hashlib.sha256(evidence.read_bytes()).hexdigest() == record["evidence_sha256"]
    )
    assert record["baseline_tags"] == ["fieldzilla-apply-dispatch-2c8a4015"]
    assert record["baseline_releases"] == []
    advisories = record["advisories"]
    assert len(advisories) == 5
    assert len({(item["package"], item["id"]) for item in advisories}) == len(
        advisories
    )
    assert all(
        item["severity"] in {"moderate", "high", "critical"} for item in advisories
    )
