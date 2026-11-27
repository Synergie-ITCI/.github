"""The operational review record grants no QA or production execution bypass."""

import json
from datetime import datetime, timedelta
from pathlib import Path


POLICY = Path(__file__).resolve().parents[1] / "policy/pr-qa-policy.json"


def test_exact_clinical_pr_review_is_narrow_and_time_limited() -> None:
    policy = json.loads(POLICY.read_text())
    matches = [
        row
        for row in policy["one_time_baseline_alignments"]
        if row.get("repository") == "Synergie-ITCI/programme-management-platform"
        and row.get("pr_number") == 886
    ]
    assert len(matches) == 1
    review = matches[0]
    assert review["enabled"] is True
    assert review["expected_head_sha"] == "3442029a2a617d09b86c340b8dbde57349f85836"
    assert review["expected_base_sha"] == "8fd8ab6abc84cc01ae6ca3b62bc6ff1a2f29df66"
    assert (review["head_ref"], review["base_ref"]) == ("feat/nidaan-clinical-delta", "main")
    assert (review["allowed_changed_files"], review["allowed_effective_additions"]) == (
        20,
        2436,
    )
    assert review["relaxations"] == []
    issued = datetime.fromisoformat(review["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(review["expires_after"].replace("Z", "+00:00"))
    assert issued < expires <= issued + timedelta(hours=24)
