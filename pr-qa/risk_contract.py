"""Risk-triggered evidence contract; existing adapter tests remain the executor."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any


def assess_risk_contracts(
    contracts: list[dict[str, Any]], changed_files: list[str], repo: Path, tests_passed: bool
) -> list[tuple[str, str]]:
    """Return (risk, outcome) pairs without running a duplicate test suite."""
    outcomes: list[tuple[str, str]] = []
    for contract in contracts:
        risk = str(contract.get("risk", "unnamed"))
        source_paths = contract.get("source_paths")
        evidence_paths = contract.get("evidence_paths")
        if not isinstance(source_paths, list) or not source_paths or not all(isinstance(p, str) and p for p in source_paths):
            outcomes.append((risk, "INVALID_CONTRACT"))
            continue
        if not isinstance(evidence_paths, list) or not evidence_paths or not all(isinstance(p, str) and p for p in evidence_paths):
            outcomes.append((risk, "INVALID_CONTRACT"))
            continue
        if not any(fnmatch.fnmatchcase(path, pattern) for path in changed_files for pattern in source_paths):
            continue
        if any(path.startswith("/") or ".." in Path(path).parts for path in evidence_paths):
            outcomes.append((risk, "INVALID_CONTRACT"))
        elif not all((repo / path).is_file() for path in evidence_paths):
            outcomes.append((risk, "MISSING_EVIDENCE_FILE"))
        elif not tests_passed:
            outcomes.append((risk, "TESTS_NOT_PASSED"))
        else:
            outcomes.append((risk, "PASS"))
    return outcomes
