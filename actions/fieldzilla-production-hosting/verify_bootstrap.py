"""Verify isolated rehearsal bootstrap after an immutable executor release changes."""

import json
import re
import sys
from pathlib import Path


CLAIM = "token.actions.githubusercontent.com:job_workflow_ref"
REVIEWED_REF = (
    "Synergie-ITCI/.github/.github/workflows/fieldzilla-production-hosting.yml"
    "@refs/tags/pr-qa-v1-rc238"
)
RELEASE_REF = re.compile(
    r"Synergie-ITCI/\.github/\.github/workflows/fieldzilla-production-hosting\.yml"
    r"@refs/tags/pr-qa-v1-rc[1-9][0-9]*\Z"
)


def verify(source: Path, temporary: Path, executing_ref: str) -> None:
    if not RELEASE_REF.fullmatch(executing_ref):
        raise ValueError("Rehearsal executor reference is not an immutable release")

    reviewed_trust = json.loads((source / "provisioner-trust.json").read_text())
    statements = reviewed_trust.get("Statement")
    if not isinstance(statements, list) or len(statements) != 1:
        raise ValueError("Reviewed rehearsal trust shape changed")
    conditions = statements[0].get("Condition", {}).get("StringEquals", {})
    if conditions.get(CLAIM) != REVIEWED_REF:
        raise ValueError("Reviewed rehearsal trust release changed")

    # The source bootstrap is bound to #717's immutable rc238. A later protected
    # executor must assume only its own exact workflow ref; every other claim is
    # still compared byte-for-byte to the reviewed source document.
    conditions[CLAIM] = executing_ref
    live_trust = json.loads((temporary / "rehearsal-trust.json").read_text())
    if reviewed_trust != live_trust:
        raise ValueError("Exact rehearsal bootstrap drift: provisioner-trust.json")

    reviewed_sink = json.loads((source / "log-sink-policy.json").read_text())
    live_sink = json.loads((temporary / "rehearsal-log-sink.json").read_text())
    if reviewed_sink != live_sink:
        raise ValueError("Exact rehearsal bootstrap drift: log-sink-policy.json")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("Expected bootstrap source, live readback and executor ref")
    verify(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
