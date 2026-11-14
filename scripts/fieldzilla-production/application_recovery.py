"""Read-only assessment of an interrupted FieldZilla application execution.

This does not authorize a retry. A missing completion record can mean that an
AWS mutation succeeded before the publisher lost its acknowledgement.
"""

import argparse
import hashlib
import json
from pathlib import Path


def assess(manifest: dict, journal: Path) -> dict:
    expected = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    records = [json.loads(line) for line in journal.read_text().splitlines()]
    if not records or records[0].get("event") != "started":
        raise ValueError("Execution journal has no start record")
    if records[0].get("manifest_sha256") != expected:
        raise ValueError("Journal is not bound to this exact manifest")
    if records[0].get("scope") != manifest.get("scope"):
        raise ValueError("Journal scope differs from manifest")
    events = [record.get("event") for record in records]
    pending = []
    for record in records:
        if record.get("event") == "mutation_started":
            pending.append(record.get("action"))
        elif record.get("event") == "mutation_completed":
            if not pending or pending[-1] != record.get("action"):
                raise ValueError("Mutation journal sequence is inconsistent")
            pending.pop()
    if len(pending) > 1:
        raise ValueError("Mutation journal has multiple unresolved calls")
    migration_started = any(
        record.get("event") == "task_launch_requested"
        and record.get("phase") == "migration"
        for record in records
    )
    after_attested = any(
        record.get("event") == "database_attested" and record.get("phase") == "after"
        for record in records
    )
    if (
        "infrastructure_increment_complete" in events
        or "production_runtime_prepared" in events
    ):
        phase = "execution_reported_complete"
    elif after_attested:
        phase = "migration_attested_after_execution"
    elif migration_started:
        phase = "migration_outcome_requires_live_reconciliation"
    else:
        phase = "before_migration"
    return {
        "phase": phase,
        "unacknowledged_mutation": pending[-1] if pending else None,
        "automatic_retry_allowed": False,
        "next_step": "Reconcile the exact journal, ECS tasks, database revisions, and approval before a reviewed recovery",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            assess(json.loads(args.manifest.read_text()), args.journal), indent=2
        )
    )


if __name__ == "__main__":
    main()
