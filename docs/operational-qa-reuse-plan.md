# Operational source QA reuse — review-only implementation plan

Scope: central opt-in authenticated exact-input source evidence; FieldZilla observe/locked-pause pilot. Resume stays on the existing authorized QA/recovery path. No activation, central publication, IAM, environments, live pins, PR418/mobile worktree or live operation changes.

1. Baseline: central main b60c11df886f0eee91fde3f403dfb05df0bc619b; FieldZilla staging ed64b353889d395540be4d667cac4859afe255cd. Read governing branch/release, validation and quiet-window runbooks. No repository AGENTS.md found at these roots; global user AGENTS applies. Separate feature worktrees under /private/tmp.
2. Evidence: verify supplied six job-duration records; inventory82 accessible repositories and sample7 manual workflow histories. Distinguish QA duplication from repeated operations, fresh security and inaccessible evidence. User-supplied runbook copy is supporting evidence, not independently committed source.
3. Implement: GitHub authenticated artifact digest/origin/run/workflow revision boundary following established GateD verifier pattern; strict bounded record, pinned central verifier/release/policy, input fingerprint and check contract; missing/invalid/unavailable => original QA. Existing PRQA unchanged.
4. Pilot: disabled caller contract and explicit dispatch opt-in defaultfalse. Source checks only. Security/advisory, migration, approvals and live worker/DB/image/snapshot/lock checks remain. No new resume dependency.
5. Deterministic QA: adversarial verifier fixtures across Python/Node FieldZilla and differently structured PHP caller; fallback/opt-out/workflow invariants; full central regression, lint, actionlint and YAML validation. No live workflows dispatched.
6. Review: exact local central/pilot commits, diffs, artifacts, timings and activation prerequisites. No merge, release/tag publication or live pin switch.
