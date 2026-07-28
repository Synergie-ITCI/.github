# Emergency Administrative Override Governance Note

## Purpose

Emergency Administrative Override exists only for governance decisions during exceptional production situations. It does not change PR QA technical analysis.

## Non-Negotiable Controls

- QA always executes before an override audit record is generated.
- QA findings are never suppressed, removed, downgraded, or rewritten.
- Gate statuses, overall result, merge readiness, and process exit code are unchanged.
- The override does not merge pull requests.
- The override does not modify GitHub Branch Protection.
- The override does not modify application repositories.

## Authorised Actor

Only the GitHub user `SaurabhVermaIN` is eligible for an accepted governance override.

All other actors produce a rejected audit record.

The Executive Release Authority must not be treated as self-approved.

If the actor and pull request author are both `SaurabhVermaIN`, GitHub Branch Protection remains authoritative. With `require_last_push_approval` enabled, GitHub must block self-approval. The correct governance decision is `ADMINISTRATOR_BYPASS_REQUIRED`.

If `SaurabhVermaIN` records an override on a pull request authored by another developer, the decision is `EXECUTIVE_RELEASE_AUTHORITY_REVIEW_RECORDED`.

## Audit Record

Every override request writes an audit record containing:

- actor
- PR author
- repository
- branch
- commit SHA
- PR number
- timestamp
- reason
- QA summary at the time of override
- administrator bypass required flag
- self-approval allowed flag
- record SHA-256

Default audit artifact:

```text
pr-qa-results/emergency-override-audit.json
```

The override request is triggered by `PR_QA_EMERGENCY_OVERRIDE_REASON` or the equivalent engine argument `--emergency-override-reason`. The actor is resolved from GitHub's triggering actor, GitHub actor, or event sender metadata.

## Branch Protection

The framework does not bypass GitHub Branch Protection automatically.

Configure GitHub Branch Protection or repository rulesets outside PR QA so that:

- Enterprise PR QA is required on every pull request.
- one approval from `SaurabhVermaIN`, or the Executive Release Authority role containing only the current holder, is required.
- developers cannot approve their own pull requests.
- approvals from reviewers other than the Executive Release Authority do not satisfy protected-branch approval.
- `require_last_push_approval` remains enabled.
- administrator bypass is permitted only for the Executive Release Authority.

Keep PR QA enabled and required. The emergency decision must be made with the truthful passed, warning, or failed QA report visible.

## Operational Use

An emergency override is acceptable only when:

- a production-impacting incident or business-critical continuity event exists
- the PR QA report has completed
- the audit record is retained
- the emergency reason is specific
- GitHub Administrator Bypass is used intentionally when the Executive Release Authority authored or last-pushed the PR
- the post-incident review verifies whether a framework defect, operational issue, or application issue caused the override

Do not use emergency override for routine release pressure, incomplete evidence, speculative improvements, or convenience.
