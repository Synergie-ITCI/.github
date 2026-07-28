# Executive Approval Policy

## Purpose

This document is the approval-focused entry point for the final Synergie Enterprise PR QA governance model.

The detailed policy is [Executive Release Policy](executive-release-policy.md).

## Mandatory Executive Approver

Every protected-branch pull request in an onboarded active repository requires approval from:

```text
SaurabhVermaIN
```

No developer approval, peer approval, repository-owner approval, automation approval, or broad administrator approval may satisfy the protected-branch Executive approval requirement.

## Approval Rules

- Enterprise PR QA must execute before any protected-branch merge decision.
- QA findings must remain truthful, visible, and unchanged.
- Build, tests, secret scanning, dependency security, deployment risk, migration risk, documentation validation, protected resource validation, and repository integrity may never be skipped.
- Developers may never approve their own pull requests.
- Reviewers other than the Executive Release Authority may comment or review, but their approvals must not satisfy protected-branch approval.
- `require_last_push_approval` must remain enabled.
- GitHub Branch Protection and repository rulesets remain the merge authority.
- No rollout PR may be merged automatically.

## Executive-Authored Pull Requests

If `SaurabhVermaIN` authored or last-pushed the pull request:

1. Enterprise PR QA still executes.
2. QA findings remain unchanged.
3. GitHub may block ordinary approval because `require_last_push_approval` is enabled.
4. GitHub Administrator Bypass may be used only after QA completes.
5. A specific bypass reason and immutable audit record are mandatory.

This process is not a QA bypass and does not weaken technical validation.
