# Executive Release Policy

## Purpose

This policy defines the organisation-wide approval model for protected branches using the Synergie Enterprise PR QA Framework v1.0.

PR QA is mandatory technical evidence. GitHub Branch Protection and repository rulesets remain the merge authority.

This is the final production governance model for repositories onboarded to the Enterprise PR QA Platform. It does not authorise framework changes, application changes, deployment changes, direct commits, automatic merges, or GitHub setting changes by the workflow.

## Authority

| Role | Current Holder |
| --- | --- |
| Executive Release Authority | `SaurabhVermaIN` |

The Executive Release Authority is the only reviewer whose approval may satisfy the protected-branch approval requirement. No protected-branch pull request may merge without approval from `SaurabhVermaIN`, except where GitHub blocks self-approval for an Executive-authored or Executive-last-pushed pull request and the documented administrator bypass process is used after QA completes.

## Non-Negotiable Controls

- Every pull request targeting a protected branch must complete Enterprise PR QA.
- QA results must remain truthful and visible.
- Build, tests, secret scanning, dependency security, deployment risk, migration risk, documentation validation, protected resource validation, and repository integrity may never be skipped for protected-branch pull requests.
- No developer may approve their own pull request.
- Non-authority reviewers may provide feedback, but their approval must not satisfy protected-branch approval.
- `require_last_push_approval` must remain enabled.
- GitHub Branch Protection and repository rulesets remain authoritative.
- Administrator bypass must never be automatic.
- Rollout pull requests introducing Enterprise PR QA follow the same approval and merge rules as any other protected-branch pull request.

## Standard Developer PR

For pull requests opened by any developer other than the Executive Release Authority:

1. Enterprise PR QA runs.
2. Findings are reported as PASS, WARNING, or FAIL.
3. The Executive Release Authority reviews the PR and QA evidence.
4. `SaurabhVermaIN`, or the active Executive Release Authority role containing only `SaurabhVermaIN`, approves if the PR is acceptable.
5. GitHub permits merge only when all required checks and reviews are satisfied.

Developer self-approval is not valid, even if GitHub records a review event.

## Executive Release Authority PR

For pull requests opened or last-pushed by `SaurabhVermaIN`:

1. Enterprise PR QA still runs.
2. Findings remain unchanged.
3. GitHub must not treat `SaurabhVermaIN` as self-approved.
4. `require_last_push_approval` remains enabled and may block ordinary approval.
5. If the change must proceed, the Executive Release Authority may use GitHub Administrator Bypass only after QA has completed.
6. The bypass reason is mandatory.
7. The emergency override audit artifact must be retained with the QA report.

This path is not a QA bypass. It is a governance exception recorded after technical analysis.

## Required GitHub Settings

Configure these settings at the organisation ruleset level where possible, and mirror them in repository rulesets for protected repositories that need explicit local controls.

| Setting | Required Value |
| --- | --- |
| Target branches | `main`, release branches, and any protected production branch |
| Require pull request before merging | enabled |
| Required approving reviews | 1 |
| Required reviewer | `SaurabhVermaIN`, or an Executive Release Authority role/team containing only `SaurabhVermaIN` |
| Dismiss stale approvals | enabled |
| Require approval of most recent push | enabled |
| Require conversation resolution | enabled |
| Required status check | Enterprise PR QA, after rollout PR merge and required-check name confirmation |
| Restrict bypass actors | Executive Release Authority only |
| Administrator bypass | permitted only after QA completes and a reason is recorded |

Do not configure repository owners, developers, automation users, or general admin teams as bypass actors for this policy.

Manual administrators must select the actual GitHub status-check context emitted by the rollout PR. The approved caller workflow is `.github/workflows/pr-qa.yml`, pinned to `Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2`.

## Audit Requirements

Every administrator bypass for an Executive Release Authority PR must preserve:

- actor
- repository
- branch
- commit SHA
- PR number
- timestamp
- reason
- PR QA report
- PR QA JSON evidence
- emergency override audit record
- GitHub merge or bypass event evidence

The audit reason must be specific enough for post-incident review. Generic reasons such as "urgent", "release", or "approval" are not sufficient.

## Prohibited Use

- Do not bypass QA.
- Do not hide or edit findings.
- Do not disable required checks to merge faster.
- Do not remove `require_last_push_approval`.
- Do not grant broad bypass permission to developer or administrator groups.
- Do not use administrator bypass for convenience, routine release pressure, or incomplete evidence.
