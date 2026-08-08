# Executive Release Policy

## Purpose

This policy defines the organisation-wide approval model for protected branches using the Synergie Enterprise PR QA Framework v1.0.

PR QA is mandatory technical evidence. GitHub Branch Protection and repository rulesets remain the merge authority.

## Authority

| Role | Current Holder |
| --- | --- |
| Executive Release Authority | `SaurabhVermaIN` |

The Executive Release Authority is the only reviewer whose approval may satisfy the protected-branch approval requirement for pull requests authored by other users.

Pull requests authored by the verified GitHub identity `SaurabhVermaIN` are exempt from the independent human-review requirement. All automated quality, security, branch-promotion, environment, and production controls remain mandatory.

## Non-Negotiable Controls

- Every pull request must complete Enterprise PR QA.
- QA results must remain truthful and visible.
- No developer other than the verified GitHub identity `SaurabhVermaIN` may merge without an independent human approval.
- Non-authority reviewers may provide feedback, but their approval must not satisfy protected-branch approval.
- GitHub Branch Protection and repository rulesets remain authoritative.
- Administrator bypass must never be automatic or used as the normal implementation of this policy.

## Standard Developer PR

For pull requests opened by any developer other than the Executive Release Authority:

1. Enterprise PR QA runs.
2. Findings are reported as PASS, WARNING, or FAIL.
3. The Executive Release Authority reviews the PR and QA evidence.
4. `SaurabhVermaIN`, or the active Executive Release Authority role, approves if the PR is acceptable.
5. GitHub permits merge only when all required checks and reviews are satisfied.

Developer self-approval is not valid, even if GitHub records a review event.

## Executive Release Authority PR

For pull requests opened by the verified GitHub identity `SaurabhVermaIN`:

1. Enterprise PR QA still runs.
2. Findings remain unchanged.
3. Required automated checks, security checks, production gates, environment protections, merge-conflict protection, and PR requirements remain mandatory.
4. Independent human review is not required.
5. GitHub permits merge only when all required automated governance checks and mergeability controls are satisfied.

This path is not a QA bypass and not an administrator bypass. It is a narrow review-policy exception keyed only to the GitHub login `SaurabhVermaIN`.

## Required GitHub Settings

Configure these settings at the organisation ruleset level where possible, and mirror them in repository rulesets for protected repositories that need explicit local controls.

| Setting | Required Value |
| --- | --- |
| Target branches | `main`, release branches, and any protected production branch |
| Require pull request before merging | enabled |
| Required approving reviews | enforced by required Enterprise PR QA review-policy gate |
| Required reviewer | `SaurabhVermaIN`, or an Executive Release Authority role/team containing only the current holder, for non-Saurabh-authored pull requests |
| Dismiss stale approvals | enabled |
| Require approval of most recent push | use only where it does not prevent the approved `SaurabhVermaIN` author exception; otherwise enforce latest review evidence through the required governance check |
| Require conversation resolution | enabled |
| Required status check | Enterprise PR QA |
| Restrict bypass actors | Executive Release Authority only |
| Administrator bypass | not part of the normal Saurabh author exception; emergency use only after QA completes and a reason is recorded |

Do not configure repository owners, developers, automation users, or general admin teams as bypass actors for this policy.

## Audit Requirements

Every emergency administrator bypass must preserve:

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
- Do not grant broad bypass permission to developer or administrator groups.
- Do not use administrator bypass for convenience, routine release pressure, or incomplete evidence.
