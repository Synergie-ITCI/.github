# GitHub Configuration Checklist

## Purpose

This checklist defines the manual GitHub organisation and repository settings required to enforce the final Synergie Enterprise PR QA governance model.

The PR QA framework must not apply these settings automatically.

## Protected Branch Ruleset

For every protected production branch, configure GitHub Branch Protection or repository rulesets as follows:

| Setting | Required Value |
| --- | --- |
| Require pull request before merging | enabled |
| Required approving reviews | 1 |
| Required reviewer | `SaurabhVermaIN`, or an Executive Release Authority team containing only `SaurabhVermaIN` |
| Developer self-approval | not accepted as satisfying approval |
| Require approval of most recent push | enabled |
| Dismiss stale approvals | enabled |
| Require conversation resolution | enabled |
| Require status checks before merging | enabled |
| Required status check | Enterprise PR QA check emitted by `.github/workflows/pr-qa.yml` |
| Bypass actors | restricted to the Executive Release Authority only |
| Administrator bypass reason | mandatory |

## Required Status Check Selection

After each repository's rollout PR runs for the first time, record the exact GitHub check context emitted by the caller workflow. Use that context as the required status check for protected branches.

The approved caller workflow must reference only:

```text
Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2
```

## Read-Only GitHub Evidence

Read-only inspection on 2026-07-28 found:

| Ruleset | ID | Target | Enforcement | Observation |
| --- | --- | --- | --- | --- |
| Main branch protection baseline | `19620452` | branch | active | `require_last_push_approval` enabled, approving review count `1`, `required_reviewers` empty |
| No unreviewed self-merge baseline | `19206270` | branch | active | `require_last_push_approval` enabled, approving review count `1`, `required_reviewers` empty, `Castrol` excluded |
| Protect Synergie PR QA release tag `pr-qa-v1-rc2` | `19897425` | tag | active | creation, update, and deletion protected for `.github` release tag |

Bypass team `saurabh-pr-review-bypass` maps to `Saurabh PR Review Bypass` and contained only `SaurabhVermaIN` during read-only inspection on 2026-07-28.

Manual administrator verification is required before rollout PRs are merged because the reviewed branch rulesets did not yet show `SaurabhVermaIN` as a configured required reviewer.

## Manual Administrator Actions Required

Before organisation rollout proceeds to merge decisions:

1. Add `SaurabhVermaIN`, or a single-holder Executive Release Authority team, as the required reviewer in protected-branch rulesets for onboarded repositories.
2. Confirm `require_last_push_approval` remains enabled.
3. Confirm developer self-approval cannot satisfy protected-branch approval.
4. Add the exact Enterprise PR QA emitted check context as a required status check after each rollout PR produces it.
5. Remove or justify repository exclusions from self-merge rulesets before onboarding excluded repositories.
6. Restrict bypass actors to the Executive Release Authority only.
7. Require a specific administrator bypass reason.
8. Record every bypass with retained QA report and emergency override audit artifact.

## Prohibited Configuration

Do not:

- require a moving workflow reference
- allow developer self-approval to satisfy protected-branch approval
- add broad administrator groups as bypass actors
- disable `require_last_push_approval`
- disable required PR QA checks for convenience
- enable automatic rollout PR merges
- change CODEOWNERS, deployments, infrastructure, or application files during rollout

## Manual Evidence To Record

For each repository, record:

- repository name
- protected branch name
- required status-check context
- ruleset or Branch Protection URL
- `SaurabhVermaIN` required reviewer evidence
- last-push approval setting evidence
- bypass actor setting evidence
- date configured
- administrator who configured it
