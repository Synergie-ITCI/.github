# Go / No-Go Checklist

Release reference: `pr-qa-v1-rc2`

Use this checklist at each decision point. A single NO in a required row means STOP.

## Phase 1: Publication Go / No-Go

| Check | Required Evidence | GO |
| --- | --- | --- |
| RC2 validation reviewed | `releases/rc2/VALIDATION_REPORT.md` |  |
| Package audit reviewed | `releases/rc2/PACKAGE_AUDIT.md` |  |
| Central repo access confirmed | `gh repo view Synergie-ITCI/.github` output |  |
| Publication PR approved | PR URL and approvers |  |
| `git diff --check` passed | command output |  |
| `actionlint` passed | command output |  |
| Schema validation passed | command output |  |
| Regression suite passed | command output |  |
| Gitleaks framework scan clean | report path |  |
| Gitleaks fixture scan detected expected fixture | report path |  |
| Release tag created | tag SHA |  |
| Tag protection active | ruleset evidence |  |
| GitHub release published | release URL |  |
| Workflow resolves at release ref | API response |  |

Publication decision:

```text
GO / NO-GO:
Approver:
Timestamp:
Evidence location:
```

## Phase 2: Single Pilot Go / No-Go

| Check | Required Evidence | GO |
| --- | --- | --- |
| Pilot repo is `Synergie-ITCI/csr-intelligence-engine` | repository-selection evidence |  |
| Rollout PR opened | PR URL |  |
| Rollout PR unmerged | PR state |  |
| Scenario PRs target rollout branch | PR URLs |  |
| Normal scenario completed | run URL and report |  |
| Broken build scenario completed | run URL and report |  |
| Secret scenario completed | run URL and redacted report |  |
| Deployment scenario completed | run URL and report |  |
| Migration scenario completed | run URL and report |  |
| Documentation scenario completed | run URL and report |  |
| Developer feedback collected | feedback record |  |
| Reviewer feedback collected | feedback record |  |
| No high-severity false negative | evidence register |  |
| No unexpected deployment | workflow evidence |  |

Pilot review decision:

```text
PASS / STOP:
Approver:
Timestamp:
Evidence location:
```

## Phase 3: Expanded Pilot Go / No-Go

| Check | Required Evidence | GO |
| --- | --- | --- |
| Single pilot passed | signed pilot review |  |
| Three repositories selected | expanded pilot register |  |
| Stack diversity confirmed | repository metadata |  |
| Rollout PRs opened | PR URLs |  |
| No automatic merge | PR state evidence |  |
| Scenario matrix completed | run URLs and reports |  |
| No high-severity false negative | evidence register |  |
| Runner stability acceptable | dashboard metrics |  |
| Owner feedback has no blocker | feedback record |  |

Expanded pilot decision:

```text
PASS / STOP:
Approver:
Timestamp:
Evidence location:
```

## Phase 4: Organisation Rollout Go / No-Go

| Check | Required Evidence | GO |
| --- | --- | --- |
| Publication passed | publication evidence |  |
| Single pilot passed | pilot evidence |  |
| Expanded pilot passed | expanded pilot evidence |  |
| Dashboard live | dashboard URL or file |  |
| Rollback runbook reviewed | approval record |  |
| Wave 1 owners notified | communication record |  |
| Wave 1 PRs ready to open | repository list |  |
| No open blockers | risk register |  |

Organisation rollout decision:

```text
GO / NO-GO:
Approver:
Timestamp:
Evidence location:
```

## Final Verdict Rule

Return `READY TO PUBLISH` only when publication prerequisites are satisfied and remaining work is operational execution in GitHub.

Return `NOT READY` if any publication prerequisite is missing, ambiguous, or unverifiable.
