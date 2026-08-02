# Governance Validation Report

## Purpose

This document validates the final Synergie Pull Request Governance Policy for protected branches.

The validation is operational. It does not require framework redesign, workflow changes, application code changes, or automatic GitHub setting updates.

The final policy is [Final Organisation Governance Policy](final-organisation-governance-policy.md). Manual GitHub enforcement settings are listed in [GitHub Configuration Checklist](github-configuration-checklist.md).

## Required Baseline

| Control | Expected State |
| --- | --- |
| Enterprise PR QA | required on every protected-branch pull request |
| Executive Release Authority | `SaurabhVermaIN` |
| Required approving reviews | 1 |
| Required reviewer | `SaurabhVermaIN` or Executive Release Authority team containing only `SaurabhVermaIN` |
| Developer self-approval | rejected |
| Require Last Push Approval | enabled |
| Administrator bypass | Executive Release Authority only, reason required |
| QA evidence | retained for every scenario |
| Mandatory gates | build, tests, secrets, dependency security, deployment risk, migration risk, documentation validation, protected resource validation, repository integrity |

## Mandatory Gate Mapping

| Governance control | Framework gate |
| --- | --- |
| Build | `build` |
| Tests | `tests` |
| Secret scanning | `secrets` |
| Dependency security | `dependencies` |
| Deployment risk | `deployment_safety` |
| Migration risk | `database_safety` |
| Documentation validation | `documentation` |
| Protected resource validation | `protected_resources` |
| Repository integrity | `repository_integrity` |

## Scenario A: Developer PR

Flow:

1. A developer opens a pull request.
2. Enterprise PR QA executes.
3. QA findings are reported.
4. `SaurabhVermaIN` reviews the PR and QA evidence.
5. `SaurabhVermaIN` approves.
6. GitHub permits merge when all required checks and reviews are satisfied.

Expected result: PASS.

Required evidence:

- PR URL
- PR author
- QA run URL
- QA report artifact
- `SaurabhVermaIN` approval event
- merge event

## Scenario B: Developer Self-Approval

Flow:

1. A developer opens a pull request.
2. Enterprise PR QA executes.
3. The same developer approves their own PR.
4. GitHub evaluates protected-branch rules.

Expected result: REJECTED.

Required evidence:

- PR URL
- PR author and approving user match
- QA run URL
- GitHub review decision remains blocked or unsatisfied
- no merge occurs from self-approval alone

## Scenario C: Executive Release Authority PR With Passing QA

Flow:

1. `SaurabhVermaIN` opens or last-pushes a pull request.
2. Enterprise PR QA executes.
3. QA findings are reported.
4. GitHub blocks self-approval because `require_last_push_approval` is enabled.
5. `SaurabhVermaIN` uses GitHub Administrator Bypass intentionally.
6. A mandatory bypass reason is recorded.
7. The emergency override audit record is retained.
8. GitHub permits merge through the explicit administrator bypass path.

Expected result: PASS WITH RECORDED ADMINISTRATOR BYPASS.

Required evidence:

- PR URL
- PR author `SaurabhVermaIN`
- last pusher evidence
- QA run URL
- QA report artifact
- GitHub blocked self-approval state before bypass
- administrator bypass reason
- emergency override audit artifact
- merge event

## Scenario D: Executive Release Authority PR With Failing QA

Flow:

1. `SaurabhVermaIN` opens or last-pushes a pull request.
2. Enterprise PR QA executes.
3. QA reports failures.
4. Findings remain visible in the Markdown and JSON reports.
5. If administrator bypass is used, the bypass reason and QA status are recorded.

Expected result: QA FAILURE PRESERVED; ANY BYPASS AUDITED.

Required evidence:

- PR URL
- failed QA run URL
- failed QA report artifact
- failed QA JSON evidence
- administrator bypass reason, if used
- emergency override audit artifact, if used
- post-event review owner

## Scenario E: Rollout PR

Flow:

1. A rollout branch adds only `.github/workflows/pr-qa.yml` and `.github/pr-qa.yml` when required.
2. The caller workflow references only `Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2`.
3. Enterprise PR QA executes.
4. Findings are reported without alteration.
5. `SaurabhVermaIN` reviews and approves before any merge.
6. Repository owners merge manually only when GitHub protected-branch rules are satisfied.

Expected result: PASS WITH EXECUTIVE APPROVAL REQUIRED.

Required evidence:

- rollout PR URL
- changed-file list showing only approved rollout files
- caller workflow pinned to `pr-qa-v1-rc2`
- QA run URL
- `SaurabhVermaIN` approval event
- no automatic merge event

## Validation Result Template

| Scenario | Result | Evidence Location | Notes |
| --- | --- | --- | --- |
| A |  |  |  |
| B |  |  |  |
| C |  |  |  |
| D |  |  |  |
| E |  |  |  |

## Acceptance Criteria

Governance validation passes only when:

- every protected-branch pull request executes Enterprise PR QA
- QA findings remain unchanged by approval or bypass decisions
- only the Executive Release Authority satisfies protected-branch approval
- developer self-approval cannot merge protected branches
- Executive-authored PRs require explicit administrator bypass when GitHub blocks self-approval
- every bypass has a specific reason and immutable audit evidence
- rollout PRs contain only approved onboarding files and are never merged automatically
