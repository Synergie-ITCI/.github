# Migration Guide For Existing Repositories

## Goal

Move existing Synergie repositories onto the central PR QA framework without changing application behavior, deployments, infrastructure, Branch Protection, or CODEOWNERS.

## Migration Pattern

Each repository gets a thin onboarding PR containing only:

```text
.github/workflows/pr-qa.yml
.github/pr-qa.yml
```

Do not fix unrelated quality findings in the onboarding PR. The first PR QA report is evidence, not a cleanup mandate.

## Before Migration

Record:

- repository name
- default branch
- active protected branches
- existing workflows
- CODEOWNERS presence
- PR template presence
- repository criticality
- dominant technology stack

The existing governance inventories can seed this data.

## Migration Steps

1. Create branch `chore/onboard-pr-qa`.
2. Add the caller workflow and config when required.
3. Set repository criticality.
4. Add protected paths already relevant to the repository.
5. Open the PR.
6. Let PR QA run.
7. Review the generated report.
8. Merge only after human approval and existing branch rules are satisfied.

## Handling Legacy Repositories

Legacy repositories often lack formatters, linters, automated tests, and lockfiles.

Default behavior:

- missing formatter: WARNING
- missing linter: WARNING
- missing tests: WARNING with "No automated test suite configured."
- missing mandatory scanner or dependency audit tooling: infrastructure blocker or FAIL
- changed secrets, generated artifacts, oversized files, destructive migrations, and incomplete evidence: FAIL

## After Migration

Create follow-up backlog items for warnings:

- add lockfile where missing
- add test suite
- add linter
- add formatter in check mode
- install Gitleaks/actionlint/hadolint/tfsec on self-hosted runners
- improve CODEOWNERS coverage
- improve PR evidence quality in a separate documentation PR when required

## Existing Workflow Interaction

The PR QA caller does not replace existing CI or deployment workflows.

Existing CI remains responsible for repository-specific runtime validation. PR QA adds common organisation-level reporting and quality gates.

## Required Check Activation

Only after the repository has a stable passing PR QA signal should administrators add it as a required status check through Branch Protection or rulesets.

That activation is an administrator action outside this workflow.
