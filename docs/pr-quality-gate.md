# Synergie PR Quality Gate

Status: implementation workflow

The Synergie PR Quality Gate is a reusable GitHub Actions workflow hosted in
`Synergie-ITCI/.github`. Participating repositories add a thin caller workflow;
all QA logic remains central.

The workflow analyzes and reports only. It does not approve PRs, merge PRs,
change branch protection, change CODEOWNERS, change deployments, or modify
application code.

## Caller Workflow

Add this file to participating repositories:

`.github/workflows/pr-qa.yml`

```yaml
name: Synergie PR QA

on:
  pull_request:

permissions:
  contents: read
  pull-requests: read

jobs:
  pr-qa:
    uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2
```

## Optional Repository Config

Repositories may add `.github/pr-qa.yml`:

```yaml
version: 1
repository:
  profile: application
  criticality: medium
```

## Failure Rules

The gate reports the true technical state of every mandatory control. Findings must not be suppressed or altered for governance convenience.

Blocking failures include:

- build failure when a build command is configured
- test failure when tests are configured
- lint failure when lint is configured
- `git diff --check` failures
- confirmed secret or credential material
- dependency security failures
- deployment and migration risk failures
- protected-resource and repository-integrity failures

Missing mandatory security or validation tooling is an infrastructure blocker. Missing repository-specific project commands are reported truthfully as configured by the frozen framework.

## Validation Checklist

- Reusable workflow exists in `Synergie-ITCI/.github`
- Caller workflow exists in the participating repository
- A test PR runs Enterprise PR QA
- The check summary is posted on the PR
- File annotations appear for failures and warnings
- Branch Protection, CODEOWNERS, approvals, and merge permissions remain owned by GitHub

## Sample Report

```text
PR QUALITY REPORT

Repository: Synergie-ITCI/example
Technology: Laravel, PHP, Node

Formatting
PASS

Lint
PASS

Build
PASS

Tests
PASS

Git Validation
PASS

Secrets
PASS

Dependency Security
WARN

Deployment Risk
LOW

Migration Risk
LOW

Large Files
PASS

Documentation
PASS

AI Advisory
INFO

Overall Result
PASS

Merge Readiness
READY FOR REVIEW
```

## Rollout Plan

1. Enable the reusable workflow in `Synergie-ITCI/.github`.
2. Add the thin caller workflow to active repositories.
3. Open one validation PR per repository.
4. Confirm the PR report, annotations, and status check.
5. Add the `PR Quality Gate` status check to branch protection manually only
   after the workflow is observed to be stable for that repository.

## Current Limitation

AI advisory is implemented as a non-blocking heuristic review. A real model-backed
review requires explicit approval for the AI provider, credentials, data-retention
terms, and prompt policy.
