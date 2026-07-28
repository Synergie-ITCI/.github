# Synergie PR Quality Gate

Status: enterprise framework

The Synergie PR Quality Gate is a reusable GitHub Actions workflow hosted in
`Synergie-ITCI/.github`. Participating repositories add a thin caller workflow;
all QA logic remains central.

The workflow analyzes and reports only. It does not approve PRs, merge PRs,
change branch protection, change CODEOWNERS, change deployments, or modify
application code.

## Caller Workflow

Add this file to participating repositories:

`.github/workflows/pr-quality-gate.yml`

```yaml
name: PR Quality Gate

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  pr-quality-gate:
    uses: Synergie-ITCI/.github/.github/workflows/reusable-pr-quality-gate.yml@main
```

## Optional Repository Config

Repositories may add `.github/pr-qa.yml`:

```yaml
checks:
  repository_hygiene: true
  formatting: true
  lint: true
  build: true
  tests: true
  git_validation: true
  secrets: true
  dependency_security: true
  licence_compliance: true
  deployment_risk: true
  migration_risk: true
  large_files: true
  documentation: true
  protected_resources: true
  ai_advisory: true
  risk_engine: true
  evidence_validation: true

large_file_threshold_mb: 10
fail_on_dependency_vulnerabilities: false
evidence_enforcement: fail
repository_criticality: medium
max_changed_files_for_low_risk: 20
```

## Failure Rules

The gate fails only on objective blockers:

- build failure when a build command is configured
- test failure when tests are configured
- lint failure when lint is configured
- `git diff --check` failures
- confirmed secret or credential material
- incomplete PR evidence when evidence enforcement is `fail`

The gate does not fail because tests, linters, build steps, or formatters are
absent. It reports those as not configured.

Dependency vulnerabilities, licence risk, deployment risk, migration risk,
protected-resource changes, documentation gaps, large files, repository hygiene
observations, and AI advisory observations are reported as warnings unless a repo
explicitly opts into stricter behavior.

## Technology Adapters

The engine detects available adapters and runs ecosystem-specific checks through
that adapter layer. Current adapters cover:

- Node / React / React Native / TypeScript
- PHP / Laravel
- Kotlin / Gradle
- Swift Package Manager
- Python
- Go
- Rust
- .NET
- Java / Maven

Docker, Terraform, Kubernetes and GitHub Actions are detected for deployment and
protected-resource risk analysis.

## Enterprise Gates

- Repository Hygiene
- Formatting
- Lint
- Build Validation
- Testing
- Git Validation
- Secret Detection
- Dependency Security
- Licence Compliance
- Deployment Safety
- Database Safety
- Documentation
- Protected Resource Validation
- AI Advisory Review
- Risk Engine
- Evidence Validation

## Validation Checklist

- Reusable workflow exists in `Synergie-ITCI/.github`
- Caller workflow exists in the participating repository
- A test PR runs `PR Quality Gate`
- The check summary is posted on the PR
- File annotations appear for failures and warnings
- Branch Protection, CODEOWNERS, approvals, and merge permissions remain owned by GitHub

## Sample Report

```text
PR QUALITY REPORT

Repository: Synergie-ITCI/example
Detected Technologies: Laravel, PHP, Node

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

Licence Compliance
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

Risk Engine
LOW

Risk Score
17 / 100 (LOW)

Overall Result
PASS

Merge Readiness
READY FOR REVIEW
```

## Rollout Plan

1. Enable the reusable workflow in `Synergie-ITCI/.github`.
2. Validate it in 3-5 representative repositories.
3. Add the thin caller workflow to active repositories after approval.
4. Open one validation PR per repository.
5. Confirm the PR report, annotations, and status check.
6. Add the `PR Quality Gate` status check to branch protection manually only
   after the workflow is observed to be stable for that repository.

## Current Limitation

AI advisory is implemented as a non-blocking heuristic review. A real model-backed
review requires explicit approval for the AI provider, credentials, data-retention
terms, and prompt policy.
