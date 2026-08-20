# Repository Onboarding Guide

## Scope

Use this guide to onboard one Synergie repository to the central PR QA framework.

Do not change application code, deployment workflows, CODEOWNERS, Branch Protection, repository permissions, or infrastructure as part of onboarding.

## Files To Add

Copy these files into the repository:

```text
.github/workflows/pr-qa.yml
.github/pr-qa.yml
.github/pull_request_template.md
```

Use:

- `examples/caller-workflow.yml` as `.github/workflows/pr-qa.yml`
- `examples/pr-qa.yml` as `.github/pr-qa.yml`
- `examples/pull_request_template.md` as `.github/pull_request_template.md`

## Onboarding Steps

1. Create a branch named `chore/onboard-pr-qa`.
2. Add the three files above.
3. Set `repository.criticality` in `.github/pr-qa.yml`.
4. Tune thresholds only when the repository has a documented reason.
5. Open a pull request.
6. Review the `PR QUALITY REPORT`.
7. Fix only onboarding-file mistakes in the onboarding PR.
8. Leave existing application quality findings for separate application PRs.

## Configuration Rules

Allowed repository-specific changes:

- enable or disable a gate with justification
- tune size and risk thresholds
- declare protected paths
- configure known script names for adapters
- disable Docker image builds where the runner cannot build safely

Not allowed:

- copying central engine code into the repository
- adding business logic to the caller workflow
- changing deployments
- changing Branch Protection
- changing CODEOWNERS
- adding secrets for PR QA without administrator approval

## Release-Governance Transition

The initial PR QA onboarding and the later release/deployment governance setup are separate activities.

### Step 1 — Base PR QA onboarding

The starter caller must use:

`Synergie-ITCI/.github/.github/workflows/pr-qa.yml@main`

The starter caller is intentionally unfiltered so PR QA covers all pull-request boundaries, including `staging` and `main`, until another approved workflow explicitly takes responsibility for those boundaries.

### Step 2 — Repository rules and release wrappers

After PR QA onboarding is proven:

1. Configure repository rulesets / Branch Protection to require the exact status contexts actually emitted by that repository.
2. If repository-specific quality-gate or production-gate wrapper workflows are introduced and those wrappers invoke PR QA for `staging` and/or `main`, scope the repo-local generic `.github/workflows/pr-qa.yml` caller to exclude the same boundaries.
3. Never run both the unfiltered generic caller and a wrapper-provided PR QA job for the same pull request.
4. Exactly one PR QA execution path must own each pull-request boundary.

This means:

- before wrappers exist: the generic PR QA caller covers all boundaries;
- after wrappers own `staging` / `main`: the generic caller excludes those boundaries.

### Step 3 — Gate D for deployable applications

For deployable applications, configure Gate D separately using `docs/gate-d-deployment-standard.md`.

Do not combine IAM, production deployment, CODEOWNERS, or infrastructure changes into the initial PR QA onboarding pull request.

## Expected First Run

Legacy repositories may initially show warnings for:

- no formatter configured
- no linter configured
- no automated test suite configured
- missing Gitleaks/actionlint/hadolint/tfsec runner tooling
- missing documentation for configuration or API changes

Warnings are visible audit evidence. They do not block merges unless the repository config or future policy makes them blocking.

## Blocking Failures

Blocking failures usually include:

- secret findings
- build failures
- configured test failures
- invalid commit/branch hygiene
- changed generated artifacts
- oversized or binary files
- destructive migrations
- protected resource changes without CODEOWNERS coverage
- incomplete mandatory PR evidence
