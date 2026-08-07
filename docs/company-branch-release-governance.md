# Synergie Branch And Release Governance Standard

This standard defines the reusable Synergie branch flow:

```text
feature/*
  -> development
  -> staging
  -> main
  -> production
```

The standard is additive and non-destructive. Existing repository security controls, CODEOWNERS requirements, environment approvals, deployment mechanisms, secret scanning, and stronger branch protections must be preserved.

## Branch Purposes

| Branch or pattern | Purpose | Company baseline |
| --- | --- | --- |
| `feature/*` | Developer implementation and work in progress | No company-wide required PR gate, reviewer, status check, merge queue, or deployment approval. Existing repo-specific protections remain. |
| `development` | Shared integration branch | No new company-wide blocking QA gate. CI may run as informational. Existing required checks/reviews remain. |
| `staging` | Company quality gate | PR required. Full QA/security/build/test gate should be required before staging deployment. Normal source is `development`. |
| `main` | Production release gate | PR required. Production/release validation, reviewer approval, and production safety checks should be required. Normal source is `staging`. |

## Promotion Rules

Normal promotion path:

```text
feature/* -> development
development -> staging
staging -> main
main -> production
```

Disallowed as a normal path:

```text
feature/* -> staging
feature/* -> main
development -> main
```

Emergency/hotfix paths must not be invented globally. If a repository already has an approved emergency flow, preserve and document it. If no emergency flow exists, the recommended pattern is:

```text
hotfix/* -> staging or main under emergency approval
then back-merge/reconcile into development and staging
```

## Reusable Workflows

The company reusable workflows are:

| Workflow | Purpose |
| --- | --- |
| `.github/workflows/synergie-quality-gate.yml` | Staging boundary governance and central PR QA. |
| `.github/workflows/synergie-production-gate.yml` | Main/production boundary governance and central PR QA. |

Repository adapters should call these workflows from a repository-local workflow, usually copied from:

```text
examples/synergie-branch-governance.yml
```

The central workflows reuse the existing Synergie PR QA framework instead of duplicating CI. They do not deploy, approve, merge, disable repository rules, change CODEOWNERS, or alter environments.

## Governance Config

Repositories may add:

```text
.github/synergie-governance.yml
```

Use `examples/synergie-governance.yml` as the starting point. The schema is:

```text
.github/synergie-governance.schema.json
```

The config is documentation and lightweight workflow input. It must never contain credentials, access keys, passwords, tokens, database secrets, cookies, or environment secret values.

## Repository Adoption Checklist

Before modifying any repository, inventory:

| Area | Required evidence |
| --- | --- |
| Branches | Existing `main`, `master`, `development`, `staging`, release, and hotfix branches. |
| Branch protection | Classic branch protection and required checks. |
| Rulesets | Repository and organization rulesets affecting branches or tags. |
| Required checks | Existing CI, security, build, deployment, and custom status checks. |
| CODEOWNERS | Existing owners and whether code-owner review is required. |
| Environments | GitHub environments, reviewers, secrets, and deployment branches. |
| Workflows | CI, deployment, release, rollback, security, dependency, and secret-scan workflows. |
| Deployment process | Existing staging, UAT, production, manual, SSM, SSH, rsync, or pipeline process. |
| Security | Secret scanning, dependency scanning, protected secrets, and compliance rules. |
| Release history | Previous production source branch and emergency process. |

Classify each proposed change:

| Classification | Meaning | Action |
| --- | --- | --- |
| `ADD` | Company baseline is missing and can be added safely. | Add the least invasive control. |
| `PRESERVE` | Existing rule is equal or stronger than the company baseline. | Keep it unchanged. |
| `CONFLICT` | Company baseline would break a legitimate existing workflow. | Do not modify automatically; document the conflict. |

## Initial Branch Bootstrap

For adopting repositories, canonical branches should exist:

```text
development
staging
main
```

Do not blindly create branches. Determine the correct source commit first.

Normally, for an initial bootstrap when no legitimate `development` or `staging` history exists:

```text
main -> development
main -> staging
```

If `development` or `staging` already exists with legitimate history, preserve it. Never reset, force-push, or rewrite branch history.

## Recommended Ruleset Baseline

Use GitHub rulesets where they add clean governance without overlapping or weakening existing protection.

For `staging`:

- Require pull request.
- Require successful Synergie staging quality gate.
- Require successful existing repository QA/build/security checks where already applicable.
- Require at least one reviewer.
- Require conversation resolution.
- Preserve CODEOWNERS where already configured or required.
- Prevent branch deletion and non-fast-forward updates.

For `main`:

- Require pull request.
- Require successful Synergie production gate.
- Require successful staging/release QA evidence.
- Require at least one reviewer.
- Require conversation resolution.
- Preserve CODEOWNERS where already configured or required.
- Preserve existing environment reviewers and deployment approvals.
- Prevent direct pushes unless an approved break-glass process already exists.
- Prevent branch deletion and non-fast-forward updates.

For `development` and `feature/*`:

- Do not add new company-wide blocking rules.
- Preserve any existing repository-specific protections.

## Staging And Production Deployment

Staging deployment may be triggered after the staging gate passes, but only if the repository already has a staging or UAT target. If no staging target exists, report:

```text
STAGING ENVIRONMENT NOT CONFIGURED
```

Do not point staging deployment at production.

Production deployment must originate only from an approved production source already defined by the repository. Preserve existing GitHub environments, manual approvals, deployment secrets, AWS deployment mechanisms, and rollback controls.

## Existing Synergie-ITCI/.github Protection

At publication time, the shared `.github` repository already has active rulesets that protect `main` with pull-request review, last-push approval, review-thread resolution, required PR QA, non-fast-forward protection, and deletion protection. Those stronger controls are preserved by this standard.
