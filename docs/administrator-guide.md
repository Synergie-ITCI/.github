# Administrator Guide

## Purpose

The PR QA framework is a required technical status check for pull requests. It validates repository hygiene, code quality, security, operational risk, documentation evidence, and PR evidence before a human review/merge decision.

The workflow never merges code and never changes Branch Protection. The required PR QA status validates technical gates and review policy. Branch Protection and repository rulesets remain the authority for required status checks, merge permissions, merge conflicts, and merge strategy.

## Central Repository Layout

Install these paths in `Synergie-ITCI/.github`:

```text
.github/workflows/pr-qa.yml
pr-qa/pr_qa.py
pr-qa/adapters/
schemas/pr-qa.schema.json
docs/
examples/
```

Participating repositories should only contain:

```text
.github/workflows/pr-qa.yml
.github/pr-qa.yml
.github/pull_request_template.md
```

## Runner Requirements

The framework runs on `ubuntu-latest` by default. Repository callers cannot select a runner.

Do not run PR QA for untrusted pull requests on persistent self-hosted runners. If self-hosted execution is ever required, use ephemeral isolated runners with no organisation secrets and no persistent workspace.

Recommended runner tools:

| Area | Tooling |
| --- | --- |
| Secrets | `gitleaks` |
| GitHub Actions | `actionlint` |
| PHP | PHP, Composer |
| Node | Node.js, npm, yarn/pnpm where used |
| Python | Python, pip, `pip-audit`, Ruff, Black, Pytest where used |
| Go | Go, `govulncheck`, `go-licenses` |
| Java/Kotlin | Java, Maven, Gradle |
| .NET | .NET SDK |
| Rust | Rust, cargo-audit |
| Docker | Docker, Hadolint, Trivy |
| Terraform | Terraform, TFLint, tfsec or Checkov |
| Kubernetes | kubeconform, kubeval, or kubectl |

Security tooling is mandatory for the gates it supports. Gitleaks is mandatory. Dependency audit tooling is mandatory for repositories whose technologies are detected.

## Security Model

- The caller workflow uses read-only repository and pull-request permissions.
- The workflow does not request deployment, environment, package-write, or repository-administration permissions.
- All checkout steps use `persist-credentials: false`.
- Static preflight runs before setup, dependency installation, build, lint, or tests.
- Mandatory gates are defined in `policy/pr-qa-policy.json` and cannot be disabled by repository configuration.
- Repository configuration is loaded from the base branch only. PR-head configuration changes are treated as protected policy changes and fail.
- Secret findings are redacted in logs and reports.
- Command artifacts contain redacted excerpts, not raw stdout/stderr.
- Dependency audits never upgrade packages.
- Formatter checks never auto-fix.
- Terraform validation uses `terraform init -backend=false` unless explicitly overridden.

## Required Status Check

After Phase 1 validation, administrators may mark the caller workflow status as required in Branch Protection or repository rulesets.

Do this outside the PR QA workflow. The workflow itself must not mutate GitHub settings.

## Repository Profiles

The default repository profile is `application`. Production/customer repositories must use this default unless a repository owner obtains explicit governance approval for another profile.

Supported profiles:

| Profile | Purpose |
| --- | --- |
| `application` | production and customer-facing applications |
| `framework` | internal engineering frameworks such as PR QA |
| `infrastructure` | Terraform, Kubernetes, and deployment-control repositories |
| `library` | shared libraries |
| `documentation` | documentation-only repositories |

The `framework` profile permits only centrally approved regression fixture paths and fixture manifests to be classified as non-blocking. It does not disable Gitleaks, does not suppress findings globally, and does not apply to production application repositories by default.

Approved governance assets such as `.gitleaks.toml`, `.github/**`, `.gitignore`, `.editorconfig`, `policy/**`, and `schemas/**` bypass only the hidden-file integrity warning. They remain subject to protected-resource review, workflow/deployment warnings, secret scanning, and human governance.

## Executive Release Governance

Protected branches must use GitHub Branch Protection or repository rulesets as the merge authority. PR QA supplies required technical evidence; it does not approve, merge, or bypass rules.

Configure the organisation governance model as follows:

| Control | Required Setting |
| --- | --- |
| Required QA | Enterprise PR QA required on every pull request |
| Required approval | enforced by the required Enterprise PR QA review-policy gate |
| Current Executive Release Authority | `SaurabhVermaIN` |
| Saurabh author exception | `SaurabhVermaIN` may merge without independent human review after all automated gates pass |
| Developer self-approval | prohibited for every other developer |
| Non-authority approval | may comment or review, but cannot satisfy protected-branch approval |
| Review thread resolution | enabled |
| Stale review dismissal | enabled |

Recommended GitHub configuration:

- Use a protected branch ruleset for `main` and every protected release branch.
- Require pull requests before merging.
- Require the Enterprise PR QA status check; its Review Policy gate enforces the Saurabh-only author exception and the independent-review requirement for all other authors.
- Do not use a native required-review-count rule when it cannot express the `SaurabhVermaIN` author exception safely.
- Restrict ruleset bypass actors to the Executive Release Authority or the controlled Executive Release Authority team.
- Permit administrator bypass only through GitHub's explicit emergency bypass flow and only after PR QA has completed.

When `SaurabhVermaIN` opens a pull request, the expected governance path is:

1. PR QA runs and publishes all findings.
2. The Review Policy gate verifies the pull request author login is exactly `SaurabhVermaIN`.
3. Required automated QA, security, production, environment, branch-promotion, and mergeability controls remain mandatory.
4. If every mandatory gate passes, independent human review is not required.

## Emergency Administrative Override

Emergency override is a governance record only. It never suppresses findings, changes gate status, changes the overall QA result, changes merge readiness, or changes the workflow exit code.

The only authorised actor in the immutable central policy is:

```text
SaurabhVermaIN
```

The normal `SaurabhVermaIN` author exception is not an emergency administrative override and does not write an emergency override audit record.

If `SaurabhVermaIN` records an override on a pull request authored by another developer, the audit decision is `EXECUTIVE_RELEASE_AUTHORITY_REVIEW_RECORDED`. This does not alter the QA result; it records the Executive Release Authority governance action.

When an emergency override reason is supplied after QA execution, the engine writes an audit record to `pr-qa-results/emergency-override-audit.json` unless an explicit audit path is provided. The record contains:

- actor
- PR author
- repository
- branch
- commit SHA
- PR number
- timestamp
- reason
- QA summary at the time of override
- administrator bypass required flag
- self-approval allowed flag
- record SHA-256

Unauthorised actors produce a rejected audit record. They do not receive an effective governance override.

The override request is triggered by `PR_QA_EMERGENCY_OVERRIDE_REASON` or the equivalent engine argument `--emergency-override-reason`. The actor is resolved from GitHub's triggering actor, GitHub actor, or event sender metadata.

The override does not bypass GitHub Branch Protection automatically. Administrator bypass remains a separate GitHub action. Keep PR QA enabled and required so the truthful QA result remains visible before any emergency decision.

## Operations

Review the generated artifacts for every failed run:

```text
pr-qa-results/pr-quality-report.md
pr-qa-results/pr-quality-report.json
pr-qa-results/gitleaks.json
pr-qa-results/emergency-override-audit.json
```

The Markdown report is the concise human report. The JSON report is the audit trail for future analytics.

## Upgrade Process

1. Change the central framework in `Synergie-ITCI/.github`.
2. Validate in Phase 1 representative repositories.
3. Publish a protected immutable framework release tag such as `pr-qa-v1-rc2`.
4. Move caller workflows to the approved immutable tag only after validation.
5. Do not expose framework-ref, runner-label, config-path, or timeout as caller-controlled inputs.
