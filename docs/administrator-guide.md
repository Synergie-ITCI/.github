# Administrator Guide

## Purpose

The PR QA framework is a required technical status check for pull requests. It validates repository hygiene, code quality, security, operational risk, documentation evidence, and PR evidence before a human review/merge decision.

The workflow never merges code and never changes Branch Protection. Branch Protection remains the authority for approvals, CODEOWNERS review, required checks, merge permissions, and merge strategy.

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

## Operations

Review the generated artifacts for every failed run:

```text
pr-qa-results/pr-quality-report.md
pr-qa-results/pr-quality-report.json
pr-qa-results/gitleaks.json
```

The Markdown report is the concise human report. The JSON report is the audit trail for future analytics.

## Upgrade Process

1. Change the central framework in `Synergie-ITCI/.github`.
2. Validate in Phase 1 representative repositories.
3. Publish a protected immutable framework release tag such as `pr-qa-v1-rc2`.
4. Move caller workflows to the approved immutable tag only after validation.
5. Do not expose framework-ref, runner-label, config-path, or timeout as caller-controlled inputs.
