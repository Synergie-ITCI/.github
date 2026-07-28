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

Security tooling is mandatory for the gates it supports. The reusable workflow installs pinned Gitleaks `8.30.1` with SHA-256 verification before Phase 1 and fails closed if it is unavailable. For Python repositories, the workflow installs pinned Pytest `9.1.1` and pip-audit `2.10.1` after Phase 1; pip-audit runs only when a Python dependency manifest is present. Other dependency audit tooling is mandatory for repositories whose technologies are detected.

## Security Model

- The caller workflow uses read-only repository permissions and pull-request write permission only for inline review comments.
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

The reusable workflow accepts a `repository-profile` input for governed central self-validation. Organisation rollout callers should omit that input and inherit the `application` profile unless an approved governance decision assigns another profile.

Approved governance assets such as `.gitleaks.toml`, `.github/**`, `.gitignore`, `.editorconfig`, `policy/**`, and `schemas/**` bypass only the hidden-file integrity warning. They remain subject to protected-resource review, workflow/deployment warnings, secret scanning, and human governance.

## Executive Release Governance

Protected branches must use GitHub Branch Protection or repository rulesets as the merge authority. PR QA supplies required technical evidence; it does not approve, merge, or bypass rules.

Configure the organisation governance model as follows:

| Control | Required Setting |
| --- | --- |
| Required QA | Enterprise PR QA required on every pull request |
| Required approval | one approval from the Executive Release Authority |
| Current Executive Release Authority | `SaurabhVermaIN` |
| Developer self-approval | prohibited |
| Non-authority approval | may comment or review, but cannot satisfy protected-branch approval |
| Require Last Push Approval | enabled |
| Review thread resolution | enabled |
| Stale review dismissal | enabled |

Recommended GitHub configuration:

- Use a protected branch ruleset for `main` and every protected release branch.
- Require pull requests before merging.
- Require at least one approving review.
- Require review from `SaurabhVermaIN` directly, or from a GitHub team/role that only contains the current Executive Release Authority.
- Keep `require_last_push_approval` enabled so the PR author or last pusher cannot satisfy their own approval requirement.
- Restrict ruleset bypass actors to the Executive Release Authority or the controlled Executive Release Authority team.
- Permit administrator bypass only through GitHub's explicit bypass flow and only after PR QA has completed.

When `SaurabhVermaIN` opens or last-pushes a pull request, GitHub must continue to block self-approval. The expected governance path is:

1. PR QA runs and publishes all findings.
2. The Executive Release Authority reviews the PR evidence.
3. If the change must proceed and GitHub blocks self-approval because of `require_last_push_approval`, the Executive Release Authority uses GitHub Administrator Bypass intentionally.
4. The bypass reason is mandatory.
5. The emergency override audit artifact is retained with the QA report.

## Emergency Administrative Override

Emergency override is a governance record only. It never suppresses findings, changes gate status, changes the overall QA result, changes merge readiness, or changes the workflow exit code.

The only authorised actor in the immutable central policy is:

```text
SaurabhVermaIN
```

An Executive-authored pull request must not be treated as self-approved. If the actor and pull request author are both `SaurabhVermaIN`, the audit decision is `ADMINISTRATOR_BYPASS_REQUIRED`.

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

Inline review comments are also published for findings that map to a changed pull request diff line. They are generated through the GitHub Pull Request Review API using `pull-requests: write`, contain no raw secrets, and are self-healing on later pushes. See `docs/inline-review-comments-architecture.md` for the implementation model.

Inline review publication runs in an isolated trusted publisher job. The untrusted QA job has `contents: read` only, receives no provider credential, receives no pull request write token, and may execute repository build, lint, and test commands. The publisher job starts on a fresh runner, checks out only the workflow-defining framework commit, downloads approved QA evidence files as untrusted data, validates the evidence bundle, and only then publishes comments.

AI Engineering Review runs after final Enterprise QA succeeds. Configure the approved hosted AI review provider through repository or organisation secrets:

```text
AI_REVIEW_PROVIDER_URL
AI_REVIEW_PROVIDER_TOKEN
```

Configure approved provider destinations through organisation or repository variables:

```text
AI_REVIEW_APPROVED_HOSTS
AI_REVIEW_APPROVED_INTERNAL_HOSTS
```

`AI_REVIEW_APPROVED_HOSTS` is an exact hostname allowlist. Do not use broad suffix rules. Provider URLs must use HTTPS, must not contain embedded credentials, and must not target localhost, loopback, link-local, or private network addresses unless the destination is explicitly governed through the internal-provider allowlist.

If the provider endpoint, token, destination governance, or authoritative QA PASS evidence is unavailable, the workflow reports `AI Review unavailable` and Enterprise QA remains unchanged. The automation runs in GitHub Actions and does not depend on a local Codex workspace or an operator machine being online.

AI Review artifacts are retained with the final PR QA evidence:

```text
pr-qa-ai-review-results/ai-review-report.md
pr-qa-ai-review-results/ai-review-report.json
```

AI Review is advisory only. It never changes QA status, risk score, merge readiness, approvals, Branch Protection, CODEOWNERS, release governance, or merge requirements.

Caller workflows pin the reusable workflow to the approved immutable release reference. For Version 1.1 this pending reference is `pr-qa-v1.1`. Inside the reusable workflow, framework source is checked out from `job.workflow_repository` at `job.workflow_sha`, so every job uses the exact commit that defines the called workflow. Do not add a caller-controlled framework reference.

## Upgrade Process

1. Change the central framework in `Synergie-ITCI/.github`.
2. Validate in Phase 1 representative repositories.
3. Publish a protected immutable framework release tag such as `pr-qa-v1.1`.
4. Move caller workflows to the approved immutable tag only after validation.
5. Do not expose framework-ref, runner-label, config-path, or timeout as caller-controlled inputs.
