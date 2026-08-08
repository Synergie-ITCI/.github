# Configuration Schema

Repository configuration lives at:

```text
.github/pr-qa.yml
```

The machine-readable schema is:

```text
schemas/pr-qa.schema.json
```

## Required Version

```yaml
version: 1
```

## Repository Settings

```yaml
repository:
  profile: application
  criticality: medium
  protected_paths:
    - .github/**
    - deployment/**
    - terraform/**
```

`profile` selects the repository governance profile. Allowed values are `application`, `framework`, `infrastructure`, `library`, and `documentation`. The default is `application`.

`criticality` affects the risk score. Allowed values are `low`, `medium`, `high`, and `critical`.

`protected_paths` are checked against CODEOWNERS coverage.

## Gates

Mandatory gates cannot be disabled by repository configuration. The central immutable policy owns mandatory gate behavior.

```yaml
gates:
  secrets: true
  tests: true
  advisory_review: true
```

Only optional gates, currently `advisory_review`, may be disabled by repository configuration. A PR that attempts to set a mandatory gate to `false` fails Phase 1 static preflight.

## Thresholds

```yaml
thresholds:
  max_file_bytes: 5242880
  max_changed_files: 200
  max_additions: 5000
  risk_warning: 40
  risk_fail: 85
```

Risk score warnings do not block. A score at or above `risk_fail` blocks.

## Branch And Commit Conventions

```yaml
branch_naming:
  allowed_patterns:
    - '^(feature|fix|hotfix|release|chore|docs|test|refactor|security|codex)/[a-zA-Z0-9._/-]+$'

commit_messages:
  allowed_patterns:
    - '^(feat|fix|docs|style|refactor|test|chore|build|ci|perf|security|release|revert)(\([^)]+\))?: .+'
```

Patterns are regular expressions. The `release:` type is reserved for governed release-publication commits and does not relax commit-message validation.

## Repository Profiles

Profiles let PR QA distinguish production application repositories from internal governance frameworks without changing security gates.

| Profile | Purpose |
| --- | --- |
| `application` | production and customer-facing application repositories |
| `framework` | internal engineering frameworks that carry policy, schema, test, and release-governance assets |
| `infrastructure` | Terraform, Kubernetes, and deployment-control repositories |
| `library` | shared libraries consumed by application repositories |
| `documentation` | documentation-only repositories |

Production repositories inherit the `application` profile by default. The `framework` profile is the only profile allowed to classify approved regression fixture paths as non-blocking. Gitleaks still runs, fixture scans remain detectable, and unknown hidden files continue to fail.

## Evidence

```yaml
evidence:
  required_fields:
    - business purpose
    - testing performed
    - rollback strategy
    - linked issue
  screenshots_required_for_ui_changes: true
```

Evidence validation reads the pull request body. It fails if required sections are empty or still contain template placeholder text.

## Runtime

```yaml
runtime:
  install_dependencies: true
  allow_network_installs: true
  fail_fast_on_secrets: true
```

`fail_fast_on_secrets` stops later gates after secret detection fails, while still generating the final report.

## phpMyAdmin Policy

Repository governance may document phpMyAdmin posture without storing secrets:

```yaml
phpmyadmin:
  local_allowed: true
  development_allowed: true
  access:
    application_scoped: true
    shared_company_admin: false
    owner_role: Application owner
    developer_group: application-developers
  environments:
    - branch: development
      environment: development
      server: dev.example.internal
      database: example_dev
      phpmyadmin_url: https://dev.example.internal/phpmyadmin
      status: configured
    - branch: staging
      environment: staging
      server: uat.example.internal
      database: example_uat
      phpmyadmin_url: https://uat.example.internal/phpmyadmin
      status: configured
  staging:
    allowed: true
    require_authentication: true
    require_database_isolation: true
    require_environment_secrets: true
    prefer_network_restriction: true
  production:
    allowed: false
    block_runtime_exposure: true
```

Production phpMyAdmin exposure is enforced by the reusable production gate, not by a feature-to-development or development-to-staging blocker. Staging/UAT phpMyAdmin is allowed only when it authenticates users, uses environment-specific secrets, and does not connect to production databases.

`environments` maps Git branches to actual runtime environments. Do not fill this from branch names alone; map only verified servers and databases. Use `status: not_configured` when the branch exists but no development/staging phpMyAdmin runtime exists.

`access.application_scoped` must remain `true`, and `access.shared_company_admin` must remain `false`. Developer phpMyAdmin access is per application and per environment, not a company-wide shared DBA account.

The governance config must not contain credential keys or secret values. Store phpMyAdmin database users, passwords, host secrets, and authentication material in the existing environment secret store or server configuration.

## Adapter Overrides

```yaml
adapters:
  node:
    lint_script_names:
      - lint
    build_script_names:
      - build
      - production
    test_script_names:
      - test
  docker:
    build_images: false
  terraform:
    init_backend: false
```

Adapter overrides must stay declarative. Do not put business logic in `.github/pr-qa.yml`.

Repository configuration is loaded from the base branch only. Changes to `.github/pr-qa.yml` in the pull request are not trusted for the current run and are reported as protected policy changes.
