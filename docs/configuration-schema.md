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
    - '^(feat|fix|docs|style|refactor|test|chore|build|ci|perf|security|release|promote|revert)(\([^)]+\))?: .+'
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
    database_scoped: true
    cross_application_access: false
    unrestricted_database_admin: false
    owner_role: Application owner
    developer_group: application-developers
  environments:
    - branch: development
      environment: development
      server: dev.example.internal
      database: example_dev
      database_user_identity: example_dev_phpmyadmin
      database_scope: example_dev
      phpmyadmin_url: https://dev.example.internal/phpmyadmin
      status: configured
    - branch: staging
      environment: staging
      server: uat.example.internal
      database: example_uat
      database_user_identity: example_uat_phpmyadmin
      database_scope: example_uat
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

Production phpMyAdmin exposure is enforced by the reusable production gate, not by a feature-to-development or development-to-staging blocker. Development and staging/UAT phpMyAdmin are allowed only when they authenticate users, use environment-specific secrets, and connect through a database identity limited to that application's non-production database.

`environments` maps Git branches to actual runtime environments. Do not fill this from branch names alone; map only verified servers, databases, database user identities, and database scopes. Use `status: not_configured` when the branch exists but no development/staging phpMyAdmin runtime exists.

`access.application_scoped` and `access.database_scoped` must remain `true`. `access.shared_company_admin`, `access.cross_application_access`, and `access.unrestricted_database_admin` must remain `false`. Developer phpMyAdmin access is per application and per environment, not a company-wide shared DBA account and not unrestricted database administration.

The governance config must not contain credential keys or secret values. Store phpMyAdmin database users, passwords, host secrets, and authentication material in the existing environment secret store or server configuration.

## Recovery Manifest

Every deployable application repository must publish `.github/synergie-recovery.yml`.
The manifest is validated by `.github/workflows/recovery-readiness.yml` and
`tools/recovery_policy.py`.

Minimum fields include:

```yaml
application_name: Example
repository: Synergie-ITCI/example
runtime: node
runtime_version: "20"
framework: express
framework_version: "4"
build_commands:
  - npm ci
  - npm run build
dependency_manifests:
  - package.json
dependency_lockfiles:
  - package-lock.json
required_source_paths:
  - src/
required_asset_paths:
  - public/app-assets/
git_lfs_paths: []
external_artifact_locations: []
environment_template: .env.example
secret_references:
  - /synergie/example/production/app
database_engine: postgres
database_backup_strategy: AWS Backup daily encrypted backup.
database_restore_reference: runbooks/database-restore.md
persistent_upload_locations: []
persistent_storage_backup_strategy: No persistent uploads.
web_server_template: deploy/nginx.conf
scheduled_jobs: []
service_definitions: []
deployment_method: github-actions-release-artifact
production_target_reference: aws-account/ap-south-1/example-production
health_checks:
  - https://example.invalid/health
rollback_method: Restore previous SHA-256 verified artifact.
rto_target: 4h
rpo_target: 24h
recovery_owner_role: Example Platform Owner
```

Production certification additionally requires:

```yaml
server_file_audit:
  last_audit_reference: runbooks/server-file-audit.md
  recovery_critical_server_only_count: 0
deployment_traceability:
  commit_marker: .deployed_commit
  artifact_manifest: release-manifest.json
  artifact_checksum_algorithm: sha256
  release_artifact_retention: keep last 10 releases
```

The manifest must not contain secret values. Required source and asset paths must
not be excluded by `.gitignore`, `.git/info/exclude`, packaging ignore files, or
artifact ignore files unless they are mapped to Git LFS or an approved external
artifact entry with URI, SHA-256 checksum, and immutable/versioned storage.

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
