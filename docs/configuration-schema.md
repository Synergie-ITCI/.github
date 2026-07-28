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
  criticality: medium
  protected_paths:
    - .github/**
    - deployment/**
    - terraform/**
```

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
    - '^(feat|fix|docs|style|refactor|test|chore|build|ci|perf|security|revert)(\([^)]+\))?: .+'
```

Patterns are regular expressions.

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
