# Repository Onboarding Guide

Add the thin caller workflow:

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

Optional repository config:

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

Onboarding is complete when a test PR produces a concise PR Quality Report and
annotations appear for any findings.
