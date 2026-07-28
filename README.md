# Synergie Organisation PR QA Framework

This bundle implements a reusable Pull Request Quality Assurance framework for Synergie GitHub repositories.

It validates and reports. It does not approve, merge, deploy, bypass repository rules, modify CODEOWNERS, or change Branch Protection.

## Architecture

- Central reusable workflow: `.github/workflows/pr-qa.yml` in `Synergie-ITCI/.github`
- Central QA engine: `pr-qa/pr_qa.py`
- Technology adapters: `pr-qa/adapters/`
- Per-repository caller workflow: `.github/workflows/pr-qa.yml`
- Per-repository configuration: `.github/pr-qa.yml`
- Standard PR template: `.github/pull_request_template.md`

## Quick Start

1. Commit this bundle into the `Synergie-ITCI/.github` repository.
2. In a pilot repository, copy `examples/caller-workflow.yml` to `.github/workflows/pr-qa.yml`.
3. In the same repository, copy `examples/pr-qa.yml` to `.github/pr-qa.yml` and tune only thresholds or adapter overrides.
4. Copy `examples/pull_request_template.md` to `.github/pull_request_template.md`.
5. Open a pull request and review the single `PR QUALITY REPORT` job summary.

## Quality Gates

The engine runs the common gates requested in the mission:

1. Repository Hygiene
2. Formatting
3. Lint
4. Build
5. Testing
6. Git Validation
7. Secret Detection
8. Dependency Security
9. Licence Compliance
10. Deployment Safety
11. Database Safety
12. Documentation
13. Protected Resource Validation
14. Advisory Architecture Review
15. Risk Engine
16. Evidence Validation

## Extension Model

Adding a new ecosystem requires one adapter module under `pr-qa/adapters/` and one registry entry in `pr-qa/adapters/__init__.py`.

Adapters must:

- detect their own project roots
- run validation only, never auto-fix
- return PASS, WARNING, or FAIL
- avoid deployment or infrastructure mutation
- keep missing optional tooling as WARNING unless the repository config makes it mandatory

## Documents

- [Release Candidate 2](releases/rc2/README.md)
- [v1.0 Production Introduction Runbooks](operations/v1.0-publication/README.md)
- [Administrator Guide](docs/administrator-guide.md)
- [Repository Onboarding Guide](docs/onboarding-guide.md)
- [Technology Adapter Guide](docs/technology-adapters.md)
- [Configuration Schema](docs/configuration-schema.md)
- [Rollout Strategy](docs/rollout-strategy.md)
- [Validation Report](docs/validation-report.md)
- [Migration Guide](docs/migration-guide.md)
- [Security Hardening Report](docs/security-hardening-report.md)
- [Before vs After Comparison](docs/before-after-comparison.md)
- [Residual Risk Register](docs/residual-risk-register.md)
- Sample reports: `examples/reports/`
