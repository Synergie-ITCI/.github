# Synergie Branch and Release Governance

## Permanent Model

Synergie repositories use four simple gates:

### Gate A — Code / CI

Normal engineering work moves through:

`feature → development`

Developers may create, test, review, and merge normal feature work without Saurabh involvement, subject to repository CI and branch rules.

Permanent automated controls include:

- Architecture Governance
- Pull Request Quality Assurance
- security and secret checks
- migration safety
- repository integrity
- technical risk detection
- QA/risk/delta evidence

### Gate B — Staging

Validated development moves through:

`development → staging`

This is a developer/self-service engineering promotion.

Saurabh approval is not required merely to place validated work on staging.

Staging must remain representative of the release candidate and must use controlled deployment with health verification.

### Gate C — Release QA to Main

Promotion from:

`staging → main`

requires explicit Saurabh release QA/authorization.

The authorization is for the exact release being promoted.

Saurabh may authorize a release he authored; GitHub native self-review limitations must not create a governance deadlock.

Main represents the approved release baseline.

### Gate D — Production

Production is separate from Gate C.

Moving code to `main` MUST NOT automatically deploy production.

Production deployment requires a separate explicit Saurabh approval.

The deployment must use the exact approved SHA/artifact and preserve a verified rollback/recovery path.

## Permanent Principles

- No routine governance bootstrap process.
- No enrollment/provenance/candidate-ID machinery.
- No one-time deployment-risk authorization registry.
- No generic administrator bypass as the normal release path.
- Automated technical QA remains mandatory where configured.
- Saurabh approval is required only at Gate C and Gate D.
- Production deployment is never implied by merge to main.
- Recovery capability is mandatory for production.
- Historical Governance V2 records may remain archived for audit history only; they are not active policy.

## Required Status Checks

The canonical permanent status checks are:

- `Architecture Governance`
- `Pull Request Quality Assurance / Pull Request Quality Assurance`

Repository-specific callers may render the PR-QA job context according to the caller workflow name; repository rulesets must require the exact context actually emitted by that repository.

## Pilot Validation

This model was live-proven using:

- Programme Management Platform
- Telemedicine Backend

Both pilots validated controlled CI, staging promotion, release governance, and secure AWS deployment without retaining Governance V2 machinery.
