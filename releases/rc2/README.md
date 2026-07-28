# Synergie PR QA Framework RC2

Release candidate: RC2

Release version: `pr-qa-v1-rc2`

Release date: 2026-07-28

Publication status: not deployed, not tagged, not published.

## Scope

RC2 resolves only the verified previous publication blockers:

- release identity standardisation
- documentation consistency
- configuration documentation validity
- real-repository publication verification checklist preparation
- publication package audit

No functionality, architecture, gates, governance model, application repositories, rollout workflows, Branch Protection rules, or CODEOWNERS files were changed.

## Release Identity

The single release identity for RC2 is:

```text
pr-qa-v1-rc2
```

All active workflow references, caller workflow references, release notes, validation reports, release checklist items, and publication instructions refer to `pr-qa-v1-rc2`.

## Changes In RC2

| Area | RC2 Change | Reason |
| --- | --- | --- |
| Release identity | Standardised workflow and caller refs on `pr-qa-v1-rc2` | Removes release-reference ambiguity |
| Documentation | Reconciled README, validation report, residual risks, known limitations, and release checklist state | Prevents overstated readiness |
| Configuration examples | Quoted regex examples in documentation | Ensures YAML examples remain valid and schema-compatible |
| Publication package | Added explicit real-GitHub publication checklist and readiness report | Separates engineering readiness from operational publication |

## Breaking Changes

No new RC2 breaking changes were introduced.

The hardened framework behavior remains:

- mandatory gates cannot be disabled by repository configuration
- repository configuration is trusted from the base branch only
- Gitleaks is mandatory
- caller workflows must use the immutable `pr-qa-v1-rc2` release reference
- caller-controlled framework refs, config paths, runner labels, and timeouts are not supported
- mandatory scanner/tooling gaps fail closed

## Upgrade Guide

From the legacy central workflow:

1. Publish the RC2 framework bundle to the central `Synergie-ITCI/.github` repository after approval.
2. Create and protect the `pr-qa-v1-rc2` release reference during publication.
3. Replace caller references to `reusable-pr-quality-gate.yml@main` with:

```yaml
uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@pr-qa-v1-rc2
```

4. Remove caller-provided framework/config/runner/timeout inputs.
5. Validate repository config with:

```bash
check-jsonschema --schemafile schemas/pr-qa.schema.json examples/pr-qa.yml
```

6. Complete the real-GitHub publication checklist before rollout.

## Package Contents

- [Validation Report](VALIDATION_REPORT.md)
- [Residual Risk Register](RESIDUAL_RISK_REGISTER.md)
- [Release Checklist](RELEASE_CHECKLIST.md)
- [Known Limitations](KNOWN_LIMITATIONS.md)
- [Publication Checklist](PUBLICATION_CHECKLIST.md)
- [Publication Readiness Report](PUBLICATION_READINESS_REPORT.md)
- [Package Audit](PACKAGE_AUDIT.md)

## RC2 Result

RC2 is ready for real-GitHub publication verification.

RC2 is not yet published. The remaining activities are operational publication checks that must be completed in the actual central Git repository and GitHub Actions environment.
