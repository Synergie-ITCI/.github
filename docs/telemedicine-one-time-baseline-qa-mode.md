# Telemedicine One-Time Production Baseline QA Mode

## Purpose

Telemedicine backend predates the current Synergie lifecycle and its `main` branch is a governance shell rather than the real Laravel application baseline. The one-time baseline mode exists only to let `Synergie-ITCI/telemedicine-backend` establish the first application baseline on `main` through a reviewed pull request.

The normal lifecycle remains:

`feature -> development -> staging -> QA -> main -> production`

This mode is not a deployment approval and is not a general QA bypass.

## Authorization

Baseline mode fails closed unless all central-policy authorization fields match:

- repository: `Synergie-ITCI/telemedicine-backend`
- source branch: `release/production-baseline-alignment-20260812`
- target branch: `main`
- expected source SHA: `f1689d9cb6d9c3276006915275257a178f50154d`
- expected destination SHA: `9d2684e82f466d3e1d2a40695f1b2987ec1906c8`
- PR body marker: `ONE-TIME TELEMEDICINE PRODUCTION BASELINE AUTHORIZATION`
- expiry: `2026-08-20T23:59:59Z`

The mode may be requested by `PR_QA_BASELINE_ALIGNMENT=true` or the `one-time-baseline-alignment` label, but request alone is not authorization.

## Source Plus Overlay Authorization

The Telemedicine baseline PR is authorized as:

approved staging application source plus a restricted governance overlay.

The approved application source remains `f1689d9cb6d9c3276006915275257a178f50154d`. The candidate PR head may differ only because the branch must preserve approved governance files from `main` and move the PR QA caller from `pr-qa-v1-rc5` to the next immutable governance release.

The only allowed overlay paths are:

- `.github/CODEOWNERS`
- `.github/actionlint.yaml`
- `.github/workflows/pr-qa.yml`

No application path, route, configuration, migration, Composer file, environment file, deployment workflow, UAT operations workflow, or arbitrary `.github/**` path is included in the overlay allowance. The PR QA caller content must be the approved workflow with only the central QA ref changed from `pr-qa-v1-rc5` to the released baseline governance ref.

## PR #29 Failure Mapping

| Check | Normal Purpose | Baseline Relevance | Relaxable? |
| --- | --- | --- | --- |
| Repository integrity hidden/generated/binary checks | Blocks suspicious hidden files, generated artifacts, unsafe binaries | `.env.testing`, generated static content, and one known `.docx` first appear in `main` as historical baseline content | Yes, exact safe paths only |
| Repository hygiene branch/commits/merge commits | Enforces branch and commit policy | Historical lineage predates new governance | Yes, only under exact baseline authorization |
| Git diff whitespace/conflict checks | Catches whitespace errors and conflict markers | Conflict markers/whitespace are real defects | No |
| Gitleaks | Detects committed secrets | Historical false positives exist in tests/config references | Yes, exact fingerprint only; Gitleaks still runs |
| Fallback secret scan | Catches env files and simple token/password assignments | Safe templates and deterministic UAT fixtures exist | Yes, exact env classification or line hash only |
| Executable classification | Ensures executable files have adapters | Shell scripts need coverage | No bypass; shell adapter added |
| Protected resources/CODEOWNERS | Enforces owner review on protected paths | Protected files are present in baseline | No |
| Deployment/workflow risk | Prevents silent production deployment architecture changes | Staging workflows differ from `main` | No |
| Migration risk | Flags destructive database operations | 117 historical migrations should not fail due to count alone | Count relaxed; forward destructive detection and execution evidence remain mandatory |
| Composer audit/dependencies | Blocks vulnerable dependencies | Current staging evidence says Composer audit is clean | No |
| PHP lint/tests | Proves application syntax and behavior | Current staging evidence says lint/tests pass | No |
| Risk engine size thresholds | Blocks oversized ordinary PRs | Initial baseline is inherently large | Yes, size/count only |

## Non-Relaxable Gates

Baseline mode keeps these gates mandatory:

- Gitleaks execution and true-secret detection
- Composer/dependency audit
- language syntax/lint and application tests
- migration syntax/executability evidence
- CODEOWNERS, human review, required checks, and branch protection
- deployment and workflow-security review
- dangerous credential files and suspicious binaries

## Relaxations

The central policy allows only these one-time relaxations:

- `diff_size`
- `changed_file_count`
- `historical_commit_volume`
- `historical_migration_count`
- `generated_static_baseline_content`
- `baseline_binary_assets`
- `environment_fixture_classification`
- `exact_gitleaks_fingerprint_allowlist`
- `exact_secret_fallback_allowlist`

All relaxations are scoped to the authorized Telemedicine backend baseline and expire with the policy authorization.

## Environment Files

The policy does not allow `.env*` globally. It classifies only these known files when their required markers are present and forbidden real-secret patterns are absent:

- `.env.example`
- `.env.testing`
- `.env.testing.example`
- `.env.uat.template`

Actual environment files, real credential values, private keys, GitHub tokens, AWS access keys, and non-placeholder secret values remain blocking.

## Gitleaks Handling

Gitleaks remains mandatory. The policy contains 29 exact historical fingerprints observed in the Telemedicine staging-vs-main baseline scan. Each entry records rule, path, line, fingerprint, justification, scope, and expiry. A new Gitleaks finding in an allowlisted file still fails unless it matches one of those exact fingerprints and has not expired.

## Migration Handling

Baseline mode relaxes migration volume as a blocker. It does not approve running migrations against production.

The gate still reports migration count, scans the forward migration path for destructive operations, flags rollback/down-method destructive operations for production DB review, and relies on application QA for fresh migration execution.

## Workflow Handling

Deployment-sensitive files and workflow changes are not waived. If the Telemedicine baseline contains `.github/workflows/deploy.yml` or related workflow changes, PR QA will flag them prominently and fail high-risk workflow/deployment changes as before. Production deployment architecture must be approved separately.

## One-Time Removal

After the Telemedicine baseline PR merges, remove or disable `one_time_baseline_alignment` in `policy/pr-qa-policy.json`, or let it expire. Ordinary PR size, changed-file, migration-count, generated-file, hidden-file, binary, and history rules then apply automatically again.

## Telemedicine Next Step

After this governance change is merged and released through the normal governance process, create `release/production-baseline-alignment-20260812` in `Synergie-ITCI/telemedicine-backend` from the approved staging application source at `f1689d9cb6d9c3276006915275257a178f50154d`, apply only the restricted governance overlay, open the PR to `main`, include the required authorization marker in the PR body, and ensure the caller workflow references the approved governance release that contains this mode.
