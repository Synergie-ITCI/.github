# Security Hardening Report

Generated: 2026-07-28

## Scope

Framework only:

- reusable workflow
- Python QA engine
- technology adapters
- central policy
- configuration schema
- caller workflow
- documentation
- regression suite

No application repositories, deployments, GitHub settings, Branch Protection, merges, or CODEOWNERS files were changed.

## Original Critical Findings

| Finding | Status | Implementation Evidence | Test Evidence | Remaining Risk |
| --- | --- | --- | --- | --- |
| PR-controlled config can disable mandatory gates | CLOSED | Immutable policy in `policy/pr-qa-policy.json`; base-branch config loading and mandatory-gate validation in `pr-qa/pr_qa.py` | `test_pr_cannot_disable_mandatory_gates` | Central policy changes must be reviewed in `Synergie-ITCI/.github`. |
| Repository code runs before secret scanning | CLOSED | Workflow runs `--static-only` before setup/build/test; engine skips later phases on Phase 1 failure | `test_malicious_install_hook_does_not_execute_when_static_fails` | GitHub checkout itself still materializes PR files, but no repo command executes before static preflight. |
| Checkout credentials persisted | CLOSED | All checkout steps use `persist-credentials: false` | `test_workflow_has_no_framework_override_or_checkout_credentials` | GitHub-hosted runner isolation is still required operationally. |
| Raw command output uploaded in artifacts | CLOSED | `CommandOutcome.sanitized_dict()` records redacted excerpts only; JSON report redacts result details | `test_output_redaction_removes_fake_tokens` | External tools may still write their own files; keep artifacts scoped to `pr-qa-results`. |
| Caller-controlled framework ref | CLOSED | `framework-ref` input removed; caller uses `@pr-qa-v1-rc2`; central checkout uses literal `ref: pr-qa-v1-rc2` | `test_workflow_has_no_framework_override_or_checkout_credentials` | Release tag governance must prevent tag mutation. |

## Original High Findings

| Finding | Status | Implementation Evidence | Test Evidence | Remaining Risk |
| --- | --- | --- | --- | --- |
| Strict runtime schema validation | CLOSED | Strict schema in `schemas/pr-qa.schema.json`; runtime config validation in `validate_repo_config()` | Regression config-disable test | `jsonschema` package not installed locally, so standards-compliant schema validation was not run locally. |
| Base branch CODEOWNERS | CLOSED | `load_base_codeowners()` reads CODEOWNERS from base SHA only | `test_codeowners_modification_fails` | Actual review approval remains enforced by Branch Protection. |
| Protected resource verification | PARTIALLY CLOSED | CODEOWNERS modification and missing base coverage fail closed | `test_codeowners_modification_fails` | Local engine cannot verify live GitHub review state without API integration. Compensating control: Branch Protection remains required merge authority. |
| Mandatory Gitleaks | CLOSED | `run_gitleaks()` fails if unavailable | Regression suite uses fake gitleaks to validate control path | Local machine does not have real Gitleaks installed. |
| Encoded secrets missed | CLOSED | Base64 decoding and UTF-16/Latin-1 text variants in fallback scanner | `test_base64_secret_is_detected` | Highly custom encodings still need Gitleaks/custom rules. |
| Technology detection misses executable code | CLOSED | `gate_executable_classification()` fails unknown executable extensions | `test_unknown_executable_language_fails` | New languages require adding adapter coverage or policy extensions. |
| Nested dependency/generated artifact bypass | CLOSED | Repository integrity checks path components, not only root globs | `test_nested_node_modules_is_generated_artifact_failure` | Some legitimate generated snapshots may need central allowlisting. |
| Migration parser too weak | CLOSED | Collapsed-token destructive operation detection plus framework-specific migration calls | `test_obfuscated_destructive_migration_fails` | Full AST/database parser coverage is future hardening, but prior bypass is closed. |
| Dependency audit warnings instead of enforcement | CLOSED | Adapters now fail when mandatory audit tooling/lockfiles are unavailable | Unit syntax/import validation | Repositories must install required audit tooling or configure approved central runner images. |
| Licence classification flags LGPL as GPL | CLOSED | `restricted_license_hit()` treats LGPL separately | Unit-level redaction/import validation | Full licence inventory still depends on ecosystem metadata/tooling. |

## Final Verdict

PASS WITH CONDITIONS.

The verified critical findings are closed. High findings are closed or have explicit compensating controls where local-only execution cannot verify live GitHub review state.

Recommendation: READY FOR CONTROLLED PILOT, not organisation-wide rollout yet.
