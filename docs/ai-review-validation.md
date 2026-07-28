# AI Review Validation Report

Status: prepared for governed pull request review

## Scope

This report covers the Version 1.1 AI Pull Request Review automation.

The enhancement is advisory and does not publish, roll out, merge, bypass protections, or modify application repositories.

## Automated Validation

| Requirement | Test Evidence |
| --- | --- |
| Review only changed lines | `tests/test_ai_review.py::test_context_filters_non_reviewable_files_and_collects_changed_lines` |
| Ignore generated/vendor/lock/binary/fixture files | `tests/test_ai_review.py::test_context_filters_non_reviewable_files_and_collects_changed_lines` |
| Normalize provider findings to advisory inline comments | `tests/test_ai_review.py::test_provider_findings_are_normalized_redacted_and_advisory_only` |
| Redact secrets in AI observations | `tests/test_ai_review.py::test_provider_findings_are_normalized_redacted_and_advisory_only` |
| Use AI namespace without touching QA comments | `tests/test_ai_review.py::test_execute_ai_review_publishes_ai_namespace_without_touching_qa_comments` |
| Remove stale AI comments after successful rerun | `tests/test_ai_review.py::test_execute_ai_review_publishes_ai_namespace_without_touching_qa_comments` |
| Provider outage does not delete comments or fail QA | `tests/test_ai_review.py::test_unavailable_provider_does_not_remove_existing_comments` |
| AI does not run when Enterprise QA has blocking findings | `tests/test_ai_review.py::test_ai_review_skips_when_enterprise_qa_has_blocking_findings` |
| AI comment format includes severity, category, observation, why, recommendation | `tests/test_review_comments.py::test_ai_comments_use_separate_namespace_and_staff_review_format` |
| QA inline comments still de-duplicate/update/remove | `tests/test_review_comments.py` |

## Review Objective Coverage

The provider instruction schema covers:

- architecture
- design consistency
- maintainability
- readability
- code duplication
- possible bugs
- null handling
- error handling
- performance
- security observations
- race conditions
- API misuse
- resource leaks
- dead code
- naming
- test coverage observations
- framework best practices

The provider must return file/line findings. The framework publishes only findings that map to changed diff lines.

## Manual End-to-End Validation Required

Before publication, validate on a governed test pull request with an approved provider endpoint configured:

| Scenario | Expected Result |
| --- | --- |
| Architecture observation | Inline AI comment appears on the changed line. |
| Maintainability observation | Inline AI comment appears on the changed line. |
| Performance suggestion | Inline AI comment appears on the changed line. |
| Potential bug | Inline AI comment appears on the changed line. |
| Security suggestion | Inline AI comment appears with sensitive values redacted. |
| Code duplication | Inline AI comment appears on one changed duplicated block. |
| Null handling | Inline AI comment appears on the affected line. |
| Naming improvement | Inline AI comment appears on the changed declaration or usage. |
| New commit fixes finding | Obsolete AI comment is removed. |
| New commit changes same finding | Existing AI comment is updated or moved according to the diff. |
| Provider unavailable | AI Review unavailable is reported; Enterprise QA result is unchanged. |
| Enterprise QA fails | AI Review does not run. |

## Evidence Artifacts

Successful AI Review writes:

```text
pr-qa-results/ai-review-report.md
pr-qa-results/ai-review-report.json
```

Unavailable AI Review writes the same artifacts with `status: UNAVAILABLE`.

## Governance Evidence

- AI Review runs only after final Enterprise QA exits successfully.
- AI Review comments use `synergie-ai-review:inline-review`.
- Enterprise QA comments use `synergie-pr-qa:inline-review`.
- No AI finding has merge-blocking authority.
- GitHub Branch Protection and Executive Release Authority remain authoritative.
