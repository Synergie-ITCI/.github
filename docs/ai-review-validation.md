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
| AI does not run without authoritative Enterprise QA PASS evidence | `tests/test_ai_review.py::test_authoritative_qa_evidence_fail_closed_cases` |
| Valid Enterprise QA PASS evidence permits AI review | `tests/test_ai_review.py::test_authoritative_qa_pass_evidence_allows_ai_review` |
| Provider endpoint must be approved HTTPS destination | `tests/test_ai_review.py::test_provider_destination_governance` |
| Provider redirects are disabled | `tests/test_ai_review.py::test_redirects_are_disabled_for_provider_requests` |
| Malicious executable evidence artifacts are rejected | `tests/test_ai_review.py::test_malicious_evidence_artifact_files_are_rejected` |
| Symlink evidence artifacts are rejected | `tests/test_ai_review.py::test_symlink_evidence_artifact_is_rejected` |
| AI comment format includes severity, category, observation, why, recommendation | `tests/test_review_comments.py::test_ai_comments_use_separate_namespace_and_staff_review_format` |
| Stale workflow runs cannot publish comments | `tests/test_review_comments.py::test_stale_head_skips_publication_without_modifying_comments` |
| Head changes before cleanup preserve existing evidence | `tests/test_review_comments.py::test_head_change_after_publication_preserves_existing_cleanup_targets` |
| Review creation failure preserves existing comments | `tests/test_review_comments.py::test_create_review_failure_preserves_existing_comments` |
| User-copied namespace marker is not managed | `tests/test_review_comments.py::test_copied_namespace_marker_from_user_is_not_managed` |
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
| Enterprise QA fails | AI Review reports unavailable; no provider request is made and no AI comments are modified. |
| QA evidence missing, malformed, mismatched, stale, or incomplete | AI Review unavailable is reported; no existing AI comments are modified or deleted. |
| Provider host not in allowlist | AI Review unavailable is reported; no provider request is made. |
| Older run completes after force-push | Inline publication is skipped and the newer run owns the latest commit. |

## Evidence Artifacts

Successful AI Review writes:

```text
pr-qa-ai-review-results/ai-review-report.md
pr-qa-ai-review-results/ai-review-report.json
```

Unavailable AI Review writes the same artifacts with `status: UNAVAILABLE`.

## Governance Evidence

- AI Review runs only after final Enterprise QA emits validated explicit PASS evidence for the same repository, PR number, and head SHA.
- AI Review comments use `synergie-ai-review:inline-review`.
- Enterprise QA comments use `synergie-pr-qa:inline-review`.
- The trusted publisher job is the only job with `pull-requests: write`.
- Provider credentials are available only inside the trusted publisher job.
- No AI finding has merge-blocking authority.
- GitHub Branch Protection and Executive Release Authority remain authoritative.
