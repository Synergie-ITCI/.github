# PR QA V1.1 Security Remediation Matrix

Status: prepared for governed pull request review

## Scope

This remediation addresses the five confirmed release blockers found during independent release approval for PR #9. It does not change Enterprise QA gate behavior, merge governance, Branch Protection, CODEOWNERS, or application repositories.

## Remediation Matrix

| Blocker | Root Cause | Implemented Control | Affected Files | Regression Test | Result |
| --- | --- | --- | --- | --- | --- |
| Token-bearing code execution | Repository commands could run before later framework scripts received `GITHUB_TOKEN` or provider credentials. | Split the reusable workflow into read-only untrusted `detect`/`qa` jobs and a fresh trusted `publisher` job. Each framework checkout uses `Synergie-ITCI/.github@pr-qa-v1.1`, and the publisher never checks out PR code. | `.github/workflows/pr-qa.yml` | `tests/test_pr_qa_regressions.py::test_workflow_has_no_framework_override_or_checkout_credentials` | FIXED |
| Require authoritative QA PASS | AI Review accepted missing or incomplete QA evidence as non-failing. | Added strict QA evidence validation requiring schema version, completion, sanitisation PASS, matching repository, PR number, head SHA, and explicit `PASS`. | `pr-qa/evidence.py`, `pr-qa/ai_review.py`, `pr-qa/pr_qa.py` | `tests/test_ai_review.py::test_authoritative_qa_evidence_fail_closed_cases`, `tests/test_ai_review.py::test_authoritative_qa_pass_evidence_allows_ai_review` | FIXED |
| Provider destination governance | Provider token and PR context could be sent to any non-empty URL. | Added HTTPS-only exact host allowlist, embedded credential rejection, localhost/loopback/link-local/private network rejection, optional governed internal-provider allowlist, and disabled redirects. | `pr-qa/ai_review.py` | `tests/test_ai_review.py::test_provider_destination_governance`, `tests/test_ai_review.py::test_redirects_are_disabled_for_provider_requests` | FIXED |
| Failure-safe comment synchronisation | Existing comments could be deleted before replacement review creation succeeded. | Changed lifecycle to plan first, create replacements first, re-check head, then update/delete cleanup last. Publication failure preserves existing evidence. | `pr-qa/review_comments.py` | `tests/test_review_comments.py::test_create_review_failure_preserves_existing_comments`, `tests/test_review_comments.py::test_head_change_after_publication_preserves_existing_cleanup_targets` | FIXED |
| Current head SHA verification | Stale reruns could publish, update, or delete comments after a newer commit. | Publisher validates QA evidence head SHA and review comment sync verifies the current PR head SHA immediately before publication and cleanup. | `pr-qa/evidence.py`, `pr-qa/review_comments.py`, `pr-qa/ai_review.py` | `tests/test_review_comments.py::test_stale_head_skips_publication_without_modifying_comments` | FIXED |

## Direct Hardening

| Hardening | Control | Regression Test | Result |
| --- | --- | --- | --- |
| Narrow permissions | Only the trusted `publisher` job has `pull-requests: write`; untrusted QA remains `contents: read`. | `tests/test_pr_qa_regressions.py::test_workflow_has_no_framework_override_or_checkout_credentials` | FIXED |
| Comment ownership | Managed comments require both the namespace marker and trusted bot author. | `tests/test_review_comments.py::test_copied_namespace_marker_from_user_is_not_managed` | FIXED |
| Malicious artifacts | Evidence bundle rejects unexpected files, executable payloads, directories, symlinks, and oversized files. | `tests/test_ai_review.py::test_malicious_evidence_artifact_files_are_rejected`, `tests/test_ai_review.py::test_symlink_evidence_artifact_is_rejected` | FIXED |
| Merge queue behavior | Caller example includes `merge_group`; inline comments remain pull-request-only. | `tests/test_pr_qa_regressions.py::test_workflow_has_no_framework_override_or_checkout_credentials`, `actionlint` | FIXED |

## Security Invariants

- Untrusted repository commands never run with provider credentials.
- Untrusted repository commands never run with pull request write authority.
- Trusted publisher code comes from `Synergie-ITCI/.github@pr-qa-v1.1`.
- Downloaded artifacts are treated as validated data only.
- AI executes only after authoritative explicit QA PASS.
- Provider credentials are sent only to approved HTTPS destinations.
- Stale runs cannot publish or remove review evidence.
- Existing evidence survives publication failure.
- AI remains advisory.
- Enterprise QA remains the deterministic merge gate.
- Provider failure remains fail-open for the pull request.
- No security control is weakened.
