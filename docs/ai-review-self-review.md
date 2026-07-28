# AI Review Automation Self-Review

Status: completed before governed pull request update

## Design Risks Reviewed

| Risk | Mitigation |
| --- | --- |
| AI review could be mistaken for a merge gate | Reports and docs state AI Review is advisory only; findings include `blocking: false`; workflow step uses `continue-on-error: true`. |
| AI could run before QA | AI Review requires validated Enterprise QA evidence with schema version 1, report completion, sanitisation PASS, matching repository, PR number, head SHA, and explicit `PASS` status. Missing, malformed, failed, warning, mismatched, or stale evidence reports AI Review unavailable. |
| Repository-controlled commands could alter publisher code before tokens are used | The workflow separates read-only untrusted QA from the trusted publisher job. The publisher starts on a fresh runner, checks out only `Synergie-ITCI/.github@pr-qa-v1.1`, and never checks out or executes PR repository code. |
| Workflow could check out a stale framework tag | Callers and internal framework checkouts use the pending immutable `pr-qa-v1.1` release reference. Publication must create and protect the tag only after governed review. |
| Provider outage could hide unresolved comments | If the provider is unavailable, comment synchronization is not executed and existing AI comments are left untouched. |
| AI comments could collide with QA comments | AI uses `synergie-ai-review:inline-review`; QA uses `synergie-pr-qa:inline-review`. Each lifecycle run edits only its own namespace. |
| Review spam on repeated commits | Existing comments are matched by stable fingerprint and trusted bot author, updated when possible, and stale comments are removed only after successful publication and current-head verification. |
| Force-push changes diff positions | The lifecycle manager validates every finding against the current GitHub PR diff and verifies the PR head SHA immediately before publication and again before cleanup. Stale runs skip all modifications. |
| Provider could return comments outside the PR diff | The service rejects findings whose `path` and `line` are not present in the current reviewable changed-line set. |
| Provider could duplicate Enterprise QA | Provider instructions explicitly exclude build, tests, secrets, dependency scanning, deployment safety, migration safety, and repository governance. |
| Provider could leak secrets or internal endpoints | Diff context and comments are redacted. Provider URLs must be HTTPS, exact-host allowlisted, credential-free, non-local, and non-private unless explicitly governed as internal. |
| Provider could review generated or dependency files | Generated directories, vendor directories, binary files, lock files, and framework regression fixtures are filtered before provider invocation. |
| Comment API limits could create excessive reviews | Findings are capped and batched into one submitted GitHub Pull Request review. |
| Missing provider credentials could fail QA | Missing provider configuration produces `AI Review unavailable` and exits successfully. |
| Failed comment publication could delete previous evidence | New review comments are published before obsolete comments are removed. If publication fails, existing comments are preserved. |
| User-created comments could be modified by copying a hidden marker | Managed comments must contain the expected marker and be authored by the trusted GitHub Actions bot identity. |

## Operational Edge Cases

| Edge Case | Behavior |
| --- | --- |
| No reviewable changed files | AI Review completes with zero findings and removes stale AI comments after successful execution. |
| Enterprise QA has blocking failures | AI Review unavailable is reported and no provider request is made. |
| Provider returns invalid JSON | AI Review reports unavailable and does not delete existing AI comments. |
| GitHub comment publication fails | AI Review reports unavailable; Enterprise QA remains unchanged. |
| Provider returns missing explanation or recommendation | The finding is rejected and not published. |
| Provider returns unsupported severity | Severity is normalized to `INFO`. |
| Evidence artifact contains unexpected executable file or symlink | Evidence validation fails and no comments are published or deleted. |
| Older workflow run is manually rerun after a newer commit | Stale-head verification skips publication and cleanup. |

## Residual Risks

| Risk | Residual Status |
| --- | --- |
| Provider quality depends on the approved AI service and model | Accepted; provider is configurable and responses are constrained to a strict schema. |
| Stable fingerprinting may not perfectly identify the same logical issue if provider wording changes significantly | Accepted; provider can supply `stable_id` for best stability. Without it, the framework still prevents duplicates per run and removes stale comments after successful reruns. |
| Redaction is pattern-based and cannot guarantee every internal value is detected | Accepted; provider context is already limited to pull request diffs, and provider endpoint must be approved under organisation data-handling policy. |

## Conclusion

The implementation is consistent with the governance model:

- Enterprise QA remains deterministic.
- AI Review is advisory.
- GitHub remains the merge authority.
- Executive Release Authority approval remains required.
- No application repositories are modified.
