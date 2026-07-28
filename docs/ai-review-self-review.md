# AI Review Automation Self-Review

Status: completed before governed pull request update

## Design Risks Reviewed

| Risk | Mitigation |
| --- | --- |
| AI review could be mistaken for a merge gate | Reports and docs state AI Review is advisory only; findings include `blocking: false`; workflow step uses `continue-on-error: true`. |
| AI could run before QA | Workflow condition requires `steps.full.outputs.exit_code == '0'`, so AI Review starts only after final Enterprise QA has completed successfully. |
| Workflow could check out a stale framework tag | Caller and central checkout both use the pending immutable `pr-qa-v1.1` release reference. Publication must create and protect this tag only after governed review. |
| Provider outage could hide unresolved comments | If the provider is unavailable, comment synchronization is not executed and existing AI comments are left untouched. |
| AI comments could collide with QA comments | AI uses `synergie-ai-review:inline-review`; QA uses `synergie-pr-qa:inline-review`. Each lifecycle run edits only its own namespace. |
| Review spam on repeated commits | Existing comments are matched by stable fingerprint, updated when possible, and stale comments are removed only after a successful AI run. |
| Force-push changes diff positions | The lifecycle manager validates every finding against the current GitHub PR diff before publishing. Findings no longer in the diff are removed after a successful run. |
| Provider could return comments outside the PR diff | The service rejects findings whose `path` and `line` are not present in the current reviewable changed-line set. |
| Provider could duplicate Enterprise QA | Provider instructions explicitly exclude build, tests, secrets, dependency scanning, deployment safety, migration safety, and repository governance. |
| Provider could leak secrets or internal endpoints | Diff context and comments are redacted. Token, password, key, private key, connection string, and URL patterns are redacted before reporting. |
| Provider could review generated or dependency files | Generated directories, vendor directories, binary files, lock files, and framework regression fixtures are filtered before provider invocation. |
| Comment API limits could create excessive reviews | Findings are capped and batched into one submitted GitHub Pull Request review. |
| Missing provider credentials could fail QA | Missing provider configuration produces `AI Review unavailable` and exits successfully. |

## Operational Edge Cases

| Edge Case | Behavior |
| --- | --- |
| No reviewable changed files | AI Review completes with zero findings and removes stale AI comments after successful execution. |
| Enterprise QA has blocking failures | AI Review is skipped. |
| Provider returns invalid JSON | AI Review reports unavailable and does not delete existing AI comments. |
| GitHub comment publication fails | AI Review reports unavailable; Enterprise QA remains unchanged. |
| Provider returns missing explanation or recommendation | The finding is rejected and not published. |
| Provider returns unsupported severity | Severity is normalized to `INFO`. |

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
