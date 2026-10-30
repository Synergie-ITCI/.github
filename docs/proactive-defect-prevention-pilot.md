# Proactive defect-prevention pilot

This pilot extends the existing central PR-QA and read-only governance inventory. It does not change branch rules, deploy applications, or create a second scanner.

## Controlled PR-QA release selection

The central reusable workflow now resolves consumer releases from `consumer_release_selection` in the centrally governed `policy/framework-releases.json`. The default is the currently approved `pr-qa-v1-rc216` at its exact commit. No pilot repository is selected yet. A future, separately reviewed central policy change may map BDPP to a newly published release; application PRs cannot edit this mapping or supply a framework override. The resolver verifies the selected tag, exact commit, protection and release provenance before either PR-QA job executes. The existing `--resolve-active` path remains the release-publication path and still checks the newest candidate.

Publishing a higher immutable tag alone therefore does not migrate consumers. Roll back a pilot by removing its mapping through a governed central PR; the verified default remains available. Promote a new default only after pilot acceptance and a separate central review. The required PR-QA status name and Gate D remain unchanged.

## Application risk contract

`policy/pr-qa-policy.json` declares pilot risk paths and existing test evidence for BDPP. When a declared source path changes, the `Application Risk Contract` gate requires the named test files and the already-running central `Tests` gate to pass, then executes only the declared focused test selectors on the same PR-QA runner. This prevents an unrelated passing test from substituting for the relevant cases. It does not run a second full suite or scanner. Unrelated changes skip the contract. Application owners still review the selected cases and negative tests.

Contracts live in the immutable central policy so a PR cannot remove its own required tests. Add a repository contract through the normal central PR, regression and immutable release process. The initial BDPP contract uses existing auth/user/grievance tests; the pilot BDPP PR adds expiry and deactivation assertions. Scholarships is the caller-onboarding case and has no risk contract until its application owners establish deterministic tests.

## Organization attestor

`tools/org_governance_attestor.py` reuses `tools/github_governance_inventory.py`'s read-only GitHub API helper. It distinguishes caller absence, non-central or disabled callers, missing effective required check, missing PR rule, unprotected promotion branches, missing repository release-workflow evidence for a declared production environment, and expired exception records. Query failure is `EVIDENCE_UNAVAILABLE`, not compliance. Historical expired one-time exceptions are review findings, not claims of an active bypass.

Live repository reads use at most six concurrent workers. The two-repository pilot completed in 12.39 seconds; a local read-only run across 81 repositories completed in 213.80 seconds. Scheduled GitHub Actions runner usage has not been measured.

The new workflow runs deterministic fixture tests on its own PR head. Scheduled and manual organization reads stay disabled until the repository variable `SYNERGIE_ORG_AUDIT_ENABLED=true` and an approved read-only `SYNERGIE_GOVERNANCE_READ_TOKEN` secret are configured through a separate authorization. Neither setting was changed in this pilot. It checks out the exact event SHA and records that identity in the artifact name. After merge, immutable versioning follows the existing central release publication and tag-protection process; this PR must not claim an unpublished tag is active.

The audit token needs access to the selected private repositories with repository **Metadata: read**, **Contents: read**, and **Actions: read** only. These cover organization enumeration/effective rules, caller contents/branch state, and workflow/environment listing. Do not grant write or administration permissions. Verify the actual token against BDPP and Scholarships before enabling the weekly run; an authorization failure must remain `EVIDENCE_UNAVAILABLE` rather than a clean report. [GitHub rules API](https://docs.github.com/en/rest/repos/rules), [workflow API](https://docs.github.com/en/rest/actions/workflows), and [repository contents API](https://docs.github.com/en/rest/repos/contents) document the endpoint permissions.

The attestor is report-only and never edits repositories or rules. A missing caller with a required check may be a merge deadlock rather than a bypass. A production environment name is only a declaration; an external release route may exist. Owners must resolve those findings before any organization ruleset change.

## Validation and rollout boundary

Local fixture tests cover healthy, missing-caller, disabled-caller, missing-check, failed-query and expired-exception cases. Live read-only pilot output from BDPP and Scholarships is stored outside the repository. Before enabling a scheduled organization run, verify token scope on the two pilot repositories, workflow execution at the exact merged/released SHA, report artifact retention, runtime, false positives and cost. Before enforcing any result, verify healthy PR mergeability and a failing test PR in an isolated branch under the actual effective ruleset.

Rollback of this pilot before merge is closing its PRs. After an approved merge or immutable publication, revert through a governed PR and publish a new immutable release; never move an existing protected tag. Disabling the opt-in variable stops scheduled organization reads without changing existing PR-QA or Gate D. Existing production deployments are unaffected.
