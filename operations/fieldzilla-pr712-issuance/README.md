# Unissued exact review candidate for FieldZilla PR712

This is preparation, not issuance, activation, a new approval of application code,
or permission to merge/deploy the application. Saurabh's review5837789245 remains
recorded on the merged package463; it is not requested again.

The existing source/base-only overlay cannot represent newly reviewed bytes.
This PR adds an explicit reviewed_sha256 selector to that existing mechanism.
The whole authorization still needs the existing exact live PR/head/base,
repository identity, trusted runner context, issuance/expiry and central release.
No ordinary consumer receives an exception. The selector compares both committed
and working bytes, rejects symlinks/noncanonical paths, missing/invalid hashes,
and hashes attached to another selector. It does not use empty/unknown selectors.
The retained PR-QA caller can match its exact authorized base without pretending
its edited-event trigger was a pin-only change. Missing base and caller byte drift
remain failures. Other caller transitions retain the existing pin-only validator.

candidate.json is deliberately OUTSIDE active policy. Its window is proposed:
10 November2026 07:04:04 UTC to11 November2026 07:04:04 UTC. If it expires before
execution, prepare new IDs/window and exact approval; do not activate stale records.
It names PR712 f34956e640faaf82d712eff74ae7c195e3d01f87 and main base
c8aee71a61059392f17343eac434d2a73dfb3b4c. The original comparison source stays
9a199f332165fd825e186b8aa6273532f0987efc; it is not replaced by the whole candidate.
23 exact source differences use base/source comparisons or6 exact SHA256 values.
Only2 of those6 are new deployment findings; the remaining4 bind unchanged
checksum/test preparation bytes and grant no scanning/test exception. The baseline
has NO relaxations: no size, secret, history, binary, dependency or test waiver.
The SQL candidate uses the existing exact full-file/five-span authorization format.
The current receipt is not installed into policy and grants nothing.

Before issuance: obtain the separately required authorization for this new contract
and exact records, pass normal full central QA, recheck original review applicability
and all live bindings, then present the exact ACTIVE policy diff for its own approval.
After that policy merge: use the existing selected-source release check-only helper,
obtain exact publication approval and verify immutable provenance. Activate through
its separate approved consumer-selection PR. Verify the executing framework and rerun
application QA. No application caller edit or staging deployment is needed merely
to prepare this package. Do not claim a new release or policy is active from merging
this preparation PR.

Rollback before activation: reviewed revert of this contract/candidate; ordinary
consumers are unaffected. After actual issuance/activation: remove records through
normal central review, publish/select a clean immutable release, verify execution.
Reverting central main alone does not remove a record from an executing old release.
Expired, moved, closed or merged PRs fail closed. Rehearsal/production execution,
IAM, database mutation, traffic and APK publication retain their own approvals.
