# PR712 mobile dependency correction: exact rebind proposal

PROPOSED ONLY. This branch requires a new exact issuance approval. Publication
of an immutable central release and FieldZilla consumer activation are separate
actions. No application merge, AWS action, staging change or APK publication is
included.

Bind only application PR712 head219ff68c08caeb850b6e21cf745ffa3f8712bcaa and
basec8aee71a61059392f17343eac434d2a73dfb3b4c. The four changed paths since the
previously issued c92 head are the mobile package/lock, the owner-approved audit
record, and its coupled architecture test. The decoder/Joi/minimatch fixes remove
the observed high/moderate findings. The only accepted advisory is the separately
approved exact-lock low deepmerge record, expiring2026-11-11T07:04:04Z. No expiry
extension is proposed. Local149 Node tests,91 Jest tests, TypeScript and lint
passed; the two coupled baseline contract checks pass. Linux dependency QA has
not yet executed because Phase1 correctly stops before it.

Governed run42808040203 measured844 files and148799 effective additions: exactly
40 more than the prior148759 cap. This proposal raises only that exact cap by40,
retaining the existing file count, two allowed size relaxations and expiry.
Ordinary organization limits and every scanner/test/release guard are unchanged.
All four new paths are bound by reviewed SHA256 values in the existing overlay
contract. Do not extend the record to another head, base, lock or finding set.

Review5837789245 is carried forward only for the unchanged40 deployment paths
and the identical historical SQL/five spans. It does not authorize this new
issuance. Previous records remain in immutable rc229, Git history and the exact
proposal.previous_* fields. Only the single existing record for this PR is
replaced; no duplicates or unrelated policy changes are permitted.

Before issuance, publication or activation: recheck live application head/base,
central head/checks, reviewed hashes, scope and expiry. Stop on any difference.
After separate activation, fresh exact-head QA must confirm the Linux fingerprint
and all other required checks. A local audit pass is not governed QA or acceptance.

Rollback before activation is a reviewed revert of this issuance. After activation,
a separate reviewed consumer-selection revert to rc229 restores the prior
fail-closed binding. There is no runtime or database rollback in this policy PR.
