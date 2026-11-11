# PR712 final-base review proposal

PROPOSED ONLY. This does not issue or activate a review, merge the application,
publish a central release, authorize image publication, or run AWS.

Application PR712 was rebased on protected main `98a95bcd379995b1cf5d1a909c40205d430a09da`
using the same unprotected task branch. Its remote head is
`14299cbe1dd7bbd5ee0762471ee901db39ab07fa`. The full binary promotion
patch against the prior base and new main is byte-identical: SHA-256
`bc0503fc4e2bbf992ff7b939816399d80b912e3924a1398b98a1b361ce48541c`.
The 17 paths added to main since the prior base do not overlap the PR712 patch.

The two proposed review records bind only that head and base. The source overlay
adds only the 13 new `deploy/production/hosting/rehearsal/` paths, each requiring
the candidate to equal the exact base. The existing hosting workflow path is
already base-bound. The 844 effective changed-file and 148823 addition caps,
40 reviewed deployment findings, SQL SHA and five DELETE fingerprints,
scanner/default settings, and `2026-11-11T07:04:04Z` expiry are unchanged.
No wildcard path or runtime permission is added. The two records use new IDs
and a new PR body marker so the previous review cannot silently authorize a
different head/base.

The proposal must pass central exact-head governance and full PR-QA, then receive
an exact protected merge approval. Issuance and immutable publication/consumer
activation are separate gates. PR712 remains draft until the active review
package matches its final head/base and fresh exact-head QA passes. If the
expiry arrives first, obtain a separately reviewed renewal; do not extend it
under this proposal.
