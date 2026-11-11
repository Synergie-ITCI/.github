# PR712 expired-review renewal proposal

PROPOSED ONLY. The exact #712 head/base review in central #483 expired at
`2026-11-11T07:04:04Z`, before rc239 consumer activation. rc239 is valid and
published, but selecting its expired review cannot authorize QA, images or
Gate C. Central #484 is on hold and must not merge in its rc239 form.

This proposal changes only the two PR712 review records. It retains exact
application head `14299cbe1dd7bbd5ee0762471ee901db39ab07fa`, final base
`98a95bcd379995b1cf5d1a909c40205d430a09da`, the complete promotion
patch SHA-256 `bc0503fc4e2bbf992ff7b939816399d80b912e3924a1398b98a1b361ce48541c`,
all 45 exact source-overlay paths, the 844-file/148823-addition caps, reviewed
SQL and five DELETE fingerprints, and scanner/default settings. It proposes
new IDs and a new body marker, with expiry `2026-11-12T07:04:04Z` (12:34:04
IST) instead of the expired one. That longer window is a new human decision,
not carried authorization. No runtime operation or image publication is granted.

The proposal requires exact-head central governance and full PR-QA, exact human
approval before protected merge, a new immutable release containing the issued
records, and a separately approved update of the existing consumer-activation
PR to that release. PR712 stays draft until the active policy and marker match
and its exact-head governed QA passes.
