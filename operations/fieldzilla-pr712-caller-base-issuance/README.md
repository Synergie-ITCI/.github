# PR712 caller-base rebind proposal

PROPOSED ONLY. Issuance, immutable publication and consumer activation remain
separate exact gates. No application merge, AWS operation, staging change,
migration, traffic switch or APK publication is included.

Application head `8c187ba9b90bba5a51b7e774a63d57784d9306f0` / base `45fc0ce54058125c1dfd4e9bc38de1487232730c`
preserves the complete previous promotion patch byte-for-byte (SHA-256
`bc0503fc4e2bbf992ff7b939816399d80b912e3924a1398b98a1b361ce48541c`). The runtime API/Admin/mobile trees are
identical to the previously checked head47782d5. The raw Git diff still has903
paths; the governed effective scope remains844 files/148823 additions. Do not
mistake raw paths for the governed effective count or expand either limit.

Main caller PR715 was independently authorized at head24538bc and merged through
the protected path. The only full-tree additions/changes to the application
candidate are its four exact base files. The two already-allowed hosting paths
continue to use `candidate=base`; add only the two named helper/test paths with
`source=absent,candidate=base`. No wildcard or reviewed runtime hash is added.
All40 deployment-sensitive paths from review5837789245 match their original
recorded hashes; the SQL file and all five DELETE fingerprints remain unchanged.
The dependency lock, approved low advisory record, scanner and QA defaults are
unchanged. Expiry remains11Nov2026 07:04:04UTC; this is not an extension.

The same unprotected task branch/PR712 was updated using an exact lease only
after proving ownership/no collaborators/no downstream PRs and required strict
main freshness. No protected branch was rewritten; no additional merge commits
were introduced. The original dirty worktree and old commits remain retained.
PR712 stays draft until the required review package is separately issued,
published and activated; only then mark ready and obtain fresh exact-head QA.
A draft or this proposal cannot pass a merge gate or replace execution approval.

Previous records remain in immutable rc231, historical proposal files and the
`previous_*` snapshots here. This branch proposes replacing only the two active
PR712 records. Recheck live application refs, scope, hashes, checks and expiry
before issuance/publication/activation. Before activation, rollback is a reviewed
issuance revert; afterward a separately reviewed selection revert restores the
previous fail-closed binding. Neither is runtime rollback.
