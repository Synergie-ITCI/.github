# Scholarships PR #19 first-cutover certification

This bounded contract certifies the exact 29-file change on Scholarships PR #19
at `b3b8a0a5e91df5699cf1a1debaa389dff6976c29`. The immutable file hashes
are in `policy/scholarships-pr19-first-cutover.json`. It does not authorize IAM
installation, backup capture, production cutover, database restore, or rollback.

The owner must personally review the exact PR head and post an unedited
Conversation comment on PR #19 with these four separate lines, substituting the
manifest digest from the reviewed central PR:

```
SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED=b3b8a0a5e91df5699cf1a1debaa389dff6976c29
CERTIFIED_MANIFEST_SHA256=72f78461522fcef2726a6d6e1924001b6f922ff80c0a695b31d053075fd71b12
REVIEWED=IAM,SSM,APPROVAL,ARTIFACT,HOST,RUNTIME,BACKUP,RESTORE,PRIVATE_DOCUMENTS,ROLLBACK
OWNER_ACCEPTS_TECHNICAL_REVIEW_RESPONSIBILITY=YES
```

Central QA reads the current GitHub comment identity and rejects edits, changed
file bytes, a different PR head, or a changed file list. Passing this gate is a
code review result. The first-cutover workflows separately require live control
readback, a recoverable off-host backup and isolated restore, and an exact
one-use owner release approval before production credentials are assumed.
