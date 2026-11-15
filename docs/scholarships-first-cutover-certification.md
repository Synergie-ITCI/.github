# Scholarships PR #19 first-cutover certification

This bounded contract certifies the exact 29-file change on Scholarships PR #19
at `c80b71a87dbec25d275bf3fbdd794b0e69e56eab`. The immutable file hashes
are in `policy/scholarships-pr19-first-cutover.json`. It does not authorize IAM
installation, backup capture, production cutover, database restore, or rollback.

The owner must personally review the exact PR head and post an unedited
Conversation comment on PR #19 with these four separate lines, substituting the
manifest digest from the reviewed central PR:

```
SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED=c80b71a87dbec25d275bf3fbdd794b0e69e56eab
CERTIFIED_MANIFEST_SHA256=8e9e3c90f70660f60f3d70f6aff4f26916b32ee38732d43bf0d5a53f744e05c2
REVIEWED=IAM,SSM,APPROVAL,ARTIFACT,HOST,RUNTIME,BACKUP,RESTORE,PRIVATE_DOCUMENTS,ROLLBACK
OWNER_ACCEPTS_TECHNICAL_REVIEW_RESPONSIBILITY=YES
```

Central QA reads the current GitHub comment identity and rejects edits, changed
file bytes, a different PR head, or a changed file list. Passing this gate is a
code review result. The first-cutover workflows separately require live control
readback, a recoverable off-host backup and isolated restore, and an exact
one-use owner release approval before production credentials are assumed.
