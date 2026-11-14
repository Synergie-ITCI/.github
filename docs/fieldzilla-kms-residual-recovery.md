# FieldZilla rehearsal KMS residual recovery

The governed cleanup apply for plan run 43589974746 removed 58 of 60 isolated
rehearsal resources. Its one-use approval was consumed. `kms:DeleteAlias`
failed because the rehearsal role could delete the alias ARN but lacked that
action on the associated key ARN. The original plan and approval cannot be
reused.

`cleanup-kms-residual` binds a fresh destroy-only plan to S3 state version
`_5D8ll2jFTMW0Nflg9u3UACnTsLaHoCx`, lineage
`d5ba55e1-56eb-a8ce-a60d-ef29aeafe0f2`, serial 35, and the original
rehearsal source and expiry. The verifier requires exactly one KMS alias and
one KMS key, with their recorded identities, target relationship, tags, and
seven-day deletion window. Planning fails closed if that version or inventory
changes. The plan authorizer permits exactly those two deletes. The apply
retains the existing fresh owner-comment, exact artifact, and one-use approval
checks.

Activation requires a governed central release, a matching consumer caller and
exact OIDC trust, and a separately approved, narrowly scoped IAM permission for
`kms:DeleteAlias` on the associated key. Before apply, obtain a new governed
plan and a new exact owner approval. After apply, verify the alias is absent and
the key is `PendingDeletion`. KMS physical deletion occurs after its waiting
period; pending deletion is not physical deletion.
