# FieldZilla OpenTofu exact-plan fallback

This fallback is approved only when GitHub native environment required
reviewers are unavailable for `synergie-app-staging`.

Native GitHub environment required reviewers remain the preferred control. If
native reviewers become available, this fallback must fail closed and not be
used.

## Control contract

The immutable central workflow
`.github/workflows/fieldzilla-staging-opentofu-apply.yml` is the only approved
workflow allowed to authorize a FieldZilla staging OpenTofu apply through
`SynergieProgrammeManagementPlatformStagingInfraApplyRole`.

The workflow fails closed unless all of the following match:

- actor: `SaurabhVermaIN`
- repository: `Synergie-ITCI/programme-management-platform`
- environment: `synergie-app-staging`
- exact 40-character deployment commit SHA
- exact SHA-256 of the reviewed OpenTofu binary plan file when applying
- exact SHA-256 of the reviewed import map when importing
- exact source plan run ID, artifact ID, artifact name and artifact digest
- expiry no more than 60 minutes in the future
- unused authorization id
- central workflow identity from an immutable `pr-qa-v1-rc*` tag
- GitHub OIDC token `job_workflow_ref` matching this central workflow
- GitHub native environment reviewers reported unavailable
- verified encrypted/versioned S3 backend and DynamoDB lock table metadata

The workflow supports `plan`, `import`, `post-import-plan`, `drift`, and
`apply` modes. Every mode renders a locked S3 backend override and verifies the
state bucket versioning, SSE-KMS encryption, public-access block, and lock-table
metadata before OpenTofu initialization.

In `plan`, `post-import-plan`, and `drift` modes, GitHub generates OpenTofu
artifacts from the exact requested commit using the staging role. The artifact
contains the raw binary plan, human-readable plan, JSON plan, backend metadata,
checksums, and release metadata.

For FieldZilla PR #521 only, the `infra/aws` plan route accepts source SHA
`a06e6f827d540a716b155ace2b33bb65491c29cf` with the reviewed existing
image tag `b1679598ea9dfbbac3b8244887fc113636169e6f`. It checks the plan
for known plaintext secrets, then uploads the exact-head plan artifact before
the authorization check so an unknown IAM value or unrelated mutation
still leaves a one-day artifact for security review. A failed plan run is not
an apply authorization. The checker requires the concrete staging role ARN,
trust, boundary, secret/KMS policy, attachment, policy updates and migration
task-definition role and image values. Unknown security-sensitive values are
reported and rejected. The `infra/aws` apply route remains closed for PR #521;
it requires a separate central change after a real plan has been examined.
OpenTofu sensitivity maps may contain `true` leaves and `false` list entries
that preserve element positions; a whole `before_sensitive` or
`after_sensitive` value may also be `false`. The capture guard rejects other
scalar marker values and still scans ordinary plan values for plaintext secrets.

### Plan-capture secret classification and failure diagnostic

The guard recursively scans ordinary JSON values. Booleans are control values,
including fields such as `manage_master_user_password`, and are never plaintext
credentials. Ordinary numbers and `null` are non-secret primitives. A number
under a secret-named key or an explicit `sensitive: true` value still fails,
preserving the prior protection for numeric credentials.
Strings under secret-named keys are rejected, except a complete AWS Secrets
Manager ARN in an `_arn` field. Such an ARN identifies a secret and does not
contain its plaintext credential; malformed ARNs and strings matching credential
patterns still fail. The ARN resource name accepts ordinary Secrets Manager
names and the AWS RDS-managed `rds!db-` form; other uses of `!` fail.
On `aws_db_instance` only, two RDS-managed secret attributes are accepted at
their exact paths: `master_user_secret[<index>].secret_status` with one of
`creating`, `active`, `rotating` or `impaired`, and the resource attribute
`master_user_secret_kms_key_id` with a KMS key id or KMS key ARN. Any other
value, path, resource type or type, and every other secret-named key, still fails.
Strings matching credential, private-key or
password-assignment patterns elsewhere (including inside lists) also fail.
The string `"true"` is a string and receives these checks. Empty strings are
treated as absent values. Objects and lists are scanned recursively. OpenTofu
`sensitive_values`, `before_sensitive` and `after_sensitive` contain marker
metadata only: `true` leaves and `false` list placeholders are accepted;
strings, numbers, nulls and false object leaves are rejected. Unknown
security-sensitive IAM and task-definition values remain subject to the
separate fail-closed authorizer checks.

On a capture-guard failure, the workflow uploads a one-day JSON diagnostic
artifact containing only the failing JSON path, JSON type, fixed classification
reason, and safe resource address/type when available. Array indices and
OpenTofu structure names remain visible; all variable/provider/map key segments
are replaced by short SHA-256 identifiers. Simple resource types remain visible,
but their instance names are hashed; unsafe or complex addresses are omitted.
The hashes can be matched against local schema names without sharing
the raw plan. No value, full plan, binary plan, variable,
secret, token, private key or database URL is written to this artifact. The full
plan upload is conditional on the guard succeeding, and the workflow fails after
uploading the sanitized diagnostic. A consumer should use the path and reason to
inspect the provider schema or plan locally in an approved secure environment;
never paste raw plan values into a PR or issue. A diagnostic does not authorize
apply, and the PR #521 apply route remains closed.

In `import` mode, the workflow verifies the approved source artifact and import
map hash, backs up any existing remote state object, validates each import entry
against FieldZilla ownership evidence, and imports only those approved
addresses into locked remote state.

In `apply` mode, the workflow does not regenerate the plan. It verifies the
source run, source commit, artifact ID, artifact name, artifact digest, raw
binary plan SHA-256, backend metadata, and plan safety constraints, then applies
that downloaded binary plan. A locally generated workstation plan is advisory
only and is not an apply authorization artifact.

## Single-use binding

Before apply, the workflow creates a GitHub deployment marker in the caller
repository with:

- environment: `synergie-app-staging`
- task: `fieldzilla-staging-opentofu-remote-state`
- ref: exact approved commit SHA
- payload: authorization id, environment, commit SHA, plan/import-map SHA-256
  and source artifact identity

Any later run with the same authorization id fails before AWS mutation.

## AWS trust binding

The AWS role trust must preserve the immutable repository/environment subject
and should additionally bind the GitHub OIDC `job_workflow_ref` claim to the
released central workflow tag whenever AWS evaluates that claim:

```text
repo:Synergie-ITCI@209829096/programme-management-platform@1315697868:environment:synergie-app-staging
Synergie-ITCI/.github/.github/workflows/fieldzilla-staging-opentofu-apply.yml@pr-qa-v1-rc*
```

Do not attach application runtime secret access or broad production permissions
to the infrastructure apply role.

## Explicit non-goals

This fallback does not approve production, DNS cutover, real data loading,
secret disclosure, branch-protection weakening, bypass actors or workstation
OpenTofu apply.
