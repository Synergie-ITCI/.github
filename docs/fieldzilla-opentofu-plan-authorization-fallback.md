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
