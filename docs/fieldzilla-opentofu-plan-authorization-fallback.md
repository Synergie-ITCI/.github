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
- exact SHA-256 of the reviewed OpenTofu binary plan file
- exact source plan run ID, artifact ID, artifact name and artifact digest
- expiry no more than 60 minutes in the future
- unused authorization id
- central workflow identity from an immutable `pr-qa-v1-rc*` tag
- GitHub OIDC token `job_workflow_ref` matching this central workflow
- GitHub native environment reviewers reported unavailable

The workflow has two stages. With `apply=false`, GitHub generates the OpenTofu
plan once from the exact requested commit using the staging role's read-only
plan-discovery permissions. It uploads the raw binary plan, human-readable
plan, JSON plan, checksums and metadata as a uniquely named one-day artifact.

With `apply=true`, the workflow does not regenerate the plan. It verifies the
source run, source commit, artifact ID, artifact name, artifact digest, raw
binary plan SHA-256, metadata and plan safety constraints, then applies that
downloaded binary plan. A locally generated workstation plan is advisory only
and is not an apply authorization artifact.

## Single-use binding

Before apply, the workflow creates a GitHub deployment marker in the caller
repository with:

- environment: `synergie-app-staging`
- task: `fieldzilla-staging-opentofu-apply`
- ref: exact approved commit SHA
- payload: authorization id, environment, commit SHA, plan SHA-256 and source
  artifact identity

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
