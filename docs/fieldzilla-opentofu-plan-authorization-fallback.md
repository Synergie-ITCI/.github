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
- exact SHA-256 of the reviewed OpenTofu plan file
- expiry no more than 60 minutes in the future
- unused authorization id
- central workflow identity from an immutable `pr-qa-v1-rc*` tag
- GitHub OIDC token `job_workflow_ref` matching this central workflow
- GitHub native environment reviewers reported unavailable

The workflow regenerates the OpenTofu plan from the exact commit immediately
before apply. If AWS state, source code or variables cause the regenerated plan
hash to differ from the reviewed plan hash, the workflow stops before apply.

## Single-use binding

Before apply, the workflow creates a GitHub deployment marker in the caller
repository with:

- environment: `synergie-app-staging`
- task: `fieldzilla-staging-opentofu-apply`
- ref: exact approved commit SHA
- payload: authorization id, environment, commit SHA and plan SHA-256

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
