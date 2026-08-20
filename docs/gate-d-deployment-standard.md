# Gate D Production Deployment Standard

## Purpose

Gate D governs deployment from an approved `main` release to production.

Gate D is always separate from Gate C. Merging or promoting a release to `main` must not automatically deploy production.

## Required Deployment Pattern

Preferred AWS deployment path:

`GitHub Actions → GitHub OIDC → scoped IAM role → AWS SSM → target server`

Public SSH is not required for this deployment pattern.

## Identity and Access

- Use GitHub OIDC and short-lived AWS credentials.
- Do not store permanent AWS access keys for CI deployment.
- Scope the IAM trust relationship to the intended repository and environment.
- Use GitHub immutable OIDC subjects where GitHub emits them.
- Do not broaden OIDC trust merely to resolve a failed deployment.
- Scope `ssm:SendCommand` to the intended managed node where practical.
- Keep production permissions separate from non-production permissions.

## Server Execution

SSM may execute commands with elevated server privileges when required.

Git operations must run as the actual checkout owner rather than root.

Do not solve Git ownership issues using a global `safe.directory` exception.

Private repository credentials used for Git fetches must be temporary and removed from the remote URL after use.

## Release Integrity

Every deployment must identify:

- `deploy_ref` — exact approved SHA/artifact
- `rollback_ref` — exact currently deployed recoverable SHA/artifact

Before deployment:

1. Verify the current deployed SHA matches `rollback_ref`.
2. Verify the approved `deploy_ref` exists.
3. Fail closed on mismatch.

After deployment:

1. Verify the checkout/artifact is exactly `deploy_ref`.
2. Run health/smoke verification.
3. Record deployment result.
4. Roll back or invoke controlled recovery if health verification fails.

## Remote Command Safety

When environment variables or secrets are passed through SSM remote shell commands:

- quote values using shell-safe quoting;
- do not rely on nested double-quoted shell expansion;
- ensure variables are expanded in the intended shell context only.

## Production Approval

Production requires a separate explicit Saurabh approval after Gate C.

The approval must be traceable to the deployment execution.

No production deployment may be inferred from:

- staging approval;
- merge to main;
- CI success alone;
- administrator privileges.

## Proven Operational Lessons

Programme and Telemedicine established the following reusable lessons:

- GitHub environments affect OIDC subject identity.
- IAM trust must match the subject GitHub actually emits.
- SSM target identity must be verified before deployment.
- Git must run as checkout owner.
- exact-SHA verification is required after deployment.
- rollback baseline must match the actual deployed state.
- health verification is part of deployment success, not an optional follow-up.
