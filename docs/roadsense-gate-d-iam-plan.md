# RoadSense Gate D IAM change for owner review

Status: the previously approved build/deploy roles and cross-account bucket grant
are live in account `918870682888`. This PR prepares a narrower deployment IAM
policy and fixed SSM document; it does not apply either or change production.

AWS account: `918870682888`; region: `ap-south-1`. The existing GitHub OIDC
provider is `token.actions.githubusercontent.com`. The RoadSense repository
uses immutable-subject format:

`repo:Synergie-ITCI@209829096/roadsense-production-dashboard@1426678649:ref:refs/heads/main`

After the central runtime is merged and released at a protected immutable tag,
create two separate roles. Both trust documents must require `aud` =
`sts.amazonaws.com` and the exact subject above with `StringEquals`, plus the
exact `job_workflow_ref` below. Do not use wildcard repository, branch, or
workflow claims.

| Role | Required `job_workflow_ref` | Allowed operations |
| --- | --- | --- |
| `SynergieRoadSenseArtifactBuildRole` | `Synergie-ITCI/.github/.github/workflows/roadsense-build-release.yml@refs/tags/roadsense-gate-d-v1` | Read the one approved corrected SQLite S3 object version; write and head RoadSense image archives only under `applications/roadsense/images/` in the existing private versioned backup bucket. |
| `SynergieRoadSenseProductionGateDRole` | `Synergie-ITCI/.github/.github/workflows/roadsense-controlled-release.yml@refs/tags/roadsense-gate-d-v1` | Head versioned RoadSense image archives; describe the exact SSM managed node; `ssm:SendCommand` only to `mi-0dade13fd68d1b435` with the reviewed SSM document; read only its command result. No S3 write or IAM rights. |

The proposed `RoadSense-GateD-Production-Command-v1` Command document embeds
the reviewed remote script at SHA-256
`459f0aa8a0eb95a9f459ad0fa042db7abfefc33a648b51d66889bde45b898e0a`.
It accepts only base64 release JSON through an environment-variable parameter;
callers cannot provide shell commands. The central workflow checks the exact
application script hash before obtaining OIDC credentials and requests document
version `1`. Replace the previously applied `AWS-RunShellScript` IAM resource
with only this document ARN after governance approval and document creation.
The SSM hybrid agent supplies `AWS_SHARED_CREDENTIALS_FILE` for its account
`918870682888` role. The fixed document preserves only that credential file,
clears other AWS credential selectors, disables IMDS fallback, and requires the
exact assumed-role ARN for managed node `mi-0dade13fd68d1b435` before any
Docker operation. The account `918870682888` bucket policy grants only
`s3:GetObjectVersion` for RoadSense image archives to this role, conditioned
on `aws:userid` = `AROA5L4HV5UECXEPEC3FY:mi-0dade13fd68d1b435`.
The host requests the exact approved S3 version and checks the archive SHA-256
before `docker load`.
No IAM change in account `507960112182` is required for this delivery path.

The trust and role-policy templates are in `iam/roadsense-*.json`. The approved
additive hybrid bucket statement is in
`iam/roadsense-hybrid-image-read-statement.json`. It is already live alongside
the existing bucket statements; no trust or deployment-role permission was
changed. The earlier host-account policy and handoff remain as historical
fallback material and are not part of this deployment design.

Do not grant either role to the intent or approval workflows. The central
authorize job must have no `id-token: write`; the deployment job must verify
the consumed approval again before OIDC. Validate emitted token claims and
denied trust attempts in a non-production integration before activation.
