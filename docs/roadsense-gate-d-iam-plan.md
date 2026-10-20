# RoadSense Gate D IAM change for owner review

Status: proposed only. No role, trust, bucket policy, SSM document or production
environment is created by this PR.

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

The current remote script calls `AWS-RunShellScript`, which allows arbitrary
shell commands to the node if role credentials are misused. Before IAM approval,
replace that with a restricted, versioned RoadSense SSM document that accepts
only the reviewed script and release tuple format, or obtain an explicit owner
risk decision for the exact document and trust scope. The host assumes
`arn:aws:iam::507960112182:role/AmazonLightsailInstanceRole`; its identity
policy and the cross-account bucket policy must permit only `s3:GetObjectVersion`
for `applications/roadsense/images/*/roadsense-image.tar`. The S3 object version
and SHA-256 are verified again on the host before `docker load`.
Because `AmazonLightsailInstanceRole` is a shared role name, both proposed
cross-account statements additionally bind the observed STS `aws:userid` to
`AROAXMRGIGQ3LHEHJV6LS:i-00f9214399e0091f5`, the current RoadSense host
role session. Recheck that identity immediately before any IAM change.

Review-only trust, role, and cross-account bucket-policy statement templates are
in `iam/roadsense-*.json`. The existing bucket policy has three statements,
including `DenyInsecureTransport`; the proposed host statement must be added
without replacing those statements. The host-side identity policy is in the
separate AWS account `507960112182` and requires that account's authorised
administrator. No current AWS policy was edited by this PR.

Do not grant either role to the intent or approval workflows. The central
authorize job must have no `id-token: write`; the deployment job must verify
the consumed approval again before OIDC. Validate emitted token claims and
denied trust attempts in a non-production integration before activation.
