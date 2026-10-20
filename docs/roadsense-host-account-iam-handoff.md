# RoadSense host-account image-read handoff

Account `507960112182` needs an existing authorised IAM administrator. The
`devops-audit` identity in account `918870682888` can reach the host through
hybrid SSM but cannot administer this separate account. The host role itself
is not an administrator and must not receive IAM permissions.

The only requested change is a new inline policy named
`RoadSenseVersionedImageReadOnly` on `AmazonLightsailInstanceRole`. Use the
reviewed `iam/roadsense-host-image-read-policy.json` from this repository.
Its SHA-256 is
`e10ece77bb21749666074cf4839ccf77a90d407904f1c9391a9554dde9a9c72a`.
It allows only `s3:GetObjectVersion` for
`applications/roadsense/images/*/roadsense-image.tar` in the approved bucket,
conditioned on the observed host session `aws:userid`.

In an already authorised account `507960112182` administrator session, from
the repository root, perform these guards before the one policy attachment:

```bash
set -euo pipefail
test "$(aws sts get-caller-identity --query Account --output text)" = 507960112182
test "$(aws iam get-role --role-name AmazonLightsailInstanceRole --query Role.RoleId --output text)" = AROAXMRGIGQ3LHEHJV6LS
printf '%s  %s\n' e10ece77bb21749666074cf4839ccf77a90d407904f1c9391a9554dde9a9c72a iam/roadsense-host-image-read-policy.json | sha256sum -c -
aws iam list-role-policies --role-name AmazonLightsailInstanceRole --query PolicyNames --output json
```

Stop if `RoadSenseVersionedImageReadOnly` already exists; compare its content
first rather than overwriting it. Preserve every other attached and inline
policy. Once the guards pass and the account administrator confirms the exact
scope, the sole mutation is:

```bash
aws iam put-role-policy \
  --role-name AmazonLightsailInstanceRole \
  --policy-name RoadSenseVersionedImageReadOnly \
  --policy-document file://iam/roadsense-host-image-read-policy.json
```

Read back the inline policy and compare the normalized JSON with the reviewed
file. Verify the host STS `UserId` remains
`AROAXMRGIGQ3LHEHJV6LS:i-00f9214399e0091f5` under the clean credential
environment in the fixed SSM document. After a governed candidate image exists,
retrieve only its exact S3 version on the host and hash the archive. A read of
an unrelated versioned object must be denied. Verify denied `s3:PutObject` with
IAM policy simulation; do not perform a write probe against the production
bucket. No deployment or database mutation is part of this handoff.
