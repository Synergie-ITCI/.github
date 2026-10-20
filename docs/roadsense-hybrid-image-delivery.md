# RoadSense hybrid SSM image delivery evidence

The governed image build for protected application main commit
`13a5cb4e116e9585ce426ab5caa9aeaebddc5461` succeeded in GitHub Actions
run `39452409916`. The release identity artifact records Docker config digest
`sha256:ac9fff358cf474b74bdcd53e0464c21424ec5a6c6ed817cadb1c354e19b03946`,
archive SHA-256 `a88e21b98268afaba877e3fba964c48aaaae9b643294c56c1912a34bd3bfba84`,
S3 version `OUJ.dehm9hclabmZ8yC3CN6fJ3GgngI.`, database SHA-256
`aaac711b0df078d12714bbd03cff72df7ae49418b8434be1a2864f1536575fa1`,
and publication policy `2026-10-16-release-candidate-hold-v1`. An independent
download of that S3 version matched the archive SHA. Its Docker config matched
the image digest, source label and database label. The object is 242,530,816
bytes, versioned, SSE-S3 (`AES256`), and tagged `publication=held`; no KMS grant
is needed for this object.

The approved bucket-policy addition is
`iam/roadsense-hybrid-image-read-statement.json`. The full applied policy had
SHA-256 `aec8f28ea9b40440549c377a3dea0589cd426a7715fb315345391b43fffdf7e5`;
readback matched it exactly. IAM simulation allowed the observed managed-node
session to `s3:GetObjectVersion` for the RoadSense image and denied `s3:PutObject`,
an unrelated versioned database object and a different node session. The role
trust permits only `ssm.amazonaws.com`. These are policy checks, not substitutes
for the runtime read.

The separately approved fixed, read-only SSM document
`RoadSense-GateD-Artifact-Probe-v1` version 1 has SHA-256
`a23d5ca743d12d14438af7df7b4652a9cc6f978b86bc5b21a8862be19b568d32`.
It accepts only the archive SHA and S3 version, checks the exact hybrid role
session and available disk, downloads to a mode-restricted temporary directory,
verifies the returned version and archive SHA, probes denial of an unrelated
versioned read, and deletes the temporary archive. SSM command
`0060bb0a-b459-4780-8068-116c919cf284` on the online RoadSense managed node
returned success and the exact archive SHA and S3 version, with unrelated read
denied. It did not run Docker or change the application/database.

The production command remains a separate fixed SSM document with one bounded
release parameter. It retains the Gate D approval, source/image/database/policy
binding, candidate health checks, publication hold checks and atomic rollback.
The deployment role's narrower document permission and the amended central
workflow are review material in PR #368; neither is active yet. No production
deployment has occurred.
