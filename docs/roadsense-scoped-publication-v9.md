# RoadSense scoped publication release control

This change prepares a new immutable central release for the data owner's exact
231-cell decision. It does not activate production or grant Gate D.

- Application inventory SHA-256: `3e3e61385f632a2a88a99cf146855e2f5f095eb72130345e1e7f624afe80f49e`.
- Candidate database SHA-256: `5f26e3081b65b095389eeaeeb1871e27c001928138a71e1363a976a402731512`; private S3 version `llxUjX.WIAcZoPCnuCoBuZ3OsAJnXiwk`.
- Candidate policy SHA-256: `003023b6060daeb99534baafc82616867b7dd5df3ba0c91af97034a8a4522e25`; private S3 version `MUNazMikruSnLjpY7zjUgxvrTt_S6GGu`.
- The build role remains limited to that one database object version. The build workflow checks the policy bytes, inventory bytes, 231 exact decisions and 11 retained rules before accessing the artifact.
- The new production SSM document embeds `iam/roadsense-production-remote-v2.sh` at SHA-256 `a7f33ee09fb8df02fbce96ec5244f7d5ebc88cb8550ef882157f0d3e5d579b71`. The old v1 document and script remain unchanged for audit and prior releases.
- GitHub's repository ruleset limit prevented a separate v9 rule. Existing ruleset `25809829` now protects exactly the v8 and v9 tags from update and deletion with no bypass actors. Both release entries pin its read-back timestamp `2026-10-28T00:47:40.788+05:30`; the classifier rejects any broader or narrower tag scope.

The application PR must reach protected `main` by feature → development → staging → main, with exact-head central PR-QA and explicit Gate C. The immutable `roadsense-gate-d-v9` tag must resolve to the reviewed workflow bytes. A separately authorized administrator must install the exact reviewed v2 SSM document (version 1), update the build-role inline policy and OIDC trust to the v9 build workflow, change the deploy-role document grant to v2, and update its OIDC trust to the v9 deploy workflow. Read back and compare each installed IAM/document identity to the reviewed files before any build. No wildcard database access or ad hoc shell deployment is permitted.

The governed build then produces the image digest, archive SHA-256 and S3 version bound to the protected main SHA and approved database version. Before intent or Gate D, reverify the executing live image/database/policy, the stopped rollback container and its bundled pair. As of the last read-only inspection, live was image `sha256:253ec10f773f461b8783bfbe0e1e21a89b03089415c807e11ba2be23f7c23e8e` with database `aaac711b0df078d12714bbd03cff72df7ae49418b8434be1a2864f1536575fa1` and policy `3fb101876224389c71f15c75af9049d0246a52012d251425f04d47a5d6c0357b`; stopped rollback image `sha256:dda9bc330ecf680b22a8b4031517193c77cd6acf6592117c9cc5333b5d1fd7fe` contained that same pair. A rollback restart has not been exercised.

Gate D must approve the exact release tuple after the image exists. Governed CI/CD verifies and consumes the separate approval before OIDC production credentials. After cutover, authenticated national, State/UT, Compare, Ask Data and Bengaluru browser acceptance is required. A critical health, publication or chart-integrity failure triggers the governed whole-image rollback.
