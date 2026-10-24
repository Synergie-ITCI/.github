# RoadSense authentication Gate D v7 proposal

This update pins the reviewed authentication-enabled RoadSense release script.
It keeps the existing exact-source/image/database release tuple, node-bound
OIDC and SSM identities, fixed document name, and Caddy Basic Auth check.

- Application script SHA-256: `aafdeb3d497afdfabff34f0efd9426f3ff984ed9cc8c0b03ac8dc4477d6d6f68`.
- Proposed fixed SSM document version: **4**; canonical JSON SHA-256:
  `f405872ccfa557ea5f832871ff5368d8040da1fd4e235c95f59929825841f817`.
- Proposed protected central release: `roadsense-gate-d-v7`.
- Deploy-role trust changes only the exact central workflow ref from v6 to v7.
  The document permission remains scoped to the same fixed RoadSense document
  and managed node.

The release script checks the host identity store and SES-only credential file,
their owner and modes, and the installed host helper hashes. It takes a
versioned encrypted backup with an exact-version restore check before and after
the identity migration. It obtains the signing key from the approved SSM
SecureString on the host, stores it only in the restricted temporary environment
file, and mounts the identity directory into the candidate container. The
candidate must prove scoped SES identity, login page availability, and denial of
an unauthenticated analytical API request before the existing container stops.
Paid AI remains disabled.

Promotion order: review and merge this central PR; protect and publish the v7
tag from the reviewed merge; install and verify SSM document version 4; promote
the exact v7 caller to RoadSense protected main; then switch the exact deploy
role trust to v7. A separate artifact-bound Gate D decision is required before
the production workflow runs. Keep Caddy Basic Auth during the first live account
journey. Its removal is a separate reversible edge cutover after authentication
and protected API tests pass.

The previous application image and database remain the rollback pair. The
release script automatically restores the prior running container on failure
during candidate validation or cutover. After a successful cutover, a failed
browser acceptance requires a separately governed restore of the retained
rollback container and Caddy configuration; the identity database is preserved.
