# RoadSense session-gateway edge release control proposal

This PR adds a **proposed, inactive** v3 production command. It does not
install an SSM document, change IAM trust, change the running Caddyfile, or
alter the protected v9 release tag. The existing v2 command and its active
workflow remain unchanged.

The v3 script matches the RoadSense PR #167 release verifier at SHA-256
`e2defbadd032e539c81ae24939eaef70a9f792cbf542fe08e815240af9a86031`.
After a separately approved edge cutover, it requires an unauthenticated
`/next/` request to redirect to the RoadSense login page without a Basic Auth
challenge, and an unauthenticated `/next/api/series` request to return 401
without a Basic Auth challenge. The approved image, database, publication
policy, identity backup, SSM target and rollback checks remain unchanged.

Activation requires a later reviewed central PR to pin a new immutable
release tag, workflow, IAM document grant and trust, plus the caller update.
The shared-host Caddy cutover must preserve the private original config and
be verified against both RoadSense and unrelated host routes. Until that
activation, v9 remains the only governed production release control and
continues to fail closed if the edge no longer returns its expected 401.
