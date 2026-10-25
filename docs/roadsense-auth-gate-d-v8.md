# RoadSense authentication proxy health correction

The authenticated release at `73cc8d04bf0f1d2f9b6c7cc8a1c2432de005fa93` passed container health but returned HTTP 503 through Caddy. Caddy's internal health request uses `Host: roadsense-next`; the authentication host allowlist rejected that request. The prior production image was restored and its proxy returned HTTP 200.

This release adds only `roadsense-next` to the exact application host allowlist. The application script SHA-256 is `16993d841889abc9a4b09c7677e91f21679eee0f65267e901c11aab56adac201`. The immutable Gate D v8 release uses fixed SSM document version 5 and the exact v8 workflow trust ref. The allowlist passed an isolated container request matching Caddy's health Host. Caddy, identity data, publication decisions, and paid AI settings remain unchanged.

Production deployment requires a fresh exact-artifact Gate D approval. The currently verified rollback image is `sha256:d487099571aa7b7bda7f144f529975e146b44de4845b97abb297ff001216109b` with the same MoRTH database.
