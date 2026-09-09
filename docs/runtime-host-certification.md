# Optional shared-host certification

Runtime Certifier can additionally certify centrally reviewed co-hosts when a
caller explicitly supplies `host-profile`. An empty input preserves the v1.6
application-only shell scripts, SSM invocation path, deployment outputs and
diagnostics. Existing immutable action releases and consumer workflows do not
change when this source is merged. A separately approved immutable release and
explicit caller opt-in are required for activation.

## Ownership and profile contract

Synergie DevOps owns the JSON files under
`actions/runtime-certifier/host-profiles/`. A profile ID is a safe lowercase label,
not a path, URL, caller file or override. Files are loaded relative to the central
action's own release checkout. Unknown IDs and symlinks fail before SSM dispatch.
Only central PR review can approve or change hosts; profiles participate in
release-drift detection.

Schema version 1 requires exactly `schema_version`, `instance_id`, `region`,
`target_hostname`, and `sites`. Each of one to eight site entries requires exactly
`label`, `hostname`, `https_required: true`, `accepted_status` (one integer 2xx),
and `marker` (one exact, printable public-content substring, at most 200 ASCII
characters). Duplicate JSON keys, labels or hosts, wildcard/IP/internal names,
URL-shaped values, target inclusion, empty lists and extra fields are rejected.
The schema intentionally has no application code, database settings, credentials,
private endpoint, header or cookie fields. Automated marker checks supplement
human review; arbitrary prose cannot be proven non-sensitive by a schema alone.

`target_hostname` binds a profile to the calling application's canonical public
hostname without placing that application in the co-host list. A different
caller requires its own centrally reviewed profile. The configured SSM managed
instance and region must match before dispatch; the returned SSM command ID and
instance ID must match the request before any result is trusted. Callers cannot
provide a co-host URL or omit individual entries.

The initial `synergieinsights-jkcement` profile contains the single unrelated
certified public application established in the 2026-09-09 read-only inventory:
safe label `bdpp-admin-auth`, HTTPS required, status 200, exact public title marker.
Evidence: Apache inventory command `787d048b-d007-4d2a-b689-308a06be6f58` and retained
successful Runtime Certifier commands `9b2e7592-0a1f-4bf5-8fb6-b120991e58cf` and
`83931f62-fab6-4fd5-baa8-5de5b720f13f`. The public title marker was verified against
the public homepage during that investigation. This is operational metadata only;
no application source, credentials, database data or excluded-vhost inventory is
included. This PR does not activate the profile.

## Execution and evidence

The existing application adapter must succeed first. Opted-in executions suppress
its raw stdout/stderr and retain only the validated deployment-state enum. Host
checks then run `apache2ctl configtest` and verify each canonical hostname belongs
to an enabled port-443 vhost with `SSLEngine on` in the same block. Included or
unrecognizable vhost layouts fail closed and need central review.

HTTPS probes disable curl config-file loading and proxies, verify certificates,
require TLS 1.2 or newer, do not follow redirects, and fetch only public `/`.
Each attempt has a five-second connection timeout, fifteen-second overall timeout
and one-MiB response cap. DNS (5/6), connection transport (7/52/55/56), timeout (28)
and TLS handshake transport (35) errors receive at most three total attempts,
with one- then two-second backoff. Certificate/security curl failures, HTTP
status mismatches, marker mismatches, other curl errors and invalid configuration
fail immediately. Failed transfers never become content-integrity successes.
Bodies are private temporary files removed on completion/interruption; raw curl
stderr is discarded. No response body, header, cookie or URL is logged.

SSM diagnostics contain only safe site label, numeric status, marker result,
fixed curl category and attempt. The caller validates the invocation identity,
terminal Success/zero response, exact aggregate PASS, one deployment-state enum
and ordered bounded probe evidence for every approved site. Missing, conflicting
or malformed evidence fails. Polling waits for the same command after the stock
SSM waiter expires, with a bounded additional 480-second deadline; it never
resends a command.

## Outputs and integration

| Output | Omitted profile | Requested profile |
| --- | --- | --- |
| `deploy-state`, `deployment-required` | Unchanged v1.6 behavior | Existing values, published only after host PASS |
| `host-certification` | Empty | Exact `PASS` or `FAIL` |
| `failed-site` | Empty | Approved safe label or `host-profile` on failure |
| `failed-reason` | Empty | Fixed reason enum on failure |

All host failures return nonzero. Callers must require both action success and
exact `host-certification == 'PASS'` when requesting a profile; empty, missing,
skipped or failed results must never authorize deployment. Run the same contract
after a switch and make non-PASS enter the application's existing rollback path.
An `ALREADY_DEPLOYED` application still receives host checks when requested.
This action remains read-only and cannot implement application rollback.

Application repositories continue to own their homepage, routes, protected/SSO/
debug endpoints, database, persistence, backups, exact runtime SHA and rollback.
No caller or application repository is modified by this extension.

Read-only compatibility review covered JK Cement, BDPP Admin Auth, Telemedicine
Backend, Telemedicine Bridgestone, Communication Portal, Castrol, CastrolWhatsApp,
Dhansamvaad, JioBP LMS and Telepathy Operations Web. Their existing PHP-FPM,
static-Vite/Apache and Django/Gunicorn/Nginx inputs and deployment output guards
remain valid. All omit `host-profile`; none activates this extension implicitly.

Run the complete central test suite and governed PR-QA before review. Release
drift against the active QA release is expected for this unreleased extension;
do not change the release pin or publish a tag as part of this PR.
