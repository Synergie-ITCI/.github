# Legacy production onboarding

`LEGACY_ONBOARDING` is a narrow, first-cutover evidence contract for a production
application that is not yet represented by the governed release/current/shared
model. It does not replace Gate C, Gate D, Runtime Certifier, exact-head PR-QA,
protected environments, or human approval.

The intended lifecycle is:

`discover once -> commission fully without public traffic -> remediate on the same PR -> govern once -> cut over once -> ordinary governance`

## Recognition and evidence source

The mode is evaluated only when a pull request contains exactly one fenced
`legacy-onboarding` JSON object. An ordinary PR without this block is skipped by
the legacy gate and is never asked to inspect production.

The evidence must identify the repository, target, exact commissioned candidate,
and an authoritative discovery evidence reference. At least one legacy condition
must be explicitly evidenced:

- no deployed SHA/release marker;
- production does not match a reachable governed commit;
- the first governed release/current/shared model is being established; or
- one-time persistence sanitation/cutover is required.

Evidence assertions are produced by the approved discovery and commissioning
workflows. The PR body transports their immutable references; it is not authority
to self-approve production state.

## Required evidence

The JSON object has these required sections:

- `production_state`: legacy recognition booleans and `evidence_reference`.
- `discovery`: production target, current webroot/runtime, production health,
  DB/storage dependencies, persistent paths, runtime/secret config paths,
  baseline, and rollback capability.
- `baseline`: `rollback_kind=legacy-baseline`, an explicit
  `UNVERSIONED/LEGACY` source kind, immutable artifact and tree SHA-256 values,
  applicable database/persistence backup references, and tested restore evidence.
  A Git SHA must never be invented for an unversioned tree.
- `commissioning`: an isolated absolute candidate path, the exact artifact
  SHA-256, `public_traffic_switched=false`, and PASS/NOT_APPLICABLE results for
  package/runtime installation, runtime compatibility, runtime config,
  persistent mappings, DB connectivity, web-server-to-application execution,
  workers/services, critical routes, backup/rollback, SSM execution, and
  readiness.
- `migration_validation`: only `none`, `dry-run`, `explain-plan`, or
  `non-production-copy`; target classification is `NONE` or `NON_PRODUCTION`;
  live production mutation and production migration requests are both false.
- `health`: expected and actual HTTP status, a sane minimum and actual body byte
  count, a stable application marker that was observed, and critical route PASS.
  A zero-length response fails even when its HTTP status is 200. Full-page exact
  matching is not required.
- `coupled_inputs`: target identity, workflow path and SHA-256, runtime release,
  runtime-config SHA-256, and persistence-mapping SHA-256. The canonical JSON
  SHA-256 is recorded in `coupled_inputs_sha256`.
- `cutover`: `PENDING` during non-public commissioning, then `COMPLETE` only
  after the exact deployed SHA marker and release/current model are established.

`candidate_sha` normally equals the exact current PR head. Evidence from an
ancestor candidate remains reusable only when every later path is unrelated
documentation or text metadata and all coupled input hashes remain unchanged.
Any executable, workflow, runtime, config, persistence, or other material change
invalidates the evidence and requires commissioning again.

## Commissioning and remediation

Commissioning exercises the complete deployment path on the real target in an
isolated, non-public release path. Recoverable packaging, permission, runtime,
configuration, mapping, or readiness defects are corrected with normal linear
commits on the same task branch and PR, then the exact resulting candidate is
commissioned again. This avoids using failed public deployments as discovery.

Commissioning never switches public traffic and never runs a migration against
the live production database. A live production migration in commissioning is a
hard failure regardless of whether it appears additive, reversible, idempotent,
or low risk. Static deployment-path detection and evidence validation both fail
closed. Migration assessment may use a dry run, an explain plan, or execution on
a non-production database/schema copy.

## Promotion and first cutover

After commissioning passes, normal promotion remains
`task/feature -> development -> staging -> main`, with exact-head PR-QA and all
required approvals. Gate D may then perform the single authorized transition
from the immutable legacy baseline/webroot to the governed
release/current/shared model. The cutover continues to require write quiesce and
drain where applicable, final persistence sync, complete database backup,
separately governed production migrations, atomic switching, automatic rollback,
Runtime Certifier, and unrelated-site isolation.

When `cutover.status=COMPLETE`, the deployed SHA must equal the commissioned
candidate, the deployed marker and current/release model must exist, and
`legacy_authorization_active` must be false. The onboarding mode is then expired;
future changes use ordinary Gate C and Gate D. The legacy artifact remains only
as permitted rollback evidence.

## Recovery safe shape

Recovery is not a broad SSM exception. The existing policy authorization remains
bound to an exact repository, workflow, recovery/failure context, target,
document, deploy reference, baseline, expiry, and one approved SSM command. It
cannot commission or forward-deploy an artifact.

An exact recovery script hash is accepted. A policy-pinned semantic hash may also
accept only conservative safe-shape differences: shell comment-only lines,
indentation, and wording of a standalone literal `echo` to stderr that contains
no variable, substitution, or escape and does not write to a resource. Shebangs,
heredoc bodies, and machine-readable stdout remain
byte-sensitive. Adding/removing a command, changing any executable argument,
target host/path/resource, SSM scope, condition, phase, or recovery behavior
changes the semantic hash and fails closed. A semantic policy change requires the
normal central release and re-validation path.

## Minimal envelope

```legacy-onboarding
{
  "mode": "LEGACY_ONBOARDING",
  "repository": "Synergie-ITCI/example",
  "candidate_sha": "<40-character exact candidate SHA>",
  "target_identity": "<approved target identity>",
  "production_state": {"evidence_reference": "<immutable discovery evidence>"},
  "discovery": {},
  "baseline": {"rollback_kind": "legacy-baseline", "source_kind": "UNVERSIONED/LEGACY"},
  "commissioning": {"isolated": true, "public_traffic_switched": false},
  "migration_validation": {"live_production_mutation": false, "production_migration_requested": false},
  "health": {"minimum_body_bytes": 1024, "marker_present": true, "critical_routes": "PASS"},
  "coupled_inputs": {},
  "coupled_inputs_sha256": "<canonical SHA-256>",
  "cutover": {"status": "PENDING", "public_traffic_switched": false, "legacy_authorization_active": true}
}
```

The envelope above illustrates names only; every required field described in
this document must be populated for PASS.
