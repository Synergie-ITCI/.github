# FieldZilla PR712: inactive central review proposal

This package is preparation only. It does not add an entry to active policy,
name an approved reviewer, issue an authorization window, change a framework,
activate a pin, or permit a deployment. The request UUID identifies this review
package and must never be reused as an issued authorization UUID.

## Observed application

PR712 is open against main at
`f34956e640faaf82d712eff74ae7c195e3d01f87`, base
`c8aee71a61059392f17343eac434d2a73dfb3b4c`, in
`Synergie-ITCI/programme-management-platform` (repository ID1315697868).
The comparison source is development
`9a199f332165fd825e186b8aa6273532f0987efc`. Source equivalence is evidence for
review, not a new authorization. Exact Git objects, file hashes, raw patch hash,
all source-tree differences, and the SQL DELETE fingerprints are in request.json.
Any head/base/path/byte change invalidates this snapshot for issuance.

The consumer executes rc225. Exact-head static run42769489647 reports Secrets PASS (zero findings), Deployment Risk FAIL and Migration Risk FAIL. Architecture Governance is tracked separately and is not inferred from this static report. Opening/updating this central proposal runs normal central QA; it cannot make the application PR green by itself.

PR713 has merged with separate owner approval; it added only CODEOWNERS coverage. The application candidate adds two verified exact Podfile checksum fingerprints using the existing process. Its disposable scanner regressions pass: baseline clean; changed checksum, secret-shaped content in the same file, and identical content in another file all remain detected. No secret value is reproduced here.

## Bounded inherited-content review

The exact central deployment patterns identify40 deployment-sensitive changed
paths. Of these,38 exactly match the comparison source. Only those byte-identical
paths are candidates for inherited classification. Two do not match:

- `.github/workflows/architecture-governance.yml` retains main's edited-PR trigger
  and development's explicit migration target; it requires fresh review.
- `deploy/production/application_plan.py` is newly authored preparation code,
  absent from that source, and must remain a new finding.

The renderer also fixes the missing migration-bootstrap context-key
reference. Its focused regression first failed and now passes;21 local tests and
14 subtests pass. No configuration value was retrieved or provisioned. Matching
strong context values and live behavior still need the governed preflight; this
new code is not inherited or approved by that local test result.

The existing source/base overlay model can express content matching those exact
committed selectors. It cannot safely classify newly authored content absent
from both as inherited using those selectors. Empty/unknown selectors or treating
the whole unreviewed candidate as an approved baseline would exceed this request.
Do not extend the schema, classifier or allowlist here. This package deliberately
stops short of a full activation record: review the new paths independently or
prepare a separately approved source split before attempting issuance.

A size-only live-main exception does not clear immutable deployment/SQL controls.
The existing documented baseline release path is required for any permitted
non-size authorization. No such entry is proposed in active policy here.

## Audited SQL request

Exact file: `apps/api/alembic/sql/20260910_0038.sql`.
SHA256: `56d29de95cd31ae88509757f414da89a679161761da07693605e0db1a631f773`.
Its five DELETE-span hashes match the prior centrally documented PR134 audit.
That historical authorization is not reused for PR712.

The statements start at375 (transaction-local projection guard cleanup),388
(normalized answers),389 (scores),390 (quality flags),391 (normalizations).
The four domain-data deletions are within the existing guarded privacy-erasure
flow. Guard cleanup can execute during upgrade; saying no DELETE executes during
upgrade would be incorrect. No SQL bytes, privileges or erasure guard are changed.

The named reviewer in request.json is requested, not recorded as having approved
this SQL for this PR. Before any future record can be issued, an authorized
central reviewer must audit the complete file and final application binding.
Fresh UUIDs and an issuance/expiry window no longer than24h must be assigned only
then. Normal central review, immutable publication and separate pin activation
remain required. This proposal authorizes none of those steps or SQL execution.

## Dependencies and order

1. Ownership PR713 is merged at main c8aee71a61059392f17343eac434d2a73dfb3b4c after its exact-head approval and passing checks. No deployment was triggered.
2. Exact Podfile checksum dispositions are committed in application f34956e. Fresh governed Secrets PASS and local adversarial regressions PASS. This central package grants no scan exception.
3. This evidence binds the current application head/base. Any further content/head/base change invalidates it for issuance; refresh before recording an authorization.
4. Resolve the two fresh deployment changes without broadening inherited scope.
5. Prepare final bounded records through the existing central mechanisms only,
   after independent review. Validate rejection on drift, expired/overlong windows,
   changed SQL, changed PR state, and unavailable live binding.
6. Merge, release/pin activation, application migration, traffic cutover and APK
   distribution each retain their applicable approval gates.

## Preservation and rollback

No active policy, engine, schema, consumer selection, workflow, tag, role, data,
staging release or production resource changes in this PR. Rollback of preparation
is a reviewed removal of this package and its tests. There is no runtime rollback
operation. If a later authorization is issued, it needs its own cleanup and
rollback review; closing/merging the application PR or expiry invalidates its use.

Nidaan and the retained mobile work stay untouched. Final mobile reconciliation,
production task/identity/image preparation, complete rehearsal, signed1.0.7 upgrade
proof, pending-work continuity, write reconciliation and Gate D remain open.
