# Proposed RoadSense production Gate D approval

**Status: proposed; not approved or active.** This document is a narrowly scoped
policy proposal for `Synergie-ITCI/roadsense-production-dashboard`. It does not
authorize a production deployment or change the existing central PR-QA, branch
rules, publication holds, or Gate C.

## Evidence and boundary

The private RoadSense repository cannot enable GitHub Environment Required
Reviewers under its current plan: GitHub returned HTTP 422, stating that the
billing plan does not support that protection rule. The partially created empty
`production` environment was deleted. Do not recreate an unreviewed production
environment as an approval substitute.

The approved FieldZilla exact-plan fallback is expressly limited to staging;
it does not authorize production. Castrol's existing Gate D uses a manual
`workflow_dispatch`, a `SaurabhVermaIN` actor check, an approval-reference input,
OIDC, and SSM. Its environment has a branch restriction but no required
reviewer. Those controls demonstrate the approved OIDC/SSM deployment shape,
but they do not independently attest an exact RoadSense release pair.
RoadSense needs the additional controls below before any deploy workflow is
activated. The established Saurabh author exception remains valid: Saurabh
may authorize and deploy his own release.

The central `docs/gate-d-deployment-standard.md` remains authoritative:
Gate D is separate from Gate C, requires explicit Saurabh authorization, an
exact deployment/rollback identity, a traceable approval, OIDC-scoped access,
SSM execution, runtime verification, and recovery.

## Proposed approval authority

The existing central Executive Release Authority, `SaurabhVermaIN`, is the
only Gate D approver. The central policy already permits Saurabh to authorize
and deploy his own release after mandatory automated gates pass. No second
human approver is required when Saurabh is the requester. For a release
requested by anyone else, the Gate D approver is necessarily independent of
that requester. The verifier checks both the login and numeric GitHub ID
against the centrally governed authority record; a caller-supplied login
cannot confer authority.

Approval is a **separate authenticated GitHub Actions dispatch** from the
release-intent and deploy dispatches. It must be issued by the authorized
Saurabh identity through an approved, protected-main approval workflow.
It must not be inferred from a PR comment, issue comment, unverified
`approval_reference`, caller-supplied login, CI success, admin rights, or merge
to `main`. The approval workflow has no `id-token: write`, AWS credential,
production secret, or SSM permission.

## Exact approval record

A successful approval run creates a single immutable Actions artifact containing
canonical JSON with only these fields (no secrets):

- repository name and numeric repository ID;
- release requester login and numeric GitHub ID, verified against a separate
  successful release-intent run;
- approver login and numeric GitHub ID, taken from the approval run actor;
- release-intent run ID, approval run ID, and unique release identifier;
- exact 40-character `main` source commit SHA;
- exact `sha256:` Docker image digest;
- exact 64-character database SHA-256 and S3 object version;
- exact publication-policy version;
- target environment `roadsense-production` and SSM managed-node identity;
- rollback image/database pair;
- issuance and expiry (no more than 60 minutes apart).

The approval run must execute the approved workflow file from protected `main`
at the exact approved source SHA. The artifact's GitHub artifact ID and digest,
run ID, workflow path, actor ID, event, conclusion, head SHA, run attempt, and
creation time are independently fetched from GitHub APIs by the deployment
verifier. The verifier downloads the artifact by run and artifact ID, checks
its API digest against the downloaded bytes, parses a strict schema with
unknown/duplicate fields rejected, and compares every binding to the
deployment request and release manifest. Missing or deleted runs/artifacts,
unavailable APIs, changed `main`, expired approvals, reruns, or a different
requester fail closed. GitHub artifacts are treated as immutable while present;
if deleted, they cannot authorize deployment.

The approval workflow must derive the requester from the release-intent run's
GitHub actor ID; the requester is never trusted from an input alone. The deploy
verifier also binds the current authenticated dispatch actor and requires a
first-attempt run to match that original requester. The deploy
verifier checks the Gate D approver's authenticated login and numeric ID against
the central Executive Release Authority. It allows the requester and approver
to be the same person only when both are the authorized Saurabh identity. The
approval remains a distinct GitHub run bound to that release intent.

## Deployment enforcement

The production workflow must be manually dispatched from protected `main` for
an exact release ID, release manifest digest, approval run ID, and rollback
pair. A central reusable workflow verifies the approval evidence in a job with
`contents: read` and `actions: read` only. It must finish successfully before
a separate deployment job can request `id-token: write` or obtain any AWS
credentials. The deployment job repeats the exact tuple verification immediately
before OIDC and fails closed if `main`, artifact, approval, or release state
changed. A caller input or local file must not be able to skip the central
verifier. The scoped AWS role trust is restricted to the RoadSense repository,
protected `main`, and the approved immutable central reusable workflow identity;
no production permission is given to the approval workflow.

The deployment records a single-use GitHub deployment marker in the distinct
`roadsense-gate-d-ledger` environment, keyed by unique release ID and approval
run ID, before SSM execution. This ledger is not a production environment or
an approval substitute; it cannot grant AWS access. A repeated or conflicting
marker fails closed. The marker, approval run URLs, artifact digest, source SHA,
image digest, database SHA, policy version, SSM command ID, and result are
recorded without secrets. OIDC then assumes a narrowly scoped production role
and SSM targets only the verified RoadSense managed node. Runtime preflight
verifies the current rollback image/database pair and candidate artifact. Post-
deploy checks verify the public HTTPS endpoint, authenticated access without
logging credentials, publication holds, health, exact active image/database
identity, and shared-host routes. Failure invokes pairwise rollback.

This workflow must not be added to the production caller, released as an
immutable central tag, granted AWS trust, or used for deployment until the
central policy PR and implementation have passed governed QA, independent
security review by the sole authorised owner Saurabh, and his explicit
policy approval. A code review alone is not a
Gate D approval for a particular deployment.

## Required rejection tests before activation

The verifier and workflow must deterministically reject: absent approval;
invalid GitHub run/artifact or API outage; failed or rerun approval; unapproved actor or a self-issued approval by anyone other than the
verified Executive Release Authority; forged comment or free-text reference; stale or expired
approval; changed source SHA, Docker digest, database hash or object version,
policy version, target, release ID or rollback pair; changed protected-main
head; duplicate release ID; replayed approval; modified or missing artifact;
unsupported schema; a deployment request that reaches AWS credential acquisition
before approval. Each test must assert no OIDC token request, AWS role assumption,
or SSM command. Positive tests must prove the complete approved tuple and
single-use marker, then a controlled non-production or mocked execution path.


## Implementation preparation in this PR

`tools/roadsense_gate_d.py` and `actions/roadsense-gate-d/action.yml` are
review-only candidates. The action fetches GitHub run, artifact, protected-main,
and deployment-marker evidence itself; it verifies the full release tuple and
records single use in the separate approval ledger before returning success. It requests no OIDC token and
invokes no AWS or SSM command. The deployment caller does not yet exist. When
implemented after policy approval, it must call this action in a serialized
job with only `contents: read`, `actions: read`, and `deployments: write`; only
a downstream job with `needs` on that job may request `id-token: write`. The
central action must be pinned to an approved immutable release tag. No caller
may use this candidate branch or an unreviewed `main` reference.

The current tests use mocked GitHub evidence and cover positive exact binding,
missing and forged artifacts, stale approval, replay markers, every tuple
mismatch, wrong approver or deployment actor/workflow/branch, reruns and malformed JSON. A live,
non-production integration test of the eventual caller, approval issuance,
artifact digest behavior and IAM trust is still required before activation.

## Governance decisions required

1. Approve this RoadSense-only alternative to native environment reviewers.
2. Confirm the Gate D authority login and numeric GitHub ID, including the
   established Saurabh self-authorization exception.
3. Approve the exact release-intent, approval-artifact, verifier, and single-use
   marker implementation after Saurabh's security review and negative tests.
   Saurabh-authored governance PRs retain the central author exception; no
   second human reviewer is required.
4. Approve the immutable central workflow release and narrowly scoped OIDC/SSM
   role separately, with no production execution during setup.
5. For each release, record Gate C first and then a separate explicit Gate D
   approval event for the exact tuple. Production remains closed until all gates pass.
