# FieldZilla application execution preparation

DRAFT — not activated, not a completed AWS rehearsal, not a Gate D package.

This is the next separately reviewed execution increment, not part of application
PR712/c92's import authorization. Keep that source/base frozen. The renderer is
an evolution of deploy/production/application_plan.py from the reviewed app;
its production target remains regression-tested. The original app scaffold is
historical preparation; do not copy new central execution code back into712.
The isolated scope has separate names, identities, secrets, targets and logs;
only exact production-registry candidate image digests are reused.

Implemented foundation: strict renderer, exact-manifest owner-comment predicate,
zero-writer and exact image/identity preflight, task/service0 preparation, bounded
migration task polling, private metadata-only before/after database attestation, one-use approval receipts,
exact running image/host/port/healthy-target readback,
exclusive private execution journal, explicit expired-approval refusal, and a
stop-writers recovery that never restores/downgrades the database. AWS retries
are disabled; ambiguous outcomes require inspection. Source-only fake-AWS tests
are not runtime evidence. No AWS mutation or secret-value retrieval has occurred.

Use the existing application-caller / central-reusable-workflow OIDC model.
Both deployment and hosting must share fieldzilla-production-hosting concurrency
(cancel-in-progress false) in the caller repository. A direct central dispatch
would lack read access to the private application repo; do not transport the
owner's OAuth token or add a broad cross-repo credential as a workaround.

The reusable `fieldzilla-production-application.yml` and `application_runner.py`
now wire the isolated infrastructure increment. The workflow has no push,
pull-request or direct-dispatch trigger. It accepts only a main-only application
caller, verifies the actual reusable-workflow OIDC identity and immutable release
provenance, then verifies the exact manifest artifact and unused owner approval
before assuming the separate rehearsal role. The runner rechecks current source,
base and exact-head checks before each authorized mutation. It registers digest-
pinned definitions, migrates, starts services and verifies executing images and
healthy targets. Production execution is deliberately rejected by this entry
point until its separate promotion/cutover integration is complete.
Unlike the old review renderer, the prepared request disables automatic ECS
image rollback. A schema migration or accepted write can make the previous image
incompatible; an unhealthy deployment must retain data and use reviewed recovery.

This is an infrastructure increment, not a complete application rehearsal. Its
report explicitly sets `rehearsal_passed=false`. Normal authenticated API/Admin,
evidence and original-client-ID reconciliation, and recovery preserving accepted
writes still need a prepared isolated fixture and actual runtime evidence. An
image-only production publisher, scoped identities/resource preparation, protected
main caller, and immutable publication remain prerequisites. Nothing here has
been dispatched, granted, published or deployed.

Rehearsal must use an authorized isolated AWS target and synthetic data, not the
production database, staging, or Docker as a substitute. No such resource plan
or cost commitment is authorized. Production existing roles Application and
TaskExecution are confirmed; AdminExecution and MigrationExecution returned
NoSuchEntity. Reuse the existing API role rather than proposing duplicate grants.

Bootstrap dependency: current main has only hosting and a NO_DEPLOY gate caller.
The small new manual application caller needs its own exact preparation merge;
it must never target staging or gain automatic push deployment. Such a main
change also changes712's base: prepare the final rebind after that reference is
known, and do not stretch the currently issued c92/c8 authorization to it.
Do not silently merge application code before the required rehearsal/Gate C.

Cutover remains in the existing hosting/IaC approval lane, scoped to production
host routing only. Do not add listener-writing permission to this executor.
API/Admin health is necessary but insufficient: final writes, old-client queued
work, accepted-write-preserving recovery and the one-writer switch require their
own live proof and exact Gate D authorization. APK publication is separate.

The read-only rehearsal context checks main-only manual caller, current main/base
and PR head, central annotated tag/source, and latest exact-head GitHub Actions
checks. The workflow additionally invokes the existing central release verifier;
a matching tag reference alone is insufficient.

`application_iam.py` renders a review-only permission document. It never creates
roles or applies IAM. ECS task discovery includes the exact approved container
instance in the request and policy, with the exact cluster condition. Its supported
resource mapping follows the [AWS ECS authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecs.html).
No live IAM simulation or grant is claimed. Migration log reads are restricted
to candidate-source streams; PassRole is restricted to four reviewed ECS task
identities. Registration is restricted to three target families and candidate
tags. Secrets, IAM mutation and listener changes are excluded.

Validation: `python3 -m unittest discover -s tests -p 'test_production_*.py'`.
The 58 deterministic checks and Ruff cover the prepared source only. They cannot
replace governed exact-head QA, an actual AWS rehearsal or authenticated acceptance.
