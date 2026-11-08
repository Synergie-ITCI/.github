# Operational source QA evidence — inactive review candidate

Status: PREPARED FOR REVIEW, not an activated central release. Normal PR-QA,
required-check names, release selectors, existing callers and IAM are unchanged.

## Trust contract

The new `actions/operational-qa-evidence` composite action and
`tools/operational_qa_evidence.py` provide a source-check decision, never an
operation approval. They follow the authenticated Actions artifact origin and
SHA-256 digest pattern already used by `tools/roadsense_gate_d.py`; the
organization governance attestor is a drift report, not execution attestation.
No new signing secret, attestation billing capability or AWS permission is needed.

The verifier requires all of these, not just a matching commit:

- Explicit reviewed caller opt-in and eligible operation class. The current
  policy allows counts-only observe (maximum 6 hours) and locked worker pause
  (maximum 1 hour). Resume is intentionally not eligible in the first pilot.
- Exact repository name and numeric identity, protected current branch tip,
  source SHA, successful completed same-repository/non-fork run, permitted
  push/manual event, exact run attempt and issuing workflow path.
- Issuing workflow bytes at the run's exact revision match the reviewed caller
  hash and contain the immutable verifier pin. The executing verifier ref must
  match too. A trusted caller must compute the contract, not accept arbitrary
  contract data from dispatch inputs or downloaded artifacts.
- The central QA release tag resolves to the expected full commit and remains
  the live approved consumer selection. The separate operational policy bytes
  are bound by SHA-256, as is the immutable operational verifier commit. This
  does not assert that inline application QA was itself run by the PR-QA engine.
- Exact source-check/category and required-job contract, successful individual
  source steps in a unique producer job, and the current effective branch
  required-check policy hash. Changed checks invalidate old evidence.
- Source tree, dependency/lockfile content, resolved Python packages, Python,
  Node and npm versions and runner OS/architecture/image version are bound by
  the caller's input fingerprint. If a repository cannot establish relevant
  immutable/resolved inputs, it is not ready to opt in.
- Authenticated same-repository artifact origin/run/head IDs, nonexpired bounded
  artifact, GitHub's SHA-256 ZIP digest, one bounded JSON member, strict field
  set and no duplicate JSON keys. Issuance time is inside the producing run,
  not in the future, and within the operation's age cap.

The authenticated GitHub API is the trust boundary for artifact/run metadata.
An artifact's self-reported issuer or checksum is insufficient. This is not a
claim of hardware/runner attestation. A compromised protected issuer or GitHub
service is outside this protocol's trust boundary and requires incident response.

## Fallback and fresh work

The output `reuse_source_checks=true` covers only named source-level checks.
`authorizes_operation` is always false. Policy excludes security/advisory,
approval, runtime, migration, deployment, snapshots and drain locks from reuse.
Those checks remain under their existing applicable policy every operation.

Missing, failed, skipped, stale, incomplete, tampered, mismatched, unavailable or
unreadable evidence yields full QA. The caller must also treat a verifier step
failure, missing output or skipped step as full QA; testing just an output flag
is insufficient. Issuance/upload failures must not prevent original QA. Never
issue replacement evidence from a run which skipped source checks by reuse.
Evidence is usable only after the entire producer workflow has completed
successfully; an artifact uploaded before a later job failure remains invalid.

Non-adopting callers have no new dependencies or configuration. Existing
`.github/workflows/pr-qa.yml`, `pr-qa/pr_qa.py` and consumer release selections
are unchanged. No successful prior PR check is synthesized, renamed or replaced.

## Caller integration

A caller supplies a protected contract with `enabled`, repository identity,
branch, exact issuer workflow hash, verifier commit, current central release,
producer/required jobs, reusable source-step categories, mandatory fresh checks,
operation mapping and resolved input fingerprint. `record_for` defines the
strict artifact schema; the tests contain FieldZilla Python/Node and PHP/composer
fixtures. Caller-specific operations, credentials, approval, runtime and input
collection stay in callers.

A full source-QA producer may invoke `issue`, then upload only `qa-evidence.json`
as `operational-source-qa` using the existing upload-artifact mechanism. Consumer
invokes `verify` with an explicit artifact ID. No search for a convenient passing
run or acceptance of a weaker/older check contract occurs. Existing artifacts
without this provenance do not become trusted retroactively: first issue a new
record after full QA on the post-adoption exact commit.

FieldZilla avoids a new remote `uses` in its shared QA job. GitHub prepares
remote actions during job initialization, before executing steps. Instead, an
eligible step fetches only the pinned verifier and policy files, checks their
reviewed SHA-256 hashes, and falls back if unavailable. Resume never fetches them.
Other callers should similarly avoid adding a job-setup dependency to recovery.
References: [runner initialization](https://github.com/actions/runner/blob/main/src/Runner.Worker/JobExtension.cs),
[composite action ref context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts).

## Review and activation boundaries

Review the central and caller changes separately. This candidate changes no
existing active release or protected branch. The FieldZilla contract is disabled,
the approval thread is deliberately unset and its dispatch opt-in defaults false.
An immutable reviewed central commit must be available before an adopting caller
is enabled; normal central publication/selection governance still applies where
required. Do not reuse a feature commit as an approved release merely because it
has been pushed. A later reviewed activation must bind final central bytes,
caller workflow hash, eligible operations, approval route and fresh-input contract.

Rollback: set the caller's opt-in false/reviewedly disable its contract; every
original source check runs again. No runtime, worker, database or IAM rollback
is part of this feature. Do not remove live recovery controls or extend evidence
age to avoid fallback.

## Regression note

The first unrestricted full regression identified ten existing positive tests
which assumed approved mobile exceptions had not expired on 7 November. Only
`tests/test_node_audit_exception.py`'s fixture clock is made deterministic; policy
files, adapters, approved expiry dates and PR418's files/fixtures stay unchanged.
Additional inherited tests assert that the exact expiry instant and later remain
blocking. No expired exception is extended or activated.
