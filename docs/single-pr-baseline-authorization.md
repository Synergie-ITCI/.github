# Live, single-PR baseline authorization

`one_time_baseline_alignment` is an optional, centrally reviewed authorization.
It is not a repository configuration override. No application is authorized by
this hardening change. Ordinary callers that do not request this mechanism keep
the existing gates and default limits (5,000 effective additions, 200 files).

## Required schema

`schemas/one-time-baseline.schema.json` is the strict schema. Unknown fields and
incomplete authorizations fail closed when the mechanism is requested. Required
fields are `enabled`, `repository`, `pr_number`, `expected_head_sha`, `head_ref`,
`base_ref`, `allowed_effective_additions`, `allowed_changed_files`, `purpose`,
`issued_at`, `expires_after`, `authorization_id`, and `relaxations`. Use a new UUIDv4
for each authorization. Timestamps must include a timezone; issuance cannot be in
the future, expiry must be later than issuance, and the entire window cannot
exceed 24 hours. The two authorized size limits remain hard upper bounds even
when the corresponding ordinary threshold is relaxed.

`repository_id` optionally binds the trusted and live numeric GitHub repository
identity to an explicit positive integer. A mismatched ID fails before live lookup.
New one-time authorizations should include this bound identity.

`expected_base_sha` and `required_pr_body_marker` remain optional additional
constraints. Historical classification controls remain recognized by the schema;
none is enabled implicitly. Old authorizations missing the new required fields
must be reissued through central review. A source overlay still needs its exact
final candidate SHA authorized; a source SHA is no longer permission to create a
new candidate with different content.

## Live identity and reruns

The trusted reusable workflow uses GitHub's `GITHUB_REPOSITORY`,
`GITHUB_REPOSITORY_ID`, `GITHUB_REF`, event type, and checkout workspace context.
An event or CLI-supplied repository cannot select a different API repository.
The validator uses the existing read-only `pull-requests: read` token permission
and fixed `https://api.github.com` endpoint. It rejects forks for this privileged
baseline mode, mismatched numeric repository identity, another PR number,
changed source/base branches, a changed checked-out SHA, and live draft, closed or
merged state. API errors, missing credentials, rate limits, malformed responses,
and redirects fail closed. Credentials and response bodies are not logged.

A fresh lookup is required on each engine invocation before technical-baseline
reuse, and again before the final governance result. Repeated runs for the same unchanged, open PR are allowed within the
window. “Single use” means single-PR bounded, not one CI invocation. A replayed
event claiming the PR is open cannot override live closed/merged state. Historical
offline callers cannot exercise this privileged mode without trusted GitHub
execution context; ordinary offline validation is unchanged.

## Reproduction and verification

In rc99, the same in-memory authorization was accepted after changing event PR
number 125 to 999, and after changing event state to closed/merged. No policy was
published for that reproduction. The new adversarial tests cover both failures,
all identity constraints, the 24-hour window, authorized size caps, malformed
schema, API failures and reruns. Historical gate regression fixtures now supply
mocked live HTTP responses and the newly required bounded schema; their gate
assertions remain in place.

## Release

The next release is `pr-qa-v1-rc100`, bound to the reviewed central merge commit.
Protect that exact tag against updates and deletions before publishing it. Publication does not move the existing consumer pin. Activation requires a
subsequent governed central pin update after the immutable tag exists; application
caller files do not change. Verify tag SHA and protection from GitHub after publication.
Remove obsolete authorization entries through central review after use; even
before cleanup, a merged/closed PR or expired window cannot reuse authorization.

## Governed framework release registration

The shared workflow pin must occur in `policy/framework-releases.json` with an
exact commit, the numeric ID and exact `updated_at` value of its tag-protection
ruleset, and an explicitly empty reviewed `bypass_actors` list. Register a newly
published release in the same governed PR that activates its pin. Do not register
expired authorization releases for activation. The manifest does not authorize
branches, arbitrary commit references, user overrides, or persistent checkout
credentials.

Architecture Governance verifies the selected tag directly against GitHub and
requires an active, exact-tag ruleset prohibiting updates and deletion with no
bypass actors. Both reusable-workflow framework checkouts must use that pin.
Tag protection and GitHub Release API immutability are separate evidence.

GitHub hides ruleset bypass actors from read-only workflow tokens. Registration
therefore requires privileged read-only inspection of the complete ruleset and
records its exact modification timestamp alongside the empty bypass list. CI
checks that timestamp against live GitHub data; missing or changed timestamps
fail closed. Any visible nonempty bypass list also fails. A changed ruleset must
be inspected and registered again through central review. Before release
activation or merge, independently repeat the full privileged read-only check.
CI does not receive administration credentials or permission to mutate rulesets.
