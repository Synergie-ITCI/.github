# Governed approval of audited runtime migration SQL

The central maintainer may approve exact SQL containing runtime deletion definitions
through a normal central policy PR, required QA, a protected release and a separate
pin activation PR. This approval does not authorize production migration execution.
Repository config, labels, comments, event data, caller arguments and cached QA
reports cannot create an authorization or disable migration safety.

`policy/audited-migration-authorizations.json` is bundled with the executing release.
The strict schema rejects unknown fields, duplicate bindings and reused UUIDs in the
bundle. An approval names the reviewer by login and numeric GitHub ID; both must
match the central `governance.migration_sql_reviewers` registry. The existing owner
review exception applies to centrally authored policy PRs; other authors still
require independent review. The record is a governed maintainer declaration, not
a fabricated GitHub review. All ordinary review and automated gates remain required.

Each new UUIDv4 binds the repository name and numeric ID, PR number, source and target
refs, exact head and base commits, exact migration path and full byte SHA256,
ordered DELETE statement line numbers and byte SHA256 fingerprints, approved
reviewer, purpose and timezone-aware issuance/expiry. The window cannot exceed
24 hours. Missing/malformed policy, local content changes, forks, unavailable live
GitHub verification and expired windows fail closed. The lookup uses the existing
fixed GitHub endpoint with no redirects and bounded responses; credentials and API
response contents are not included in diagnostics.

This mechanism is deliberately not a SQL safety parser. A reviewer must audit the
complete file and authorization context. Fingerprints cover exact bytes from DELETE
through the terminating semicolon, including internal whitespace. Only those exact
spans are excluded from the in-memory static classification after the full file hash,
committed bytes and live PR binding pass. The source SQL is never rewritten. All
other files and other destructive operations remain subject to the ordinary gate.

Preflight runs before technical-cache reuse. Final governance checks the live binding
and expiry again after repository validation. The authorization is single-PR bounded:
repeated checks for the same unchanged open candidate are allowed within the window.
Replaying an event after merge/closure, against a different candidate or after cleanup
cannot reuse it. Remove the record immediately following completion, then publish and
activate a clean release. Do not reactivate a historical authorization release.
Default limits remain 5,000 effective additions and 200 changed files.

## PR 134 audit

At application head `2f5b88d7a99cd5ad0d1f74404880e4492c195d5d`, the complete
`apps/api/alembic/sql/20260910_0038.sql` SHA256 is
`56d29de95cd31ae88509757f414da89a679161761da07693605e0db1a631f773`.

| Line | Target | Bound and guard |
| --- | --- | --- |
| 375 | `app_private.submission_projection_guards` | Current transaction, tenant and submission; cleans only the ephemeral projection guard. |
| 388 | `submission_answers` | Tenant and submission; authorized privacy guard and scrubbed parent required. |
| 389 | `submission_scores` | Same authorized privacy boundary. |
| 390 | `data_quality_flags` | Same authorized privacy boundary. |
| 391 | `submission_normalizations` | Same boundary; removes identifying hashes on erasure. |

The four domain-data deletions execute only inside the existing authorized runtime
erasure flow. The transient guard cleanup also executes during upgrade backfill;
therefore it would be inaccurate to claim no DELETE statement executes at upgrade.
The upgrade never deletes or rewrites the original submitted JSON or existing
submission identities. Public projection tables enforce tenant RLS and grant the
restricted application role SELECT only. SECURITY DEFINER functions are privileged
paths: explicit tenant/submission predicates, private transaction guards, approved
privacy-request state and authenticated project-scoped permission enforce erasure.
They must not be described as relying solely on owner-role RLS. Function execution
and private guard access are revoked from PUBLIC; search paths are fixed.

Fresh PostgreSQL and 0037-to-0038 upgrade tests, original JSON/hash reconciliation,
negative tenant/permission and private-guard tests, projection rollback, replay,
restricted-role RLS and authorized erasure tests passed at the exact application
head. A nonempty normalized history refuses destructive downgrade. Final application
QA must still pass after activation; this record does not approve dependency,
security, architecture, migration execution or other gate failures.
