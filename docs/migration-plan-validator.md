# Reviewed migration plans

The central `actions/migration-plan-validator` composite action validates a deployment
path before a database migration runs. It reads a reviewed plan from the exact workflow
checkout and trusted JSON evidence gathered by the consuming workflow. The Python
validator is offline; it does not call AWS or GitHub. The action keeps the consumer's
existing job and OIDC `job_workflow_ref`.

## Plan and evidence

Add `.github/migration-plans/<plan_id>.json` to the consumer repository in a PR.
The file must be present at the workflow SHA. The schema is
`actions/migration-plan-validator/schema.json` (`$defs.plan` and `$defs.evidence`).
Unknown fields and versions fail. A plan approves one exact database-head transition:
`expected_pre_head` to `expected_post_head`. It binds repository, environment,
service, migration tool, runner task-definition family, allowed services, allowed
changed paths, centrally constrained non-runtime paths, forbidden legacy Compose/SSM
paths, image registries/repositories, and a rollback note. Optional
`baseline_ancestor_sha` must be an ancestor of the workflow SHA. Paths are
repository-relative. Migration-change globs need at least two literal leading
segments; `**` matches path segments and cannot authorize the whole repository.

Plans contain no own-PR head SHA, merge SHA, image digest, or expiry. The runtime
evidence binds `workflow_sha` to `github.sha`, `base_sha` to the last deployed SHA,
and `artifact_sha` to the commit used to build the deployed images. The image tag
must equal `artifact_sha`; it can differ from `workflow_sha` only when the artifact
is an ancestor and the intervening paths are allowed non-runtime paths. The
consumer supplies `artifact_is_ancestor_of_workflow: true` and the full
`paths_changed_between_artifact_and_workflow` list from
`git diff --name-only --no-renames artifact_sha..workflow_sha`. The validator
rechecks both facts against the local checkout. Consumers must fetch enough Git
history for these offline checks; unavailable history fails closed.

The central non-runtime categories are exactly `.github/workflows/**`, `docs/**`,
`**/tests/**`, and `*.md`. A plan may use those four patterns or exact paths
within them. `allowed_non_runtime_paths` cannot expand central policy. Unknown
paths are runtime by default. Changes under `deploy/`, `infra/`, migrations,
application source, Dockerfiles, package/lock files, or runtime configuration
cannot be waived by the plan.

Runtime evidence also includes changed paths (including old and new names for
renames), live and target database
heads, one registry/repository/tag per allowed service, and the actual field-level
task-definition diff. Every task-definition change must be a container image
change to that exact image reference. The caller
must gather evidence from trusted checkout, deployment, database and task-definition
steps, not user-controlled workflow inputs.

Example plan (shortened paths only for illustration):

```json
{
  "schema_version": 1,
  "plan_id": "example-migration-0002",
  "repository": "Synergie-ITCI/example",
  "environment": "staging",
  "service": "api",
  "migration_tool": "alembic",
  "expected_pre_head": "revision_0001",
  "expected_post_head": "revision_0002",
  "allowed_changed_paths": ["apps/api/alembic/versions/*", "apps/api/app/modules/*", ".github/migration-plans/example-migration-0002.json"],
  "allowed_non_runtime_paths": [".github/workflows/**", "docs/**", "**/tests/**", "*.md"],
  "forbidden_paths": ["deploy/legacy/compose.yml", "deploy/legacy/ssm.sh"],
  "migration_runner": "example-staging-migration",
  "allowed_services": ["api"],
  "image_rule": {
    "registries": ["registry.example.invalid"],
    "repositories": {"api": "example/api"},
    "task_definition_families": {"api": "example-staging-api"}
  },
  "rollback_note": "Restore the reviewed pre-migration backup; downgrade may be limited."
}
```

Evidence uses `evidence_schema_version: 1` and the same `plan_id`, repository,
environment, service, migration tool and runner. `changed_paths` is an array of
`{"status":"modified","path":"..."}` entries; statuses are `added`, `modified`,
`deleted`, or `renamed` (rename also requires `previous_path`). `image_evidence`
contains `{service,registry,repository,tag,digest}` records. `task_definition_diff`
contains `{service,family,changes}` records with changes such as
`{"path":"/containerDefinitions/0/image","before":"old","after":"registry/repository@sha256:<digest>"}`.
The task-definition image digest must match image evidence. The digest never
belongs in a plan.

## Consumer wiring

In the existing governed deployment job, check out the consumer at the exact
`github.sha` and the approved central release at an immutable tag. Gather the
evidence JSON using the existing governed steps. Then call:

```yaml
- uses: ./.central-framework/actions/migration-plan-validator
  with:
    plan-id: example-migration-0002
    evidence-file: ${{ runner.temp }}/migration-evidence.json
    base-sha: ${{ steps.last-deployed.outputs.sha }}
    service: api
    environment: staging
    report-file: ${{ runner.temp }}/migration-plan-report.json
```

The action checks the consumer checkout's `HEAD` against `github.sha`; the
validator reads the plan blob from that exact commit tree. A new migration adds
a new reviewed plan file; the workflow does not need a new hardcoded head. The
plan directory **must** be
protected by CODEOWNERS or an equivalent required review rule. Without that,
the plan is not an approval gate.

This standard applies prospectively. It does not certify old deployments. The
FieldZilla `0059→0060` deployment is a pre-standard negative replay: deployment
code and infrastructure changed between its image artifact SHA and workflow SHA,
so this validator rejects it. The later `0060→0061` replay has matching artifact
and workflow SHAs and passes the path-boundary check.

A migration plan approves the **deployment path only**. The consumer remains
responsible for migration correctness, data safety, upgrade and downgrade tests,
and rollback limits. Adopt the central action first, FieldZilla in a separate
first-adopter task, then other repositories. Moving per-PR audit exceptions
(such as mobile audit) into consumers is a future candidate pattern and is not
part of this standard.
