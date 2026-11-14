# FieldZilla production hosting gate (proposed)

This workflow is for the isolated hosting root at
`deploy/production/hosting` in `Synergie-ITCI/programme-management-platform`.
It does not deploy the team application or migrate records. The staging
OpenTofu caller, state and AWS role remain unchanged.

GitHub returned HTTP 422 when required reviewers were requested for the
private repository's `synergie-app-production` environment. The empty
environment created by that failed request was deleted. This workflow uses
an exact-plan owner approval fallback only while native reviewers are
unavailable. If GitHub later supports required reviewers, the fallback fails
closed and should be replaced by the native rule.

The application repository calls this reusable workflow from protected
`main` at an immutable `pr-qa-v1-rcNNN` tag. The dedicated AWS OIDC role must
accept only its exact `job_workflow_ref`, repository ID, production
environment and main ref, with production-only state-key and resource access.
The repository's live OIDC customization setting is `use_default: true` and
`use_immutable_subject: true`, with subject prefix
`repo:Synergie-ITCI@209829096/programme-management-platform@1315697868`.
The trust must match its immutable production-environment subject ending
`:environment:synergie-app-production`.
The central workflow checks the matching OIDC claims at runtime. It uses a
separate encrypted S3 state key and the existing DynamoDB lock.
The central PR-QA policy explicitly classifies this root as governed critical
infrastructure. Without that reviewed classification, the application PR's
Deployment Risk gate fails before technical QA; the policy addition is
required for the protected path, not a QA bypass.

`plan` creates a one-day immutable GitHub artifact containing the binary
plan, readable diff, JSON diff, provider lock and metadata. The verifier
requires every managed action to be an addition. Phase one allows no shared
ALB addition; phase two allows exactly the production SNI certificate and
two production hostname rules. Neither phase accepts a staging reference
in a created resource. `apply` downloads the exact plan artifact, verifies
the successful plan run, source and caller commits, artifact digest, binary
SHA-256, provider lock, state key and current plan safety, then applies that
binary. It does not re-plan during apply.

The designated owner must post this exact, unedited comment on hosting PR
`Synergie-ITCI/programme-management-platform#674` after reviewing the artifact. Values in angle
brackets are substituted with the verified artifact evidence:

After a successful plan upload, the workflow derives that exact text from the
uploaded plan artifact ID and digest, checked binary plan hash and metadata.
It shows the text in the run summary and uploads a separate one-day
`fieldzilla-owner-approval-*` artifact containing `approval.txt`. The owner can
download that file and post it with `gh pr comment <674 or 717> --body-file
approval.txt` after reviewing the plan. The workflow does not post or grant an
approval for the owner; the apply gate still checks the owner-authored,
unedited, fresh, one-use comment and exact plan artifact.

```text
APPROVE FIELDZILLA PRODUCTION HOSTING <phase1 or phase2>
Source: <40-character source commit>
Caller: <40-character protected main commit>
Plan run: <GitHub Actions run ID>
Artifact ID: <GitHub artifact ID>
Artifact SHA-256: <64-character GitHub artifact digest>
Plan SHA-256: <64-character binary plan hash>
State key: programme-management-platform/fieldzilla/production/hosting/opentofu.tfstate
```

The approval must be authored by `SaurabhVermaIN`, be unedited, be no older
than 60 minutes, and be unused. The workflow records a GitHub deployment
marker before mutation to consume the comment once. A failed or uncertain
apply requires establishing actual AWS and state before any new plan.

The cost envelope and isolated design were approved by the owner on
2026-11-07 IST, capped at USD 65/month incremental before tax, egress and
growth. A materially changed resource plan or higher estimated cost requires
a new decision. The reviewed fallback and IAM trust need normal central
governance approval and an immutable release before this workflow can run.
