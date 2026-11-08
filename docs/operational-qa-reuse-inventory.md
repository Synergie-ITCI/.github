# Synergie operational QA inventory — 8 November 2026

Read-only sample, not an organization-wide rollout recommendation. The current
authenticated inventory exposes 82 repositories. Seven repositories were sampled
for workflow definitions/current QA callers and their latest ten manual runs.
All seven samples were readable; repositories not visible to this credential
cannot be counted or presumed compliant. Empty manual history does not mean no QA.
Raw API records and run/job links are in the external review evidence package.

| Repository | Sample result | Current PR-QA path | Reuse recommendation |
| --- | --- | --- | --- |
| programme-management-platform | Confirmed six full QA jobs on exact staging ed64b353889d395540be4d667cac4859afe255cd | central pr-qa.yml@main resolves approved rc225/aca405d | First disabled observe/locked-pause pilot only |
| saksham | Ten manual runs sampled; no repeated workflow/commit pair in sample | central @main; approved default rc216/300758c | PHP >=7.4/composer fixture validates protocol only; measure duplication before adoption |
| scholarships | No manual runs in latest-ten query | central @main; approved default rc216/300758c | No confirmed operational opportunity |
| roadsense-production-dashboard | release-intent repeated at 3e8b630c… (40741091573,40740720571); no repeated QA job observed | central @main; approved default rc216/300758c | Independent release approval is not a QA-cache opportunity |
| csr-intelligence-engine | deploy-uat repeated at a655a2d5… (30187058851,30186959450); no repeated QA job observed | central @main; approved rc219/75a3024 | Diagnose source validation versus deploy steps before proposing reuse |
| telemedicine-backend | uat-operations repeated at 42583ae4… (34194719036,34194575891); no repeated QA job observed | central @main; approved default rc216/300758c | Potential operational candidate, not measured QA duplication |
| giving-web | No manual runs in latest-ten query | central @main; approved default rc216/300758c | No confirmed operational opportunity |

Pins are snapshots of current central consumer selection, not a claim that older
runs executed today's selection. Those historical sample workflows did not
expose central QA pins in the inspected operation definition. Do not invent one.
Full SHAs and source definition/read errors are retained in the machine-readable
records. No sampled repository was modified or dispatched.

## Confirmed FieldZilla durations

All runs resolve to ed64b353889d395540be4d667cac4859afe255cd. GitHub started/completed
metadata confirms these QA job seconds: post-merge42410585109=615;
DB precheck42443559812=596; observe42444538725=604; pause42445308233=636;
migration/rollout42446824811=548; resume42448757854=619. Manual QA total3003s
(50m03s); all six3618s(60m18s). Observe/pause/resume1859s(30m59s).
These are measured job times, not achieved savings or billing totals.

The eight proposed reusable step durations total315s in observe and352s in pause.
Their667s(11m07s) sum is only an upper-bound future savings estimate. Verification,
fresh checks, dependency installs and human waiting remain. Resume stays fresh.
Migration/rollout, image publication and ECS/ALB timings remain outside this work.

## Adoption waves

1. Central capability review and disabled FieldZilla pilot review; separately
   approve activation only after issuer provenance, approval thread, protected
   source and fresh checks are bound to exact final reviewed commits.
2. After measured check-only/pilot evidence, invite repositories with confirmed
   same-input source QA duplication. Investigate UAT operational candidates,
   but do not opt them in based on repeated dispatch alone.
3. Broader language/platform coverage is an opt-in reviewed caller change for
   each repository. PHP/composer fixture success does not authorize Saksham,
   production releases, privileged recovery, migrations or deployments.

Always-fresh candidates: security/advisory scans, required approval, runtime and
credential identity, database/snapshot/image checks, drain/claim locks, actual
resume/recovery, migration/rollout/deployment. A matching SHA alone never qualifies.
