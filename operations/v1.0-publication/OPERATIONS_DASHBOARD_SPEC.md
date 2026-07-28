# Operations Dashboard Specification

Release reference: `pr-qa-v1-rc2`

Objective: define the dashboard needed to monitor publication, pilot, expanded pilot, and organisation rollout without changing the framework.

## Data Sources

| Source | Purpose |
| --- | --- |
| GitHub pull requests | rollout status, owner review, merge state |
| GitHub Actions runs | runtime, conclusion, runner stability, workflow failures |
| PR QA report artifacts | gate results, risk levels, scanner output summaries |
| Release evidence register | publication integrity, tag SHA, workflow SHA |
| Repository inventory | rollout wave scope and exclusions |
| Developer feedback form | usability, clarity, false positives |
| Reviewer feedback form | report usefulness, review time, confidence |

## Dashboard Sections

### 1. Publication Health

| Metric | Definition | Target |
| --- | --- | --- |
| Release tag exists | `pr-qa-v1-rc2` present in central repo | yes |
| Tag protected | ruleset or tag protection active | yes |
| Workflow resolvable | reusable workflow readable by API at release ref | yes |
| Release published | GitHub release exists for release ref | yes |
| Integrity hash recorded | archive SHA-256 and workflow SHA recorded | yes |

### 2. Adoption

| Metric | Definition | Target |
| --- | --- | --- |
| Repositories protected | repositories with merged caller workflow | increasing by wave |
| Open rollout PRs | rollout PRs awaiting owner review | tracked daily |
| Merged rollout PRs | rollout PRs merged by owners | tracked daily |
| Closed rollout PRs | rollout PRs closed or rolled back | reviewed |
| Excluded repositories | no default branch, archived, or owner blocked | explicitly listed |

### 3. Workflow Performance

| Metric | Definition | Target |
| --- | --- | --- |
| Average runtime | mean PR QA runtime | stable |
| p95 runtime | slowest routine runs | no uncontrolled growth |
| Queue delay | run queued time before start | monitored |
| Runner failure rate | infrastructure failures divided by total runs | near zero |
| Retry rate | runs re-executed due to platform instability | low |

### 4. Gate Outcomes

| Metric | Definition |
| --- | --- |
| Secrets blocked | PRs failed by secret detection |
| Broken builds detected | PRs failed by build/test gates |
| High-risk PRs | PRs classified high risk |
| Deployment-change PRs | PRs touching deploy workflows or manifests |
| Migration PRs | PRs touching database migration paths |
| Documentation-only PRs | PRs classified low risk |

### 5. Quality Signal

| Metric | Definition | Review Cadence |
| --- | --- | --- |
| False positives | expected safe PRs blocked unexpectedly | daily during pilot, weekly after rollout |
| False negatives | expected risky PRs not flagged | immediate incident review |
| Reviewer confidence | reviewer survey score | per wave |
| Developer satisfaction | developer survey score | per wave |
| Review duration | time from PR open to review decision | per wave |

### 6. Security Assurance

| Metric | Definition | Target |
| --- | --- | --- |
| Secret redaction failures | logs or artifacts exposing synthetic or real secret values | zero |
| Mandatory scanner execution | required scanners actually ran | 100 percent |
| Dependency audit coverage | supported ecosystems scanned | per repo |
| Artifact retention compliance | reports retained according to policy | 100 percent |

## Recommended Views

- Executive view: adoption by wave, go/no-go status, unresolved blockers.
- DevSecOps view: scanner execution, secret detections, false negatives, runner failures.
- QA view: test/build failures, report clarity, false positives, scenario outcomes.
- Release Manager view: PR status, approvals, evidence completeness, rollback readiness.

## Minimal Implementation

A spreadsheet or GitHub Project is sufficient for pilot and expanded pilot. Required columns:

| Column |
| --- |
| phase |
| wave |
| repository |
| default branch |
| rollout PR |
| rollout PR status |
| reusable ref |
| latest run |
| conclusion |
| runtime minutes |
| false positive count |
| false negative count |
| runner failures |
| owner approval |
| rollback status |
| go/no-go |

## Alerts

Create manual or automated alerts for:

- workflow resolution failure
- synthetic secret not blocked
- unredacted secret in logs or artifacts
- p95 runtime greater than agreed pilot threshold
- more than one runner failure in a wave
- rollout PR merged without owner approval
- release tag mutation or deletion
