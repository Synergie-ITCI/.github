# Synergie Full Application Recovery Remediation - 2026-08-09

Overall company status: `PARTIALLY RECOVERY CERTIFIED`.

Backup layer remains `COMPANY BACKUP RECOVERY CERTIFIED`; this run did not redo the backup layer. Synergie Hub reached full application recovery certification for a recovery-canonical release. Bayer, Mobile Kids, and JioBP LMS received safe repository remediation but remain blocked by secret-value migration approval and/or deployment trace requirements.

## Application Results

| Application | Source | Assets | Secrets | Runtime | Deploy Trace | Manifest | Artifact | Clean-room | Status |
| ----------- | ------ | ------ | ------- | ------- | ------------ | -------- | -------- | ---------- | ------ |
| `bayer` | `COMPLETE` | `COMPLETE` | `BLOCKED_REQUIRES_APPROVAL` | `REPRODUCIBLE` | `CANONICAL_COMMIT_KNOWN` | `BLOCKED` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `bridgestone` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `datamatics-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `dhansamvaad` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `fis-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `icicir2s` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `jiobp-lms` | `COMPLETE` | `COMPLETE` | `BLOCKED_REQUIRES_APPROVAL` | `REPRODUCIBLE` | `CANONICAL_COMMIT_KNOWN` | `BLOCKED` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `jiobpcares` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `jiobptransporter` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `mobilekids` | `COMPLETE` | `COMPLETE` | `BLOCKED_REQUIRES_APPROVAL` | `REPRODUCIBLE` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `BLOCKED` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `projectdemo-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `sankalptraining-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `REPRODUCIBLE` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `shareasmile` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `syncsr` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `synergie-hub` | `COMPLETE` | `COMPLETE` | `COMPANY_CONTROLLED` | `REPRODUCIBLE` | `RECOVERY_CANONICAL_RELEASE_CREATED_CURRENT_PRODUCTION_UNKNOWN` | `VALID` | `CREATED` | `PASS` | `FULL_APPLICATION_RECOVERY_CERTIFIED_RECOVERY_CANONICAL` |
| `synergielms-root` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `REPRODUCIBLE` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `telemedicine` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `REPRODUCIBLE` | `CANONICAL_COMMIT_KNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `timesheet-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `REPRODUCIBLE` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `wearesynergie` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |
| `wearesynergie-insights` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `MISSING` | `NOT_CREATED` | `BLOCKED` | `NOT_RECOVERABLE` |

## This Run

- applications: `20`
- full_recovery_certified: `1`
- ready_for_clean_room: `0`
- not_recoverable: `19`
- applications_remediated_this_run: `4`
- manifests_created: `1`
- manifests_valid: `1`
- artifacts_created: `1`
- clean_room_attempted: `1`
- clean_room_passed: `1`
- clean_room_blocked: `19`
- env_missing_names_previously: `701`
- env_names_resolved_this_run: `155`
- env_names_remaining: `546`
- sensitive_runtime_names_previously: `204`
- company_controlled_secret_names: `4`
- rotation_required: `0`
- secret_names_unknown_or_blocked: `200`
- scan_findings_active: `0`
- scan_findings_historical: `0`
- scan_findings_false_positive: `0`
- scan_findings_unknown: `132`

## Gap Classification

Original server-only/source-asset gap population: `35,900`. Counts below are heuristic categories from sanitized path/class metadata, used to prioritize remediation and avoid treating uploads/dependencies/logs as source.

- True source: `1264`
- Static assets: `16646`
- Dependencies: `20`
- Persistent: `3678`
- Generated: `16`
- Logs/cache: `29`
- Backups: `980`
- Secrets: `160`
- Unknown: `13107`

## Persistent Classification

Original persistent-like population: `19,109`.

- Covered by certified backup: `0`
- Not covered: `6639`
- Unknown: `12470`

## Application Details

### Bayer

- Assets: `COMPLETE` after classification; no recovery-critical server-only files remain for the selected commit.
- Env template: `.env.example` created with all 53 production-observed names.
- Secrets: `BLOCKED_REQUIRES_APPROVAL`; no production secret values copied.
- Runtime: `REPRODUCIBLE` for PHP 8.1.2, Composer 2.10.2, MariaDB 10.6.23, Apache 2.4.52; Node lockfile added for build reproducibility.
- Manifest: `BLOCKED` pending company-controlled secret references.
- Artifact: `NOT_CREATED`.
- Clean-room: `BLOCKED`.
- Status: `NOT_RECOVERABLE`.

### Mobile Kids

- Assets: `COMPLETE` after classification; no recovery-critical server-only files remain for the selected commit.
- Env template: completed with all 45 production-observed names.
- Secrets: `BLOCKED_REQUIRES_APPROVAL`; no production secret values copied.
- Runtime: `REPRODUCIBLE` for PHP 8.1.2, Composer 2.10.2, MariaDB 10.6.23, Apache 2.4.52.
- Deploy trace: `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN`.
- Manifest: `BLOCKED` pending secret references and deployment trace.
- Artifact: `NOT_CREATED`.
- Clean-room: `BLOCKED`.
- Status: `NOT_RECOVERABLE`.

### Synergie Hub

- Assets: `COMPLETE`.
- Env template: production-oriented template updated.
- Secrets: `COMPANY_CONTROLLED`; existing Secrets Manager records verified by metadata and SSM alias references created under `/synergie/synergie-hub/production/`.
- Runtime: `REPRODUCIBLE`; production host has `php8.2=8.2.33` and Apache `proxy_fcgi`.
- Deploy trace: `RECOVERY_CANONICAL_RELEASE_CREATED_CURRENT_PRODUCTION_UNKNOWN`; current production deployed marker remains absent.
- Manifest: `VALID`; production recovery policy passed.
- Artifact: `CREATED`; S3 VersionId `P78vd48sdDUZYoe_T05AgJOzS92rTzE9`, SHA-256 `412dd55283afedffea5ee440ecde7fdab275ddcca67c5a0845087ad8291f602a`.
- Clean-room: `PASS`; DB dump checksum matched, 18 tables restored, `/admin/login`, `/up`, CSS and JS returned 200.
- Status: `FULL_APPLICATION_RECOVERY_CERTIFIED_RECOVERY_CANONICAL`.

### Additional Apps Processed

- `jiobp-lms`: env template created with all 50 production-observed names, Node lockfile added, Apache template and blocker runbook added; remains blocked on secret migration approval, secret-scan triage, npm audit findings, and clean-room prerequisites.

## Artifacts

- Synergie Hub artifact: `s3://synergie-production-app-backups-918870682888-ap-south-1/full-recovery-artifacts/20260809/synergie-hub/synergie-hub-recovery-artifact-0916cdc75e0555.tar.gz`, VersionId `P78vd48sdDUZYoe_T05AgJOzS92rTzE9`, SHA-256 `412dd55283afedffea5ee440ecde7fdab275ddcca67c5a0845087ad8291f602a`.
- Synergie Hub release manifest: `s3://synergie-production-app-backups-918870682888-ap-south-1/full-recovery-artifacts/20260809/synergie-hub/release-manifest-0916cdc75e0555.json`, VersionId `tc1oE71vuReaGvcQN.ghxLjgB994x5u9`.

## Safety

- Production deployments: `0`.
- Production DB restores: `0`.
- Production application restarts: `0`.
- Production file deletions/replacements: `0`.
- Live secret value copying: `0`; attempted automation was blocked by safety review and not worked around.
- Temporary clean-room compute: local only; shut down after test.

## Next Action

Approve value-safe, one-application-at-a-time SSM SecureString migration for Bayer so its manifest can be created and clean-room restore can run.
