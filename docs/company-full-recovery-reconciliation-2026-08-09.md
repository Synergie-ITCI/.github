# Synergie Full Application Recovery Reconciliation - 2026-08-09

Overall company status: `NOT FULLY RECOVERABLE`.

Backup layer remains `COMPANY BACKUP RECOVERY CERTIFIED`; this pass did not redesign it. No application reached full certification because every app is blocked before clean-room restore by missing recovery manifests, unmanaged/server-local secrets, source/asset gaps, dependency gaps, deployment traceability gaps, or untriaged repository secret-scan findings.

## Summary

| Metric | Value |
| --- | ---: |
| Applications | 20 |
| Full certified | 0 |
| Certified with conditions | 0 |
| Ready for clean-room | 0 |
| Not recoverable | 20 |
| External-provider blocked | 0 |
| Source complete | 4 |
| Assets complete | 1 |
| Runtime reproducible | 5 |
| Canonical deploy trace known | 7 |
| Valid recovery manifests | 0 |
| Clean-room blocked | 20 |
| Server-only source/asset gap files | 35900 |
| Persistent-like files requiring classification | 19109 |
| Missing env template variable names | 701 |
| Sensitive runtime variable names needing approved secret refs | 204 |
| Selected-repo redacted secret-scan findings | 132 |

## Application Results

| Application | Source | Assets | Secrets | Runtime | Deploy Trace | Artifact | Manifest | Clean-room | RTO | RPO | Status |
| ----------- | ------ | ------ | ------- | ------- | ------------ | -------- | -------- | ---------- | --- | --- | ------ |
| `bayer` | `COMPLETE` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T120444Z` | `NOT_RECOVERABLE` |
| `bridgestone` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T115852Z` | `NOT_RECOVERABLE` |
| `datamatics-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T120632Z` | `NOT_RECOVERABLE` |
| `dhansamvaad` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T120654Z` | `NOT_RECOVERABLE` |
| `fis-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T120733Z` | `NOT_RECOVERABLE` |
| `icicir2s` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T120803Z` | `NOT_RECOVERABLE` |
| `jiobp-lms` | `COMPLETE` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T120819Z` | `NOT_RECOVERABLE` |
| `jiobpcares` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T120843Z` | `NOT_RECOVERABLE` |
| `jiobptransporter` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121144Z` | `NOT_RECOVERABLE` |
| `mobilekids` | `COMPLETE` | `GAP` | `NOT_COMPANY_CONTROLLED` | `REPRODUCIBLE` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121201Z` | `NOT_RECOVERABLE` |
| `projectdemo-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `CANONICAL_COMMIT_KNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121237Z` | `NOT_RECOVERABLE` |
| `sankalptraining-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `REPRODUCIBLE` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121259Z` | `NOT_RECOVERABLE` |
| `shareasmile` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121315Z` | `NOT_RECOVERABLE` |
| `syncsr` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121333Z` | `NOT_RECOVERABLE` |
| `synergie-hub` | `COMPLETE` | `COMPLETE` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121351Z` | `NOT_RECOVERABLE` |
| `synergielms-root` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `REPRODUCIBLE` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121403Z` | `NOT_RECOVERABLE` |
| `telemedicine` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `REPRODUCIBLE` | `CANONICAL_COMMIT_KNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121607Z` | `NOT_RECOVERABLE` |
| `timesheet-lms` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `REPRODUCIBLE` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121657Z` | `NOT_RECOVERABLE` |
| `wearesynergie` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121713Z` | `NOT_RECOVERABLE` |
| `wearesynergie-insights` | `GAP` | `GAP` | `NOT_COMPANY_CONTROLLED` | `GAP` | `LEGACY_DEPLOYMENT_COMMIT_UNKNOWN` | `NOT_CREATED` | `MISSING` | `BLOCKED` | `NOT_MEASURED` | `24h target; latest certified backup 20260809T121744Z` | `NOT_RECOVERABLE` |

## Per-App Blockers

- `bayer`: 17 upload-like/persistent files are outside the certified persistent path map or need explicit classification
- `bridgestone`: 2090 source/asset files differ from or are absent in selected repository commit
- `datamatics-lms`: 2 source/asset files differ from or are absent in selected repository commit
- `dhansamvaad`: 1115 source/asset files differ from or are absent in selected repository commit
- `fis-lms`: 370 source/asset files differ from or are absent in selected repository commit
- `icicir2s`: 404 source/asset files differ from or are absent in selected repository commit
- `jiobp-lms`: 7 upload-like/persistent files are outside the certified persistent path map or need explicit classification
- `jiobpcares`: 2177 source/asset files differ from or are absent in selected repository commit
- `jiobptransporter`: 4468 source/asset files differ from or are absent in selected repository commit
- `mobilekids`: 11 upload-like/persistent files are outside the certified persistent path map or need explicit classification
- `projectdemo-lms`: 2 source/asset files differ from or are absent in selected repository commit
- `sankalptraining-lms`: 221 source/asset files differ from or are absent in selected repository commit
- `shareasmile`: 2879 source/asset files differ from or are absent in selected repository commit
- `syncsr`: canonical repository unknown
- `synergie-hub`: Node lockfile missing
- `synergielms-root`: 179 source/asset files differ from or are absent in selected repository commit
- `telemedicine`: 2 source/asset files differ from or are absent in selected repository commit
- `timesheet-lms`: 128 source/asset files differ from or are absent in selected repository commit
- `wearesynergie`: 6252 source/asset files differ from or are absent in selected repository commit
- `wearesynergie-insights`: 15532 source/asset files differ from or are absent in selected repository commit

## Evidence Artifacts

- Production inventory: `s3://synergie-production-app-backups-918870682888-ap-south-1/full-recovery-audit/20260809/production-inventory-full.json`, VersionId `YwrkM9vtOPe7CM75M_7R0ZOa4b0wWuud`, AES256.
- GitHub repo inventory: `s3://synergie-production-app-backups-918870682888-ap-south-1/full-recovery-audit/20260809/github-repo-inventory.json`, VersionId `dj8uqciRFJYkTF_9VxeL6_6kZDdSZmbR`, AES256.
- Redacted repo secret scan: `s3://synergie-production-app-backups-918870682888-ap-south-1/full-recovery-audit/20260809/github-gitleaks-redacted.json`, VersionId `nRFCAJgC6_gNJyTAFZqXXV.S5_6BR3Dc`, AES256.
- Backup framework: unchanged at `/opt/synergie-backup-framework/current`.

## Safety

- Application deployments: none.
- Production database restores: none.
- Production code modifications: none.
- Production secret value migration: not performed; bulk value export to Secrets Manager requires explicit approval.
- Clean-room restore attempts: none, because prerequisite gates failed.

## Cost

- Temporary recovery compute: USD 0.00; no temporary recovery server was created.
- Additional S3 artifacts: two sanitized inventories and one redacted scan report; expected storage impact is cents/month at current size.
- Secret management: USD 0.00 incremental this run because secret value migration was not performed.
- Backup framework: unchanged.

## Next Action

Create and validate recovery manifests plus complete env templates for the three source-complete apps first: Bayer, Mobile Kids, and Synergie Hub.
