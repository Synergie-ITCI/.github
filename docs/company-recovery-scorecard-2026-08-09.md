# Synergie Company Recovery Scorecard - 2026-08-09

- Generated from live production metadata at `2026-08-09T11:00:47Z` UTC.
- Core control: `Ignored from Git must never mean not backed up anywhere.`
- Scope: company application recoverability, not a production release.

## Company Status

`NOT RECOVERABLE AS A COMPANY`

Only Sankalp has enough evidence for `RECOVERY CERTIFIED WITH CONDITIONS`. The remaining active production applications are `NOT RECOVERABLE` because they lack independent, restore-tested database backup evidence, persistent runtime-data backup evidence, canonical recovery manifests, and clean-room restore proof.

Sankalp is intentionally tracked separately so Mappls/Google provider access does not block the company queue.

## Evidence

| Evidence | Value |
| --- | --- |
| SSM live inventory command | `3ea44e66-feda-43a8-814c-45bc93fd5d2f` |
| Git remote token classification command | `6ed7ddd9-5984-4886-8121-31b47416ee38` |
| Git remote cleanup command | `97d618b8-81c6-4ce4-acee-2fe3dc45c537` |
| GitHub inventory generated | `2026-08-09T07:48:48.211818+00:00` |
| EC2 instance | `i-060e4ec1fd5345c30` / `t3.xlarge` / public IP `13.204.116.185` / private IP `172.31.34.212` |
| EBS volume | `vol-03d5e3fb77ec77d35` |
| Runtime observed | Apache 2.4.52, PHP 8.1.2, MariaDB 10.6.23, Composer 2.10.2 |

## Scorecard

| Metric | Result |
| --- | ---: |
| GitHub repositories inspected | 71 |
| Deployable candidates in GitHub inventory | 59 |
| Host-matched GitHub repositories | 14 |
| Canonical recovery manifests observed in prior main-branch inventory | 0 |
| Active roots on production EC2 | 24 |
| Active production roots | 21 |
| Production-hosted non-production roots | 3 |
| Fully recovery-certified production apps | 0 |
| Recovery certified with conditions | 1 |
| Not recoverable production apps | 20 |
| P0 production apps excluding Sankalp | 20 |
| Production apps with Git checkout | 6 / 21 |
| Production apps with deployed marker | 2 / 21 |
| Production apps with env template | 13 / 21 |
| Production apps with lockfiles | 16 / 21 |
| Production apps with parsed database names | 19 / 21 |
| Non-Sankalp parsed DB-backed prod apps missing independent backup proof | 18 |
| Production apps with persistent data observed | 20 / 21 |
| Production persistent data observed | 32.83 GiB |
| Non-Sankalp persistent data without backup proof | 28.05 GiB |

## Sankalp Status

| Field | Status |
| --- | --- |
| Certification | `RECOVERY CERTIFIED WITH CONDITIONS` |
| PR | `https://github.com/Synergie-ITCI/sankalp/pull/19` |
| PR state | draft, open, merge state clean, head `36682a1125bb7a9f3367e32952608a07158c88fd` |
| Production marker | `.deployed_commit=b7884336f3aac9cd01b8d55c639f6c9055b082c4`, not canonical release evidence |
| Logical DB backups | S3 backups for `sankalp_db` and `sankalptraining_db`, restore-tested |
| Persistent backups | S3 backup and representative restore for `assets/SurveyData`, `assets/ASSETS`, `assets/recharge` |
| Release artifact | S3 VersionId `o0ncFi8Pfzxx82xUrN_mKNIST_bc3fl4`, SHA-256 `7452e1e872bfa62ffa28641b89b573aafb27067c91071b34aada8f2636aa416d` |
| External blockers | Mappls OAuth client credential requires provider-side replacement; historical Google Maps key status requires Google project access |
| Remaining restore blocker | Full clean-room web restore is pending |

## AWS Backup And Cost

- Backup plans: 1 (`sankalp-production-ebs-daily-35d`).
- Backup vaults: 1 (`synergie-sankalp-recovery-vault`).
- Recovery points: 1; current completed point protects EBS volume `vol-03d5e3fb77ec77d35` with reported size `320.00 GiB` and 35-day retention.
- Interpretation: EBS backup is infrastructure DR. It is not a substitute for per-application logical DB backup, persistent upload backup, manifest, or restore test.
- AWS Cost Explorer August month-to-date unblended total: USD 298.37 for 2026-08-01 through 2026-08-09, queried with End=2026-08-10 exclusive.

| Top Cost Service | MTD USD |
| --- | ---: |
| Amazon Lightsail | 122.52 |
| Amazon Elastic Compute Cloud - Compute | 67.46 |
| Tax | 45.53 |
| EC2 - Other | 43.97 |
| Amazon Simple Storage Service | 13.57 |
| Amazon Virtual Private Cloud | 3.76 |
| AWS Secrets Manager | 0.92 |
| AWS Cost Explorer | 0.36 |

## Active Production P0 Queue

| Priority | App | Hostnames | Repo | DB | Persistent | Status | First blocker |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| `P0` | `bridgestone.synergieinsights.in` | `bridgestone.synergieinsights.in` | `Synergie-ITCI/bridgestone.synergieinsights.in` | `bridgestone_db` | 15.49 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `jiobpcares.synergieinsights.in` | `jiobpcares.synergieinsights.in` | `Synergie-ITCI/BP` | `jiobpcares_db` | 8.15 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `telemedicine.synergieinsights.in` | `telemedicine.synergieinsights.in` | `Synergie-ITCI/telemedicine-backend`, `Synergie-ITCI/telemedicine-bridgestone`, `Synergie-ITCI/TelemedicineNew` | `telemedicine_db` | 2.35 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `dhansamvaad.synergieinsights.in` | `dhansamvaad.synergieinsights.in` | `Synergie-ITCI/dhansamvaad-new.synergieinsights.in` | `dhansamvaad_db` | 0.74 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `jiobptransporter.synergieinsights.in` | `jiobptransporter.synergieinsights.in` | `Synergie-ITCI/BP` | `jiobptransporter_db` | 0.49 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `wearesynergie.com` | `wearesynergie.com`, `www.wearesynergie.com` | `Synergie-ITCI/wearesynergie` | `wearesynergie_website` | 0.25 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `wearesynergie.synergieinsights.in` | `wearesynergie.synergieinsights.in` | `Synergie-ITCI/wearesynergie` | `wearesynergie_db` | 0.19 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `fis.synergielms.com` | `fis.synergielms.com` | `Synergie-ITCI/fis.synergielms.com` | `fis_db` | 0.09 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `bayer.synergieinsights.in` | `bayer.synergieinsights.in` | `Synergie-ITCI/bayer.synergieinsights.in` | `bayer_db` | 0.07 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `projectdemo.synergielms.com` | `projectdemo.synergielms.com` | `Synergie-ITCI/projectdemo.synergielms.com` | `projectdemo_db` | 0.07 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `mobilekids.synergieinsights.in` | `mobilekids.synergieinsights.in` | `Synergie-ITCI/mobilekids.synergieinsights.in` | `mobilekids_db` | 0.04 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `sankalptraining.synergielms.com` | `sankalptraining.synergielms.com` | `Synergie-ITCI/sankalp`, `Synergie-ITCI/synergielms.com` | `sankalptraining_db` | 0.04 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `icicir2s.synergieinsights.in` | `icicir2s.synergieinsights.in` | `Synergie-ITCI/ICICI` | `icicir2s_db` | 0.04 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `synergielms.com` | `synergielms.com`, `www.synergielms.com` | `Synergie-ITCI/synergielms.com` | `unknown/not parsed` | 0.03 GiB | `NOT RECOVERABLE` | Database/config source could not be parsed by the generic probe; classify manually before certification. |
| `P0` | `shareasmile.wearesynergie.com` | `shareasmile.wearesynergie.com` | `Synergie-ITCI/wearesynergie` | `unknown/not parsed` | 0.01 GiB | `NOT RECOVERABLE` | Database/config source could not be parsed by the generic probe; classify manually before certification. |
| `P0` | `syncsr.in` | `syncsr.in`, `www.syncsr.in` | `unknown` | `shorturl_db` | 0.00 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `timesheet.synergielms.com` | `timesheet.synergielms.com` | `Synergie-ITCI/synergielms.com` | `timesheet_db` | 0.00 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `datamatics.synergielms.com` | `datamatics.synergielms.com` | `Synergie-ITCI/datamatics.synergielms.com` | `datamatics_lms` | 0.00 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `jiobp.synergielms.com` | `jiobp.synergielms.com` | `Synergie-ITCI/jiobp.synergielms.com` | `jiobp_db` | 0.00 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |
| `P0` | `synergie-hub` | `hub.synergieinsights.in` | `Synergie-ITCI/synergie-hub` | `synergie_hub` | 0.00 GiB | `NOT RECOVERABLE` | No independent current logical DB backup and restore-test evidence. |

## Production-Hosted Non-Production Roots

| Priority | Root | Hostnames | DB | Persistent | Status |
| --- | --- | --- | --- | ---: | --- |
| `P0-NONPROD` | `/var/www/projectdemo-staging/public_html` | `staging-projectdemo.synergielms.com` | `projectdemo_staging` | 0.00 GiB | `NOT CERTIFIED - production-hosted non-production root` |
| `P0-NONPROD` | `/var/www/sankalpdev.synergieinsights.in/public_html` | `sankalpdev.synergieinsights.in` | `unknown/not parsed` | 0.00 GiB | `NOT CERTIFIED - production-hosted non-production root` |
| `P0-NONPROD` | `/var/www/wearesynergie.synergieinsights.in/public_html/synergiestaging` | `staging.wearesynergie.com` | `wearesynergie_db` | 0.22 GiB | `NOT CERTIFIED - production-hosted non-production root` |

## Control Gaps

- DB backups: only Sankalp has current independent logical DB backup and restore-test evidence. The EBS recovery point protects the volume but does not prove application-level DB recovery for the remaining apps.
- Persistent data: non-Sankalp production roots contain 28.05 GiB of observed persistent data without independent backup proof. Largest roots are Bridgestone, JioBP Cares, Telemedicine, Dhansamvaad, and JioBP Transporter.
- Secrets: Secrets Manager coverage is visible for Synergie Hub and Sankalp PR references only. Other apps still rely on server-local env/wp-config style secrets or unclassified config.
- Traceability: only Sankalp and Telemedicine have any deployed marker, and neither is certified as canonical production release evidence. Six production roots have Git checkouts; the rest are server-only roots or indirect repo mappings.
- Manifests: no canonical main-branch recovery manifests were observed in the prior company inventory. Sankalp has a manifest only in draft PR #19.
- Clean-room restore: no production app is fully clean-room web-restored from company-controlled sources. Sankalp still needs the final web restore after provider and deployment conditions close.
- Ignore policy: the existing standard is correct, but app manifests must now classify every ignored recovery-critical component and name a tested alternate source of truth.

## Production Changes This Turn

- Ran SSM read-only inventory probes against `i-060e4ec1fd5345c30`.
- Removed embedded GitHub access-token material from the Bayer and FIS production Git remote URLs; verification reported both `CLEAN`.
- No application code was deployed, no application was restarted, no database writes were performed, no secrets were rotated, and no production files were deleted.

## Certification Lists

- `RECOVERY CERTIFIED`: none.
- `RECOVERY CERTIFIED WITH CONDITIONS`: `sankalp.synergieinsights.in`.
- `NOT RECOVERABLE`: `bayer.synergieinsights.in`, `bridgestone.synergieinsights.in`, `datamatics.synergielms.com`, `dhansamvaad.synergieinsights.in`, `fis.synergielms.com`, `icicir2s.synergieinsights.in`, `jiobp.synergielms.com`, `jiobpcares.synergieinsights.in`, `jiobptransporter.synergieinsights.in`, `mobilekids.synergieinsights.in`, `projectdemo.synergielms.com`, `sankalptraining.synergielms.com`, `shareasmile.wearesynergie.com`, `syncsr.in`, `synergie-hub`, `synergielms.com`, `telemedicine.synergieinsights.in`, `timesheet.synergielms.com`, `wearesynergie.com`, `wearesynergie.synergieinsights.in`.
- `NOT CERTIFIED - production-hosted non-production root`: `projectdemo-staging`, `sankalpdev.synergieinsights.in`, `wearesynergie.synergieinsights.in`.

## Highest Priority Next Action

Implement restore-tested independent logical DB backups and persistent-file S3 backups for the 20 non-Sankalp P0 production apps, starting with Bridgestone because it has the largest observed persistent footprint.
