# PR #489 mobile dependency audit evidence

Scope: FieldZilla PR #489 at exact head `1b52a16fa563b9367555e5da692015bd5f88827d`, targeting `development`; staging mobile release foundation only. Saurabh Verma requested the controlled evidence-based process. Mobile Platform Lead owns remediation. This record does not authorize merge, app build, distribution, production, or tenant-data changes.

The PR changes no dependency versions or lockfile. `apps/mobile/package.json` changes test/config scripts only and has SHA-256 `a1993fa439f969368651c56bdecb8516c5d45723868a9fb6c4ed07d23fcbd301`; the unchanged lockfile has SHA-256 `1393ec5cb4710b4bb9d5b19ecb8dc24363a4c5d98598359892fe95f7a742e69b`. The unchanged `audit:ci` command has SHA-256 `f5a44419fe62aee20f13a0f1cbfcedebbc50361d3c2c7f3cf067ac4e413bf927`.

At this exact head local `npm audit --json` found 59 vulnerabilities (6 moderate, 52 high, 1 critical), while governed PR-QA reported 58 (6 moderate, 51 high, 1 critical). This count variation occurred in the approved #487 baseline. Local direct advisories, severity, ranges, and package paths match all five baseline findings: braces `GHSA-vfj7-8cjw-p6xm`, compression `GHSA-vc2v-76pw-4v95`, joi `GHSA-wr44-6hxh-3jwq`, shell-quote `GHSA-pqg4-j6r4-53mv`, and sprintf-js `GHSA-hp3w-g68c-fv3c`. No new or more severe direct advisory was observed. The audit remains visible and blocking unless this exact exception matches.

Android and iOS release JS bundles were generated from the exact head with explicit staging URLs, source SHA, and build number 1 using Node 22.23.2 and `react-native bundle --dev false`. Both passed the staging URL bundle guard. Neither source map contains braces, micromatch, shell-quote, compression, joi, sprintf-js, metro-config, the React Native CLI, or Jest. The normalized source lists are pinned here. No installable app was built.

| Platform | Bundle SHA-256 | Source map SHA-256 | Source list SHA-256 | Modules |
| --- | --- | --- | --- | --- |
| Android | `f91ae77fa49082a02fc9568f0d010303db33896437341f13ac4944a65a3e48cc` | `5acb3907ccf8cd346443a5fe4ca6c569325598c59ef364be243f503a03654c07` | `dbf244b7527cc8906ad54cce404ca7d794480c649d1212944493cfdd400c5b3e` | 1251 |
| iOS | `e46c9eaef3f954e59a2088d65ba93a6a7fdfbf914766a7b32d2340d23af76be5` | `c70e09ffcb09f7f764c1a280ba3a6aa92a29afa1c0f828220cd898feebf4c128` | `2ed3bc924175e6c397dea79b384dfb35f173d64da8045938895b4e55498daf37` | 1251 |

The absence of these packages from release JS does not remove vulnerable install/build tooling or CI exposure. The exception expires on 2026-11-09 07:29:44 UTC or any new FieldZilla tag or GitHub Release, whichever is first. Current baseline: tag `fieldzilla-apply-dispatch-2c8a4015`; no GitHub Releases. Different PR/head, dependency hash, audit script, advisory identity/severity/path, missing or contaminated bundle evidence, expiry, or feature-repository exception edits fail closed.
