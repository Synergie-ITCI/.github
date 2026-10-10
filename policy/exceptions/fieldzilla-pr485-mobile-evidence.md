# PR #485 mobile dependency audit evidence

The task authorization approves applying the existing controlled, exact-head mobile audit exception only if all its conditions pass. This record is scoped to FieldZilla PR #485 at `22b368c58b4db7881381f87ff0fcd91295bf1557`, staging only. It does not authorize production, merge, or deployment. Saurabh Verma is the recorded approver; the Mobile Platform Lead owns remediation.

The project dependency files are unchanged against the approved PR #476 dependency baseline and against PR #485's development base. SHA-256: `apps/mobile/package.json` = `6bc69c28df41f51a60b4384cf565c3107556b577da58c7c1ebce3ae53791f678`; `apps/mobile/package-lock.json` = `1393ec5cb4710b4bb9d5b19ecb8dc24363a4c5d98598359892fe95f7a742e69b`. The `audit:ci` script is `npm audit --audit-level=high`, SHA-256 `f5a44419fe62aee20f13a0f1cbfcedebbc50361d3c2c7f3cf067ac4e413bf927`.

At this head, `npm audit --json` reports 59 inherited vulnerabilities (6 moderate, 52 high, 1 critical). The approved baseline evidence recorded 58 in PR-QA and 59 in a later registry scan. The direct advisory identities, severities, ranges, and package paths remain unchanged: braces `GHSA-vfj7-8cjw-p6xm` high; compression `GHSA-vc2v-76pw-4v95` high; joi `GHSA-wr44-6hxh-3jwq` moderate; shell-quote `GHSA-pqg4-j6r4-53mv` critical; sprintf-js `GHSA-hp3w-g68c-fv3c` moderate. The audit still runs and its findings remain visible.

Android and iOS release JavaScript bundles were generated at this exact head with `npx react-native bundle --platform android|ios --dev false --entry-file index.js`. Each source map contains 1,250 sources. The relative source lists are checked into central governance and pinned by SHA-256. Neither list contains `braces`, `micromatch`, `shell-quote`, `compression`, `joi`, `sprintf-js`, Metro configuration, React Native CLI, or Jest. Absence from the JavaScript release bundles does not eliminate install, build, or CI exposure.

| Platform | Bundle SHA-256 | Source map SHA-256 | Central source-list SHA-256 |
| --- | --- | --- | --- |
| android | `23518fb13410f7946da50009ef8faccfcf3cba088f57f7ad8b695696a733aae4` | `c0e2ffa5db11d5adba0e6a52b0101a638112868f1c0e2965e2abe8a39cc1c6f8` | `30d828c9f1a490c7587d7375204e817dfdce82b1a72f2083aef4066f95934a85` |
| ios | `4b4366ff227123c978bb22b9b669b08dd73ba88294418e51221bcf17251fecaf` | `2c4763339845ab1d452b799730cadf2879208332a231276f1defe9478acf4e8d` | `2d5fe6be887335821c8e7cb3f2f7da14df26d34e13a35c30244d29d97d2305e5` |

The exception expires on 2026-11-07 at 16:40:21 UTC or on any new FieldZilla tag or GitHub Release, whichever comes first. At approval, the sole tag was `fieldzilla-apply-dispatch-2c8a4015` and there were no GitHub Releases. It fails closed on a different PR or head, dependency or audit-script change, new or changed advisory, altered package path, missing or contaminated bundle evidence, or an exception file changed in the feature repository. Production is excluded.
