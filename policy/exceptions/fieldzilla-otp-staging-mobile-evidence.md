# FieldZilla OTP staging-push mobile audit evidence

The reviewed staging repair PR #479 merged as `132e08e0af987e78275602b18e3e258d31056f71`. Its mobile tree object is `28fbd276d78a32325f84ce58ddeb9df5e7ca8fba`, byte-identical to PR #477 head `79a44636930214b4dd9383a1975f3b9bd0466c30`. The repair changes only the backend Mypy narrowing, staging workflows, migration verifier, and their focused guards/tests. It changes no mobile source or dependency file.

A fresh `npm audit --json` on the staging candidate found 59 inherited vulnerabilities: one critical, 52 high, and six moderate. The five direct advisories remain `GHSA-vfj7-8cjw-p6xm` (`braces`), `GHSA-vc2v-76pw-4v95` (`compression`), `GHSA-wr44-6hxh-3jwq` (`joi`), `GHSA-pqg4-j6r4-53mv` (`shell-quote`), and `GHSA-hp3w-g68c-fv3c` (`sprintf-js`). The unchanged package and lockfile hashes are recorded in the manifest.

The Android and iOS release JavaScript maps generated for #477 listed 3,235 sources each and none of the directly flagged packages. Android map SHA-256: `918a0da093e7198886d217ff10fcf88ffccdba1d57f3d3b9a393eed070b50000`; iOS map SHA-256: `c6082fc8bc8cf6b263017e96d7cdd2a10fcdf6976f4f30f387be697da061d79f`. These are historical release JS bundle checks, not signed device builds. An unchanged lockfile alone cannot prove bundle absence after app code changes. Every staging SHA using this exception must build fresh Android and iOS release JS bundles, list modules and packages from both source maps, fail if an exception-covered package appears, and preserve a SHA-bound evidence artifact. The production install graph still contains vulnerable build/install packages, so risk is not zero.

At review, FieldZilla had tag `fieldzilla-apply-dispatch-2c8a4015` and no GitHub Releases. The proposed exception ends at 2026-11-07 16:40:21 UTC or the first new FieldZilla tag/GitHub Release, whichever comes first. A changed dependency or audit-script hash, new or more severe advisory, missing bundle proof, evidence change, missing approval, or changed release state leaves the normal mobile audit blocking. Fixed advisories may disappear from the observed set; the usage artifact records the reduced set. The staging audit continues to run, and each accepted warning records the exception ID, repository, staging SHA, workflow run ID, observed advisories, Android/iOS bundle result, and expiry. The Mobile Platform Lead remains the remediation owner for full React Native/Metro/Jest dependency work.

## OTP consent security and product follow-ups

- State in OTP consent review and operator guidance that a successful OTP proves control of a phone number at that moment, not the beneficiary's identity.
- Capture a reason code for guardian or proxy consent, with review of authority and relationship semantics before production use.
- Track approved SMS wording, provider delivery evidence, and template identifiers as release evidence.
- Define and test the consent withdrawal path before production.
- Register the relevant India DLT SMS template before sending real beneficiary OTP messages.
