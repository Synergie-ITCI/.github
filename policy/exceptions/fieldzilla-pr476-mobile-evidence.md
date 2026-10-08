# PR #476 mobile dependency audit evidence

Saurabh Verma approves a one-time exception for the unchanged FieldZilla mobile dependency set at PR #476 head `7c6d77d45bf25bec670dc5b175fcebb17a25ef17`. The Mobile Platform Lead owns full remediation. This accepts residual CI and native build-tooling risk; it does not assert that the packages are safe.

At that exact head, `npm audit --json` found direct advisories affecting `braces`, `compression`, `joi`, `shell-quote`, and `sprintf-js`. The inherited vulnerability count was 58 in PR-QA and 59 in a later registry scan without a change to those five direct advisory identities. `npm audit --omit=dev` still reported 26 inherited vulnerabilities, so an install-graph-only claim of development isolation is not justified.

Android and iOS release JavaScript bundles were generated with `npx react-native bundle --platform android|ios --dev false --entry-file index.js` at the PR head. Each source map listed 1,250 sources. Neither map listed `braces`, `micromatch`, `shell-quote`, `compression`, `joi`, `sprintf-js`, Metro configuration, React Native CLI, or Jest. SHA-256 of the Android map: `995ec9d656a7ee978ea10e47d7bdf1b401be7ba8e8a66465a1bd1fc7ea84cb5a`; iOS map: `81dd3d8e763f452f466c85634c99817c719da50011a44202796d1f8ee581ed9d`. Bundle absence does not eliminate install, build, or CI exposure.

The exception expires on 2026-11-07 at 16:40:21 UTC, or on the first new FieldZilla tag or GitHub Release, whichever occurs first. At approval, the tag baseline was `fieldzilla-apply-dispatch-2c8a4015` and there were no GitHub Releases. Any new tag ends the exception conservatively because the repository has no dedicated mobile release tag convention. The mobile dependency files must remain byte-identical, and the PR must remain at the approved head. The normal audit continues to run and its findings remain visible in the PR-QA report/artifact.

The Mobile Platform Lead must plan full React Native/Metro/Jest toolchain and transitive dependency remediation before the exception expires. The exception is not transferable to another PR, head, lockfile, or advisory set.
