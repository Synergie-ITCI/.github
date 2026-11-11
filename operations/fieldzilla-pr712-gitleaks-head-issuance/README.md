# PR712 exact Gitleaks head rebind proposal

PROPOSED ONLY. No central release, consumer activation, image publication,
AWS mutation, Gate C or Gate D is authorized here.

The first current governed QA run 42981193910 stopped in Phase 1 Secrets with
exact `generic-api-key` fingerprints at `apps/mobile/ios/Podfile.lock` lines
2265 and 2336, introduced by rebased commit `68fd7c26438250b3c71b52dd1a31ddab1ab8529f`.
Its redacted artifact digest is
`sha256:37045a65b3289c8ebb0b3971edb70df44b306674f14aa5cbe5731af2e12dea0a`.
Git object IDs prove that lockfile at the new introducing commit, previous
reviewed commit `f924742f97ae8b43c210d2954eccaa1b4995da77`, and current
head is the same blob `bffb676f18c07ec6f3388276ea7b1f6f2db533dd`.
No suspected value was printed or copied. The two prior exact false-positive
entries in `.gitleaksignore` were changed only to the new commit ID. A local
redacted Gitleaks 8.30.1 scan of 84 commits found no leaks. This is not a
path-wide or rule-wide suppression; all other findings remain enforced.

Application PR712 remains on the same task branch, head
`9630b2a44560fe2eb65c7578752da4b082f018c9`, base
`98a95bcd379995b1cf5d1a909c40205d430a09da`. The only changed path
from the previous head is `.gitleaksignore`; lockfile, API, Admin, mobile,
SQL and Docker recipe bytes remain identical. The two proposed central records
change exact head, IDs, issued time and the `.gitleaksignore` reviewed hash.
The 844-file/148823-addition caps, 45 overlay paths, SQL/five DELETE
fingerprints, scanner/default settings and expiry `2026-11-12T07:04:04Z`
remain unchanged. A new PR body marker prevents the old head review being
reused silently.

Require exact-head central governance and full PR-QA, separate protected merge
approval, immutable release publication and consumer-selection activation.
Only then rerun #712 exact-head QA. A green local scan is not governed QA.
