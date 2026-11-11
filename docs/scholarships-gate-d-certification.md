# Scholarships PR #15 privileged release certification

This contract applies only to `Synergie-ITCI/scholarships` PR #15 at the exact
head recorded in `policy/scholarships-pr15-gate-d.json`. It is not a general
consumer exemption. Central QA checks the full changed-file set and bytes,
the controlled rc216 workflow shape, execution ordering, owner-led technical review,
least-privilege IAM/SSM boundaries, exact OIDC trust, environment reviewer,
fixed SSM document/script binding, backup markers and PHP 8.3 serving checks.
Any changed file or PR head invalidates the certification until this central
contract is reviewed under the active central owner-authored PR policy and updated in a new immutable release.

The verified Synergie owner must personally review the privileged scripts, IAM
policies, SSM documents, workflow authorization and rollback behavior at the
exact PR head. After review, the owner must submit an unedited GitHub PR comment
containing these exact lines, with the SHA-256 of the central certification
manifest substituted below:

`SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED=<exact 40-character PR head SHA>`
`CERTIFIED_MANIFEST_SHA256=<64-character SHA-256 of policy/scholarships-pr15-gate-d.json>`
`REVIEWED=IAM,SSM,APPROVAL,ARTIFACT,HOST,RUNTIME,BACKUP,RESTORE,PRIVATE_DOCUMENTS,ROLLBACK`
`OWNER_ACCEPTS_TECHNICAL_REVIEW_RESPONSIBILITY=YES`

This is explicit technical security certification, not an automatic consequence
of the owner-authored PR review exception. Central QA reads live GitHub
comment evidence and fails closed when it is unavailable, edited, from a
different actor, bound to another head or manifest, or missing the attestation.
The owner must perform the review personally; Codex must not post the comment
using the owner's credentials. A passing Deployment Risk result is a WARNING, not
permission to install IAM/SSM controls or deploy. Live installation needs
separate owner approval and readback. Production cutover needs a further exact
Gate D approval and successful runtime certification.

The current legacy PHP 7 service cannot use this recurring release contract.
See [the separate first-transition proposal](scholarships-first-runtime-transition.md).
