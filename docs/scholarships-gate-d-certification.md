# Scholarships PR #15 privileged release certification

This contract applies only to `Synergie-ITCI/scholarships` PR #15 at the exact
head recorded in `policy/scholarships-pr15-gate-d.json`. It is not a general
consumer exemption. Central QA checks the full changed-file set and bytes,
the controlled rc216 workflow shape, execution ordering, independent review,
least-privilege IAM/SSM boundaries, exact OIDC trust, environment reviewer,
fixed SSM document/script binding, backup markers and PHP 8.3 serving checks.
Any changed file or PR head invalidates the certification until this central
contract is independently reviewed and updated in a new immutable release.

The independent reviewer must review the privileged scripts, IAM policies,
SSM documents, workflow authorization and rollback behavior at the exact PR
head. An eligible reviewer other than the PR author must submit an APPROVED
GitHub review on that head with this exact line in its review body:

`SCHOLARSHIPS_GATE_D_SECURITY_CERTIFIED=<exact 40-character PR head SHA>`

This is technical security certification; it is separate from Synergie's
ordinary owner-authored PR review exception. Central QA reads live GitHub
review evidence and fails closed when it is unavailable, dismissed, stale or
missing the attestation. A passing Deployment Risk result is a WARNING, not
permission to install IAM/SSM controls or deploy. Live installation needs
separate owner approval and readback. Production cutover needs a further exact
Gate D approval and successful runtime certification.

The current legacy PHP 7 service cannot use this recurring release contract.
See [the separate first-transition proposal](scholarships-first-runtime-transition.md).
