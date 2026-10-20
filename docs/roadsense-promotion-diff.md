# RoadSense promotion when branch histories differ

RoadSense's protected `development`, `staging`, and `main` can have different
histories while containing the same tree. Before proposing `development` to
`staging` (or `staging` to `main`), fetch both branch heads and compare their
trees and direct content diff:

```sh
git fetch origin development staging main
git rev-parse origin/development^{tree} origin/staging^{tree}
git diff --stat origin/staging origin/development
```

If the tree IDs match, there is no content to promote. Do not open a PR merely
to reconcile history. If they differ, review the direct diff, then create one
promotion branch from the **target** branch and apply only that reviewed content
delta. Open the PR against the target branch so GitHub shows the actual proposed
changes. Repeat with `staging` as source and `main` as target for Gate C.

Keep the central 5,000-addition limit and exact changed-path review. If the
direct content delta exceeds that limit, split real changes into reviewable PRs
through the normal protected-branch process. Do not rewrite protected history or
force a history-only promotion.
