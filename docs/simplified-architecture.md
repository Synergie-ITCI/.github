# Simplified Architecture

Generated: 2026-07-28

## Architecture Diagram

```text
Developer opens or updates PR
        |
        v
Enterprise PR QA reusable workflow
        |
        +-- Detect repository technologies
        |
        +-- Phase 1 static preflight
        |      - config validation
        |      - repository hygiene
        |      - git validation
        |      - secret scanning
        |      - protected resources
        |      - deployment and migration risk
        |
        +-- Phase 2 and Phase 3 validation
        |      - formatting
        |      - lint
        |      - build
        |      - tests
        |      - dependency scanning
        |      - licence scanning
        |      - documentation and evidence checks
        |      - deterministic risk scoring
        |
        v
QA report, JSON evidence, and workflow status
        |
        v
Saurabh reviews manually using Codex native GitHub integration
        |
        v
Executive Release Authority approval
        |
        v
Merge through GitHub Branch Protection
```

## Operating Model

Enterprise PR QA is automated. It remains the only automated technical gate in the framework.

Engineering review is human-driven. The Executive Reviewer uses Codex's native GitHub integration interactively to inspect the PR, reason about design and implementation, request changes, and decide whether the pull request is ready for Executive Release Authority approval.

The framework intentionally does not automate AI review. It does not call an AI provider, manage AI provider credentials, publish AI comments, or generate AI review artifacts.

## Preserved Automation Work

The removed automated AI review implementation is preserved outside the active framework on:

```text
feature/automated-ai-review-v1.1
```

That branch is archival. It is not part of the active release path and must not be referenced by rollout caller workflows.
