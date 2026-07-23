# DevSecOps Supply-Chain Template Status

- **Overall status:** In Progress
- **Current milestone:** M01 — Reference Service and Pipeline Baseline
- **Last reviewed:** 2026-07-21

## Milestone checklist

| Milestone | Status | Completion evidence |
| --- | --- | --- |
| M01 — Reference service and pipeline baseline | In Progress | [Local verification passed; hosted run pending](evidence/M01/verification.md) |
| M02 — Source, dependency, IaC, and container scanning | Not Started | Planned after M01 |
| M03 — SBOM and SLSA provenance | Not Started | Planned after M02 |
| M04 — Keyless signing and identity verification | Not Started | Planned after M03 |
| M05 — Release policy and deployment eligibility | Not Started | Planned after M04 |
| M06 — Reusable template, demonstration, and release | Not Started | Planned after M05 |

## Current decision

[ADR 0001](../decisions/0001-use-go-reference-service.md) selects Go 1.26.5 and a deliberately small standard-library service for M01.

## Next action

Push `feat/m01-pipeline-baseline`, open a pull request, and record the first successful GitHub-hosted workflow run in the [M01 evidence](evidence/M01/verification.md).

## Open verification work

- A GitHub-hosted pull-request run has not yet been recorded.
- Remote branch-protection behavior cannot be verified until the repository settings and pull-request checks are active.

These are pending M01 gates. The completed local checks are not evidence that the later M02–M06 controls exist.
