# DevSecOps Supply-Chain Template Status

- **Overall status:** In Progress
- **Current milestone:** M01 — Reference Service and Pipeline Baseline
- **Last reviewed:** 2026-07-21

## Milestone checklist

| Milestone | Status | Completion evidence |
| --- | --- | --- |
| M01 — Reference service and pipeline baseline | In Progress | Not yet recorded |
| M02 — Source, dependency, IaC, and container scanning | Not Started | Planned after M01 |
| M03 — SBOM and SLSA provenance | Not Started | Planned after M02 |
| M04 — Keyless signing and identity verification | Not Started | Planned after M03 |
| M05 — Release policy and deployment eligibility | Not Started | Planned after M04 |
| M06 — Reusable template, demonstration, and release | Not Started | Planned after M05 |

## Current decision

[ADR 0001](../decisions/0001-use-go-reference-service.md) selects Go 1.26.5 and a deliberately small standard-library service for M01.

## Next action

Complete the M01 implementation workstreams, review their integrated diff, and run the fresh host, workflow, and container verification gates from the [M01 implementation plan](implementation-plans/2026-07-21-M01-pipeline-baseline.md). Record only observed results before considering any M01 exit criterion complete.

## Open verification work

- Host formatting, vet, unit, race, and static-build checks have not been recorded here.
- Workflow syntax and effective least-privilege configuration have not been recorded here.
- Container build, runtime user, health, and endpoint smoke results have not been recorded here.
- Manual input, shutdown, workflow-trust-boundary, secret-pattern, and runtime-content reviews have not been recorded here.

These are pending M01 gates, not evidence that the later M02–M06 controls exist.
