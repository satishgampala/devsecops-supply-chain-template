# DevSecOps Supply-Chain Template Status

- **Overall status:** In Progress
- **Current milestone:** M03 — SBOM and SLSA Provenance
- **Last reviewed:** 2026-07-21

## Milestone checklist

| Milestone | Status | Completion evidence |
| --- | --- | --- |
| M01 — Reference service and pipeline baseline | In Progress | [Local verification passed; hosted run pending](evidence/M01/verification.md) |
| M02 — Source, dependency, IaC, and container scanning | Implemented Locally | [Eight-scanner local gate and negative fixtures passed; hosted run pending](evidence/M02/verification.md) |
| M03 — SBOM and SLSA provenance | Implemented Locally | [Reproducibility, linkage, and tamper gates passed; hosted attestations pending](evidence/M03/verification.md) |
| M04 — Keyless signing and identity verification | Not Started | Planned after M03 |
| M05 — Release policy and deployment eligibility | Not Started | Planned after M04 |
| M06 — Reusable template, demonstration, and release | Not Started | Planned after M05 |

## Current decision

The M03 local evidence is verified: one OCI manifest digest is shared by the archive parser, SPDX root package, and local provenance subject. Two clean builds produced byte-identical OCI archives, canonical SBOM projections, and local provenance statements.

## Next action

Implement M04 keyless signing and strict workflow-identity verification. Record hosted M01–M03 workflow runs only after the owner authorizes a push.

## Open verification work

- A GitHub-hosted pull-request run has not yet been recorded.
- CodeQL has not yet executed on GitHub-hosted infrastructure.
- The hosted scanner artifact and code-scanning upload have not yet been inspected.
- GitHub artifact-attestation bundles have not yet been generated or verified on hosted infrastructure.
- Remote branch-protection behavior cannot be verified until the repository settings and pull-request checks are active.

These are pending remote gates. The completed local checks are not evidence that M04–M06 controls exist.
