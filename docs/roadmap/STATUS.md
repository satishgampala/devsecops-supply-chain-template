# DevSecOps Supply-Chain Template Status

- **Overall status:** In Progress
- **Current milestone:** M04 — Keyless Signing and Identity Verification
- **Last reviewed:** 2026-07-21

## Milestone checklist

| Milestone | Status | Completion evidence |
| --- | --- | --- |
| M01 — Reference service and pipeline baseline | In Progress | [Local verification passed; hosted run pending](evidence/M01/verification.md) |
| M02 — Source, dependency, IaC, and container scanning | Implemented Locally | [Eight-scanner local gate and negative fixtures passed; hosted run pending](evidence/M02/verification.md) |
| M03 — SBOM and SLSA provenance | Implemented Locally | [Reproducibility, linkage, and tamper gates passed; hosted attestations pending](evidence/M03/verification.md) |
| M04 — Keyless signing and identity verification | Implemented Locally | [Identity, context, artifact, and workflow isolation gates passed; hosted signature pending](evidence/M04/verification.md) |
| M05 — Release policy and deployment eligibility | Not Started | Planned after M04 |
| M06 — Reusable template, demonstration, and release | Not Started | Planned after M05 |

## Current decision

The M04 local policy accepts only the exact Fulcio issuer, workflow certificate identity, repository, workflow name, protected ref, workflow commit, approved trigger, and three required artifact roles. Pull-request, unsigned, wrong-identity, and wrong-digest observations fail with stable reason codes.

## Next action

Implement M05 release eligibility across scanner, SBOM, provenance, signature, and test evidence. Record hosted M01–M04 workflow runs only after the owner authorizes a push.

## Open verification work

- A GitHub-hosted pull-request run has not yet been recorded.
- CodeQL has not yet executed on GitHub-hosted infrastructure.
- The hosted scanner artifact and code-scanning upload have not yet been inspected.
- GitHub artifact-attestation bundles have not yet been generated or verified on hosted infrastructure.
- Fulcio certificates, Rekor entries, embedded SCTs, and Cosign bundles have not yet been generated or verified on hosted infrastructure.
- Remote branch-protection behavior cannot be verified until the repository settings and pull-request checks are active.

These are pending remote gates. The completed local checks are not evidence that M05–M06 controls exist.
