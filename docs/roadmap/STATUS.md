# DevSecOps Supply-Chain Template Status

- **Overall status:** Implemented Locally
- **Current milestone:** M06 — Reusable Template, Demonstration, and Release
- **Last reviewed:** 2026-07-23

## Milestone checklist

| Milestone | Status | Completion evidence |
| --- | --- | --- |
| M01 — Reference service and pipeline baseline | Implemented Locally | [Local verification passed; hosted run pending](evidence/M01/verification.md) |
| M02 — Source, dependency, IaC, and container scanning | Implemented Locally | [Eight-scanner local gate and negative fixtures passed; hosted run pending](evidence/M02/verification.md) |
| M03 — SBOM and SLSA provenance | Implemented Locally | [Reproducibility, linkage, and tamper gates passed; hosted attestations pending](evidence/M03/verification.md) |
| M04 — Keyless signing and identity verification | Implemented Locally | [Identity, context, artifact, and workflow isolation gates passed; hosted signature pending](evidence/M04/verification.md) |
| M05 — Release policy and deployment eligibility | Implemented Locally | [Complete release contract, policy, path, and tamper gates passed; hosted eligible run pending](evidence/M05/verification.md) |
| M06 — Reusable template, demonstration, and release | Implemented Locally | [Reusable validation, clean-consumer, governance, architecture, and operations gates passed; publication pending](evidence/M06/verification.md) |

## Current decision

The M06 initializer rewrites exact repository identities and dependent policy hashes in a detached clean consumer. The initialized consumer passes host, signing-policy, release-policy, and integrity gates; malformed initialization and a seeded source defect fail as specified. Reusable workflows, governance, architecture, threat analysis, control mapping, and release procedures are present and pass local static validation.

## Next action

After owner authorization, push the branch, configure repository rules, observe hosted validation and Scorecard, produce real keyless evidence, then create and verify an immutable versioned release.

## Open verification work

- A GitHub-hosted pull-request run has not yet been recorded.
- CodeQL has not yet executed on GitHub-hosted infrastructure.
- The hosted scanner artifact and code-scanning upload have not yet been inspected.
- GitHub artifact-attestation bundles have not yet been generated or verified on hosted infrastructure.
- Fulcio certificates, Rekor entries, embedded SCTs, and Cosign bundles have not yet been generated or verified on hosted infrastructure.
- Remote branch-protection behavior cannot be verified until the repository settings and pull-request checks are active.
- The reusable validation workflow has not run in a hosted same-repository or external-consumer caller.
- OpenSSF Scorecard has not run on the hosted repository.
- No immutable tag, registry artifact, or versioned release has been published.

These are pending remote gates. Completed local checks do not establish hosted release authorization or publication.
