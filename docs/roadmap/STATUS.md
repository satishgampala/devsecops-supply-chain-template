# DevSecOps Supply-Chain Template Status

- **Overall status:** Implemented Locally
- **Current milestone:** Corrective portfolio hardening after M06
- **Last reviewed:** 2026-09-23

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

The [corrective hardening plan](implementation-plans/2026-09-23-portfolio-hardening.md) closes scanner execution/stale-output bugs, coordinated Go toolchain drift, ignored-source contamination, incomplete signed evidence, mismatched tested/scanned artifacts, report freshness gaps, mixed-case initialization failures, and duplicated CI. The [corrective verification record](evidence/hardening/verification.md) supersedes historical milestone evidence for current behavior.

Local candidate checks exercise one OCI manifest across runtime and all eight scanner reports. Rehashed evidence and rewritten signed statements are rejected by explicit test-only signature fixtures. Those fixtures prove policy behavior, not hosted cryptographic authenticity.

## Hosted blocker and next action

GitHub returned: **“The job was not started because your account is locked due to a billing issue.”** Repository workflow jobs did not execute; successful Dependabot activity does not validate this pipeline. Remote `main` protections/rulesets, template status, topics, and releases were not configured at the time of review.

The account owner must resolve billing before hosted validation can run. After explicit authorization, push the branch, observe PR checks, configure their exact required names and repository protections, then run trusted default-branch signing and attestations. Publication follows independent evidence review; no remote changes are included in the local implementation.

## Open verification work

- A successful repository pull-request validation run has not yet been recorded.
- CodeQL has not yet executed on GitHub-hosted infrastructure.
- The hosted scanner artifact and code-scanning upload have not yet been inspected.
- GitHub artifact-attestation bundles have not yet been generated or verified on hosted infrastructure.
- Fulcio certificates, Rekor entries, embedded SCTs, and Cosign bundles have not yet been generated or verified on hosted infrastructure.
- Remote branch-protection behavior cannot be verified until the repository settings and pull-request checks are active.
- The reusable validation workflow has not run in a hosted same-repository or external-consumer caller.
- OpenSSF Scorecard has not run on the hosted repository.
- No immutable tag, registry artifact, or versioned release has been published.

These are blocked or unverified remote gates. Completed local checks do not establish hosted release authorization or publication.
