# M06 - Reusable Template, Demonstration, and Release

- **Status:** Implemented Locally
- **Depends on:** M05
- **Implementation plan:** [2026-07-23 M06 Reusable Template and Release Operations](../implementation-plans/2026-07-23-M06-template-release.md)

## Outcome

The secure workflow is packaged as a documented template, adopted by a detached clean consumer, and covered by reproducible local evidence. Hosted execution and versioned publication remain pending.

## Scope and non-goals

This milestone focuses on reuse, documentation, adoption testing, release evidence, and community adoption. It does not build a hosted CI product.

## Deliverables

- [x] Secure-by-default reusable workflow with explicit interfaces and permissions.
- [x] Clean-consumer adoption and seeded-failure integration test.
- [x] Complete architecture, security, operations, adoption, and walkthrough documentation.
- [ ] Hosted Scorecard, signed evidence, immutable tag, and versioned release.

## Tasks and subtasks

- [x] **T1: Extract reusable workflow boundaries.**
  - [x] Expose the mandatory Make contract through a reusable validation workflow.
  - [x] Define explicit outputs and grant no inputs, secrets, write permissions, or OIDC.
  - [x] Keep secure defaults mandatory and document the repository-specific signing boundary.
- [x] **T2: Build a clean-consumer adoption test.**
  - [x] Create a detached consumer fixture with no hidden repository or credential state.
  - [x] Initialize the template using only documented identity inputs.
  - [x] Verify clean local gates and seeded-failure behavior in the consumer context.
- [x] **T3: Complete documentation and operations.**
  - [x] Publish architecture, threat model, trust boundaries, quick start, workflow reference, exception process, troubleshooting, and update strategy.
  - [x] Add security policy, license, contribution guide, dependency automation, Scorecard workflow, and release runbook.
  - [x] Map controls to relevant NIST SSDF and SLSA concepts without claiming certification.
- [ ] **T4: Demonstrate and release.**
  - [x] Record a concise flow from source change to locally eligible synthetic evidence, including one failed release.
  - [ ] Run OpenSSF Scorecard on the hosted repository and address material findings.
  - [ ] Publish a versioned release with sample SBOM, provenance, signature verification, eligibility decision, and release notes.

## Verification and evidence

- [Local M06 verification evidence](../evidence/M06/verification.md) records initialization, clean-consumer, host, container, scanner, integrity, policy, workflow, documentation, and negative gates.
- Hosted workflow URLs, Scorecard results, real signing bundles, release artifacts, an immutable tag, and a release URL remain pending.

## Exit criteria

- [x] A detached clean consumer adopts the repository using documented initialization inputs.
- [x] Positive and seeded-negative consumer runs behave as specified.
- [x] Documentation explains permissions, trust boundaries, limitations, and updates.
- [ ] A versioned release and independently reproducible release evidence exist.

## Risks and controls

- **Risk:** Reusable workflows become overly configurable. **Control:** Support only demonstrated inputs and preserve mandatory security gates.
- **Risk:** The reference repository passes while consumers fail. **Control:** Make clean consumer adoption a release-blocking integration test.
