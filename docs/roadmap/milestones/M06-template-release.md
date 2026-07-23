# M06 - Reusable Template, Demonstration, and Release

- **Status:** Not Started
- **Depends on:** M05
- **Implementation plan:** Not written; planned after the dependency milestone.

## Outcome

The secure workflow is packaged as a documented template, adopted by a clean consumer example, demonstrated publicly, and published as a versioned release.

## Scope and non-goals

This milestone focuses on reuse, documentation, adoption testing, release evidence, and community adoption. It does not build a hosted CI product.

## Deliverables

- Secure-by-default reusable workflow with explicit interfaces and permissions.
- Clean consumer adoption and seeded-failure integration test.
- Complete documentation, public demonstration, and versioned release evidence.

## Tasks and subtasks

- [ ] **T1: Extract reusable workflow boundaries.**
  - [ ] Separate service-specific tests from reusable scanning, evidence, signing, and verification jobs.
  - [ ] Define explicit inputs, outputs, permissions, secrets, and supported artifact types.
  - [ ] Keep secure defaults mandatory and document every opt-out.
- [ ] **T2: Build a clean consumer adoption test.**
  - [ ] Create a minimal consumer repository or fixture with no hidden local state.
  - [ ] Adopt the template using only documented inputs.
  - [ ] Verify clean release and seeded-failure behavior in the consumer context.
- [ ] **T3: Complete documentation and operations.**
  - [ ] Publish architecture, threat model, trust boundaries, quick start, workflow reference, exception process, troubleshooting, and update strategy.
  - [ ] Add security policy, license, contribution guide, dependency automation, and release runbook.
  - [ ] Map controls to relevant NIST SSDF and SLSA concepts without claiming certification.
- [ ] **T4: Demonstrate and release.**
  - [ ] Record a concise flow from source change to signed eligible artifact, including one failed release.
  - [ ] Run OpenSSF Scorecard and address material repository-hygiene findings.
  - [ ] Publish a versioned release with sample SBOM, provenance, signature verification, eligibility decision, and release notes.

## Verification and evidence

- From a clean consumer, run tests, scans, build, SBOM, provenance, signing, and release verification with no private infrastructure.
- Retain consumer commit, workflow run URLs, Scorecard result, release artifacts, verification output, demo recording, and release URL under `docs/roadmap/evidence/M06/`.

## Exit criteria

- [ ] A clean consumer adopts the workflow using documented configuration only.
- [ ] Positive and seeded-negative consumer runs behave as specified.
- [ ] Documentation explains permissions, trust boundaries, limitations, and updates.
- [ ] A versioned release and independently reproducible release evidence exist.

## Risks and controls

- **Risk:** Reusable workflows become overly configurable. **Control:** Support only demonstrated inputs and preserve mandatory security gates.
- **Risk:** The reference repository passes while consumers fail. **Control:** Make clean consumer adoption a release-blocking integration test.
