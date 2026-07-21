# M03 - SBOM and SLSA Provenance

- **Status:** Implemented Locally
- **Depends on:** M02
- **Implementation plan:** [2026-07-21 M03 SBOM and Provenance](../implementation-plans/2026-07-21-M03-sbom-provenance.md)

## Outcome

Every release candidate has a standards-based SBOM and build provenance that identify its components, source revision, builder, workflow, and immutable artifact digest.

## Scope and non-goals

This milestone generates and validates SBOM and SLSA provenance. It does not yet sign the release artifact or make a final deployment-eligibility decision.

## Deliverables

- Validated SPDX or CycloneDX SBOM bound to the immutable release artifact.
- SLSA provenance that identifies source, builder, workflow, and artifact digest.
- Reproducibility, association, tampering, and malformed-evidence tests.

## Tasks and subtasks

- [x] **T1: Generate the SBOM.**
  - [x] Select SPDX or CycloneDX and document the choice.
  - [x] Generate an SBOM from the final container or release artifact, not only source dependencies.
  - [x] Validate schema, package identifiers, versions, licenses, and artifact association.
- [x] **T2: Make SBOM generation reproducible.**
  - [x] Pin generator versions and record their metadata.
  - [x] Compare SBOM content across identical source builds while excluding expected timestamps or nondeterministic fields.
  - [x] Fail if the SBOM is empty, malformed, or associated with the wrong digest.
- [x] **T3: Generate SLSA provenance.**
  - [x] Use GitHub artifact attestations and a documented local SLSA statement.
  - [x] Bind provenance to source repository, commit, builder identity, invocation, and subject digest.
  - [x] Keep hosted workflow permissions minimal and isolate untrusted pull requests.
- [x] **T4: Validate provenance and linkage.**
  - [x] Verify provenance syntax and expected local builder identity.
  - [x] Detect artifact modification or subject-digest mismatch.
  - [x] Preserve SBOM and provenance beside the release candidate with clear naming.

## Verification and evidence

- Required local checks: SBOM semantic validation, package sanity tests, provenance verification, subject-digest comparison, and tampered-artifact negative tests.
- Retain sample SBOM, provenance, verification output, tamper failure, workflow identity, and commit SHA under `docs/roadmap/evidence/M03/`.

## Exit criteria

- [x] SBOM and local provenance are generated for the exact release artifact digest.
- [x] Both documents pass syntax and semantic sanity checks.
- [ ] Provenance identifies the expected source and GitHub workflow identity.
- [x] A modified artifact fails provenance linkage verification.

## Risks and controls

- **Risk:** An SBOM exists but omits runtime components. **Control:** Generate from the final artifact and add package sanity assertions.
- **Risk:** Provenance is attached to the wrong artifact. **Control:** Treat digest equality as a required release check.
