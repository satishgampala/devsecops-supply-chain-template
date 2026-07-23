# M03 - SBOM and SLSA Provenance

- **Status:** Not Started
- **Depends on:** M02
- **Implementation plan:** Not written; planned after the dependency milestone.

## Outcome

Every release candidate has a standards-based SBOM and build provenance that identify its components, source revision, builder, workflow, and immutable artifact digest.

## Scope and non-goals

This milestone generates and validates SBOM and SLSA provenance. It does not yet sign the release artifact or make a final deployment-eligibility decision.

## Deliverables

- Validated SPDX or CycloneDX SBOM bound to the immutable release artifact.
- SLSA provenance that identifies source, builder, workflow, and artifact digest.
- Reproducibility, association, tampering, and malformed-evidence tests.

## Tasks and subtasks

- [ ] **T1: Generate the SBOM.**
  - [ ] Select SPDX or CycloneDX and document the choice.
  - [ ] Generate an SBOM from the final container or release artifact, not only source dependencies.
  - [ ] Validate schema, package identifiers, versions, licenses, and artifact association.
- [ ] **T2: Make SBOM generation reproducible.**
  - [ ] Pin generator versions and record their metadata.
  - [ ] Compare SBOM content across identical source builds while excluding expected timestamps or nondeterministic fields.
  - [ ] Fail if the SBOM is empty, malformed, or associated with the wrong digest.
- [ ] **T3: Generate SLSA provenance.**
  - [ ] Use the official SLSA GitHub generator or a documented equivalent.
  - [ ] Bind provenance to source repository, commit, workflow, builder identity, and subject digest.
  - [ ] Keep release workflow permissions minimal and isolate untrusted pull requests.
- [ ] **T4: Validate provenance and linkage.**
  - [ ] Verify provenance syntax and expected builder/workflow identity.
  - [ ] Detect artifact modification or subject-digest mismatch.
  - [ ] Publish SBOM and provenance beside the release candidate with clear naming.

## Verification and evidence

- Required future checks: SBOM schema validation, package sanity tests, provenance verification, subject-digest comparison, and tampered-artifact negative test.
- Retain sample SBOM, provenance, verification output, tamper failure, workflow identity, and commit SHA under `docs/roadmap/evidence/M03/`.

## Exit criteria

- [ ] SBOM and provenance are generated for the exact release artifact digest.
- [ ] Both documents pass schema and semantic sanity checks.
- [ ] Provenance identifies the expected source and GitHub workflow identity.
- [ ] A modified artifact fails provenance linkage verification.

## Risks and controls

- **Risk:** An SBOM exists but omits runtime components. **Control:** Generate from the final artifact and add package sanity assertions.
- **Risk:** Provenance is attached to the wrong artifact. **Control:** Treat digest equality as a required release check.
