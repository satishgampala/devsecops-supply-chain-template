# M04 - Keyless Signing and Identity Verification

- **Status:** Not Started
- **Depends on:** M03
- **Implementation plan:** Not written; planned after the dependency milestone.

## Outcome

Release artifacts are keylessly signed through Sigstore, and verification confirms the digest, issuer, repository, workflow, and protected release context.

## Scope and non-goals

This milestone signs and verifies artifacts and attestations. It does not introduce long-lived private signing keys or a private PKI.

## Deliverables

- Explicit trusted-workflow and OIDC signing-identity policy.
- Keyless artifact and attestation signing workflow.
- Local and CI verification with identity, digest, tampering, and context tests.

## Tasks and subtasks

- [ ] **T1: Define the signing identity policy.**
  - [ ] Specify allowed OIDC issuer, repository, workflow path, branch or tag context, and subject digest.
  - [ ] Separate pull-request build identity from protected release identity.
  - [ ] Document transparency-log expectations and offline-verification limitations.
- [ ] **T2: Implement keyless signing.**
  - [ ] Grant OIDC token permission only to the protected signing job.
  - [ ] Sign the immutable artifact digest after all prerequisite checks succeed.
  - [ ] Sign or attest SBOM and provenance associations as required by the selected release format.
- [ ] **T3: Implement strict verification.**
  - [ ] Verify signature cryptography, issuer, subject identity, repository, workflow, and digest.
  - [ ] Fail closed on missing identity constraints or unavailable required evidence.
  - [ ] Produce human-readable and machine-readable verification summaries.
- [ ] **T4: Test signing failures.**
  - [ ] Verify unsigned artifacts fail.
  - [ ] Verify modified artifacts and signatures from an unapproved identity fail.
  - [ ] Verify protected release identity cannot be obtained in an untrusted pull-request job.

## Verification and evidence

- Run keyless sign and strict verify against the clean artifact, then execute unsigned, tampered, and wrong-identity negative tests.
- Retain public signature metadata, certificate identity, transparency-log reference, verification output, and negative-test results under `docs/roadmap/evidence/M04/`.

## Exit criteria

- [ ] The approved release artifact verifies against every identity constraint.
- [ ] Unsigned, tampered, and wrong-identity artifacts fail.
- [ ] OIDC permission exists only on the protected signing job.
- [ ] No long-lived signing key is created or stored.

## Risks and controls

- **Risk:** Verification checks cryptography but not signer identity. **Control:** Require explicit issuer and workflow-identity constraints.
- **Risk:** Pull-request code reaches privileged signing context. **Control:** Isolate protected release jobs and never execute untrusted repository code with elevated permissions.
