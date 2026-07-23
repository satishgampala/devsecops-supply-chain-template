# M04 - Keyless Signing and Identity Verification

- **Status:** Implemented Locally
- **Depends on:** M03
- **Implementation plan:** [2026-07-21 M04 Keyless Signing](../implementation-plans/2026-07-21-M04-keyless-signing.md)

## Outcome

Release artifacts are keylessly signed through Sigstore, and verification confirms the digest, issuer, repository, workflow, and protected release context.

## Scope and non-goals

This milestone signs and verifies artifacts and attestations. It does not introduce long-lived private signing keys or a private PKI.

## Deliverables

- Explicit trusted-workflow and OIDC signing-identity policy.
- Keyless artifact and attestation signing workflow.
- Local and CI verification with identity, digest, tampering, and context tests.

## Tasks and subtasks

- [x] **T1: Define the signing identity policy.**
  - [x] Specify allowed OIDC issuer, repository, workflow path, protected branch context, source SHA, and artifact digests.
  - [x] Separate pull-request build identity from protected release identity.
  - [x] Document transparency-log expectations and offline-verification limitations.
- [x] **T2: Implement keyless signing.**
  - [x] Grant OIDC token permission only to the protected signing job.
  - [x] Configure signing of immutable evidence after prerequisite checks succeed.
  - [x] Configure signing of the raw SPDX document and local provenance beside the OCI archive.
- [x] **T3: Implement strict verification.**
  - [x] Require signature cryptography, issuer, subject identity, repository, workflow, and digest verification.
  - [x] Fail closed on missing identity constraints or unavailable required evidence.
  - [x] Produce machine-readable verification observations and policy decisions.
- [x] **T4: Test signing failures.**
  - [x] Verify an unsigned observation fails.
  - [x] Verify modified digest and unapproved identity observations fail.
  - [x] Verify pull-request context cannot satisfy protected signing policy.

## Verification and evidence

- Run keyless sign and strict verify against the clean artifact, then execute unsigned, tampered, and wrong-identity negative tests.
- Retain public signature metadata, certificate identity, transparency-log reference, verification output, and negative-test results under `docs/roadmap/evidence/M04/`.

## Exit criteria

- [ ] The approved release artifact verifies against every identity constraint.
- [ ] Unsigned, tampered, and wrong-identity artifacts fail.
- [x] OIDC permission exists only on the protected signing job.
- [x] No long-lived signing key is created or stored.

## Risks and controls

- **Risk:** Verification checks cryptography but not signer identity. **Control:** Require explicit issuer and workflow-identity constraints.
- **Risk:** Pull-request code reaches privileged signing context. **Control:** Isolate protected release jobs and never execute untrusted repository code with elevated permissions.
