# M04 Keyless Signing Implementation Plan

> **Execution note:** Implement this plan task by task and use the checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keylessly sign the verified M03 artifact set in an isolated protected workflow and require exact Sigstore certificate, workflow, source, and artifact identities during verification.

**Architecture:** An unprivileged build job creates and uploads M03 evidence. A dependent signing job downloads only that artifact, receives GitHub OIDC, installs immutable Cosign, checks the transferred files, signs the OCI archive, raw SPDX document, and local provenance as blobs, and immediately verifies every bundle against exact Fulcio and GitHub workflow claims. Repository code is never checked out or executed in the signing job. Local policy tests model the same identity and context constraints; successful keyless cryptography remains a hosted gate.

**Tech stack:** Go 1.26.5, Cosign 3.1.2, Sigstore bundles, Fulcio keyless certificates, Rekor transparency log, GitHub Actions OIDC.

## Global constraints

- Work on `feat/m04-keyless-signing`; do not implement directly on `main`.
- Never create, store, upload, or document a long-lived signing private key.
- Sign only evidence transferred from a successful M03 build job.
- Permit signing only for `refs/heads/main` on `push` or `workflow_dispatch`.
- Never expose OIDC to pull-request jobs or jobs that check out and execute repository code.
- Require exact issuer, certificate identity, repository, workflow name, ref, commit SHA, trigger, artifact role, and SHA-256 values.
- Keep transparency-log and embedded SCT verification enabled.
- Treat absent bundles, missing constraints, unapproved context, and any mismatch as hard failures.
- Do not claim a successful signature until the hosted workflow has run and its public bundle has been verified.

## Immutable references

| Component | Reference |
| --- | --- |
| Cosign image | `gcr.io/projectsigstore/cosign@sha256:d91bc4e7e95e8d2f549c747a72dc174f90579e410a1695f57f686674f84ce849` (`v3.1.2`) |
| Cosign installer | `sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6` (`v4.1.2`) |
| Checkout | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`) |
| Artifact upload | `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (`v7.0.1`) |
| Artifact download | `actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3` (`v8.0.0`) |

## Shared identity contract

- OIDC issuer: `https://token.actions.githubusercontent.com`.
- Certificate identity: `https://github.com/satishgampala/devsecops-supply-chain-template/.github/workflows/signing.yml@refs/heads/main`.
- Repository: `satishgampala/devsecops-supply-chain-template`.
- Workflow name: `Signing`.
- Ref: `refs/heads/main`.
- Allowed triggers: `push`, `workflow_dispatch`.
- Commit SHA: exact 40-character lowercase workflow commit, supplied at verification time.
- Artifact roles: `oci-archive`, `spdx-sbom`, and `local-provenance`, each with an exact SHA-256.

## Task 1: Define and evaluate signing identity policy

**Files:**

- Create: `policy/signing-identity.json`
- Create: `internal/signingpolicy/model.go`
- Create: `internal/signingpolicy/policy.go`
- Create: `internal/signingpolicy/policy_test.go`

- [ ] Strictly decode a versioned policy with no unknown fields or trailing JSON.
- [ ] Validate exact HTTPS issuer and certificate identity, repository, workflow, ref, and nonempty allowed triggers.
- [ ] Validate lowercase full Git SHA and SHA-256 artifact digests.
- [ ] Return deterministic, stable reason codes for every failed constraint.
- [ ] Reject pull requests, missing constraints, duplicate artifact roles, and wildcard identities.

## Task 2: Add machine-readable signing verification records

**Files:**

- Create: `cmd/signing-policy/main.go`
- Create: `cmd/signing-policy/main_test.go`
- Create: `testdata/signing/**`

- [ ] Evaluate observed certificate/workflow claims and exact artifact hashes against policy.
- [ ] Produce stable JSON with eligibility, sorted reason codes, identity, source SHA, and artifact digests.
- [ ] Fail nonzero for wrong issuer, identity, repository, workflow, ref, SHA, trigger, role, or digest.
- [ ] Keep local fixtures synthetic and clearly separate from cryptographic Sigstore verification.

## Task 3: Add isolated keyless signing workflow

**Files:**

- Create: `.github/workflows/signing.yml`
- Create: `scripts/signing-policy-fixtures.sh`
- Update: `Makefile`

- [ ] Build M03 evidence in a read-only job with no OIDC permission.
- [ ] Transfer a bounded artifact to a signing job that never checks out or executes transferred repository programs or scripts.
- [ ] Grant `id-token: write` only to the signing job and gate it to protected default-branch context.
- [ ] Keylessly sign the OCI archive, raw SPDX SBOM, and local provenance with Cosign 3.1.2.
- [ ] Verify each bundle immediately using all exact certificate and GitHub workflow flags.
- [ ] Preserve bundles, observed claims, policy decision, and source evidence for later release evaluation.

## Task 4: Verify and document M04

**Files:**

- Update: `README.md`
- Update: `docs/architecture/pipeline-flow.md`
- Update: `docs/roadmap/milestones/M04-signing.md`
- Update: `docs/roadmap/ROADMAP.md`
- Update: `docs/roadmap/STATUS.md`
- Create: `docs/security/signing.md`
- Create: `docs/roadmap/evidence/M04/verification.md`

- [ ] Run policy, negative, host, scanner, actionlint, and zizmor gates.
- [ ] Prove signing context rejects pull requests, feature refs, wrong SHAs, and wrong artifact digests.
- [ ] Confirm no private signing key or credential file exists in tracked content or history.
- [ ] Record local policy implementation complete while hosted keyless sign/verify remains pending.

## Completion gate

M04 is locally complete when deterministic policy tests reject every wrong identity and artifact class, the signing workflow structurally isolates OIDC from repository code, all workflow/security gates pass, and documentation clearly identifies hosted keyless cryptography as pending. Full M04 exit remains pending until an authorized hosted run produces bundles that Cosign verifies with every exact identity constraint.
