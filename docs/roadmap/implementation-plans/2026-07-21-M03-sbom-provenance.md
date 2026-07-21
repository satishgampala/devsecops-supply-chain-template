# M03 SBOM and Provenance Implementation Plan

> **Execution note:** Implement this plan task by task and use the checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a reproducible Linux OCI release candidate with a validated SPDX 2.3 inventory and SLSA provenance bound to its immutable manifest digest.

**Architecture:** BuildKit exports one `linux/amd64` OCI archive with provenance disabled and a fixed source epoch. A standard-library Go verifier independently parses the archive, validates every referenced OCI blob, derives the manifest digest, validates Syft's SPDX document, and verifies an in-toto SLSA provenance statement. Deterministic local evidence proves linkage and tamper rejection; a protected GitHub workflow creates platform attestations for the same subject digest.

**Tech stack:** Go 1.26.5, OCI Image Layout 1.1, SPDX 2.3 JSON, Syft 1.48.0, in-toto Statement v1, SLSA Provenance v1, GitHub artifact attestations, Docker Buildx.

## Global constraints

- Work on `feat/m03-sbom-provenance`; do not implement directly on `main`.
- Build only `linux/amd64` until per-platform SBOM and provenance handling is added.
- Identify the image by `sha256:<manifest-digest>`, never by a mutable tag.
- Generate the SBOM from the final OCI archive, not only `go.mod` or source files.
- Keep raw Syft output unchanged; compare a canonical projection that removes only documented nondeterministic fields.
- Treat malformed archives, missing blobs, digest mismatch, empty SBOMs, duplicate identifiers, wrong source, wrong builder, and tampering as hard failures.
- Do not claim hosted attestation verification until the GitHub workflow has run.
- Do not sign artifacts in M03; keyless signing begins in M04.

## Immutable references

| Component | Reference |
| --- | --- |
| Syft | `docker.io/anchore/syft@sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c` (`v1.48.0`) |
| Artifact attestation | `actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6` (`v4.2.0`) |
| Artifact upload | `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (`v7.0.1`) |

## Shared contracts

### OCI subject

- OCI layout contains exactly one image manifest.
- Platform is exactly `linux/amd64`.
- Index, manifest, config, and every layer descriptor use SHA-256.
- Descriptor size and digest match the actual tar entry bytes.
- Subject digest is the verified image-manifest digest, not the archive-file checksum.
- The archive SHA-256 is recorded separately for evidence-file integrity.

### SPDX document

- `spdxVersion` is `SPDX-2.3`, `dataLicense` is `CC0-1.0`, and document ID is `SPDXRef-DOCUMENT`.
- A `DESCRIBES` relationship selects exactly one root image package.
- Root package version and SHA-256 checksum equal the independently derived OCI manifest digest.
- Package IDs are unique and every package has name, version, declared/concluded license fields, and download location.
- Inventory contains the application module and Go standard library at the expected version.

### Provenance statement

- Statement type is `https://in-toto.io/Statement/v1`.
- Predicate type is `https://slsa.dev/provenance/v1`.
- Exactly one subject contains the OCI manifest digest.
- Build definition binds source URI, source commit, and build type.
- Run details bind builder ID and invocation ID.
- Local statements identify the repository-owned local builder. GitHub-generated attestations retain the platform-provided workflow identity and are not replaced by local claims.

## Task 1: Parse and validate OCI archives

**Files:**

- Create: `internal/integrity/oci.go`
- Create: `internal/integrity/oci_test.go`
- Create: `testdata/integrity/oci/**`

- [x] Parse OCI `index.json` and its single image manifest without extracting archive paths.
- [x] Validate platform, media types, descriptor sizes, SHA-256 syntax, blob presence, and blob hashes.
- [x] Stream large layer hashing instead of loading layers into memory.
- [x] Return manifest digest and independent archive-file SHA-256.
- [x] Reject missing, duplicate, malformed, wrong-platform, and tampered fixtures.

## Task 2: Validate and canonicalize SPDX 2.3

**Files:**

- Create: `internal/integrity/spdx.go`
- Create: `internal/integrity/spdx_test.go`
- Create: `testdata/integrity/spdx/**`

- [x] Validate SPDX document identity, creator time, package fields, unique IDs, and root description.
- [x] Bind the root image package checksum and version to the OCI manifest digest.
- [x] Require the application module and `stdlib` package at Go 1.26.5.
- [x] Produce a stable canonical projection excluding `creationInfo.created` and `documentNamespace` only.
- [x] Reject empty, malformed, duplicate-ID, missing-runtime, and wrong-digest documents.

## Task 3: Generate and verify SLSA provenance

**Files:**

- Create: `internal/integrity/provenance.go`
- Create: `internal/integrity/provenance_test.go`
- Create: `cmd/supply-chain/main.go`
- Create: `testdata/integrity/provenance/**`

- [x] Generate an in-toto SLSA Provenance v1 statement from explicit inputs only.
- [x] Verify artifact name/digest, source URI/commit, build type, builder ID, and invocation ID.
- [x] Sort subjects and dependencies before encoding.
- [x] Add `subject`, `canonicalize`, `provenance`, and `verify` command modes.
- [x] Prove wrong subject, source, builder, predicate type, and tampered artifact fail.

## Task 4: Add reproducible local generation

**Files:**

- Create: `scripts/generate-integrity.sh`
- Create: `scripts/integrity-repro.sh`
- Update: `Makefile`
- Update: `.gitignore`

- [x] Export one OCI archive with `SOURCE_DATE_EPOCH=0`, `--provenance=false`, and `linux/amd64`.
- [x] Generate raw SPDX 2.3 from the final archive through the digest-pinned Syft container.
- [x] Generate the local SLSA statement and run the integrated verifier.
- [x] Record artifact, SBOM, provenance, and canonical-SBOM checksums.
- [x] Build twice and prove byte-identical OCI archives, canonical SBOMs, and local provenance statements.

## Task 5: Add hosted artifact attestations

**Files:**

- Create: `.github/workflows/provenance.yml`

- [x] Trigger only protected default-branch pushes and manual dispatch, never pull requests.
- [x] Grant `id-token`, `attestations`, and artifact-metadata writes only to the attestation job.
- [x] Generate provenance and SPDX attestations for the exact manifest digest with SHA-pinned `actions/attest`.
- [x] Preserve the OCI archive, raw/canonical SBOM, local statement, checksums, and platform bundles as a bounded artifact.
- [x] Keep action references immutable and repository checkout credential-free.

## Task 6: Verify and document M03

**Files:**

- Update: `README.md`
- Update: `docs/architecture/pipeline-flow.md`
- Update: `docs/roadmap/milestones/M03-sbom-provenance.md`
- Update: `docs/roadmap/ROADMAP.md`
- Update: `docs/roadmap/STATUS.md`
- Create: `docs/security/sbom-provenance.md`
- Create: `docs/roadmap/evidence/M03/verification.md`

- [x] Run host, race, scanner, container, actionlint, integrity, reproducibility, and tamper gates.
- [x] Record exact subject, archive, SBOM, provenance, and canonical hashes.
- [x] Document raw-versus-canonical SBOM behavior and the distinction between local statements and hosted attestations.
- [x] Mark local M03 implementation complete while keeping hosted attestation execution pending.

## Completion gate

M03 is locally complete only when two clean builds have byte-identical OCI archives, canonical SBOMs, and local provenance; the integrated verifier binds all evidence to one manifest digest; every malformed or tampered fixture fails; M01 and M02 gates remain green; and hosted attestation execution is stated as pending until observed.
