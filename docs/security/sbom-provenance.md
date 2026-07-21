# SBOM and Provenance

M03 creates a deterministic local release candidate and verifies that its component inventory and provenance refer to the same immutable OCI image manifest. Local evidence is intentionally distinct from GitHub-hosted attestations.

## Evidence set

`make integrity` writes ignored build output under `dist/`:

| File | Purpose |
| --- | --- |
| `image.oci.tar` | Single-platform `linux/amd64` OCI image layout. |
| `image.spdx.raw.json` | Complete Syft SPDX 2.3 document used for semantic verification and hosted SBOM attestation. |
| `image.spdx.canonical.json` | Stable comparison projection with only the generated namespace and creation time removed. |
| `provenance.local.json` | In-toto Statement v1 with a SLSA Provenance v1 predicate for the local builder. |
| `verification.json` | Independent linkage result and evidence-file hashes. |
| `tooling.json` | Pinned generator and build parameters. |
| `checksums.sha256` | SHA-256 checksums for the local evidence set. |

The command refuses a dirty working tree. This prevents a statement for `HEAD` from describing uncommitted build inputs.

## OCI subject contract

The verifier reads the tar stream without extracting paths. It requires exactly one `linux/amd64` manifest, validates index and manifest media types, and recomputes the SHA-256 and size for the manifest, config, and every layer. Archive size is limited to 2 GiB and each layer to 1 GiB. The release subject is the image-manifest digest; the archive checksum is recorded separately because tar-container bytes are not the OCI image identity.

## SPDX contract

Syft 1.48.0 runs from a digest-pinned container against the final OCI archive. The semantic gate requires SPDX 2.3 identity, a unique root container package, unique package IDs, package metadata, the application module, and `stdlib` at `go1.26.5`. The root version and SHA-256 checksum must equal the independently derived OCI manifest digest.

Syft intentionally emits a fresh `documentNamespace` and `creationInfo.created`. The raw document remains unchanged and standards-valid. Reproducibility compares a canonical projection that removes only those two fields and sorts unordered arrays. It does not substitute for the raw SBOM.

## Provenance contract

The local statement records explicit source URI and commit, build type, `linux/amd64` platform, fixed source epoch, repository-owned local builder ID, invocation ID, and OCI subject. Strict decoding rejects unknown fields and trailing content. Verification requires exact equality for every identity and digest field.

Local provenance does not claim a GitHub identity. `.github/workflows/provenance.yml` separately runs on default-branch pushes and manual dispatch, obtains OIDC only in the attestation job, and asks GitHub to create provenance and SPDX artifact-attestation bundles for the same manifest digest. Pull requests cannot invoke that privileged job. Hosted execution remains unverified until an authorized push produces inspectable bundles.

## Reproducibility and failure behavior

`make integrity-repro` performs two clean generations and byte-compares the OCI archive, canonical SBOM projection, local provenance, and tooling metadata. The raw SBOM is not byte-compared because its namespace and timestamp are generated values.

Unit and integration gates reject wrong platforms, missing or duplicate archive entries, altered layers, oversized descriptors, malformed SPDX, duplicate package identifiers, absent runtime inventory, incorrect checksums, wrong predicates, changed sources, unexpected builders, and mismatched invocation IDs. Any failed verification exits nonzero and no successful result is written.
