# Keyless Signing and Identity Verification

M04 defines a fail-closed Sigstore signing boundary. It creates no private key. The protected workflow uses GitHub OIDC to obtain an ephemeral Fulcio certificate, records its signature in a Sigstore bundle with Rekor material, and immediately verifies exact identity and artifact constraints.

## Trusted identity

`policy/signing-identity.json` requires:

| Claim | Exact value |
| --- | --- |
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Certificate identity | `https://github.com/satishgampala/devsecops-supply-chain-template/.github/workflows/signing.yml@refs/heads/main` |
| Repository | `satishgampala/devsecops-supply-chain-template` |
| Workflow name | `Signing` |
| Ref | `refs/heads/main` |
| Triggers | `push` or `workflow_dispatch` |
| Commit | Exact 40-character workflow SHA supplied to the verifier |

Wildcards, pull-request triggers, feature refs, unknown fields, trailing JSON, duplicate roles, malformed hashes, and incomplete constraints fail.

## Three-job boundary

The `build` job has `contents: read`, checks out source without persisted credentials, runs `make candidate` to test and scan one immutable OCI subject, and uploads an explicit file set. It has no OIDC permission.

The dependent `sign` job has only `actions: read` and `id-token: write`. It runs only for the default branch on `push` or `workflow_dispatch`, downloads the bounded evidence set, checks its M03 checksums, installs immutable Cosign 3.1.2, and never checks out source. It signs the OCI archive, raw SPDX document, local provenance, and complete validation statement as separate blobs.

Each bundle is immediately passed to `cosign verify-blob` with exact certificate identity, issuer, workflow name, repository, ref, SHA, and trigger flags. Neither transparency-log verification nor embedded SCT verification is disabled. A fixed shell step records hashes and claims only after all four commands succeed.

The final `policy` job has no OIDC permission. It checks out the standard-library verifier, compares the observation against the versioned policy and exact workflow SHA, then emits a deterministic decision.

## Signed artifacts

| Role | Blob | Bundle |
| --- | --- | --- |
| OCI archive | `image.oci.tar` | `image.oci.sigstore.json` |
| SPDX SBOM | `image.spdx.raw.json` | `image.spdx.sigstore.json` |
| Local provenance | `provenance.local.json` | `provenance.local.sigstore.json` |
| Validation evidence | `validation-evidence.json` | `validation-evidence.sigstore.json` |

The OCI archive signature binds its archive-file SHA-256. M03 separately binds the archive contents, SPDX root, and provenance subject to the OCI manifest digest. M05 must require both relationships. GitHub artifact attestations are already signed DSSE statements; M04 does not wrap those platform signatures in another Cosign signature.

The validation statement binds the source commit, OCI identity, test summary, normalized scanner reports, security decision, integrity result, all policy digests, evaluation time, and workflow trigger. It excludes signature bundles and the signing decision to avoid circular hashes. The release verifier compares the statement with the assembled manifest before requiring its independent Cosign signature. Recalculating evidence hashes cannot authorize substituted test or scanner results.

## Local and hosted evidence

`make signing-test` exercises strict decoding, normalization, identity, context, artifact roles, hashes, and stable failure codes with synthetic observations. These fixtures do not contain a certificate, signature, Rekor entry, or proof of cryptographic verification.

Real keyless verification requires network access to Sigstore trust material and a hosted OIDC identity. The public transparency log also exposes signature metadata. Offline verification requires an independently captured trusted root and complete bundle; this repository does not weaken SCT or transparency verification to make offline checks pass. Until an authorized hosted run succeeds, the workflow configuration and local policy are implemented but no signature is claimed.
