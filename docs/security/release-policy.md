# Release Evidence and Eligibility Policy

M05 turns the preceding controls into one deterministic, machine-readable decision. The verifier does not trust a precomputed success flag: it opens, hashes, parses, and cross-checks the original evidence beneath a caller-supplied root.

## Evidence contract

`policy/release-v1.json` pins the accepted schema, artifact name, platform, security-policy digest, signing-policy digest, Cosign version, required tests, and required scanners. The referenced signing policy pins signed roles; the verifier enforces fixed evidence-size limits. A release manifest binds these requirements to one immutable OCI manifest digest and one 40-character source commit.

The manifest references:

- the OCI archive and independent M03 verification result;
- the raw SPDX 2.3 document and local SLSA provenance;
- every normalized M02 scanner report and its recorded security decision;
- exact test outcomes for host, race, build, container, scanner fixtures, and integrity;
- the M04 identity-policy decision and a complete validation statement; and
- four Sigstore bundles for the archive, SPDX document, local provenance, and validation statement.

Every reference has a relative path and expected SHA-256. Unknown fields, duplicate identifiers, malformed digests, trailing JSON, and omitted required entries fail closed.

## Rooted evidence access

The verifier opens manifest-controlled inputs only below one explicit evidence directory. Absolute paths, `..` traversal, symlink components, non-regular files, oversized content, duplicate paths, and changed file hashes are rejected before semantic evaluation. The archive is streamed with bounded consumption; JSON inputs use strict bounded decoding.

## Independent evaluation

The decision engine:

1. re-runs the M02 policy against every normalized scanner report and compares the result with the recorded decision;
2. checks required tests and exact policy digests at the manifest evaluation time;
3. parses the OCI archive and independently derives its manifest digest, platform, config, layers, and archive hash;
4. verifies SPDX and provenance subjects against that derived OCI digest;
5. validates the exact M04 workflow identity and artifact hash relationships;
6. compares the signed validation statement with every pre-signing field in the manifest, including report and test hashes, policy identities, source, artifact, time, and trigger; and
7. invokes Cosign 3.1.2 for all four blobs with exact issuer and GitHub workflow constraints.

The Cosign executable name is literal, arguments are passed without a shell, and `--` terminates options before the artifact path. The source-analysis suppression required for this fixed argument vector is governed by exact rule, scanner, file, owner, reason, and expiry in `policy/security-policy.json`.

## Decision use

`cmd/releaseverify` writes a stable JSON decision containing the artifact identity, source commit, release-policy digest, evaluation time, eligibility, sorted reason codes, and sorted evidence states. Consumers must require `eligible: true`, match the immutable artifact digest they intend to use, and archive the decision with its complete evidence set. A mutable tag alone is never sufficient.

`scripts/collect-release-evidence.sh --unsigned` prepares the validation statement in the unprivileged build job. After signing, the same script without that flag assembles the hosted evidence tree and preserves the original signed statement. The protected signing workflow retains both the original evidence and final decision as explicit artifacts; it does not deploy or publish them.

## Local test boundary

Run:

```sh
make release-policy-test
```

The positive fixture injects a clearly isolated test-only Cosign substitute so the full deterministic contract can be exercised without GitHub OIDC. It is not a signature, certificate, transparency-log record, or release authorization. A real eligible decision requires an authorized hosted run whose four bundles pass the unmodified Cosign verifier.

Tamper regressions change test references, remove blocking findings, recalculate aggregate decisions and manifest hashes, and then rewrite the validation statement itself. An isolated verifier with frozen accepted hashes models the signature boundary: altered references fail `VALIDATION_EVIDENCE_MISMATCH`; altered signed bytes fail `SIGNATURE_INVALID`. This proves policy wiring and substitution rejection, not hosted cryptographic execution.
