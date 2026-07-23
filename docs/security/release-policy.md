# Release Evidence and Eligibility Policy

M05 turns the preceding controls into one deterministic, machine-readable decision. The verifier does not trust a precomputed success flag: it opens, hashes, parses, and cross-checks the original evidence beneath a caller-supplied root.

## Evidence contract

`policy/release-v1.json` pins the accepted schema, artifact name, platform, security-policy digest, signing-policy digest, Cosign version, required tests, required scanners, required signed roles, and maximum evidence sizes. A release manifest binds these requirements to one immutable OCI manifest digest and one 40-character source commit.

The manifest references:

- the OCI archive and independent M03 verification result;
- raw and canonical SPDX 2.3 documents plus local SLSA provenance;
- every normalized M02 scanner report and its recorded security decision;
- exact test outcomes for host, race, build, container, scanner fixtures, and integrity;
- the M04 signing observation and identity-policy decision; and
- three Sigstore bundles for the archive, SPDX document, and local provenance.

Every reference has a relative path and expected SHA-256. Unknown fields, duplicate identifiers, malformed digests, trailing JSON, and omitted required entries fail closed.

## Rooted evidence access

The verifier opens manifest-controlled inputs only below one explicit evidence directory. Absolute paths, `..` traversal, symlink components, non-regular files, oversized content, duplicate paths, and changed file hashes are rejected before semantic evaluation. The archive is streamed with bounded consumption; JSON inputs use strict bounded decoding.

## Independent evaluation

The decision engine:

1. re-runs the M02 policy against every normalized scanner report and compares the result with the recorded decision;
2. checks required tests and exact policy digests at the manifest evaluation time;
3. parses the OCI archive and independently derives its manifest digest, platform, config, layers, and archive hash;
4. verifies SPDX and provenance subjects against that derived OCI digest;
5. validates the exact M04 workflow identity and artifact hash relationships; and
6. invokes Cosign 3.1.2 for all three blobs with exact issuer and GitHub workflow constraints.

The Cosign executable name is literal, arguments are passed without a shell, and `--` terminates options before the artifact path. The source-analysis suppression required for this fixed argument vector is governed by exact rule, scanner, file, owner, reason, and expiry in `policy/security-policy.json`.

## Decision use

`cmd/releaseverify` writes a stable JSON decision containing the artifact identity, source commit, release-policy digest, evaluation time, eligibility, sorted reason codes, and sorted evidence states. Consumers must require `eligible: true`, match the immutable artifact digest they intend to use, and archive the decision with its complete evidence set. A mutable tag alone is never sufficient.

`scripts/collect-release-evidence.sh` assembles the hosted evidence tree. The protected signing workflow retains both the original evidence and final decision as explicit artifacts; it does not deploy or publish them.

## Local test boundary

Run:

```sh
make release-policy-test
```

The positive fixture injects a clearly isolated test-only Cosign substitute so the full deterministic contract can be exercised without GitHub OIDC. It is not a signature, certificate, transparency-log record, or release authorization. A real eligible decision requires an authorized hosted run whose three bundles pass the unmodified Cosign verifier.
