# Release Evidence Walkthrough

This walkthrough demonstrates the local evidence path and one rejected tamper scenario. It does not create a hosted signature, registry artifact, tag, or release.

## Complete local path

Start from a clean revision:

```sh
make verify
make container-build
make container-smoke
make security-fixtures
make security-scan
make integrity-repro
make signing-test
make release-policy-test
```

The expected control flow is:

1. host, race, and restricted-container tests pass;
2. each seeded scanner defect is detected;
3. eight live scanner reports are normalized and evaluated at one explicit time;
4. two clean OCI builds produce the same archive and canonical integrity evidence;
5. the SPDX and provenance subjects match the independently derived OCI manifest digest;
6. exact signing-identity fixtures accept only the protected repository workflow context; and
7. the complete synthetic release fixture becomes eligible only when its isolated test verifier accepts all three bundles.

Inspect local outputs:

```sh
jq . .local/security-reports/latest/decision.json
jq . dist/verification.json
jq . .local/release-fixtures/decisions/clean.json
```

The clean release fixture identifies itself as synthetic. Its eligible result validates policy composition, not cryptographic authenticity.

## Rejected tamper path

`make release-policy-test` creates independent negative evidence trees and verifies stable reasons. Representative cases include:

| Change | Required result |
| --- | --- |
| Remove SPDX evidence | `SBOM_MISSING` |
| Substitute invalid signature behavior | `SIGNATURE_INVALID` |
| Change the release-policy digest | `POLICY_DIGEST_MISMATCH` |
| Evaluate at a different time | `EVALUATION_TIME_MISMATCH` |
| Change a referenced file after hashing | `EVIDENCE_HASH_MISMATCH` |
| Supply traversal, symlink, special, or oversized paths | Fail before semantic evaluation |

Package tests additionally reject blocking vulnerabilities, expired exceptions, scanner failures, failed tests, invalid provenance, absent signatures, wrong workflow identity, wrong Cosign version, and mutable artifact references.

## Hosted continuation

After an authorized push to protected `main`:

1. reusable validation and repository workflows must pass for the exact source SHA;
2. GitHub-hosted provenance and SPDX attestations must bind to the same OCI subject;
3. the no-checkout signer must create and verify three keyless Sigstore bundles;
4. the no-OIDC policy job must emit a real eligible decision; and
5. an independent reviewer must follow the [release runbook](../operations/release-runbook.md).

Until those events are recorded, only local implementation and negative behavior are demonstrated.
