# Release Evidence Walkthrough

This demo shows a real local candidate, then separate synthetic release-policy and tamper scenarios. It does not create hosted signatures, registry artifacts, tags, or releases.

## 1. Validate one real candidate

Use the prerequisites in the [README](../../README.md) and a clean committed checkout:

```sh
make candidate
jq . dist/container-smoke.json
jq '{sourceDigest, subjectDigest, tests}' dist/tests.json
jq . dist/security/decision.json
jq . dist/verification.json
```

Expected results:

1. Host, race, build, and seeded scanner rejection checks pass.
2. One OCI archive is built from the committed source snapshot.
3. The restricted runtime reports the same image digest as the archive and test summary.
4. All eight live scanners complete, and the security decision has `eligible: true` with no reason codes.
5. SPDX and provenance subjects match the independently derived OCI manifest digest.

The normalized reports in `dist/security/normalized/` record exact scanner references, source, subject, scan time, and available database timestamps. Live results can change with advisory updates; a failure is a result to investigate, not an instruction to weaken policy.

Preserve these outputs before commands that regenerate `dist/`:

```sh
candidate_dir=".local/demo-candidate-$(git rev-parse --short HEAD)-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$candidate_dir"
cp -R dist/. "$candidate_dir/"
printf 'Candidate evidence: %s\n' "$candidate_dir"
```

## 2. Reproduce integrity and policy behavior

```sh
make integrity-repro
make signing-test release-policy-test
jq '{eligible, reasonCodes}' .local/release-fixtures/decisions/clean.json
jq '{eligible, reasonCodes}' .local/release-fixtures/decisions/rehashed-tests.json
jq '{eligible, reasonCodes}' .local/release-fixtures/decisions/rewritten-validation.json
```

Reproducibility compares the OCI archive, canonical SBOM, local provenance, and tooling across two builds. The raw SBOM retains generated namespace/time fields and is not expected to be byte-identical.

The clean release fixture returns `eligible: true` using synthetic reports and four test-only signature substitutes. Its verifier freezes accepted content hashes outside the evidence directory. This exercises the complete policy contract and byte binding; it does not verify Sigstore cryptography.

| Deliberate change | Required rejection |
| --- | --- |
| Rewrite test evidence and recalculate its manifest hash | `VALIDATION_EVIDENCE_MISMATCH` |
| Also rewrite the signed validation statement and its public hashes | `SIGNATURE_INVALID` |
| Remove SPDX evidence | `SBOM_MISSING` |
| Change the release-policy digest | `POLICY_DIGEST_MISMATCH` |
| Evaluate at a different time | `EVALUATION_TIME_MISMATCH` |
| Substitute traversal, symlink, special, or oversized paths | Reject before semantic evaluation. |

Package tests also reject stale advisory data, wrong scanner/source/image identities, blocking findings, expired exceptions, scanner failures, failed tests, invalid provenance, missing signatures, wrong workflow identities, and mutable artifact references.

## 3. Demonstrate adoption and maintenance

```sh
make template-test
make workflow-check docs-check
```

Consumer fixtures initialize lowercase and mixed-case GitHub identities, recalculate dependent policy hashes, run host and release contracts, and prove malformed identities and a seeded Go defect fail. In an already adopted repository, `template-test` validates current signing/release contracts without attempting initialization again.

Workflow lint covers every workflow. Documentation checks validate local links and fragments and render every fenced Mermaid diagram; they do not check external URLs.

## Hosted continuation

Hosted execution is currently blocked by the account billing lock. After that is resolved and an authorized push reaches protected `main`:

1. Required PR/default-branch checks must pass for the exact source SHA.
2. Platform attestations must bind to the same OCI subject.
3. The no-checkout signer must create and verify four real Sigstore bundles.
4. The no-OIDC verifier must emit a real eligible decision.
5. An independent reviewer must complete the [release runbook](../operations/release-runbook.md).

Local fixture success never substitutes for those hosted gates.
