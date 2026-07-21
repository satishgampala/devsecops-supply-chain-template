# M05 Release Policy Implementation Plan

> **Execution note:** Implement this plan task by task and use the checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce one deterministic deployment-eligibility decision by independently checking the immutable artifact and every required test, scanner, SBOM, provenance, signing, policy, and evidence-file relationship.

**Architecture:** A versioned release manifest references original evidence files by relative path and SHA-256. A standard-library verifier opens them beneath one traversal-resistant evidence root, rejects symlinks and oversized JSON, re-evaluates normalized scanner reports, re-validates OCI/SPDX/provenance linkage, checks exact signing identity, and invokes Cosign for each required Sigstore bundle. The decision contains stable reason codes and evidence references and is bound to one OCI manifest digest and source commit.

**Tech stack:** Go 1.26.5, Cosign 3.1.2, OCI Image Layout, SPDX 2.3, SLSA Provenance v1, M02 normalized scanner policy, M04 signing policy.

## Global constraints

- Work on `feat/m05-release-policy`; do not implement directly on `main`.
- Accept only immutable `sha256:<64 lowercase hex>` artifact identities.
- Read all manifest-controlled files beneath one explicit relative evidence root.
- Reject absolute paths, traversal, symlinks, duplicate IDs or paths, non-regular files, oversized JSON, unknown fields, trailing JSON, and digest mismatches.
- Re-evaluate source scanner reports; do not trust an unexplained security boolean.
- Re-run OCI, SBOM, provenance, signing identity, and Cosign bundle verification.
- Keep embedded SCT and transparency-log verification enabled.
- Treat missing tools and missing or failed evidence as ineligible, never as skipped.
- Sort reason codes and evidence summaries before encoding.
- Keep local deterministic fixtures separate from a real hosted keyless eligible decision.

## Immutable policy inputs

| Input | Required value |
| --- | --- |
| Security policy SHA-256 | `95c6cdef0b7e6da8775f8e7622468bf32024e6bc147ba9eca8c3106b7b3491fb` |
| Signing policy SHA-256 | `f5f43f291e56e05d3454d7d8d220134e2cdbcbdc29666531ea98c1a8613ab4d2` |
| Cosign | `v3.1.2` |
| Platform | `linux/amd64` |
| Artifact name | `ghcr.io/satishgampala/devsecops-supply-chain-template` |

## Task 1: Define release contracts and safe evidence access

**Files:**

- Create: `policy/release-v1.json`
- Create: `internal/releasepolicy/model.go`
- Create: `internal/releasepolicy/store.go`
- Create: `internal/releasepolicy/store_test.go`

- [ ] Define versioned policy, manifest, test-summary, decision, and evidence-reference schemas.
- [ ] Require exact artifact, source, platform, policy digest, test, scanner, and tool identities.
- [ ] Open evidence through a rooted store that rejects absolute paths, traversal, every symlink component, special files, and duplicate paths.
- [ ] Bound JSON and streamed artifact reads and verify every referenced SHA-256 before semantic decoding.

## Task 2: Implement deterministic release evaluation

**Files:**

- Create: `internal/releasepolicy/evaluate.go`
- Create: `internal/releasepolicy/evaluate_test.go`
- Create: `internal/releasepolicy/cosign.go`
- Create: `cmd/releaseverify/main.go`
- Create: `cmd/releaseverify/main_test.go`

- [ ] Re-run security policy from original normalized reports and compare the recorded decision.
- [ ] Require every named host, race, build, container, scanner-fixture, and integrity test.
- [ ] Re-derive the OCI manifest digest and validate raw SPDX and local provenance against it.
- [ ] Validate the exact signing-policy digest, decision identity, artifact hashes, and required bundles.
- [ ] Invoke Cosign 3.1.2 with exact issuer and GitHub workflow flags for all three blobs.
- [ ] Emit stable eligible/ineligible JSON with exact artifact identity, source SHA, policy digest, reasons, and sorted evidence states.

## Task 3: Build positive and negative release scenarios

**Files:**

- Create: `testdata/release/**`
- Create: `scripts/release-policy-fixtures.sh`
- Update: `Makefile`

- [ ] Prove the evaluator's complete synthetic contract can become eligible only after every injected verifier succeeds.
- [ ] Reject blocking vulnerability, expired exception, scanner failure, failed test, missing SBOM, invalid provenance, absent signature, wrong workflow identity, artifact mismatch, policy mismatch, and evidence hash mismatch.
- [ ] Confirm each scenario contains its primary stable reason code.
- [ ] Prove malformed, duplicate, traversal, symlink, oversized, and mutable-reference inputs fail closed.

## Task 4: Integrate protected release verification

**Files:**

- Update: `.github/workflows/signing.yml`
- Create: `scripts/collect-release-evidence.sh`

- [ ] Build tests, scanner reports, OCI, SPDX, and provenance without OIDC.
- [ ] Transfer bounded evidence to a no-checkout OIDC signing job and create three Sigstore bundles.
- [ ] Assemble the manifest and run the release verifier in a separate no-OIDC job with immutable Cosign.
- [ ] Retain original evidence, bundles, manifest, and final decision without deploying or publishing.

## Task 5: Verify and document M05

**Files:**

- Update: `README.md`
- Update: `docs/architecture/pipeline-flow.md`
- Update: `docs/roadmap/milestones/M05-release-policy.md`
- Update: `docs/roadmap/ROADMAP.md`
- Update: `docs/roadmap/STATUS.md`
- Create: `docs/security/release-policy.md`
- Create: `docs/roadmap/evidence/M05/verification.md`

- [ ] Run release-policy, host, scanner, container, actionlint, zizmor, path-security, and tamper gates.
- [ ] Record stable reason matrix and exact synthetic clean-decision hash.
- [ ] Document decision use, trust boundaries, evidence retention, and hosted-signature limitation.
- [ ] Mark local implementation complete while the real hosted eligible path remains pending.

## Completion gate

M05 is locally complete when every evidence class is independently parsed and cross-checked, deterministic positive and negative tests pass, the protected workflow has no OIDC/source-execution overlap, and all repository gates remain green. A real release becomes eligible only after an authorized hosted run supplies keyless bundles that pass Cosign and every other control; local synthetic fixtures are not release authorization.
