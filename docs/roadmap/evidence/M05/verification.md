# M05 Local Verification Evidence

- **Recorded:** 2026-07-21T11:58:09Z
- **Implementation revision:** `23471aa37f3c2ee5802f804f647a5bc0e4a6f117`
- **Branch:** `feat/m05-release-policy`
- **Release policy SHA-256:** `308b469ab2de5069ce81c17d662d65d541c2528eb9db4c30a10fe0040b862f1d`
- **Result:** Complete local release-policy, evidence-path, and tamper gates passed; hosted keyless eligibility remains pending.

## Tested subject

| Property | Observed value |
| --- | --- |
| OCI artifact | `ghcr.io/satishgampala/devsecops-supply-chain-template@sha256:c3119bf025a06578bb974c9a08611d72af6a45d40e292c25210043c660816837` |
| OCI archive SHA-256 | `3257a9e465b7e39c1bb2c5471cab8b2228f23fe5d89ae9f420e3df987ca10738` |
| Platform | `linux/amd64` |
| Source commit | `23471aa37f3c2ee5802f804f647a5bc0e4a6f117` |
| Security policy SHA-256 | `d9a881d5e4752ab6af5e31be9958ce0ec02a96dfc108ee23a0734e5d9828e736` |
| Signing policy SHA-256 | `f5f43f291e56e05d3454d7d8d220134e2cdbcbdc29666531ea98c1a8613ab4d2` |
| Cosign contract | `v3.1.2` |

## Deterministic fixture decisions

| Scenario | Eligibility | Required reason | Decision SHA-256 |
| --- | --- | --- | --- |
| Complete synthetic evidence | Eligible | No reason codes | `e74ad130b8983bcb647ed33068cfc3bc4ce04c26f7ea2fcde6d38364093a186b` |
| Missing SPDX evidence | Ineligible | `SBOM_MISSING` | `0ab404c19fcf9a2c891f15f187a850ab8f05442fe41dfe518542056730f7002f` |
| Invalid signature | Ineligible | `SIGNATURE_INVALID` | `7af11d254a06a0f6a69326286c3396018ab4756418be206a704cf793a1f78bb2` |
| Release-policy digest mismatch | Ineligible | `POLICY_DIGEST_MISMATCH` | `4e1f03187a1bf826afe63317bf7ac3ff0115db2785e190c566f090e34496f0e6` |
| Evaluation-time mismatch | Ineligible | `EVALUATION_TIME_MISMATCH` | `eec0be5b0ae9d7f9a90b07a4f60069998b09a3f197a0570302571b0d243a280a` |

The positive fixture uses an explicit test-only Cosign substitute. It proves evaluator composition and deterministic output, not cryptographic authenticity or release authorization.

Package tests additionally rejected blocking vulnerabilities, expired exceptions, scanner failures, failed tests, invalid provenance, absent signatures, wrong workflow identities, artifact and evidence hash mismatches, missing and wrong-version Cosign, malformed references, duplicates, traversal, symlinks, non-regular files, oversized content, unknown fields, and trailing JSON.

## Observed local gates

| Check | Command | Observed result |
| --- | --- | --- |
| Release policy | `make release-policy-test` | Exit 0; complete fixture eligible and all negative fixtures rejected with expected codes. |
| Host verification | `make verify` | Exit 0; format, vet, uncached tests, race tests, and static build passed. |
| Restricted container | `make container-smoke` | Exit 0 as numeric user `65532:65532`. |
| Layered scanners | `REPORT_DIR=.local/security-reports/m05 EVALUATION_TIME=2026-07-21T12:30:00Z make security-scan` | Exit 0; 8 reports completed, 1 finding, 0 blocking, 1 exact accepted exception. |
| Scanner fixtures | `make security-fixtures` | Exit 0; each isolated defect rejected by its intended scanner. |
| Workflow semantics | `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/*.yml` | Exit 0. |
| Workflow security | Run digest-pinned zizmor 1.27.0 in offline, strict-collection, regular-persona mode | Exit 0; no reportable findings. |
| Source-path safety | `go test -count=1 ./internal/releasepolicy ./cmd/releaseverify` | Exit 0; path, schema, hash, tool, and policy tests passed. |

The accepted Gosec `G204` finding is limited to `internal/releasepolicy/cosign.go`: the executable is the literal `cosign`, no shell is used, and `--` terminates options. Policy exception `release-cosign-argv-g204` expires on 2026-10-19 and cannot match another scanner, rule, or file.

The live advisory gate used govulncheck database update `2026-07-08T17:05:00Z` and Trivy database update `2026-07-21T01:08:43Z`.

## Workflow isolation evidence

The `build` job runs tests, scanners, and M03 generation without OIDC. Only the protected no-checkout `sign` job has `id-token: write`; it signs and verifies the three bounded blobs. The dependent `policy` job has no OIDC, checks out the verifier, assembles the rooted evidence tree, and evaluates the complete release policy. No job deploys or publishes an artifact.

## Remaining hosted gate

The branch has not been pushed. No real eligible decision, Fulcio certificate, Rekor entry, embedded SCT, Sigstore bundle, hosted attestation, or successful hosted `cosign verify-blob` output is claimed. After an authorized default-branch run, record its workflow URL, source SHA, artifact digest, bundle hashes, certificate identity, Rekor entries, and final decision hash.
