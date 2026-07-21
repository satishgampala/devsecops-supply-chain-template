# M03 Local Verification Evidence

- **Recorded:** 2026-07-21T11:18:08Z
- **Implementation revision:** `46663d2ff3252afc29046d9b48537e2bab3353c8`
- **Branch:** `feat/m03-sbom-provenance`
- **Result:** Local M03 gate passed; GitHub-hosted artifact attestations remain pending.

## Immutable subject and evidence hashes

| Evidence | SHA-256 |
| --- | --- |
| OCI manifest subject | `c3119bf025a06578bb974c9a08611d72af6a45d40e292c25210043c660816837` |
| OCI archive | `3257a9e465b7e39c1bb2c5471cab8b2228f23fe5d89ae9f420e3df987ca10738` |
| Raw SPDX 2.3 | `c7ce34109605ede12ac3c84856eec738a727e3b1036a687f5fe1547dfb1a251a` |
| Canonical SPDX projection | `e1d32e4db2b0f72e6c5b9f4b47397b976c0ce0b4b668a70a407de49699a42675` |
| Local SLSA provenance | `cb10b40bca5f4d800c4465ea086cc639090f3cba9966988685315d6867f450ed` |
| Verification result | `e73e76d3973dd393da822ab34cc819e0d2a318b0b3e767bf2636fc7e7efe38bb` |

The OCI parser, SPDX root package, and local provenance subject independently resolved to `sha256:c3119bf025a06578bb974c9a08611d72af6a45d40e292c25210043c660816837`. The provenance source and invocation bind revision `46663d2ff3252afc29046d9b48537e2bab3353c8`.

## Observed local gates

| Check | Command | Observed result |
| --- | --- | --- |
| Integrity generation | `make integrity` | Exit 0; OCI, raw/canonical SPDX, local provenance, verification, tooling, and checksums generated. |
| Reproducibility | `make integrity-repro` | Exit 0; two OCI archives, canonical SBOM projections, local statements, and tooling files were byte-identical. |
| Host verification | `make verify` | Exit 0; format, vet, uncached tests, race tests, and static build passed. |
| Negative integrity tests | `go test -count=1 ./internal/integrity` | Exit 0; malformed, wrong-platform, missing, duplicate, oversized, wrong-identity, and tampered cases were rejected. |
| Restricted container | `make container-smoke` | Exit 0 as numeric user `65532:65532`. |
| Layered scanners | `REPORT_DIR=.local/security-reports/m03 EVALUATION_TIME=2026-07-21T11:30:00Z make security-scan` | Exit 0; 8 reports completed, 0 failed, 0 findings, 0 exceptions, decision eligible. |
| Workflow semantics | `GOTOOLCHAIN=go1.26.5 go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/*.yml` | Exit 0. |
| Workflow security | Run digest-pinned zizmor 1.27.0 in offline, strict-collection, regular-persona mode | Exit 0; no reportable findings. |

The live advisory gate used govulncheck database update `2026-07-08T17:05:00Z` and Trivy database update `2026-07-21T01:08:43Z`. Advisory results can change after those timestamps.

## Rejected evidence classes

Tests prove rejection of a changed layer, wrong platform, absent manifest, duplicate index, oversized layer, malformed or trailing JSON, duplicate SPDX package IDs, wrong image checksum, missing Go runtime, wrong provenance predicate, wrong subject, changed source, changed builder, and changed invocation ID.

## Remaining hosted gate

The branch has not been pushed. No GitHub OIDC certificate, platform provenance bundle, platform SPDX bundle, artifact URL, or hosted verification result is claimed. After an authorized default-branch run, append its workflow URL, commit, subject digest, attestation URLs, and identity-verification result.
