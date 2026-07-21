# M04 Local Verification Evidence

- **Recorded:** 2026-07-21T11:29:36Z
- **Implementation revision:** `11a7ad41c267db2f17b8ef89a6f20a6b7d0fc687`
- **Branch:** `feat/m04-keyless-signing`
- **Cosign contract:** `v3.1.2` (`193d2153431f8bb0d945a4c1ee721872f73add67`)
- **Result:** Local identity and signing-context gates passed; hosted keyless signing remains pending.

## Policy decisions

| Fixture | Eligibility | Required result | Decision SHA-256 |
| --- | --- | --- | --- |
| Exact identity and artifact set | Eligible | No reason codes | `1b95c3b3dc82d4ca3ca5bd14619ca280547cd9091cdbac0b612b311e71147746` |
| Pull-request trigger | Ineligible | `WORKFLOW_TRIGGER_DENIED` | `6b4bbfdd828e4ee482ed6c8fdf86ade17647001cef2707b046b023d3a8838594` |
| Cryptographic verification absent | Ineligible | `CRYPTOGRAPHIC_VERIFICATION_FAILED` | `6b55fefc97f699d9b234d87dded83e8c82d3aa532c00f26a9a4aa6a8e85ed2a8` |
| Wrong certificate identity | Ineligible | `CERTIFICATE_IDENTITY_MISMATCH` | `6b80862a0d8d35ca4f700a603e227ddad078e599377c10dfeb4fc8d94f5223b7` |
| Malformed artifact digest | Ineligible | `ARTIFACT_DIGEST_INVALID` | `49d11fd9eae0861fb66b8eba421828ec63fc5379977201c01860a667912eb3b9` |

Package tests additionally rejected wrong issuer, repository, workflow name, ref, workflow SHA, feature context, bundle digest, artifact role, duplicate role, missing transparency log, missing SCT, unknown fields, trailing JSON, oversized input, wildcard identity, and unapproved policy triggers.

## Observed local gates

| Check | Command | Observed result |
| --- | --- | --- |
| Signing policy | `make signing-test` | Exit 0; exact fixture eligible and all negative fixtures rejected with expected codes. |
| Host verification | `make verify` | Exit 0; format, vet, uncached tests, race tests, and static build passed. |
| Restricted container | `make container-smoke` | Exit 0 as numeric user `65532:65532`. |
| Layered scanners | `REPORT_DIR=.local/security-reports/m04 EVALUATION_TIME=2026-07-21T11:45:00Z make security-scan` | Exit 0; 8 reports completed, 0 failed, 0 findings, 0 exceptions. |
| Workflow semantics | `GOTOOLCHAIN=go1.26.5 go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/*.yml` | Exit 0. |
| Workflow security | Run digest-pinned zizmor 1.27.0 in offline, strict-collection, regular-persona mode | Exit 0; no reportable findings. |
| Private-key path audit | Search tracked paths for Cosign keys, common SSH keys, PEM, PKCS#12, and generic key files | No matching tracked path. |
| Complete-history secret scan | Included in the M04 Gitleaks gate | 26 commits scanned; no leaks found. |

The live advisory gate used govulncheck database update `2026-07-08T17:05:00Z` and Trivy database update `2026-07-21T01:08:43Z`.

## Workflow isolation evidence

Only `sign` declares `id-token: write`. That job depends on `build`, is gated to `refs/heads/main` and approved triggers, downloads the explicit build artifact, and has no checkout step. The `build` and `policy` jobs have no OIDC permission. Cosign verification supplies every exact certificate and GitHub workflow flag and uses no `insecure-ignore` option.

## Remaining hosted gate

The branch has not been pushed. No Fulcio certificate, Rekor log entry, embedded SCT, Sigstore bundle, public signature, or successful hosted `cosign verify-blob` result is claimed. After an authorized default-branch run, append its workflow URL, commit SHA, bundle hashes, certificate identity, Rekor entries, and exact verification output.
