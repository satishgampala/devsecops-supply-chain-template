# M02 Local Verification Evidence

- **Recorded:** 2026-07-21T07:21:44Z
- **Implementation revision:** `646df50`
- **Branch:** `feat/m02-security-scanning`
- **Policy version:** `2026-07-21`
- **Result:** Local M02 gate passed; GitHub-hosted CodeQL and scanner execution remain pending.

## Clean-state verification

| Check | Command | Observed result |
| --- | --- | --- |
| Integrated host gate | `make verify` | Exit 0; formatting, vet, uncached unit tests, race tests, and static build passed. |
| Report and policy tests | `make security-test` | Exit 0; strict parsing, normalization, stable encoding, scanner-state, severity, license, exception, and reason-code tests passed. |
| Live scanner gate | `make security-scan` | Exit 0; 8 required reports completed, 0 failed, 0 findings, 0 exceptions, decision eligible. |
| Restricted container smoke | `make container-smoke` | Exit 0 as numeric user `65532:65532`. |
| Workflow semantics | `GOTOOLCHAIN=go1.26.5 go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/*.yml` | Exit 0. |
| Workflow security | Run digest-pinned zizmor 1.27.0 in offline, strict-collection, regular-persona mode | Exit 0; no reportable findings. |

The live run evaluated at `2026-07-21T07:21:18Z`. govulncheck used database update `2026-07-08T17:05:00Z`. Trivy used database update `2026-07-21T01:08:43Z`. Live advisory results can change after these timestamps.

## Seeded-defect verification

`make security-fixtures` exited 0 only after every isolated scanner command returned its expected nonzero status and emitted its expected rule:

| Control | Seed | Expected evidence |
| --- | --- | --- |
| Gosec | World-writable file mode | `G302` |
| govulncheck | Reachable `golang.org/x/text` 0.3.5 call | `GO-2021-0113` |
| Gitleaks | Non-credential `M02_CANARY` token | `m02-synthetic-canary` |
| zizmor | Untrusted issue-title interpolation in a shell step | `zizmor/template-injection` |
| OSV-Scanner | Vulnerable `golang.org/x/text` dependency | `CVE-2022-32149` |
| Trivy configuration | Mutable base and root-user Dockerfile | `DS-0001` and related findings |
| Trivy license | Restricted package license | `GPL-3.0-only` |
| Trivy image | Digest-pinned end-of-life Alpine 3.7 image | At least one high or critical vulnerability rule |

Fixtures live only under `testdata/security/`, are excluded from clean scans and normal builds, contain no usable credential, and are not executed as application code.

## Deterministic policy failures

Package tests separately proved these stable rejection paths without relying on current advisory data:

- missing required scanner;
- scanner execution failure;
- malformed or duplicate report;
- medium, high, or critical blocking finding;
- unapproved or prohibited license;
- invalid wildcard exception;
- exact active exception acceptance; and
- expired exception rejection.

## Remaining remote gate

The branch has not been pushed and no pull request exists. No GitHub-hosted CodeQL result, scanner artifact, code-scanning entry, scheduled scan, or required-check behavior is claimed. Append the workflow URL, commit SHA, artifact digest, and observed permissions after an authorized push and successful hosted run.
