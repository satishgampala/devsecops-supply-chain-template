# M06 Local Verification Evidence

- **Recorded:** 2026-07-23T07:02:02Z
- **Implementation revision:** `3a062c74f44710b4c9a127ff48869db99a0e56c8`
- **Branch:** `feat/m06-template-release`
- **Result:** Reusable validation, deterministic initialization, clean-consumer, governance, architecture, operations, and local security gates passed; hosted publication remains pending.

## Template identities

| Property | Template value | Initialized consumer value |
| --- | --- | --- |
| Repository | `satishgampala/devsecops-supply-chain-template` | `example-org/secure-service` |
| Go module | `github.com/satishgampala/devsecops-supply-chain-template` | `github.com/example-org/secure-service` |
| OCI artifact | `ghcr.io/satishgampala/devsecops-supply-chain-template` | `ghcr.io/example-org/secure-service` |
| Service | `devsecops-supply-chain-template` | `secure-service` |
| Code owner | `@satishgampala` | `@example-org/security` |
| OCI subject | `sha256:c3119bf025a06578bb974c9a08611d72af6a45d40e292c25210043c660816837` | `sha256:56f4b98755c18c0d26c941ad64e5271cf9cc59450479461307efad8af22a3105` |

The fixture copied tracked working files into a new temporary Git repository, initialized exact identities, committed the initialized state, and ran its local gates without copying `.git`, `.local`, `dist`, or host credential state.

## Clean-consumer and negative gates

| Scenario | Observed result |
| --- | --- |
| Invalid repository identity | Initialization exited nonzero and changed no files. |
| Valid detached initialization | Exact code, workflow, policy, documentation, and ownership identities changed; dependent policy hashes were recalculated. |
| Initialized host verification | Formatting, vet, uncached tests, race tests, and static build passed. |
| Initialized signing policy | Exact identity, context, artifact, and negative fixtures passed. |
| Initialized release policy | Complete synthetic evidence was eligible; negative fixtures were ineligible. |
| Initialized integrity generation | OCI, SPDX 2.3, provenance, and digest linkage passed for the consumer subject. |
| Seeded malformed Go source | `make verify` exited nonzero as required. |

The synthetic eligible decision uses the test-only Cosign substitute. It proves evaluator composition, not cryptographic authenticity or release authorization.

## Release-policy fixture decisions

| Scenario | Eligibility | Reason codes | Decision SHA-256 |
| --- | --- | --- | --- |
| Complete synthetic evidence | Eligible | None | `dad33dd15847175ff4ccfbb8dd9b14f8b5d9b22818c8a6fcf461587880e78f67` |
| Missing SPDX evidence | Ineligible | `SBOM_MISSING`, `SIGNATURE_MISSING` | `a04e6e2a44dd92d62c69501dee1314a9914d12819aba22197d930aec2ca803e4` |
| Release-policy digest mismatch | Ineligible | `POLICY_DIGEST_MISMATCH` | `0e1c8d92cddec72a3f4ba97763948f87c416b704a8a70a85482e53c385603f4f` |
| Invalid signature | Ineligible | `SIGNATURE_INVALID` | `f92e0bc6842421c3d51f2cb7c7bc83c9c3c0433878b84631bbc4f1d16383d0ca` |
| Evaluation-time mismatch | Ineligible | `EVALUATION_TIME_MISMATCH` | `2e7ad4c2bb274095c254e99998cd70acbaa1e2040d2dc1fed1cc65b2113c999d` |

## Observed local gates

| Check | Command | Observed result |
| --- | --- | --- |
| Integrated host gate | `make verify` | Exit 0; formatting, vet, uncached tests, race tests, and static build passed. |
| Container build and smoke | `make container-build && make container-smoke` | Exit 0; health and digest endpoints passed as numeric user `65532:65532`. |
| Scanner fixtures | `make security-fixtures` | Exit 0; every isolated defect was rejected by its intended scanner. |
| Live scanner gate | `REPORT_DIR=.local/security-reports/m06 EVALUATION_TIME=2026-07-23T06:53:59Z make security-scan` | Exit 0; 8 reports completed, 2 findings, 0 blocking findings, and 1 exact accepted exception. |
| Integrity reproducibility | `make integrity-repro` | Exit 0; both OCI archives, canonical SPDX projections, local provenance statements, and tooling records matched. |
| Signing policy | `make signing-test` | Exit 0; positive and negative identity fixtures passed. |
| Release policy | `make release-policy-test` | Exit 0; complete evidence was eligible and expected negative cases were rejected. |
| Clean-consumer adoption | `make template-test` | Exit 0; initialization and positive and seeded-negative consumer checks passed. |
| Workflow semantics | `GOTOOLCHAIN=go1.26.5 go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/*.yml` | Exit 0. |
| Workflow security | Run digest-pinned zizmor 1.27.0 in offline, strict-collection, regular-persona mode | Exit 0; no reportable findings. |
| Configuration syntax | Parse Dependabot and issue-form YAML with Ruby safe loading | Exit 0. |
| Documentation | Resolve local Markdown links and render every Mermaid block with Mermaid CLI 11.12.0 | 4 diagrams rendered; all local links resolved. |
| Repository content | Scan for secret, attribution, and audience-targeting markers; run `git diff --check` | Exit 0; no prohibited marker or whitespace error found. |

The accepted Gosec `G204` finding remains limited to `internal/releasepolicy/cosign.go`. Policy exception `release-cosign-argv-g204` is exact, owned, justified, and expires on 2026-10-19. The live advisory gate used govulncheck database update `2026-07-22T20:36:55Z` and Trivy database update `2026-07-23T01:07:10Z`.

## Workflow boundary review

The reusable workflow has top-level `permissions: {}`, grants only job-level `contents: read`, defines no inputs or secrets, and has no OIDC permission. Its same-repository caller grants only `contents: read`. Repository-specific signing remains in the protected signing workflow, where only the no-checkout signing job receives `id-token: write`. All action references are immutable commit SHAs, artifacts use explicit paths and bounded retention, and untrusted pull-request code cannot reach a write or signing credential.

## Remaining remote gates

No branch was pushed. No GitHub-hosted reusable-workflow call, repository-rule result, Scorecard result, Fulcio certificate, Rekor entry, embedded SCT, real Cosign bundle, registry artifact, immutable tag, or versioned release is claimed. After owner authorization, record hosted run URLs, source SHA, artifact digest, signing identity, bundle hashes, Scorecard result, repository-rule behavior, tag, and release URL.
