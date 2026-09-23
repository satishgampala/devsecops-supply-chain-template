# Corrective Hardening Verification

## Scanner reliability — 2026-09-23

Scope: working tree on `fix/supply-chain-hardening`, following baseline commit `4803990`.

- `make security-test`: passed package tests and execution fixtures. Failed SARIF invocations, error notifications, malformed timestamps, stale output, missing output, invalid SARIF, ambiguous error exit codes, and Gosec processing errors are rejected. Database timestamps survive the CLI.
- `make verify`: passed formatting, vet, uncached tests, race tests, and static service build.
- Actionlint 1.7.7 on `ci.yml` and 1.7.12 on all seven workflows: passed. The older version does not support `artifact-metadata`; the maintenance milestone will align the documented version.
- `make container-build` and `make container-smoke`: passed with user `65532:65532`, health and digest endpoints, read-only filesystem, no capabilities, no new privileges, and PID limit 100.
- Mermaid CLI 11.12.0: rendered all six repository diagrams. Local Markdown file links, shell syntax, and high-confidence secret patterns in tracked/proposed files: passed.
- Live eight-scanner gate: **rejected**, with all eight scanners completed, 22 findings, 17 blocking findings, and one existing accepted exception. Reasons: `blocking_finding`, `prohibited_license`. Reports are retained locally in `.local/security-reports/hardening/`.

The live scan detected vulnerable Go 1.26.5 standard-library code and scanned seeded defects inside an ignored nested worktree. Toolchain updates and controlled source snapshots remain required; no new scanner exception was added. This is evidence that the scanner gate rejects the current inputs, not evidence that the repository is ready for release.

## Toolchain and source isolation — 2026-09-23

Scope: corrective working tree following `86e70f7`.

- Updated Go to 1.26.8 and the official multi-platform builder digest `sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d`, checked against the upstream registry. Actions and shell runners derive their version from `go.mod`; drift fixtures reject mismatched Docker, release-policy, and workflow pins.
- `make verify`, Actionlint 1.7.7 on `ci.yml` and 1.7.12 on all workflows, container build/smoke, shell syntax, local Markdown links, and high-confidence secret checks passed. The six existing Mermaid diagrams were unchanged from the preceding successful render.
- Maintenance fixtures verify modified tracked files and new filenames containing spaces enter snapshots; ignored output, an ignored nested worktree, and `.git` do not. Formatting ignores those same ignored trees. Existing snapshot directories and symlinks are rejected.
- Live gate at `.local/security-reports/toolchain-update/`: **eligible**, eight completed scanners, zero failed scanners, two findings, zero blocking findings, and the one pre-existing exception. Gosec processed 23 files with no processing errors. Trivy no longer suppresses unfixed high/critical image vulnerabilities.
- The first snapshot scan exposed an unshared macOS temporary directory and correctly failed the gate. Bind-mounted source snapshots now reside under ignored `.local/` within the shared checkout; the successful rerun used that path.
- A clean temporary Git repository containing the proposed changes passed `make integrity-repro`: the OCI archive, canonical SBOM, provenance, and tooling matched across two builds. Subject: `sha256:a1f15e9a8fb114258059b80b8d6b8171b90127777be50c6ad913e33149f6c520`. A false `SOURCE_DIGEST` was rejected before building. The builder and verifier compile from the committed archive; evidence path validation remains rooted at the checkout.

These checks prove source isolation and coordinated toolchain behavior. They do not yet prove that the release workflow signs the exact candidate tested by its earlier stages.

## Authenticated validation evidence — 2026-09-23

Scope: corrective working tree following `317fba9`.

- The new regression first demonstrated that rewritten test evidence with a recalculated manifest hash was accepted by the previous verifier.
- The signing policy now requires a fourth blob, `validation-evidence.json`. Its signed content covers every pre-signing manifest field, including test and scanner hashes, source and subject identities, policy digests, evaluation time, and trigger. The signer still has no checkout; the builder has no OIDC permission. Signing checkout now fetches complete history for Gitleaks.
- Unit regressions reject changed test references, laundered blocking findings, rewritten validation statements, and mismatched triggers. The positive fixture requires four independent signature-verifier calls.
- A clean temporary Git repository passed `make release-policy-test` and `make signing-test`. CLI decisions were: clean `eligible: true`; rehashed tests `VALIDATION_EVIDENCE_MISMATCH`; rewritten signed statement `SIGNATURE_INVALID`. The test-only Cosign substitute freezes accepted hashes outside the evidence directory. It models byte binding and does not prove real Sigstore cryptography.
- `make verify`, both documented/current Actionlint checks, container build/smoke, shell syntax, local Markdown links, and high-confidence secret checks passed. Existing Mermaid diagrams were unchanged.
- Live eight-scanner gate passed at `.local/security-reports/validation-binding/`, with zero blocking findings and the pre-existing accepted exception.

Real hosted signatures remain unverified. Exact candidate test/scan binding and scanner identity/freshness validation remain the next controls.

## Candidate identity and scanner freshness — 2026-09-23

Scope: corrective working tree following `131b389`.

- A clean temporary Git repository passed `make candidate`: host/race/build checks, all eight seeded scanner controls, one release OCI build, restricted runtime smoke tests by manifest digest, and all eight live scanners. The image digest observed by the container matched the archive and every report: `sha256:a1f15e9a8fb114258059b80b8d6b8171b90127777be50c6ad913e33149f6c520`. The live gate recorded eight completed scanners, two findings, zero blocking findings, and one pre-existing exception.
- Trivy 0.72.0 does not accept an OCI tar directly. The runner imports the verified archive, exports its immutable digest through Docker, independently verifies that the export retains the original OCI manifest, and mounts that export read-only for scanning. No release scan or smoke stage rebuilds the image. Docker 29.5.2 with the containerd image store was used locally and is explicitly configured in the signing workflow.
- The OCI verifier now derives architecture and OS from the hashed config, rejects a conflicting config, and accepts an omitted optional index platform field as emitted by Docker export.
- Scanner references have one source in `policy/release-v1.json`. Normalized reports retain source commit, candidate digest, scan time, and database time. Release policy rejects mismatched references, sources, and subjects; missing/stale/future scan and required database timestamps; and test summaries from another image. Tests cover the exact 24-hour report and 336-hour database boundaries, with five-minute clock-skew tolerance.
- The live govulncheck database timestamp was `2026-09-16T18:00:43Z`; Trivy recorded `2026-09-23T01:09:35.013781075Z`. Both survived normalization. A clean CLI release-policy fixture passed with the new bindings and retained tamper rejection. Its signature boundary remains a test double.
- Final `make verify security-test`, Actionlint 1.7.7 on `ci.yml` and 1.7.12 on all workflows, development container build/smoke, shell syntax, local Markdown links, and high-confidence secret checks passed. Existing Mermaid diagrams were unchanged.
- Source-selection fixtures additionally cover unstaged tracked-file deletions and reject formatting through symlinks. Seeded scanner runs clear previous SARIF output before invocation.

## Adoption and CI maintenance — 2026-09-23

Scope: corrective working tree following `090fa07`.

- A regression reproduced mixed-case repository rejection. Signing policy now accepts valid uppercase characters while retaining exact, case-sensitive identity comparisons. Lowercase `example-org/secure-service` and mixed-case `ExampleOrg/Secure-Service` consumers both pass initialization, host/race checks, signing contracts, release fixtures, and deliberate invalid-identity/source rejection. OCI artifact names remain lowercase.
- `ci.yml` calls reusable candidate validation once; the duplicate Security scanner job is removed, while independent CodeQL remains. Reusable jobs cover candidate evidence, policy rejection contracts, and workflow/documentation checks. The consumer workflow now runs `make template-test`. Adopted repositories use that target to validate current contracts without reinitialization.
- `make workflow-check` passes Actionlint 1.7.12 across all seven workflows. Offline zizmor 1.27.0 reports zero findings. Workflow permissions remain explicit; PR jobs receive no OIDC or secrets. Docker 29.5.2 with the containerd image store is configured where digest-addressable runtime checks are required.
- `make docs-check` uses registry-verified immutable Lychee 0.24.2 and Mermaid CLI 11.12.0 images. Local links/fragments and diagram rendering pass; temporary broken-link and invalid-Mermaid probes each cause nonzero failure. External URLs are intentionally excluded. Required-check guidance no longer requires the default-branch-only Scorecard job on PRs.
- `make verify security-test`, development container build/smoke, shell syntax, proposed-source Gitleaks scan, and whitespace checks pass. Consumer evidence remains under ignored `.local/template-fixtures.CohLeU/`.

## Final integrated validation — 2026-09-23

Executable and documentation revision: `81702be919a0e1ec5ccb9af773fbba879199ea89`. The final follow-up commit records verification only; it changes no executable, workflow, or policy. A [machine-readable local record](local-results.json) contains the measured artifact, environment, checks, and explicit signature limitation.

| Check | Observed result |
| --- | --- |
| `make candidate` | Passed host checks, race tests, all eight seeded scanner controls, one OCI build, restricted runtime by digest, and eight live scanners. |
| `make workflow-check docs-check security-test signing-test` | Passed all seven workflow files, local links/fragments, all five Mermaid diagrams, scanner execution fixtures, and signing contracts. |
| `make template-test` | Lowercase and mixed-case detached consumers passed; each exercised the adopted-repository target. Invalid identity and seeded Go source were rejected. |
| `make integrity-repro` | OCI archive, canonical SBOM, local provenance, tooling, and subject matched across two clean builds. |
| `make release-policy-test` | Synthetic positive and all CLI tamper scenarios passed; signatures remain explicit test substitutes. |
| `make container-build container-smoke` | Development image passed both endpoints and runtime restrictions. |
| Shell syntax, secret checks, `git diff --check` | Passed. Gitleaks checked history during the live gate and proposed source separately. |

The real candidate's scan decision was evaluated at `2026-09-23T04:39:04Z`: eight completed scanners, zero failed scanners, two findings, zero blocking findings, and one accepted exception. The findings were the governed Gosec G204 subprocess warning and a low-severity Apache-2.0 license notice. No new exception was added. The G204 exception expires `2026-10-19`.

All eight reports and the test summary named source `81702be919a0e1ec5ccb9af773fbba879199ea89`. Those reports, the test summary, and the observed running container shared subject `sha256:a1f15e9a8fb114258059b80b8d6b8171b90127777be50c6ad913e33149f6c520`. Scan start was `2026-09-23T04:38:24Z`. Govulncheck recorded database time `2026-09-16T18:00:43Z`; Trivy recorded `2026-09-23T01:09:35.013781075Z`.

The OCI tar was **2,881,536 bytes**, SHA-256 `647b5ee7a1880711f12fcda2063fa24b57930478407d789bf53f966be91d687b`. Direct layer inspection found only `/service`, a **6,725,758-byte** binary owned by `65532:65532`. Image config retained that user, `/service` entrypoint, and the executable health check. Candidate validation took **87.52 seconds** on Darwin arm64 with Docker server 29.5.2/containerd, warm caches, and concurrent consumer checks. This single observation is not a benchmark or hosted-runtime prediction.

An additional local integration reused the real candidate archive, actual runtime test summary, and live scanner reports through both collector phases and the release verifier. Only the signature boundary was replaced with the existing frozen-hash test double. The unmodified evidence was eligible; rehashed tests failed `VALIDATION_EVIDENCE_MISMATCH`; rewritten validation bytes failed `SIGNATURE_INVALID`. This closes the local producer/verifier integration check without claiming hosted cryptography.

Candidate outputs are retained locally under `.local/final-candidate-81702be/`; integrated evidence and decisions under `.local/final-live-contract/`; command logs under `.local/verification/81702be/`. These ignored paths are local diagnostics, not public release assets. Later synthetic fixture commands regenerate `dist/`, so the preserved candidate directory is the authoritative local snapshot for this record.

## External gates

All authorized local corrective milestones and portfolio documentation are implemented and verified. Hosted execution remains blocked by the observed GitHub account billing lock. Real signatures/attestations, applied repository protections, hosted consumer calls, tags, and publication remain unverified and outside this local completion claim. No push, pull request, settings change, tag, or release was performed.
