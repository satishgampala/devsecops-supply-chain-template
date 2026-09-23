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

## Remaining work

Initializer case handling, CI consolidation, consumer CI, portfolio documentation, and final integrated validation remain pending under the [implementation plan](../../implementation-plans/2026-09-23-portfolio-hardening.md).

Hosted execution remains blocked by the observed GitHub account billing lock. Repository protections and publication remain separate, unverified remote gates.
