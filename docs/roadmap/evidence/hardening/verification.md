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

## Remaining work

Artifact/test/scan binding, complete evidence authentication, scanner identity/freshness enforcement, initializer case handling, CI consolidation, consumer CI, portfolio documentation, and final integrated validation remain pending under the [implementation plan](../../implementation-plans/2026-09-23-portfolio-hardening.md).

Hosted execution remains blocked by the observed GitHub account billing lock. Repository protections and publication remain separate, unverified remote gates.
