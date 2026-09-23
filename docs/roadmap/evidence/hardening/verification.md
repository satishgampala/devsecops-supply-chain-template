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

## Remaining work

Artifact/test/scan binding, complete evidence authentication, scanner identity/freshness enforcement, initializer case handling, coordinated version maintenance, CI consolidation, consumer CI, portfolio documentation, and final integrated validation remain pending under the [implementation plan](../../implementation-plans/2026-09-23-portfolio-hardening.md).

Hosted execution remains blocked by the observed GitHub account billing lock. Repository protections and publication remain separate, unverified remote gates.
