# Portfolio Hardening Implementation Plan

This corrective plan follows M01–M06. The reference service remains deliberately small. Local implementation, hosted enforcement, and public release evidence remain separate completion criteria.

## Milestones

1. **Scanner reliability (M02):** reject failed SARIF invocations and scanner errors, prevent stale report reuse, preserve advisory metadata, and define unknown-severity behavior. Verify positive, finding, failed, malformed, stale-output, and metadata scenarios.
2. **Artifact and evidence binding (M03–M05):** build one release candidate, test and scan that candidate, authenticate a complete evidence manifest, and reject report substitution even when hashes are recalculated. Verify source, artifact, policy, scanner, timestamp, and signature bindings with negative tests.
3. **Adoption and maintenance (M06):** reconcile initializer identity validation, coordinate toolchain versions, consolidate workflows, run actual consumer initialization in CI, and enforce workflow/documentation checks. Verify a detached consumer and deliberate identity/version drift.
4. **Portfolio demonstration:** present the problem, architecture, tradeoffs, reproducible demo, measured results, and verified evidence clearly. Correct required-check guidance and document observed hosted blockers.
5. **Complete validation:** run host, race, workflow, container, scanner fixtures, live scans, reproducibility, signing, release-policy, consumer, Markdown, Mermaid, and secret checks. Record commands and outcomes against the final revision.

## Release boundary

Commits are authorized. Pushes, pull requests, repository-setting changes, tags, and releases require explicit owner direction. The observed GitHub billing lock must be resolved by the account owner before hosted validation can run. No local fixture or green unit test substitutes for real hosted signatures, applied repository protections, or independently verified release assets.

## Handoff state

- Completed corrective commit: scanner reliability (`86e70f7`); the live gate still found vulnerable toolchain code and ignored-worktree contamination.
- Verified: coordinated toolchain maintenance and isolated source inputs; live scanner gate and clean-fixture reproducibility pass.
- Working: artifact/evidence binding.
- Pending: remaining artifact/evidence binding, adoption/maintenance, portfolio demonstration, complete validation.
- External: hosted execution, repository protections, and publication.
