# M02 Security Scanning Implementation Plan

> **Execution note:** Implement this plan task by task and use the checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add layered source, dependency, secret, infrastructure, container, and license checks whose outputs are normalized and enforced by a deterministic policy gate.

**Architecture:** GitHub Actions runs CodeQL and digest-pinned scanner containers against the checked-out source and locally built image. Scanner-native SARIF remains available for inspection while a small Go normalizer converts results into a stable repository-owned contract. A separate gate evaluates required scanner state, finding severity, license policy, and time-bounded exceptions. Isolated fixtures prove both clean and expected-failure paths without placing usable credentials in the repository.

**Tech stack:** Go 1.26.5, GitHub CodeQL, Gitleaks 8.30.1, OSV-Scanner 2.4.0, Trivy 0.72.0, SARIF 2.1.0, Docker, GitHub Actions.

## Global constraints

- Work on `feat/m02-security-scanning`; do not implement directly on `main`.
- Keep scanner execution unprivileged and free of repository secrets.
- Pin every GitHub Action to a full commit SHA and every scanner container to a multi-platform image digest.
- Preserve native reports; normalized reports augment rather than replace scanner evidence.
- Treat missing output, malformed output, scanner execution failure, expired vulnerability data, and blocking findings as distinct states.
- Do not suppress findings inline. Exceptions live in the versioned policy and require owner, reason, exact scope, and expiry.
- Keep synthetic secrets isolated under `testdata/security/` and use only public, documented non-credential examples.
- Separate deterministic policy fixtures from live advisory-database results.
- Do not claim a hosted scan has run until GitHub-hosted evidence exists.

## Immutable tool references

| Tool | Reference |
| --- | --- |
| CodeQL Action | `7188fc363630916deb702c7fdcf4e481b751f97a` (`codeql-bundle-v2.26.1`) |
| Gitleaks | `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` (`v8.30.1`) |
| OSV-Scanner | `ghcr.io/google/osv-scanner@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475` (`v2.4.0`) |
| Trivy | `docker.io/aquasec/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f` (`v0.72.0`) |
| Artifact upload | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (`v7.0.1`) |

## Shared contracts

### Normalized scanner report

Each report is one JSON document with:

- schema version;
- scanner name and immutable version/reference;
- execution state: `completed`, `failed`, or `not_run`;
- advisory-database timestamp when the scanner exposes one;
- zero or more findings containing scanner, rule, artifact, location, severity, message, and remediation;
- an optional diagnostic for scanner failures that contains no environment dump or credential data.

Severities normalize to `unknown`, `note`, `low`, `medium`, `high`, or `critical`.

### Gate result

The gate writes a stable JSON decision with `eligible`, sorted reason codes, scanner counts, finding counts, accepted-exception identifiers, and policy version. It exits nonzero when the decision is ineligible.

Stable M02 reason codes are:

- `required_scanner_missing`;
- `scanner_failed`;
- `blocking_finding`;
- `prohibited_license`;
- `exception_invalid`;
- `exception_expired`;
- `report_invalid`.

## Task 1: Version the security policy and report model

**Files:**

- Create: `policy/security-policy.json`
- Create: `internal/securityreport/model.go`
- Create: `internal/securityreport/policy.go`
- Create: `internal/securityreport/policy_test.go`

- [ ] Define required scanner names and the blocking threshold.
- [ ] Define approved and prohibited SPDX license identifiers.
- [ ] Parse exceptions strictly and reject unknown fields, empty ownership fields, broad scopes, malformed dates, and duplicate IDs.
- [ ] Evaluate expiry against an injected clock so tests remain deterministic.
- [ ] Sort all findings and reason codes before serialization.

## Task 2: Normalize SARIF without losing provenance

**Files:**

- Create: `cmd/sarif-normalizer/main.go`
- Create: `internal/securityreport/sarif.go`
- Create: `internal/securityreport/sarif_test.go`
- Create: `testdata/security/sarif/clean.sarif`
- Create: `testdata/security/sarif/blocking.sarif`
- Create: `testdata/security/sarif/malformed.sarif`

- [ ] Parse the SARIF 2.1.0 fields emitted by the selected scanners.
- [ ] Resolve result severity from `level`, security-severity properties, and rule metadata in a documented order.
- [ ] Preserve rule identifier, artifact URI, start line, message, help URI/remediation, scanner name, and scanner reference.
- [ ] Fail closed on malformed or unsupported input.
- [ ] Prove byte-stable normalized output for identical input.

## Task 3: Enforce the aggregate security gate

**Files:**

- Create: `cmd/security-gate/main.go`
- Create: `internal/securityreport/gate.go`
- Create: `internal/securityreport/gate_test.go`
- Create: `testdata/security/reports/**`

- [ ] Accept an explicit policy path, report paths, evaluation time, and output path.
- [ ] Reject missing required scanners, duplicate scanner reports, malformed reports, tool failure, blocking severity, prohibited license, and invalid or expired exceptions.
- [ ] Accept only exact, unexpired exceptions and include their IDs in the result.
- [ ] Add deterministic clean, blocking, scanner-failure, missing-scanner, prohibited-license, accepted-exception, and expired-exception cases.
- [ ] Verify every reason code and exit status.

## Task 4: Add live scanner orchestration and safe fixtures

**Files:**

- Create: `scripts/security-scan.sh`
- Create: `.gitleaks.toml`
- Create: `testdata/security/secrets/**`
- Create: `testdata/security/dependencies/**`
- Create: `testdata/security/iac/**`
- Update: `.gitignore`
- Update: `Makefile`

- [ ] Run Gitleaks, OSV-Scanner, and Trivy through digest-pinned containers with a read-only source mount and a writable report directory only.
- [ ] Build and scan the local application image without registry credentials.
- [ ] Record each scanner's immutable reference and execution state even when it exits nonzero.
- [ ] Add an isolated public synthetic-secret fixture, a known-vulnerable dependency fixture, and an intentionally insecure Dockerfile fixture.
- [ ] Add `make security-test`, `make security-scan`, and `make security-fixtures` targets.
- [ ] Confirm the clean repository passes and every seeded fixture fails for its expected scanner/rule.

## Task 5: Add least-privilege hosted scanning

**Files:**

- Create: `.github/workflows/security.yml`
- Update: `.github/dependabot.yml`

- [ ] Run CodeQL for Go with manual build steps and `security-extended` queries.
- [ ] Run the digest-pinned scanner orchestration for source and image checks.
- [ ] Normalize scanner outputs and apply the aggregate policy gate.
- [ ] Upload native and normalized reports with a bounded retention period even when the gate fails.
- [ ] Give only the CodeQL upload job `security-events: write`; keep all other jobs at `contents: read`.
- [ ] Avoid privileged pull-request triggers, mutable action references, untrusted expression interpolation in shell, and credential persistence.

## Task 6: Verify and document M02

**Files:**

- Update: `README.md`
- Update: `docs/architecture/pipeline-flow.md`
- Update: `docs/roadmap/milestones/M02-security-scanning.md`
- Update: `docs/roadmap/ROADMAP.md`
- Update: `docs/roadmap/STATUS.md`
- Create: `docs/security/scanning.md`
- Create: `docs/roadmap/evidence/M02/verification.md`

- [ ] Run unit, race, formatting, vet, actionlint, container, and live clean scan checks.
- [ ] Run every isolated negative fixture and record its expected nonzero result without committing generated reports.
- [ ] Verify action pins, workflow permissions, safe expression use, local links, and tracked-file secret patterns.
- [ ] Document policy interpretation, exception review, report locations, scanner database variability, and local commands.
- [ ] Mark local M02 implementation complete while keeping GitHub-hosted execution explicitly pending.

## Completion gate

M02 is locally complete only when:

1. source, dependency, secret, infrastructure, container, and license controls run on the clean repository;
2. deterministic policy tests prove missing, failed, blocking, prohibited, invalid-exception, and expired-exception paths;
3. every safe seeded defect is detected by its intended scanner;
4. normalized and native reports retain scanner provenance;
5. the full M01 verification gate still passes; and
6. evidence records exact commands, observed results, and any hosted checks that remain pending.
