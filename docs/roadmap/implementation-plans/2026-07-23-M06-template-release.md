# M06 Reusable Template and Release Operations Implementation Plan

> **Execution note:** Implement this plan task by task and use the checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the locally verified control set into a safely initialized repository template with a secret-free reusable validation workflow, clean adoption tests, complete public-project operations, architecture and threat documentation, and a reproducible release procedure.

**Architecture:** A `workflow_call` entry point runs the caller repository's mandatory Make contract with read-only contents access and no inherited secrets or OIDC. A fail-closed initializer rewrites the repository, module, artifact, service, provenance, and signing identities, then recalculates dependent policy hashes. Clean-room tests initialize a detached copy, verify every identity change, exercise the complete local control set, and seed one expected failure. Repository-specific keyless signing remains outside the reusable workflow so its Fulcio identity can be exact.

**Tech stack:** GitHub Actions reusable workflows, Go 1.26.5, POSIX shell, Docker BuildKit, Cosign 3.1.2, OpenSSF Scorecard Action 2.4.3, Mermaid C4, NIST SSDF 1.1, SLSA 1.2, Apache License 2.0.

## Global constraints

- Work on `feat/m06-template-release`; do not implement directly on `main`.
- Keep every reusable-workflow action pinned to a full commit SHA.
- Grant no secret, write, or OIDC access to the reusable validation workflow.
- Do not make signing identity configurable at run time; initialize it in versioned policy before execution.
- Reject malformed repository, module, artifact, and service identities before editing.
- Require a clean tracked tree before initialization and replace only exact template identities.
- Recalculate signing-policy and release-policy digest relationships after initialization.
- Test adoption in a detached temporary repository with no `.git`, `.local`, `dist`, or host credential state copied.
- Keep local synthetic signatures explicitly separate from real hosted keyless evidence.
- Do not publish a branch, workflow run, tag, package, or release without repository-owner authorization.

## Immutable external references

| Dependency | Reference |
| --- | --- |
| OpenSSF Scorecard Action | `ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a` (`v2.4.3`) |
| GitHub Actions reusable workflow contract | `workflow_call`; caller permissions can only be maintained or reduced |
| NIST SSDF | SP 800-218 version 1.1 |
| SLSA | Specification version 1.2; no level claimed without independent assessment |
| License | Apache License 2.0 |

## Task 1: Add the reusable validation boundary

**Files:**

- Create: `.github/workflows/reusable-validation.yml`
- Create: `.github/workflows/template-self-test.yml`
- Update: `.github/workflows/signing.yml`
- Update: `Makefile`

- [x] Expose a `workflow_call` workflow with documented outputs and no secrets or variable command inputs.
- [x] Run host, race, container, scanner-fixture, live scanner, integrity, signing-policy, and release-policy checks against caller-controlled source.
- [x] Keep every job on ephemeral GitHub-hosted runners with top-level deny-all and job-level `contents: read`.
- [x] Upload explicit scanner and integrity evidence with bounded retention.
- [x] Add a same-repository caller that grants only `contents: read`.
- [x] Fix the signing workflow to build the container before its smoke test.

## Task 2: Implement deterministic template initialization

**Files:**

- Create: `scripts/initialize-template.sh`
- Create: `scripts/template-fixtures.sh`
- Update: `Makefile`
- Create: `docs/guides/adoption.md`
- Create: `docs/reference/reusable-workflow.md`

- [x] Validate repository, Go module, OCI artifact, and service-name arguments before any write.
- [x] Require a clean tracked tree and an exact uninitialized template identity.
- [x] Replace code imports, policies, workflows, scripts, tests, and active documentation using exact values only.
- [x] Recalculate signing-policy SHA-256 in the release policy and verify all old executable identities are absent.
- [x] Prove a clean initialized copy passes host tests and policy fixtures.
- [x] Prove malformed input and a seeded source defect fail with expected nonzero results.

## Task 3: Complete public-project security and operations

**Files:**

- Create: `LICENSE`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `.github/CODEOWNERS`
- Create: `.github/ISSUE_TEMPLATE/bug-report.yml`
- Create: `.github/ISSUE_TEMPLATE/config.yml`
- Create: `.github/workflows/scorecard.yml`
- Update: `.github/dependabot.yml`
- Create: `docs/operations/release-runbook.md`
- Create: `docs/operations/security-exceptions.md`

- [x] Add Apache-2.0 licensing and concise contribution, conduct, vulnerability-reporting, and ownership policies.
- [x] Document protected-branch, code-owner, dependency-update, exception, and incident expectations without claiming remote settings exist.
- [x] Add the official immutable Scorecard workflow with isolated write and OIDC permissions.
- [x] Preserve grouped weekly Go, Docker, and Actions updates with delayed version adoption.
- [x] Define a tag-to-evidence release procedure, rollback criteria, and post-release verification.

## Task 4: Publish architecture, threat, and control documentation

**Files:**

- Update: `docs/architecture/c4-context.md`
- Update: `docs/architecture/c4-containers.md`
- Update: `docs/architecture/README.md`
- Create: `docs/security/devsecops-supply-chain-template-threat-model.md`
- Create: `docs/compliance/control-mapping.md`
- Create: `docs/demo/release-walkthrough.md`

- [x] Refresh C4 context and container views for runtime, validation, signing, policy, registry, and consumer boundaries.
- [x] Model runtime and CI/build threats separately with concrete path evidence, attacker capabilities, abuse paths, mitigations, and residual risk.
- [x] Map implemented controls to NIST SSDF 1.1 practices and SLSA 1.2 concepts without claiming certification or a SLSA level.
- [x] Provide one successful local evidence flow and one rejected-tamper flow.

## Task 5: Verify and document M06

**Files:**

- Update: `README.md`
- Update: `docs/roadmap/milestones/M06-template-release.md`
- Update: `docs/roadmap/ROADMAP.md`
- Update: `docs/roadmap/STATUS.md`
- Create: `docs/roadmap/evidence/M06/verification.md`

- [ ] Run initialization, clean-consumer, host, race, container, scanner, integrity, policy, Actionlint, zizmor, link, Mermaid, secret, and public-content gates.
- [ ] Review every workflow trigger, permission, action pin, expression, artifact boundary, and untrusted-code path.
- [ ] Record exact local evidence, clean-copy revision, expected negative result, and remote limitations.
- [ ] Mark M06 implemented locally while hosted workflows, repository rules, Scorecard result, tag, and public release remain pending.

## Completion gate

M06 is locally complete when a detached copy can be initialized with new exact identities, the reusable validation contract and same-repository caller pass static security validation, clean and seeded-negative adoption scenarios behave as documented, project operations and threat documentation are complete, and all local gates pass. Project publication remains incomplete until the owner authorizes a push and the hosted default-branch workflows, repository rules, Scorecard analysis, signed evidence, immutable tag, and public release are independently observed.
