# M02 - Source, Dependency, IaC, and Container Scanning

- **Status:** Implemented Locally
- **Depends on:** M01
- **Implementation plan:** [2026-07-21 M02 Security Scanning](../implementation-plans/2026-07-21-M02-security-scanning.md)

## Outcome

Layered security checks find seeded defects, produce reviewable reports, and enforce a documented severity and exception policy without hiding tool provenance.

## Scope and non-goals

This milestone covers code, dependency, secret, IaC, container, and license scanning. It does not treat scanner output as proof that the application is vulnerability-free.

## Deliverables

- Versioned finding, severity, exception, and scanner-failure policy.
- Layered source, dependency, secret, IaC, container, and license checks.
- Normalized reports and seeded positive and negative scanner tests.

## Tasks and subtasks

- [x] **T1: Define finding policy and ownership.**
  - [x] Define blocking severities, allowed reasons, exception owner, expiry, and review cadence.
  - [x] Distinguish tool failure, database failure, no findings, and accepted findings.
  - [x] Require scanner name, rule, artifact, location, severity, and remediation in normalized summaries.
- [x] **T2: Add source and secret scanning.**
  - [x] Configure CodeQL and Gosec for Go source analysis.
  - [x] Add a secret scanner with a safe synthetic canary used only in an isolated negative test fixture.
  - [x] Verify ignored paths are narrow and documented.
- [x] **T3: Add dependency and license checks.**
  - [x] Scan application and build dependencies against current advisories.
  - [x] Enforce the approved license policy with explicit exceptions.
  - [x] Prove a seeded vulnerable dependency produces the expected failure.
- [x] **T4: Add IaC and container checks.**
  - [x] Scan workflows and Dockerfiles with dedicated workflow and misconfiguration controls.
  - [x] Use Trivy for container vulnerabilities, misconfiguration, and licenses.
  - [x] Prove seeded Dockerfile and image defects fail before release.

## Verification and evidence

- Run each scanner on the clean state and its isolated seeded-defect fixture.
- Required future scan aggregate must fail if a scanner crashes, a blocking finding exists, or an exception is expired.
- Retain sanitized reports, seeded-defect failure output, clean-state results, tool versions, and policy configuration under `docs/roadmap/evidence/M02/`.

## Exit criteria

- [x] Clean source, dependencies, IaC, and container satisfy the documented local gate.
- [x] Each locally executable scanner has a safe negative test that proves the gate can fail.
- [x] Exceptions require owner, reason, scope, and expiry.
- [x] Workflow configuration retains native and normalized reports as CI artifacts.
- [ ] CodeQL and the complete scanner workflow have passed on GitHub-hosted infrastructure.

## Risks and controls

- **Risk:** Scanner databases make results nondeterministic. **Control:** Record database timestamps and separate policy regression fixtures from live advisory scans.
- **Risk:** Synthetic secret tests trigger real revocation systems. **Control:** Use documented non-secret canaries and isolated fixture paths.
