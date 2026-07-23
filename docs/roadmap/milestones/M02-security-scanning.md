# M02 - Source, Dependency, IaC, and Container Scanning

- **Status:** Not Started
- **Depends on:** M01
- **Implementation plan:** Not written; planned after the dependency milestone.

## Outcome

Layered security checks find seeded defects, produce reviewable reports, and enforce a documented severity and exception policy without hiding tool provenance.

## Scope and non-goals

This milestone covers code, dependency, secret, IaC, container, and license scanning. It does not treat scanner output as proof that the application is vulnerability-free.

## Deliverables

- Versioned finding, severity, exception, and scanner-failure policy.
- Layered source, dependency, secret, IaC, container, and license checks.
- Normalized reports and seeded positive and negative scanner tests.

## Tasks and subtasks

- [ ] **T1: Define finding policy and ownership.**
  - [ ] Define blocking severities, allowed reasons, exception owner, expiry, and review cadence.
  - [ ] Distinguish tool failure, database failure, no findings, and accepted findings.
  - [ ] Require scanner name, rule, artifact, location, severity, and remediation in normalized summaries.
- [ ] **T2: Add source and secret scanning.**
  - [ ] Configure CodeQL or Semgrep for the selected language.
  - [ ] Add a secret scanner with a safe synthetic canary used only in an isolated negative test fixture.
  - [ ] Verify ignored paths are narrow and documented.
- [ ] **T3: Add dependency and license checks.**
  - [ ] Scan application and build dependencies against current advisories.
  - [ ] Enforce the approved license policy with explicit exceptions.
  - [ ] Prove a seeded vulnerable dependency produces the expected failure.
- [ ] **T4: Add IaC and container checks.**
  - [ ] Scan workflow, Dockerfile, and any deployment example with Checkov or equivalent controls.
  - [ ] Use Trivy for container vulnerabilities, misconfiguration, and secrets.
  - [ ] Prove seeded Dockerfile and image defects fail before release.

## Verification and evidence

- Run each scanner on the clean state and its isolated seeded-defect fixture.
- Required future scan aggregate must fail if a scanner crashes, a blocking finding exists, or an exception is expired.
- Retain sanitized reports, seeded-defect failure output, clean-state results, tool versions, and policy configuration under `docs/roadmap/evidence/M02/`.

## Exit criteria

- [ ] Clean source, dependencies, IaC, and container satisfy the documented gate.
- [ ] Each scanner has at least one safe negative test that proves the gate can fail.
- [ ] Exceptions require owner, reason, scope, and expiry.
- [ ] Reports preserve scanner provenance and are available as CI artifacts.

## Risks and controls

- **Risk:** Scanner databases make results nondeterministic. **Control:** Record database timestamps and separate policy regression fixtures from live advisory scans.
- **Risk:** Synthetic secret tests trigger real revocation systems. **Control:** Use documented non-secret canaries and isolated fixture paths.
