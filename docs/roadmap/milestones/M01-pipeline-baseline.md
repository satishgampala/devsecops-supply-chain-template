# M01 - Reference Service and Pipeline Baseline

- **Status:** In Progress
- **Depends on:** None
- **Implementation plan:** [2026-07-21 M01 Pipeline Baseline](../implementation-plans/2026-07-21-M01-pipeline-baseline.md)

## Outcome

A deliberately small service has reproducible local tests, a minimal container, and a least-privilege GitHub Actions baseline that can be reused by later security stages.

## Scope and non-goals

This milestone establishes source, tests, container build, CI permissions, and workflow conventions. It does not add security scanners or publish releases.

## Deliverables

- Deliberately small tested reference service and pinned runtime decision.
- Minimal non-root container with build and smoke tests.
- Least-privilege, immutably pinned GitHub Actions baseline.

## Tasks and subtasks

- [ ] **T1: Select and define the reference service.**
  - [ ] Compare Python and Go for dependency footprint, test clarity, image size, and architecture clarity.
  - [ ] Record the language decision and choose one health endpoint plus one deterministic business endpoint.
  - [ ] Define supported runtime and dependency versions.
- [ ] **T2: Implement test-first application behavior.**
  - [ ] Add unit tests for valid requests, invalid input, and health behavior.
  - [ ] Add formatting, linting, type or static checks appropriate to the selected language.
  - [ ] Make local test output deterministic and free of network dependencies.
- [ ] **T3: Build the minimal container.**
  - [ ] Use a pinned base image by digest and a non-root runtime user.
  - [ ] Exclude build tools, source control metadata, caches, and credentials from the runtime image.
  - [ ] Add container health and smoke tests.
- [ ] **T4: Establish the CI trust boundary.**
  - [ ] Set explicit workflow permissions and grant write capabilities only to release jobs that require them.
  - [ ] Pin third-party actions to immutable commit SHAs with documented source versions.
  - [ ] Separate untrusted pull-request checks from protected release behavior.

## Verification and evidence

- Required future commands: local test, lint/static check, container build, container smoke test, and workflow syntax validation.
- Inspect effective workflow permissions and runtime container user.
- Retain decision record, test output, image metadata, workflow-permission review, and commit SHA under `docs/roadmap/evidence/M01/`.

## Exit criteria

- [ ] A fresh clone can test and build the service without cloud credentials.
- [ ] The container runs as non-root and passes its health check.
- [ ] Pull-request workflows have read-only permissions unless a documented check requires more.
- [ ] Third-party actions and base images are immutably pinned.

## Risks and controls

- **Risk:** Application complexity consumes project effort. **Control:** Reject features unrelated to demonstrating the supply chain.
- **Risk:** Pinned dependencies become stale. **Control:** Add automated update proposals but retain human review and verification.
