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

- [x] **T1: Select and define the reference service.**
  - [x] Compare Python and Go for dependency footprint, test clarity, image size, and architecture clarity.
  - [x] Record the language decision and choose one health endpoint plus one deterministic business endpoint.
  - [x] Define supported runtime and dependency versions.
- [x] **T2: Implement test-first application behavior.**
  - [x] Add unit tests for valid requests, invalid input, and health behavior.
  - [x] Add formatting, linting, type or static checks appropriate to the selected language.
  - [x] Make local test output deterministic and free of network dependencies.
- [x] **T3: Build the minimal container.**
  - [x] Use a pinned base image by digest and a non-root runtime user.
  - [x] Exclude build tools, source control metadata, caches, and credentials from the runtime image.
  - [x] Add container health and smoke tests.
- [x] **T4: Establish the CI trust boundary.**
  - [x] Set explicit workflow permissions and grant write capabilities only to release jobs that require them.
  - [x] Pin third-party actions to immutable commit SHAs with documented source versions.
  - [x] Separate untrusted pull-request checks from protected release behavior.

## Verification and evidence

- [Local verification evidence](../evidence/M01/verification.md) records the host, container, workflow, documentation, and manual-review gates.
- A GitHub-hosted workflow run and repository-settings review remain pending.

## Exit criteria

- [x] A fresh clone can test and build the service without cloud credentials.
- [x] The container runs as non-root and passes its health check.
- [x] Pull-request workflows have read-only permissions unless a documented check requires more.
- [x] Third-party actions and base images are immutably pinned.
- [ ] The workflow passes on a GitHub-hosted pull-request run and the run is recorded as evidence.

## Risks and controls

- **Risk:** Application complexity consumes project effort. **Control:** Reject features unrelated to demonstrating the supply chain.
- **Risk:** Pinned dependencies become stale. **Control:** Add automated update proposals but retain human review and verification.
