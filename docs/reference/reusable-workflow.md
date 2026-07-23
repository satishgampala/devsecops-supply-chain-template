# Reusable Validation Workflow Reference

## Location

`.github/workflows/reusable-validation.yml`

The workflow uses `workflow_call`. It checks out and executes the caller repository, not the repository that stores the reusable workflow.

## Interface

| Type | Name | Contract |
| --- | --- | --- |
| Input | None | Commands and security controls cannot be replaced by caller-provided strings. |
| Secret | None | The caller must not use `secrets: inherit`. |
| Permission | `contents: read` | Required for checkout; the called workflow cannot elevate caller permissions. |
| Output | `subject-digest` | Lowercase `sha256:<64 hex>` OCI manifest digest from verified M03 evidence. |

The workflow has no OIDC, package, deployment, release, pull-request-write, or security-event-write permission.

## Required caller Make targets

| Target | Expected behavior |
| --- | --- |
| `verify` | Format check, static analysis, uncached tests, race tests, and deterministic binary build. |
| `container-build` | Build the digest-pinned, non-root runtime image. |
| `container-smoke` | Run health and API checks under read-only, capability-free restrictions. |
| `security-fixtures` | Prove each scanner rejects its isolated seeded defect. |
| `security-scan` | Run the complete normalized scanner policy and write to `REPORT_DIR`. |
| `integrity` | Produce and verify the OCI archive, SPDX, provenance, tooling, and checksums under `dist/`. |
| `signing-test` | Exercise exact signing identity and negative policy scenarios. |
| `release-policy-test` | Exercise complete synthetic release evidence and tamper scenarios. |

Changing a target to skip or soften a gate changes the caller's security contract and must receive the same review as a workflow change.

## Jobs

| Job | Dependencies | Purpose | Retained output |
| --- | --- | --- | --- |
| `validation` | None | Host, race, build, container, health, and endpoint checks. | Check result |
| `security` | None | Scanner fixtures and live eight-scanner policy. | Normalized and source reports for 14 days |
| `integrity` | `validation`, `security` | Artifact-bound OCI, SPDX, and provenance generation. | Explicit integrity evidence for 14 days |
| `policy` | `integrity` | Signing identity and complete release-policy fixtures. | Check result |

All jobs use ephemeral `ubuntu-24.04` runners, immutable action references, `persist-credentials: false`, fixed Go 1.26.5, bounded timeouts, and job-level `contents: read`.

## Failure behavior

Any required command failure prevents dependent jobs and the workflow call from succeeding. Scanner evidence uploads with `always()` so failed policy runs remain diagnosable. Missing integrity files fail artifact upload. The digest output exists only after validation, security, and integrity jobs succeed.

## Signing boundary

This workflow does not sign or publish. Keyless signing remains in the initialized repository's protected `signing.yml`, where the certificate identity, repository, branch, workflow SHA, trigger, and artifact hashes are exact. Moving that job into a shared workflow would introduce `job_workflow_ref` and a second repository trust relationship that the current M04 policy does not accept.
