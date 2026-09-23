# Reusable Validation Workflow Reference

`.github/workflows/reusable-validation.yml` uses `workflow_call`. It checks out and executes the caller repository, so the caller must retain the complete Make and policy contracts.

## Interface

| Type | Contract |
| --- | --- |
| Inputs and secrets | None. Do not pass `secrets: inherit`. |
| Permission | `contents: read` for checkout; no OIDC or write permission. |
| Output | `subject-digest`: the immutable OCI manifest digest tested and scanned by candidate validation. |

The caller in `ci.yml` runs on pull requests, pushes to `main`, a weekly schedule, and manual dispatch. `security.yml` retains independent CodeQL analysis. `template-self-test.yml` exercises actual consumer initialization rather than calling the same validation workflow again.

## Jobs

| Job | Commands | Evidence |
| --- | --- | --- |
| `candidate` | `make candidate` | One OCI archive, SPDX, local provenance, runtime identity, tests, scanner reports and decisions, checksums; retained for 14 days. |
| `contracts` | `make security-test signing-test release-policy-test` | Positive and negative scanner, identity, evidence, and tamper fixtures. Synthetic signatures are test-only. |
| `lint` | `make workflow-check docs-check` | All-workflow Actionlint, local Markdown links and fragments, Mermaid rendering. |

These jobs are independent and all must pass. Candidate validation runs `verify`, scanner rejection fixtures, integrity generation, restricted runtime tests, and live scans. It builds one release image and binds runtime and scanner evidence to that image and source commit. The candidate job explicitly installs Docker 29.5.2 with the containerd image store so imported OCI manifest digests remain addressable.

All jobs use ephemeral `ubuntu-24.04` runners, immutable action references, `persist-credentials: false`, the Go toolchain in `go.mod`, bounded timeouts, and job-level `contents: read`. Complete Git history is available for secret scanning. Changing a required Make target changes the caller's security contract and requires equivalent review.

## Failure and signing boundaries

Any required command failure fails the workflow call. Candidate evidence uploads with `always()` so available failed-run reports remain diagnosable; a missing evidence directory fails upload. The subject is exported only after candidate validation succeeds. Callers must depend on the successful workflow result, not merely the presence of an output or uploaded artifact.

This workflow does not sign or publish. Repository-specific keyless signing stays in `signing.yml`, with exact repository, certificate, workflow, ref, SHA, trigger, and artifact constraints. Shared signing would introduce another repository trust relationship that the current policy does not accept. Successful hosted same-repository and external-consumer execution remains unverified until recorded.
