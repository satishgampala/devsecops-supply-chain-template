# M01 Local Verification Evidence

- **Recorded:** 2026-07-21T06:31:58Z
- **Implementation revision:** `a587098`
- **Branch:** `feat/m01-pipeline-baseline`
- **Host toolchain:** `go1.26.5 darwin/arm64`
- **Container engine:** Docker client `24.0.7`, server `28.1.1`
- **Result:** Local M01 gate passed; GitHub-hosted execution remains pending.

## Host verification

| Check | Command | Observed result |
| --- | --- | --- |
| Integrated host gate | `make verify` | Exit 0; formatting, `go vet`, uncached unit tests, race tests, and static build passed. |
| Clean-checkout gate | Clone the local repository into a new temporary directory, then run `make verify` | Exit 0 at `a587098` without cloud credentials. |
| Reproducible binary | Build twice with the documented static build flags, then compare with `cmp` | Byte-identical; SHA-256 `93e78a82dde341864bdb9bd9ed0e57cc5761c017317dd50765f1fbe1ed107af0`. |
| Process lifecycle | Start on an operating-system-assigned port, wait for health, send `SIGTERM`, and wait | Service became healthy, logged shutdown, and exited 0. |

The unit suite covers deterministic success responses, invalid and oversized input, unsupported methods and media types, security headers, port validation, server timeouts, and health-check failure modes.

## Container verification

| Check | Command | Observed result |
| --- | --- | --- |
| Dockerfile validation | `docker build --check .` | Exit 0 with no warnings. |
| Image build | `make container-build` | Exit 0 using the digest-pinned Go builder and `scratch` runtime. |
| Runtime smoke | `make container-smoke` | Exit 0; health and digest endpoints passed as user `65532:65532`. |
| Image metadata | Review build output and run `docker image inspect devsecops-supply-chain-template:local` | Platform manifest `sha256:1104d1ff6f250ea24b011cfc375b045801752a28cee9b05fe96e0ccccfbded08`; config `sha256:a598226a705be6cf25fd4992ddf01b81d5b14ead5270ee4f3ac81f8d5c128091`; 2,609,490 bytes; one runtime layer; entrypoint `/service`; in-binary health check. |
| Restricted runtime | Create and inspect a temporary container with the smoke-test restrictions | Read-only root filesystem, all capabilities dropped, `no-new-privileges`, PID limit 100, numeric non-root user; temporary container removed. |

The static service binary is reproducible under the documented build flags. The local BuildKit manifest-list digest is not presented as reproducible because generated attestation metadata can change between builds even when the runtime binary and image contents are unchanged.

## Workflow and repository verification

| Check | Command or review | Observed result |
| --- | --- | --- |
| Workflow syntax and semantics | `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/ci.yml` | Exit 0. |
| Dependency automation YAML | Parse `.github/dependabot.yml` with Ruby safe YAML loading | Exit 0. |
| Workflow trust boundary | Inspect triggers, runner, permissions, action references, and secret usage | Top-level permissions are empty; jobs receive `contents: read`; only unprivileged triggers and GitHub-hosted runners are used; actions are pinned to full commit SHAs; no secret context is used. |
| Secret-pattern review | Scan tracked and untracked project files, excluding Git metadata and ignored local evidence | No private-key markers, high-confidence provider tokens, secret assignments, or environment-secret files found. |
| Documentation | Render all Mermaid sources with Mermaid CLI 11.16.0, visually review the images, validate local links, and scan placeholders | Render and visual review passed; local links resolved; no placeholders remained. |
| Commit integrity | Inspect reachable commits and repository text | Commits use the configured maintainer identity and current dates; no automated attribution markers or audience-specific positioning language found. |

## Remaining remote gate

The branch has not been pushed and no pull request exists, so there is no GitHub-hosted workflow run to cite. M01 is **Implemented Locally**; remote verification remains pending until the workflow passes on GitHub and its run URL and commit SHA are appended here. Later milestone evidence is recorded in its corresponding evidence directory.
