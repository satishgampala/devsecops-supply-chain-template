# M01 Pipeline Baseline Implementation Plan

> **Execution note:** Implement this plan task by task and use the checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a minimal, reproducible, secure-by-default Go service with deterministic tests, a non-root scratch container, least-privilege GitHub Actions, and reviewable architecture evidence.

**Architecture:** A standard-library `net/http` service exposes health and SHA-256 digest endpoints. The same static binary supplies a bounded container health-check command. GitHub Actions runs unprivileged source and container checks; later milestones will add scanners, SBOMs, provenance, signing, and release policy without changing the M01 trust boundary.

**Tech Stack:** Go 1.26.5, Go standard library, GNU Make, Docker BuildKit, scratch runtime image, GitHub Actions, Mermaid C4 diagrams.

## Global Constraints

- Work on `feat/m01-pipeline-baseline`; do not implement directly on `main`.
- Every Git commit uses its genuine current author and committer date. Never set date environment variables or use `git commit --date`.
- Keep M01 limited to service behavior, tests, containerization, CI foundations, architecture, and adoption documentation. Security scanners and releases begin in later milestones.
- Use module path `github.com/satishgampala/devsecops-supply-chain-template`.
- Pin Go to `1.26.5`; `go.mod` uses `go 1.26.0` and `toolchain go1.26.5`.
- Use no third-party runtime packages.
- Expose `GET /healthz` and deterministic `POST /v1/digest` only.
- Limit request bodies to 4 KiB and digest input values to 1 KiB.
- Configure explicit HTTP server timeouts, `MaxHeaderBytes`, and graceful `SIGINT`/`SIGTERM` shutdown.
- Use the builder image `docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651`.
- Use a `scratch` runtime and numeric non-root identity `65532:65532`.
- Pin `actions/checkout` to `3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`).
- Pin `actions/setup-go` to `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` (`v7.0.0`).
- Set workflow permissions explicitly and do not use `pull_request_target`, `workflow_run`, self-hosted runners, or repository secrets in M01.
- Every task must be independently reviewed. Contributors stay within their assigned workstream; the maintainer verifies and commits coherent slices.

---

## File map and parallel ownership

| Workstream | Exclusive write scope | Responsibility |
| --- | --- | --- |
| Service | `go.mod`, `cmd/service/**`, `internal/httpapi/**` | HTTP behavior, runtime configuration, health-check mode, unit/race tests. |
| Container/tooling | `Dockerfile`, `.dockerignore`, `.gitignore`, `Makefile` | Reproducible static build, scratch runtime, local verification commands. |
| CI automation | `.github/workflows/ci.yml`, `.github/dependabot.yml` | Least-privilege CI and reviewable pin updates. |
| Documentation | `README.md`, `docs/architecture/**`, `docs/decisions/**`, `docs/roadmap/**` except this implementation-plan file | Architecture diagrams, decision record, roadmap migration, user guidance. |

The maintainer owns integration fixes. A contributor must not edit outside an assigned exclusive scope.

## Shared interfaces

### HTTP API

`GET /healthz`

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"ok"}
```

`POST /v1/digest`

```json
{"value":"supply-chain"}
```

```json
{
  "algorithm": "sha256",
  "digest": "<lowercase 64-character hexadecimal SHA-256 digest>"
}
```

Error responses use this stable shape and never echo untrusted input:

```json
{"error":{"code":"invalid_request","message":"request body is invalid"}}
```

Required error codes are `method_not_allowed`, `unsupported_media_type`, `request_too_large`, and `invalid_request`.

### Binary interface

```text
/service                 Start the HTTP server on PORT (default 8080).
/service healthcheck     Probe http://127.0.0.1:${PORT}/healthz with a two-second timeout.
```

An invalid `PORT` must fail before binding. Valid ports are integers from 1 through 65535.

### Make interface

```text
make fmt
make fmt-check
make vet
make test
make test-race
make build
make verify
make container-build
make container-smoke
```

`make verify` runs every host-side M01 check without requiring Docker. Container targets require an available Docker daemon.

---

### Task 1: Test-first HTTP service

**Files:**

- Create: `go.mod`
- Create: `internal/httpapi/handler.go`
- Create: `internal/httpapi/handler_test.go`

**Interfaces:**

- Produces: `httpapi.New() http.Handler`.
- Consumes: only Go standard-library packages.
- Later tasks rely on the exact endpoints and response contracts above.

- [ ] **Step 1: Establish the exact Go module contract.**

  Create `go.mod` with:

  ```go
  module github.com/satishgampala/devsecops-supply-chain-template

  go 1.26.0

  toolchain go1.26.5
  ```

- [ ] **Step 2: Write failing handler tests.**

  Add table-driven `httptest` coverage for:

  - `GET /healthz` returning status 200 and exactly `{"status":"ok"}`.
  - `POST /v1/digest` returning the known SHA-256 digest for `supply-chain`.
  - repeated valid requests producing byte-identical bodies.
  - empty value, value above 1024 bytes, malformed JSON, unknown fields, and trailing JSON.
  - absent or non-JSON content type.
  - body above 4096 bytes.
  - unsupported methods.
  - `Content-Type`, `Cache-Control`, `X-Content-Type-Options`, `Content-Security-Policy`, and `Referrer-Policy` response headers.

- [ ] **Step 3: Run the tests and confirm the expected red state.**

  Run:

  ```sh
  go test ./internal/httpapi
  ```

  Expected: compilation fails because `httpapi.New` is not implemented.

- [ ] **Step 4: Implement the minimum secure handler.**

  `handler.go` must:

  - construct a private `http.ServeMux` rather than use `http.DefaultServeMux`;
  - register method-aware Go 1.22+ routes;
  - apply response security headers centrally;
  - enforce `application/json` with `mime.ParseMediaType`;
  - bound the body with `http.MaxBytesReader` before decoding;
  - call `DisallowUnknownFields` and reject a second JSON value;
  - hash the exact UTF-8 bytes supplied in `value` using `crypto/sha256`;
  - encode JSON using `json.Encoder`;
  - never include the submitted value or decoder internals in an error response.

- [ ] **Step 5: Verify the green state and determinism.**

  Run:

  ```sh
  go test -count=1 ./internal/httpapi
  go test -race -count=1 ./internal/httpapi
  ```

  Expected: all handler and race tests pass.

### Task 2: Server lifecycle and in-binary health check

**Files:**

- Create: `cmd/service/main.go`
- Create: `cmd/service/main_test.go`

**Interfaces:**

- Consumes: `httpapi.New() http.Handler`.
- Produces: `newServer(address string, handler http.Handler) *http.Server`, `parsePort(raw string) (string, error)`, and `runHealthcheck(ctx context.Context, port string) error` for package-local tests.

- [ ] **Step 1: Write failing lifecycle/configuration tests.**

  Test:

  - empty `PORT` resolves to `8080`;
  - `1`, `8080`, and `65535` are accepted;
  - text, zero, negative, and values above 65535 are rejected;
  - `newServer` sets `ReadHeaderTimeout=5s`, `ReadTimeout=10s`, `WriteTimeout=10s`, `IdleTimeout=60s`, and `MaxHeaderBytes=1<<20`;
  - health check succeeds against an `httptest.Server` returning 200;
  - health check fails on non-200 responses, connection errors, and expired context.

- [ ] **Step 2: Confirm the expected red state.**

  Run:

  ```sh
  go test ./cmd/service
  ```

  Expected: compilation fails because the lifecycle helpers are absent.

- [ ] **Step 3: Implement process behavior.**

  `main.go` must:

  - validate `PORT` before starting or probing;
  - use `signal.NotifyContext` for `os.Interrupt` and `syscall.SIGTERM`;
  - start an explicit `http.Server` with the timeouts above;
  - perform shutdown with a fresh ten-second timeout context;
  - treat `http.ErrServerClosed` as normal termination;
  - write operational logs with `log/slog` without request bodies or headers;
  - invoke an `http.Client` with a two-second timeout for `healthcheck`;
  - exit nonzero for invalid configuration, failed health checks, or unexpected server errors.

- [ ] **Step 4: Verify tests and build.**

  Run:

  ```sh
  go test -count=1 ./cmd/service
  go test -race -count=1 ./...
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -o ./bin/service ./cmd/service
  ./bin/service healthcheck
  ```

  Expected: tests/build pass; the final command fails cleanly because no server is running.

### Task 3: Reproducible non-root container and local tooling

**Files:**

- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `.gitignore`
- Create: `Makefile`

**Interfaces:**

- Consumes: `go.mod` and `./cmd/service`.
- Produces: image `devsecops-supply-chain-template:local` and the Make interface above.

- [ ] **Step 1: Add host-side Make targets.**

  `fmt-check` must fail when `gofmt -l` prints any file. `verify` must run formatting check, `go vet ./...`, uncached tests, race tests, and a static build into `bin/service`.

- [ ] **Step 2: Add a minimal build context.**

  `.dockerignore` must exclude at least `.git`, `.github`, `.local`, `bin`, `coverage*`, `*.out`, `.DS_Store`, and Markdown documentation. `.gitignore` must exclude `bin/`, coverage output, editor files, `.DS_Store`, and `.env*` while allowing `.env.example`.

- [ ] **Step 3: Implement the digest-pinned multi-stage Dockerfile.**

  Required structure:

  ```dockerfile
  FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build
  WORKDIR /src
  COPY go.mod ./
  RUN go mod download && go mod verify
  COPY cmd ./cmd
  COPY internal ./internal
  ARG TARGETOS=linux
  ARG TARGETARCH
  RUN --network=none CGO_ENABLED=0 GOTOOLCHAIN=local GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/service ./cmd/service

  FROM scratch
  COPY --from=build --chown=65532:65532 /out/service /service
  USER 65532:65532
  EXPOSE 8080
  HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/service", "healthcheck"]
  ENTRYPOINT ["/service"]
  ```

- [ ] **Step 4: Add container verification targets.**

  `container-build` builds the local image. `container-smoke` starts it bound to `127.0.0.1`, uses `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges=true`, and `--pids-limit 100`, checks `/healthz` and `/v1/digest`, inspects `.Config.User`, and always removes the container with a shell trap.

- [ ] **Step 5: Verify when Docker is available.**

  Run:

  ```sh
  make verify
  make container-build
  make container-smoke
  ```

  Expected: host checks pass; the image reports user `65532:65532`, becomes healthy, and both endpoints return their exact expected output.

### Task 4: Least-privilege GitHub Actions and dependency updates

**Files:**

- Create: `.github/workflows/ci.yml`
- Create: `.github/dependabot.yml`

**Interfaces:**

- Consumes: Make targets from Task 3.
- Produces: independent `go` and `container` CI jobs.

- [ ] **Step 1: Implement the CI trust boundary.**

  `ci.yml` must:

  - trigger on `pull_request`, pushes to `main`, and manual dispatch;
  - set top-level `permissions: {}` and grant only `contents: read` to jobs that check out code;
  - use GitHub-hosted `ubuntu-24.04` runners with ten-minute job timeouts;
  - pin checkout/setup-go to the exact SHAs in Global Constraints and set `persist-credentials: false`;
  - configure setup-go with `go-version: 1.26.5`, `check-latest: false`, and `cache: false`;
  - run `make verify` in the Go job;
  - run `make container-build` and `make container-smoke` in the container job;
  - avoid interpolating event or branch data directly into any `run:` block;
  - use no secrets and no write permissions.

- [ ] **Step 2: Configure reviewable dependency updates.**

  Add weekly Monday 09:00 `Asia/Kolkata` updates for `gomod`, `docker`, and `github-actions`, each rooted at `/`. Group minor/patch updates per ecosystem, limit open version-update PRs to five, and use `deps` commit-message prefixes.

- [ ] **Step 3: Validate workflow and configuration syntax.**

  Run:

  ```sh
  go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/ci.yml
  ruby -e 'require "yaml"; YAML.safe_load_file(".github/dependabot.yml", aliases: true); puts "dependabot yaml ok"'
  ```

  Expected: actionlint reports no findings and Ruby prints `dependabot yaml ok`.

### Task 5: Architecture, decision, and roadmap documentation

**Files:**

- Create: `README.md`
- Create: `docs/architecture/README.md`
- Create: `docs/architecture/c4-context.md`
- Create: `docs/architecture/c4-containers.md`
- Create: `docs/architecture/pipeline-flow.md`
- Create: `docs/decisions/0001-use-go-reference-service.md`
- Create: `docs/roadmap/ROADMAP.md`
- Create: `docs/roadmap/STATUS.md`
- Create: `docs/roadmap/milestones/M01-pipeline-baseline.md`
- Create: `docs/roadmap/milestones/M02-security-scanning.md`
- Create: `docs/roadmap/milestones/M03-sbom-provenance.md`
- Create: `docs/roadmap/milestones/M04-signing.md`
- Create: `docs/roadmap/milestones/M05-release-policy.md`
- Create: `docs/roadmap/milestones/M06-template-release.md`

**Interfaces:**

- Consumes: shared HTTP, binary, Make, and CI interfaces.
- Produces: contributor-facing explanation of exactly what exists now and what remains planned.

- [ ] **Step 1: Record the Go decision.**

  ADR 0001 compares Go and Python for dependency footprint, deterministic static builds, test clarity, image size, patching, and architecture clarity. Select Go 1.26.5 and explicitly note that the service is intentionally not feature-rich.

- [ ] **Step 2: Create focused architecture diagrams.**

  - C4 context: contributor/reviewer, template repository, GitHub Actions, and future OCI registry.
  - C4 container: source/test package, service binary, scratch image, and CI jobs.
  - Flowchart: source change through M01 tests/build/container checks, with M02–M05 controls visibly labeled as planned rather than implemented.

  Keep each diagram under 20 elements, use unidirectional verb-labeled relationships, and provide explanatory prose beside each Mermaid block.

- [ ] **Step 3: Consolidate the roadmap without changing future scope.**

  Make `docs/roadmap/` the authoritative home for the roadmap and six milestone specifications. Adjust internal links, mark M01 `In Progress`, and leave M02–M06 `Not Started`. Do not claim any exit criterion until its verification command has run.

- [ ] **Step 4: Write the README as a task-oriented landing page.**

  Include project outcome, current milestone, architecture links, prerequisites, quick start, exact curl examples, Make command reference, security properties, limitations, and roadmap. Clearly state that SBOM/provenance/signing/release policy are planned and not yet implemented.

- [ ] **Step 5: Validate documentation integrity.**

  Run:

  ```sh
  rg -n 'TBD|TODO|FIXME|SLSA.*implemented|signed release' README.md docs
  ```

  Expected: no placeholders or false claims; any mention of later controls explicitly says planned.

### Task 6: Coordinated integration and evidence gate

**Files:**

- Modify only files requiring integration fixes.
- Create: `docs/roadmap/evidence/M01/verification.md`

**Interfaces:**

- Consumes every M01 workstream.
- Produces evidence for the milestone decision and coherent current-dated commits.

- [ ] **Step 1: Review every workstream diff before accepting it.**

  Confirm exclusive scopes were respected, no unrelated files changed, no secret-like values exist, no mutable action/base-image references exist, and documentation matches implemented behavior.

- [ ] **Step 2: Run the fresh host verification gate.**

  Run:

  ```sh
  make verify
  go test -race -count=1 ./...
  go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/ci.yml
  git diff --check
  ```

  Expected: every command exits zero with no test, race, workflow, or whitespace findings.

- [ ] **Step 3: Run the fresh container gate.**

  Start Docker if needed, then run:

  ```sh
  make container-build
  make container-smoke
  ```

  Expected: build and smoke tests exit zero; the container runs as `65532:65532`, with a read-only filesystem and no Linux capabilities during the smoke test.

- [ ] **Step 4: Perform a manual security review.**

  Trace HTTP input through parsing and hashing, inspect server limits/shutdown, map workflow triggers/permissions/action pins, scan tracked files for secret patterns, and verify that Docker build/runtime stages contain only necessary material.

- [ ] **Step 5: Record evidence without generated noise.**

  Write `verification.md` with UTC timestamp, branch, genuine commit SHA when available, exact commands, exit results, Go/Docker versions, image ID/digest, runtime user, endpoint output, and known limitations. Do not commit raw logs containing machine paths or credentials.

- [ ] **Step 6: Create coherent genuine commits.**

  Suggested current work slices:

  ```text
  docs: add M01 implementation plan
  feat: add deterministic Go reference service
  build: add reproducible non-root container
  ci: add least-privilege validation workflow
  docs: document M01 architecture and roadmap
  test: record M01 verification evidence
  ```

  Create only commits backed by actual changes and fresh verification. Do not target an activity count or alter timestamps.

## Completion criteria

M01 is complete only when:

- a fresh clone can run `make verify` without cloud credentials;
- handler, lifecycle, and race tests pass;
- Docker build and smoke tests pass;
- the runtime is scratch-based and numeric non-root;
- pull-request CI has explicit read-only permissions and immutable action references;
- the builder image is pinned by digest;
- diagrams and documentation distinguish current controls from future milestones;
- verification evidence records the exact commands and observed results;
- every commit reflects genuine current work.
