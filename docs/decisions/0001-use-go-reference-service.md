# ADR 0001: Use a Go Reference Service

- **Status:** Accepted
- **Date:** 2026-07-21
- **Decision owners:** Project maintainers
- **Applies to:** M01 reference service

## Context

The repository needs a workload that makes software-supply-chain controls concrete without turning application development into the project. The service must support deterministic tests, a minimal non-root container, understandable CI, and later scanner, SBOM, provenance, signing, and policy demonstrations.

Go and Python were considered because both are familiar to cloud and DevSecOps reviewers and can express the two required HTTP endpoints clearly.

## Options considered

| Decision factor | Go | Python |
| --- | --- | --- |
| Dependency footprint | HTTP server, JSON handling, hashing, testing, and shutdown behavior are available in the standard library; no third-party runtime package is required. | The standard library can serve HTTP, but a production-oriented framework/server commonly adds package and transitive-dependency decisions. |
| Deterministic static build | Produces one statically linked, cross-compilable executable with explicit reproducibility flags. | Ships source plus an interpreter and installed packages; reproducing the complete runtime requires more packaging inputs. |
| Test clarity | `httptest` and table-driven tests keep request/response contracts close to the implementation. | `unittest` is clear, though framework choices may introduce additional fixtures and conventions. |
| Runtime image size | A static binary can run directly in `scratch`, leaving no shell or package manager. | Requires a Python runtime and its supporting files, so `scratch` is not a practical runtime target. |
| Patching | Toolchain and builder-image patches can be reviewed as explicit version/digest changes; the rebuilt runtime remains only the application binary. | Interpreter, base image, system libraries, and Python package patches can create a wider maintenance surface. |
| Architecture clarity | A small `net/http` service, one binary, and a two-stage Dockerfile expose build and runtime boundaries directly. | The application may be shorter, but framework and environment packaging can distract from the supply-chain controls being verified. |

## Decision

Use Go 1.26.5 for the M01 reference service, with module language version `go 1.26.0` and toolchain directive `toolchain go1.26.5`.

The service is intentionally not feature-rich. It exposes only `GET /healthz`, deterministic `POST /v1/digest`, and an in-binary health-check mode. It uses the Go standard library and introduces no third-party runtime package.

## Consequences

### Positive

- One static binary supports a small `scratch` runtime and a clear build/runtime boundary.
- Standard-library handlers and tests keep the behavior auditable for reviewers who are not application specialists.
- The compact dependency graph leaves later supply-chain controls visible rather than buried in application dependencies.
- Cross-compilation and reproducibility flags can be exercised without a separate packaging tool.

### Trade-offs

- A Go toolchain is required for host-side development and race testing.
- A `scratch` image has no shell, CA bundle, or timezone database; future outbound TLS or timezone requirements would require an explicit runtime-design review.
- This decision optimizes for demonstrating the delivery system, not for evaluating Go as the best language for every production service.

## Validation

Acceptance of this ADR selects the design; it does not prove the implementation. M01 remains In Progress until the documented host, race, container, workflow, and manual-review gates run successfully and their observed results are recorded.
