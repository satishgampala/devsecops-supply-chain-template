# DevSecOps Supply-Chain Template

An open-source reference implementation for taking a deliberately small Go service through a progressively hardened software-supply-chain workflow. The six-milestone roadmap separates the pipeline baseline from later scanning, SBOM, provenance, signing, and release-policy work so that each control can be verified with evidence.

> **Current state:** M01 — Reference Service and Pipeline Baseline is **In Progress**. [Local verification evidence](docs/roadmap/evidence/M01/verification.md) is recorded; the first GitHub-hosted run remains pending. Security scanning, SBOM generation, provenance, signing, and release eligibility are planned for M02–M05 and are not implemented by M01.

## Project outcome

The completed template is intended to produce a tested, scanned, SBOM-described, provenance-attested, signed, and policy-verified release artifact. M01 establishes only the small reference service, deterministic tests, hardened container design, least-privilege CI foundation, and documentation needed by those later controls.

## Explore the architecture

- [Architecture guide](docs/architecture/README.md)
- [C4 system context](docs/architecture/c4-context.md)
- [C4 container view](docs/architecture/c4-containers.md)
- [Pipeline flow and planned controls](docs/architecture/pipeline-flow.md)
- [ADR 0001: Use a Go reference service](docs/decisions/0001-use-go-reference-service.md)
- [Roadmap](docs/roadmap/ROADMAP.md) and [current status](docs/roadmap/STATUS.md)

## Prerequisites

- Go 1.26.5
- GNU Make
- Docker with BuildKit for the container-only commands
- `curl` for manual endpoint checks

The host-side verification path does not require Docker, cloud credentials, a paid registry, or a cluster.

## Quick start

Run the host-side M01 checks:

```sh
make verify
```

Start the reference service in a second terminal:

```sh
go run ./cmd/service
```

Check health:

```sh
curl --fail --silent --show-error \
  http://127.0.0.1:8080/healthz
```

Expected response:

```json
{"status":"ok"}
```

Generate a deterministic SHA-256 digest:

```sh
curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  --data '{"value":"supply-chain"}' \
  http://127.0.0.1:8080/v1/digest
```

Expected response:

```json
{"algorithm":"sha256","digest":"3f412634a4ea9da04b558d0e32b0062a692e41a1c1d10f0c5c707f14440392ce"}
```

The API accepts values up to 1 KiB in JSON request bodies capped at 4 KiB. It is a supply-chain demonstration workload, not a production business service.

## Make commands

| Command | Purpose | Docker required |
| --- | --- | --- |
| `make fmt` | Format Go source. | No |
| `make fmt-check` | Fail if Go source is not formatted. | No |
| `make vet` | Run Go static analysis. | No |
| `make test` | Run uncached unit tests. | No |
| `make test-race` | Run tests with the race detector. | No |
| `make build` | Build the static service binary. | No |
| `make verify` | Run every host-side M01 check. | No |
| `make container-build` | Build the local scratch-based image. | Yes |
| `make container-smoke` | Exercise the hardened container and both endpoints. | Yes |

## M01 security design

The M01 contract is intentionally narrow:

- standard-library HTTP service with no third-party runtime packages;
- bounded JSON input, explicit server timeouts, response security headers, and graceful shutdown;
- deterministic endpoint behavior and host-side unit, race, static-analysis, and build checks;
- digest-pinned Go builder and a `scratch` runtime using numeric user `65532:65532`;
- explicit read-only GitHub Actions permissions and immutable action references; and
- no repository secrets or privileged release behavior in pull-request validation.

These properties remain milestone requirements until the fresh verification gate is completed and evidence is recorded.

## Current limitations

- No source, dependency, secret, IaC, container, or license scanner is part of M01; those controls are planned for M02.
- No SBOM or SLSA provenance is generated; those controls are planned for M03.
- No artifact or attestation is signed; keyless signing is planned for M04.
- No release-eligibility decision or deployment gate exists; that policy is planned for M05.
- The future OCI registry shown in the context diagram is not used by M01.
- No successful GitHub Actions run or completed M01 verification is claimed here.

## Roadmap

| Milestone | Status | Outcome |
| --- | --- | --- |
| [M01 — Pipeline baseline](docs/roadmap/milestones/M01-pipeline-baseline.md) | In Progress | Minimal service, deterministic tests, hardened container, and least-privilege CI foundation. |
| [M02 — Security scanning](docs/roadmap/milestones/M02-security-scanning.md) | Not Started | Layered source, dependency, secret, IaC, container, and license checks. |
| [M03 — SBOM and provenance](docs/roadmap/milestones/M03-sbom-provenance.md) | Not Started | Artifact-bound component inventory and build provenance. |
| [M04 — Signing](docs/roadmap/milestones/M04-signing.md) | Not Started | Keyless signing with strict workflow-identity verification. |
| [M05 — Release policy](docs/roadmap/milestones/M05-release-policy.md) | Not Started | Explainable deployment-eligibility decisions bound to immutable artifacts. |
| [M06 — Template release](docs/roadmap/milestones/M06-template-release.md) | Not Started | Clean consumer adoption, demonstration, and versioned release. |

Do not mark a task or milestone complete until its documented verification command has run and the observed result has been recorded.
