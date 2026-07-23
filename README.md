# DevSecOps Supply-Chain Template

An open-source reference implementation for taking a deliberately small Go service through a progressively hardened software-supply-chain workflow. The six-milestone roadmap separates the pipeline baseline, layered security scanning, SBOM, provenance, signing, and release policy so each control can be verified with evidence.

> **Current state:** M03 SBOM and provenance is **implemented locally**. The [reproducibility, linkage, and tamper gates](docs/roadmap/evidence/M03/verification.md) pass. GitHub-hosted runs remain pending; signing and release eligibility begin in M04–M05.

## Project outcome

The completed template is intended to produce a tested, scanned, SBOM-described, provenance-attested, signed, and policy-verified release artifact. M01 establishes the service and hardened CI baseline. M02 adds layered security controls with normalized evidence. M03 adds a reproducible OCI archive, SPDX 2.3 inventory, SLSA Provenance v1 statement, and digest-bound verification.

## Explore the architecture

- [Architecture guide](docs/architecture/README.md)
- [C4 system context](docs/architecture/c4-context.md)
- [C4 container view](docs/architecture/c4-containers.md)
- [Pipeline flow and planned controls](docs/architecture/pipeline-flow.md)
- [Security scanning and policy](docs/security/scanning.md)
- [SBOM and provenance](docs/security/sbom-provenance.md)
- [ADR 0001: Use a Go reference service](docs/decisions/0001-use-go-reference-service.md)
- [Roadmap](docs/roadmap/ROADMAP.md) and [current status](docs/roadmap/STATUS.md)

## Prerequisites

- Go 1.26.5
- GNU Make
- Docker with BuildKit for the container-only commands
- `curl` for manual endpoint checks
- Network access for current advisory databases when running live security scans

The host-side verification path does not require Docker, cloud credentials, a paid registry, or a cluster. The live M02 scanner path requires Docker but no registry credentials.

## Quick start

Run the host-side M01 checks:

```sh
make verify
```

Run deterministic M02 policy tests:

```sh
make security-test
```

Run the live clean-state scanner gate:

```sh
make security-scan
```

Generate and verify the M03 integrity evidence from a clean working tree:

```sh
make integrity
```

Build twice and compare the OCI archive, canonical SBOM projection, local provenance, and tooling metadata:

```sh
make integrity-repro
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
| `make security-test` | Test normalized reports, policy, exceptions, and stable failure codes. | No |
| `make security-scan` | Run the complete live M02 scanner gate and retain local reports. | Yes |
| `make security-fixtures` | Prove each local scanner rejects its isolated seeded defect. | Yes |
| `make integrity` | Build the OCI archive and verify its SPDX and local provenance evidence. | Yes |
| `make integrity-repro` | Run two clean generations and compare deterministic outputs. | Yes |

## Current security design

The current contract is intentionally explicit:

- standard-library HTTP service with no third-party runtime packages;
- bounded JSON input, explicit server timeouts, response security headers, and graceful shutdown;
- deterministic endpoint behavior and host-side unit, race, static-analysis, and build checks;
- digest-pinned Go builder and a `scratch` runtime using numeric user `65532:65532`;
- explicit read-only GitHub Actions permissions and immutable action references; and
- CodeQL plus digest- or version-pinned Gosec, govulncheck, Gitleaks, zizmor, OSV-Scanner, and Trivy checks;
- native SARIF, normalized scanner reports, current advisory metadata, and deterministic policy decisions;
- exact, expiring exceptions with no wildcard scope; and
- no repository secrets, Docker socket mount, or privileged release behavior in pull-request scanner jobs;
- a single-platform OCI archive whose index, manifest, config, and layers are independently hashed;
- an SPDX 2.3 inventory generated from the final archive and bound to its manifest digest; and
- explicit local SLSA provenance plus a protected default-branch workflow for platform attestations.

The [M02 scanning guide](docs/security/scanning.md) documents scanner policy. The [M03 integrity guide](docs/security/sbom-provenance.md) documents artifact, SBOM, provenance, and hosted-attestation boundaries.

## Current limitations

- No artifact or attestation is signed; keyless signing is planned for M04.
- No release-eligibility decision or deployment gate exists; that policy is planned for M05.
- The OCI archive and local statements are not published by local commands.
- No successful GitHub Actions, hosted CodeQL, hosted scanner, or hosted attestation run is claimed here.

## Roadmap

| Milestone | Status | Outcome |
| --- | --- | --- |
| [M01 — Pipeline baseline](docs/roadmap/milestones/M01-pipeline-baseline.md) | In Progress | Minimal service, deterministic tests, hardened container, and least-privilege CI foundation. |
| [M02 — Security scanning](docs/roadmap/milestones/M02-security-scanning.md) | Implemented Locally | Layered source, dependency, secret, workflow, IaC, container, and license checks. |
| [M03 — SBOM and provenance](docs/roadmap/milestones/M03-sbom-provenance.md) | Implemented Locally | Artifact-bound component inventory and build provenance. |
| [M04 — Signing](docs/roadmap/milestones/M04-signing.md) | Not Started | Keyless signing with strict workflow-identity verification. |
| [M05 — Release policy](docs/roadmap/milestones/M05-release-policy.md) | Not Started | Explainable deployment-eligibility decisions bound to immutable artifacts. |
| [M06 — Template release](docs/roadmap/milestones/M06-template-release.md) | Not Started | Clean consumer adoption, demonstration, and versioned release. |

Do not mark a task or milestone complete until its documented verification command has run and the observed result has been recorded.
