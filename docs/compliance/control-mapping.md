# Control Mapping

This mapping is an implementation aid, not certification, attestation, or a claim of complete framework conformance. Organizational governance, hosted settings, operating procedures, and independent assessment remain necessary.

## NIST SSDF 1.1

The practice names and identifiers follow [NIST SP 800-218, Secure Software Development Framework 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).

| SSDF practice | Repository implementation | Evidence | Remaining work |
| --- | --- | --- | --- |
| PO.1 — Define security requirements | Versioned scanner, signing, and release policies define required tools, severities, identities, evidence, and tests | `policy/`; `docs/security/` | Validate requirements against each adopter's risk tolerance |
| PO.3 — Implement supporting toolchains | Fixed Go toolchain; layered scanners; BuildKit; Syft; Cosign; Actionlint; zizmor; Dependabot | `Makefile`; `scripts/`; `.github/dependabot.yml` | Operate update review and tool retirement |
| PO.5 — Implement and maintain secure environments | Least-privilege jobs, ephemeral runners, separated OIDC signer, no signer checkout | `.github/workflows/` | Confirm hosted rules, runner, and Actions settings |
| PS.1 — Protect code from unauthorized access and tampering | Git history, CODEOWNERS, protected-branch baseline, pull-request checks | `.github/CODEOWNERS`; `docs/operations/repository-settings.md` | Apply and capture remote repository rules |
| PS.2 — Provide a mechanism for verifying release integrity | OCI hashes, checksums, SPDX/provenance subjects, exact Sigstore identity, complete release verifier | `internal/integrity/`; `internal/releasepolicy/`; `policy/` | Produce and independently verify hosted release evidence |
| PS.3 — Archive and protect release data | Workflows retain bounded original evidence and decisions; release runbook defines final archive | `.github/workflows/signing.yml`; `docs/operations/release-runbook.md` | Publish first authorized immutable release |
| PW.4 — Reuse well-secured software | Standard library runtime, fixed external actions and container digests, dependency update automation | `go.mod`; `Dockerfile`; `.github/dependabot.yml` | Continue upstream integrity and advisory review |
| PW.6 — Configure the compilation and build process securely | Reproducible static build, fixed epoch, no network during compile, digest-pinned builder, minimal runtime | `Dockerfile`; `scripts/generate-integrity.sh` | Reassess when dependencies or platforms change |
| PW.7 — Review or analyze code | CodeQL, Gosec, Gitleaks, zizmor, Trivy configuration checks, code-owner baseline | `.github/workflows/security.yml`; `scripts/security-scan.sh` | Record hosted results and review metrics |
| PW.8 — Test executable code | Unit, race, integration, restricted-container, negative scanner, tamper, and clean-template tests | `Makefile`; `*_test.go`; `scripts/*fixtures.sh` | Add tests for any new runtime feature |
| PW.9 — Configure software securely by default | Bounded HTTP parsing, timeouts, security headers, non-root scratch image, read-only smoke test | `internal/httpapi/handler.go`; `cmd/service/main.go`; `Dockerfile`; `Makefile` | Add ingress controls for real internet deployment |
| RV.1 — Identify and confirm vulnerabilities | CodeQL, govulncheck, OSV-Scanner, Trivy, Gosec, Gitleaks, workflow scanning | `scripts/security-scan.sh`; `docs/security/scanning.md` | Maintain current advisory data and hosted triage |
| RV.2 — Assess, prioritize, and remediate vulnerabilities | Deterministic severity policy, exact expiring exceptions, stable reason codes, private reporting | `policy/security-policy.json`; `SECURITY.md`; `docs/operations/security-exceptions.md` | Operate response targets and exception expiry |
| RV.3 — Analyze vulnerabilities to identify root causes | Contribution rules require regression tests; release runbook retains incident evidence | `CONTRIBUTING.md`; `docs/operations/release-runbook.md` | Record root-cause reviews after real incidents |

## SLSA 1.2

The [SLSA 1.2 specification](https://slsa.dev/spec/v1.2/) defines separate Build and Source tracks. This repository uses its concepts but claims no SLSA level.

| SLSA concept | Implementation | Current statement |
| --- | --- | --- |
| Immutable build subject | OCI manifest digest independently derived from the archive | Implemented and locally verified |
| Build provenance | In-toto statement with `https://slsa.dev/provenance/v1`, source, build type, builder, invocation, and subject | Local statement implemented; tenant-controlled and not sufficient for Build L2 |
| Hosted signed provenance | GitHub artifact attestation workflow with protected OIDC permissions | Workflow implemented; hosted result pending |
| Provenance distribution | Explicit workflow artifacts and release runbook | Local contract implemented; public release pending |
| Artifact and provenance verification | Subject, source, builder, policy, hash, and signature checks before eligibility | Implemented locally |
| Hosted build platform | Ephemeral GitHub-hosted runners | Defined, but no independent platform assessment is recorded |
| Source history and controls | Git, review baseline, CODEOWNERS, required-check guidance | Source files implemented; remote enforcement and source attestations pending |
| Reproducibility | Fixed platform, epoch, flags, builder, and two-build comparison | Additional integrity evidence; not used as a SLSA level claim |

SLSA Build L2 requires signed provenance generated by a hosted build platform and consumer authenticity validation. The hosted workflow is designed for those properties, but this project does not claim the level until a real run and the applicable platform guarantees are independently assessed. SLSA Source levels likewise depend on source-control enforcement and attestations not established by repository files alone.
