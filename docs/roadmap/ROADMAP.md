# DevSecOps Supply-Chain Template Roadmap

## Goal

Create a reusable public-repository template that takes a small service from source to a tested, scanned, SBOM-described, provenance-attested, signed, policy-verified release artifact.

## Intended architecture

- A minimal Go HTTP service with deterministic unit and container tests.
- GitHub Actions with least-privilege permissions and pinned third-party actions.
- Code, dependency, secret, IaC, container, and license checks.
- SPDX or CycloneDX SBOM, SLSA provenance, and Sigstore Cosign keyless signing.
- A release-verification command that checks the artifact, signature, provenance, SBOM, and policy result before deployment eligibility.

## Scope

- Secure SDLC controls, evidence, reusable workflow design, artifact integrity, release policy, and developer documentation.

## Non-goals

- Building a feature-rich application or a complete enterprise CI platform.
- Claiming that scanners eliminate application-security review.
- Requiring a paid registry, cluster, or cloud account for the default workflow.

## Milestones

| ID | Milestone | Status | Depends on | Exit outcome |
| --- | --- | --- | --- | --- |
| M01 | [Reference service and pipeline baseline](milestones/M01-pipeline-baseline.md) | Implemented Locally | None | A minimal service builds and tests reproducibly with a hardened CI foundation. |
| M02 | [Source, dependency, IaC, and container scanning](milestones/M02-security-scanning.md) | Implemented Locally | M01 | Security checks detect seeded defects and enforce documented severity policy. |
| M03 | [SBOM and SLSA provenance](milestones/M03-sbom-provenance.md) | Implemented Locally | M02 | Every release artifact has verifiable component inventory and build provenance. |
| M04 | [Keyless signing and identity verification](milestones/M04-signing.md) | Implemented Locally | M03 | Artifacts are signed and verification binds them to the expected workflow identity. |
| M05 | [Release policy and deployment eligibility](milestones/M05-release-policy.md) | Implemented Locally | M04 | A single verifier produces an evidence-backed eligible or ineligible decision. |
| M06 | [Reusable template, demonstration, and release](milestones/M06-template-release.md) | Implemented Locally | M05 | A detached consumer can adopt the template and reproduce its local security controls. |

M01–M06 are implemented and verified locally. GitHub-hosted execution, repository rules, Scorecard results, keyless signing, registry publication, immutable tags, and releases remain pending.

## Project completion gate

Local implementation is complete when all checks pass, seeded vulnerabilities and tampering fail for expected reasons, and a detached consumer can adopt the template without private infrastructure. Publication is complete only after hosted signatures and provenance bind to the intended workflow identity and an immutable versioned release is independently verified.

## Planning source

This roadmap became the repository's authoritative planning source on 2026-07-21. Completion claims require command output and evidence generated from this repository.
