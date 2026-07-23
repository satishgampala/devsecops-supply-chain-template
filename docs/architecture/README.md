# Architecture

These views explain the implemented M01–M05 trust boundaries and distinguish them from later delivery controls.

| View | Question answered |
| --- | --- |
| [C4 system context](c4-context.md) | Who interacts with the template, and which external systems surround it? |
| [C4 container view](c4-containers.md) | Which build and runtime units make up the M01 implementation? |
| [Pipeline flow](pipeline-flow.md) | How do validation, scanning, OCI generation, signing, and release policy connect? |

## Scope legend

- **M01–M05:** service validation, layered scanning, reproducible OCI generation, SPDX/provenance linkage, isolated signing policy, and complete release-evidence verification.
- **Pending hosted execution:** OIDC certificate issuance, transparency-log material, hosted attestations, and a real eligible release decision.

The diagrams describe intended interfaces and boundaries. They do not constitute execution evidence or imply that a planned control is present.
