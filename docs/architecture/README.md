# Architecture

These views explain the implemented M01–M04 trust boundaries and distinguish them from later delivery controls.

| View | Question answered |
| --- | --- |
| [C4 system context](c4-context.md) | Who interacts with the template, and which external systems surround it? |
| [C4 container view](c4-containers.md) | Which build and runtime units make up the M01 implementation? |
| [Pipeline flow](pipeline-flow.md) | How do validation, scanning, OCI generation, SBOM, and provenance connect? |

## Scope legend

- **M01–M04:** service validation, layered scanning, reproducible OCI generation, SPDX/provenance linkage, and isolated signing policy.
- **Planned:** release policy in M05.

The diagrams describe intended interfaces and boundaries. They do not constitute execution evidence or imply that a planned control is present.
