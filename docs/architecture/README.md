# Architecture

These views explain the M01 trust boundary and distinguish it from controls reserved for later milestones.

| View | Question answered |
| --- | --- |
| [C4 system context](c4-context.md) | Who interacts with the template, and which external systems surround it? |
| [C4 container view](c4-containers.md) | Which build and runtime units make up the M01 implementation? |
| [Pipeline flow](pipeline-flow.md) | Which checks belong to M01, and where do the planned M02–M05 controls enter? |

## Scope legend

- **M01:** the service, tests, local build, minimal container, and unprivileged CI validation foundation.
- **Planned:** scanners in M02, SBOM and provenance in M03, keyless signing in M04, and release policy in M05.

The diagrams describe intended interfaces and boundaries. They do not constitute execution evidence or imply that a planned control is present.
