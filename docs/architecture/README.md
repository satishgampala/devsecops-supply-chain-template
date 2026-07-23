# Architecture

These views explain runtime and release-control-plane boundaries across M01–M06 and distinguish implemented local controls from pending hosted state.

| View | Question answered |
| --- | --- |
| [C4 system context](c4-context.md) | Who interacts with the template, and which external systems surround it? |
| [C4 container view](c4-containers.md) | Which runnable units build, validate, sign, and verify the service? |
| [Pipeline flow](pipeline-flow.md) | How do validation, scanning, OCI generation, signing, and release policy connect? |
| [Threat model](../security/devsecops-supply-chain-template-threat-model.md) | Which assets, boundaries, and abuse paths drive security priorities? |

## Scope legend

- **M01–M06 local controls:** service validation, layered scanning, reproducible OCI generation, SPDX/provenance linkage, isolated signing policy, complete release-evidence verification, deterministic initialization, and reusable validation.
- **Pending hosted execution:** OIDC certificate issuance, transparency-log material, hosted attestations, and a real eligible release decision.

The diagrams describe intended interfaces and boundaries. They do not constitute execution evidence or imply that a planned control is present.
