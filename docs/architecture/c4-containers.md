# C4 Container View

This C4 container view uses “container” for independently runnable applications, commands, jobs, or data stores. Internal Go packages remain implementation components and are not promoted to deployable units.

```mermaid
C4Container
  title Container view — runtime and release control plane

  Person(contributor, "Contributor", "Changes source and controls")
  Person(maintainer, "Maintainer", "Reviews evidence and authorizes release")

  System_Boundary(repository, "Supply-chain template") {
    ContainerDb(source, "Git source repository", "Git", "Versioned service, workflows, policy, scripts, and documentation")
    Container(service, "Reference service", "Static Go binary in scratch", "Serves health and bounded digest endpoints")
    Container(validation, "Reusable validation workflow", "GitHub Actions", "Runs host, container, scanner, integrity, and policy gates")
    Container(builder, "Evidence builder", "Go, BuildKit, Syft", "Produces OCI, SPDX, provenance, reports, and checksums")
    Container(signer, "Keyless signer", "Cosign on GitHub Actions", "Signs four bounded blobs without source checkout")
    Container(verifier, "Release verifier", "Go CLI and Cosign", "Revalidates every evidence class and emits eligibility")
  }

  System_Ext(github, "GitHub services", "Reviews, rules, hosted runners, artifacts, attestations, and releases")
  System_Ext(sigstore, "Sigstore services", "Fulcio, Rekor, and trusted roots")
  System_Ext(registry, "OCI registry", "Immutable artifacts")

  Rel(contributor, source, "Proposes changes to", "Git")
  Rel(source, validation, "Supplies caller-controlled source to", "Checkout")
  Rel(validation, builder, "Runs evidence generation with", "Make and Docker")
  Rel(builder, signer, "Transfers bounded unsigned evidence to", "GitHub artifact")
  Rel(signer, sigstore, "Obtains and verifies ephemeral identity with", "OIDC and HTTPS")
  Rel(signer, verifier, "Transfers signed evidence to", "GitHub artifact")
  Rel(verifier, maintainer, "Returns artifact-bound decision to", "JSON")
  Rel(source, service, "Builds", "Go and Docker")
  Rel(validation, github, "Publishes checks and retained evidence to", "GitHub API")
  Rel(maintainer, github, "Reviews and authorizes release in", "GitHub UI and API")
  Rel(github, registry, "Publishes only after authorization", "OCI")

  UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")
```

Within the signing workflow, only the protected signer receives `id-token: write`; it does not check out source. The separate provenance and Scorecard workflows also use OIDC for their hosted attestations or results. Reusable validation receives no secrets or OIDC. The release verifier runs in a separate no-OIDC job and treats transferred artifacts as untrusted until path, hash, schema, identity, and cryptographic checks pass.
