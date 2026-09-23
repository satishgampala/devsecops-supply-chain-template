# Pipeline Flow

The PR workflow validates one candidate and independent policy contracts. Trusted default-branch workflows separately produce hosted attestations and signatures. Dashed edges below require hosted execution, which remains blocked by the observed account billing lock.

```mermaid
flowchart TB
  source[Clean source commit] --> host[Toolchain and source checks<br/>Unit tests, race tests, build]
  host --> fixtures[Eight seeded scanner rejection fixtures]
  fixtures --> oci[One reproducible OCI candidate<br/>linux/amd64, fixed epoch]
  oci --> runtime[Run exact manifest digest<br/>Non-root, read-only, no capabilities]
  oci --> imageScan[Export same manifest for Trivy<br/>No rebuild]
  source --> sourceScan[Source, dependency, secret<br/>workflow, configuration, license scans]
  sourceScan --> reports[Normalize reports<br/>Execution state, identity, timestamps]
  imageScan --> reports
  reports --> security[Versioned security policy]
  oci --> inventory[SPDX and local SLSA provenance]
  inventory --> linkage[Independently verify OCI<br/>manifest, config, layers, inventory]
  runtime --> tests[Test summary<br/>Source and observed image digest]
  tests --> statement[Complete validation statement]
  security --> statement
  linkage --> statement
  statement -.-> signer[Hosted signer<br/>Four blobs, OIDC, no checkout]
  signer -.-> sigstore[Fulcio, Rekor, SCT verification]
  sigstore -.-> verifier[Separate no-OIDC release verifier]
  statement --> local[Local positive and tamper fixtures<br/>Explicit signature test double]
  local --> verifier
  verifier --> decision{Artifact-bound eligibility}
  decision -.-> release[Independent review<br/>Authorized immutable release]
  source --> contracts[Policy rejection tests]
  source --> docs[Workflow lint, local links<br/>Mermaid rendering]
  source --> consumer[Detached lowercase and mixed-case consumers]
  source -.-> codeql[Hosted CodeQL analysis]
```

`ci.yml` calls the reusable workflow once. Its candidate, contract, and documentation jobs are all required. CodeQL and consumer initialization are separate PR checks. Scorecard, Provenance, and Signing are not PR-required checks because their triggers do not cover pull requests.

Scanner containers receive no repository credentials or Docker socket. Source snapshots exclude ignored output and nested worktrees. Integrity generation requires a clean committed tree. Runtime tests and image scans use the same verified OCI manifest; the signed validation statement covers their evidence hashes. The verifier independently checks scanner identity/freshness, tests, OCI structure, SPDX, provenance, policy identities, and four signatures.

Within `signing.yml`, the builder has no OIDC, the signer has no source checkout, and the release verifier has no OIDC. The separate platform-attestation workflow also requires OIDC. These boundaries reduce credential exposure but cannot prove that a compromised trusted builder reported the truth. Protected review and observed hosted evidence remain required before release.
