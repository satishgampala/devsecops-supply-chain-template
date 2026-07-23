# Pipeline Flow

M01 provides independent host and container validation. M02 adds normalized scanner policy. M03 binds SPDX and provenance to one reproducible OCI subject. M04 separates evidence production, OIDC signing, cryptographic verification, and identity-policy evaluation. Dashed edges denote hosted signing execution and M05 release policy that remain unobserved.

```mermaid
flowchart TB
  change[Source change] -->|triggers| ci[GitHub Actions validation]

  subgraph baseline["M01 — validation baseline"]
    direction TB
    ci -->|runs| host[Host checks<br/>format · vet · tests · race · build]
    ci -->|runs| container[Container checks<br/>build · health · smoke]
    host -->|reports| m01[M01 validation result]
    container -->|reports| m01
  end

  subgraph scanning["M02 — security control boundary"]
    direction TB
    m01 --> source[Source and workflow<br/>CodeQL · Gosec · Gitleaks · zizmor]
    m01 --> dependency[Dependency and license<br/>govulncheck · OSV · Trivy]
    m01 --> artifact[Infrastructure and image<br/>Trivy configuration · vulnerability]
    source --> normalize[SARIF normalization]
    dependency --> normalize
    artifact --> normalize
    normalize --> policy[Versioned security policy]
    policy --> m02[M02 gate decision]
  end

  subgraph integrity["M03 — integrity evidence"]
    direction TB
    m02 --> oci[Reproducible OCI archive<br/>linux/amd64 · fixed epoch]
    oci --> subject[Independent OCI parser<br/>manifest · config · layers]
    oci --> syft[Syft SPDX 2.3<br/>final artifact inventory]
    subject --> bind[Digest linkage verifier]
    syft --> bind
    provenance[SLSA Provenance v1<br/>source · builder · invocation] --> bind
    bind --> m03[M03 verified evidence]
  end

  subgraph signing["M04 — isolated signing boundary"]
    direction TB
    m03 --> transfer[Bounded unsigned evidence<br/>no OIDC]
    transfer -.-> signer[Hosted keyless signer<br/>OIDC · no checkout]
    signer -.-> cosign[Cosign verification<br/>Fulcio · Rekor · SCT]
    cosign -.-> identity[Exact identity observation]
    fixtures[Local negative fixtures] --> signPolicy[Signing identity policy]
    identity -.-> signPolicy
    signPolicy --> m04[M04 policy decision]
  end

  subgraph future["M05 — planned release control"]
    direction TB
    m04 -.-> m05[M05<br/>release policy]
    m05 -.-> eligibility[Deployment eligibility]
  end

  classDef currentNode fill:#e8f2ff,stroke:#2167ae,color:#102a43;
  classDef planned fill:#f5f5f5,stroke:#777,stroke-dasharray:5 5,color:#333;
  class ci,host,container,m01,source,dependency,artifact,normalize,policy,m02,oci,subject,syft,provenance,bind,m03,transfer,fixtures,signPolicy,m04 currentNode;
  class signer,cosign,identity,m05,eligibility planned;
```

M02 scanners receive no repository credentials or Docker socket. M03's local generator requires a clean tree and grants no cloud credentials. M04 grants `id-token: write` only to a protected signer that downloads bounded evidence and never checks out source. A separate no-OIDC job executes the repository policy verifier. The workflow structure and local failure policy are implemented; Fulcio, Rekor, and certificate verification remain pending until hosted execution.
