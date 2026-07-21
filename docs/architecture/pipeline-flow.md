# Pipeline Flow

M01 provides independent host and container validation. M02 adds a scanner boundary whose native reports are normalized before policy evaluation. M03 creates one reproducible OCI subject and binds both SPDX inventory and provenance to its verified manifest digest. The dashed path shows signing and release policy that remain planned.

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

  subgraph future["M04–M05 — planned delivery controls"]
    direction TB
    m03 -.-> m04[M04<br/>keyless signing]
    m04 -.-> m05[M05<br/>release policy]
    m05 -.-> eligibility[Deployment eligibility]
  end

  classDef currentNode fill:#e8f2ff,stroke:#2167ae,color:#102a43;
  classDef planned fill:#f5f5f5,stroke:#777,stroke-dasharray:5 5,color:#333;
  class ci,host,container,m01,source,dependency,artifact,normalize,policy,m02,oci,subject,syft,provenance,bind,m03 currentNode;
  class m04,m05,eligibility planned;
```

M02 scanner containers receive the repository read-only, write only to an ignored report directory, and receive no repository credentials. The final image is exported to an archive for scanning, so scanner containers do not receive the Docker socket. M03's local generator requires a clean tree, uses a digest-pinned Syft container, and grants no cloud credentials. Its hosted workflow runs only on default-branch pushes or manual dispatch and confines OIDC and attestation writes to one job. M04–M05 remain outside the implemented boundary.
