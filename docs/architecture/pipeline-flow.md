# Pipeline Flow

M01 provides independent host and container validation. M02 adds a separate scanner boundary whose native reports are normalized before policy evaluation. The dashed path shows later delivery controls that remain planned. A local M02 pass therefore represents neither a signed release nor a deployment-eligibility decision.

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

  subgraph future["M03–M05 — planned delivery controls"]
    direction TB
    m03[M03<br/>SBOM and provenance]
    m03 -.-> m04[M04<br/>keyless signing]
    m04 -.-> m05[M05<br/>release policy]
    m05 -.-> eligibility[Deployment eligibility]
  end

  m02 -.->|planned extension| m03

  classDef currentNode fill:#e8f2ff,stroke:#2167ae,color:#102a43;
  classDef planned fill:#f5f5f5,stroke:#777,stroke-dasharray:5 5,color:#333;
  class ci,host,container,m01,source,dependency,artifact,normalize,policy,m02 currentNode;
  class m03,m04,m05,eligibility planned;
```

M02 scanner containers receive the repository read-only, write only to an ignored report directory, and receive no repository credentials. The final image is exported to an archive for scanning, so scanner containers do not receive the Docker socket. CodeQL alone receives `security-events: write`; every other scanner job is read-only. M03–M05 remain outside the implemented boundary until their own negative tests and evidence gates pass.
