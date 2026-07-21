# Pipeline Flow

M01 ends with independent host and container validation results. The dashed path shows the planned controls that will extend the pipeline only after their own milestones are implemented and verified. An M01 pass therefore represents neither a release carrying a signature nor a deployment-eligibility decision.

```mermaid
flowchart TB
  change[Source change] -->|triggers| ci[GitHub Actions validation]

  subgraph current["M01 — current validation boundary"]
    direction TB
    ci -->|runs| host[Host checks<br/>format · vet · tests · race · build]
    ci -->|runs| container[Container checks<br/>build · health · smoke]
    host -->|reports| m01[M01 validation result]
    container -->|reports| m01
  end

  subgraph future["M02–M05 — planned delivery controls"]
    direction TB
    m02[M02<br/>security scanning] -.-> m03[M03<br/>SBOM and provenance]
    m03 -.-> m04[M04<br/>keyless signing]
    m04 -.-> m05[M05<br/>release policy]
    m05 -.-> eligibility[Deployment eligibility]
  end

  m01 -.->|planned extension| m02

  classDef currentNode fill:#e8f2ff,stroke:#2167ae,color:#102a43;
  classDef planned fill:#f5f5f5,stroke:#777,stroke-dasharray:5 5,color:#333;
  class ci,host,container,m01 currentNode;
  class m02,m03,m04,m05,eligibility planned;
```

Both M01 branches are deliberately unprivileged and separable: host checks do not require Docker, while container checks exercise the image boundary. M02–M05 remain visually and operationally outside the current milestone until their documented negative tests and evidence gates pass.
