# C4 System Context

This view separates source contribution, hosted evidence production, public transparency services, and downstream artifact verification.

```mermaid
C4Context
  title System context — DevSecOps Supply-Chain Template

  Person(contributor, "Contributor", "Changes source, tests, controls, or documentation")
  Person(maintainer, "Maintainer", "Reviews policy and authorizes releases")
  Person(consumer, "Artifact consumer", "Verifies evidence before using an immutable artifact")

  System(template, "Supply-chain template", "Go service and fail-closed build, scan, evidence, signing, and release policy")

  System_Ext(actions, "GitHub Actions", "Runs validation, attestation, signing, policy, and Scorecard workflows")
  System_Ext(sigstore, "Sigstore", "Issues Fulcio certificates and records Rekor transparency material")
  System_Ext(github, "GitHub repository services", "Stores source, reviews, rules, advisories, releases, and workflow artifacts")
  System_Ext(registry, "OCI registry", "Stores immutable release artifacts when publishing is authorized")

  Rel(contributor, template, "Proposes reviewed changes", "Git and pull requests")
  Rel(maintainer, template, "Reviews controls and release evidence", "Git and JSON")
  Rel(template, actions, "Triggers protected workflows", "GitHub events")
  Rel(actions, sigstore, "Requests and verifies keyless signing", "OIDC and HTTPS")
  Rel(actions, github, "Stores checks, attestations, and bounded evidence", "GitHub API")
  Rel(actions, registry, "May publish an authorized immutable artifact", "OCI")
  Rel(consumer, github, "Downloads source and release evidence", "HTTPS")
  Rel(consumer, registry, "Pulls by manifest digest", "OCI")
```

The repository currently implements local controls and hosted workflow definitions. No registry publication, hosted keyless result, repository-rule state, or public release is claimed until independently observed.
