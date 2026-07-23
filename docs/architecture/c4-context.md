# C4 System Context

This context view places the template between a human contributor/reviewer and GitHub Actions. The OCI registry is shown only as a future integration: M01 validates source and a local container but does not publish a release artifact.

```mermaid
C4Context
  title System context — DevSecOps Supply-Chain Template

  Person(contributor, "Contributor / reviewer", "Changes source, reviews controls, and evaluates evidence")
  System(template, "Template repository", "Small Go service, tests, container definition, CI configuration, and documentation")
  System_Ext(actions, "GitHub Actions", "Runs unprivileged M01 validation jobs")
  System_Ext(registry, "OCI registry (planned)", "Stores immutable release artifacts in a later milestone")

  Rel_D(contributor, template, "Authors and reviews", "Git and pull requests")
  Rel_D(template, actions, "Triggers validation and receives results", "Workflow events and checks")
  Rel_D(actions, registry, "Will publish verified artifacts to (planned)", "OCI")
```

The M01 trust boundary excludes registry credentials, publishing permissions, OIDC signing, and release jobs. Pull-request validation is expected to read repository content and report results without obtaining write access or repository secrets.
