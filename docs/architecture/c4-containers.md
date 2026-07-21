# C4 Container View

This C4 container view uses “container” in the architectural sense: a separately runnable or build-time unit. It shows how the source/test package becomes one static service binary and then a minimal runtime image. The two CI jobs validate host and container concerns independently.

```mermaid
C4Container
  title M01 container view — source, runtime, and validation

  Person(contributor, "Contributor / reviewer", "Changes and reviews the template")

  System_Boundary(repository, "Template repository") {
    Container(source, "Source and tests", "Go standard library", "HTTP handlers and deterministic tests")
    Container(binary, "Service binary", "Static Go executable", "API server and health-check command")
    Container(image, "Runtime image", "scratch", "Numeric non-root runtime")
    Container(go_ci, "Go CI job", "GitHub-hosted runner", "Runs host verification")
    Container(container_ci, "Container CI job", "GitHub-hosted runner", "Builds and smoke-tests the image")
  }

  Rel_D(contributor, source, "Reviews")
  Rel_D(source, binary, "Builds")
  Rel_R(binary, image, "Packages")
  Rel_U(go_ci, binary, "Validates")
  Rel_U(container_ci, image, "Runs container checks")

  UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")
  UpdateRelStyle(contributor, source, $offsetX="-55", $offsetY="-10")
```

The runtime image intentionally contains the service binary rather than a shell, package manager, or language toolchain. M01 defines no scanner, evidence generator, signer, registry publisher, or release-policy engine; those containers and jobs belong to later milestones.
