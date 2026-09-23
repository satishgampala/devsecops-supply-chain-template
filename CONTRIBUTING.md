# Contributing

Contributions that improve the reference service, supply-chain controls, evidence verification, tests, or documentation are welcome.

## Before changing code

- Read [SECURITY.md](SECURITY.md) for private vulnerability reporting.
- Keep the service small so the delivery controls remain inspectable.
- Open an issue before a broad interface, policy, workflow-permission, evidence-schema, or dependency change.
- Do not include credentials, private data, generated local evidence, or unrelated formatting changes.

## Local development

Required tools are listed in the [README](README.md). Run the smallest relevant check while developing, then run:

```sh
make workflow-check docs-check
make security-test
make candidate
make integrity-repro
make signing-test
make release-policy-test
make template-test
```

`make candidate`, integrity generation, and release fixtures require a clean committed revision. Candidate validation runs host and race checks, scanner rejection fixtures, and smoke tests and live scans against one OCI image. `make workflow-check` lints every workflow with Actionlint 1.7.12. `make docs-check` validates local Markdown links and fragments and renders Mermaid diagrams using digest-pinned tools. External URLs are excluded from this deterministic gate.

## Change expectations

- Add tests for new behavior and negative tests for validation or policy changes.
- Keep schemas strict, bounded, and versioned.
- Pin containers and Actions to immutable digests or full commit SHAs.
- Grant GitHub token and OIDC permissions only to the job that requires them.
- Update architecture, security, reference, and operations documentation when their contracts change.
- Do not weaken a scanner, signature, provenance, or digest failure to make a check pass.

## Pull requests

Describe the problem, security impact, implementation, verification commands, and remaining limitations. Keep each change reviewable and focused. A maintainer may request a threat-model or policy update for changes that introduce a new trust boundary.

By submitting a contribution, you agree that it is licensed under the Apache License 2.0.
