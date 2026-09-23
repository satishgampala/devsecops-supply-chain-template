# Security Scanning

M02 adds independent source, dependency, secret, workflow, infrastructure, image, and license controls. Native SARIF remains available for investigation; a repository-owned normalizer removes source snippets and maps scanner output into one deterministic policy contract.

## Control set

| Scanner | Scope | Local execution | Blocking behavior |
| --- | --- | --- | --- |
| CodeQL | Go source and data flow | GitHub-hosted workflow | The dedicated CodeQL job must succeed. |
| Gosec 2.28.0 | Go source patterns and taint paths | Digest-pinned container | Medium, high, and critical findings block. |
| govulncheck 1.6.0 | Reachable Go and standard-library vulnerabilities | Version-pinned Go module | Reachable findings block. |
| Gitleaks 8.30.1 | Complete reachable Git history | Digest-pinned container | Any detected synthetic or real secret blocks. |
| zizmor 1.27.0 | Workflows, actions, and Dependabot configuration | Digest-pinned container in offline mode | Regular-persona findings block. |
| OSV-Scanner 2.4.0 | Direct and transitive dependency advisories | Digest-pinned container | Medium, high, and critical findings block. |
| Trivy 0.72.0 | Dockerfile and infrastructure configuration | Digest-pinned container | Medium, high, and critical findings block. |
| Trivy 0.72.0 | Final image vulnerabilities and source licenses | Digest-pinned container | High or critical image findings and unapproved licenses block. |

The exact container digests and module versions are stored in `scripts/security-scan.sh`. GitHub Actions and scanner containers are never referenced by mutable tags.

## Run the controls

Run deterministic report and policy tests without Docker or advisory-network access:

```sh
make security-test
```

Run the live clean-state gate:

```sh
make security-scan
```

This command requires Docker and network access to current advisory databases. It builds the application image, exports it as an archive, and scans the archive without mounting the Docker socket into a scanner container.

Run the isolated expected-failure suite:

```sh
make security-fixtures
```

Fixtures prove detection of unsafe Go permissions, a reachable vulnerable dependency, a non-credential secret canary, unsafe workflow interpolation, dependency advisories, Dockerfile defects, a prohibited license, and a vulnerable end-of-life image. They are excluded narrowly from clean scans and normal builds.

## Reports and decisions

The default live output is `.local/security-reports/latest/`:

```text
raw/          scanner-native SARIF
normalized/   stable repository-owned scanner reports
metadata/     tool and advisory-database versions
decision.json aggregate gate result
```

Generated output is ignored by Git. The hosted workflow retains the same tree as a 14-day artifact even when the gate fails.

Each normalized finding contains scanner, rule, artifact, location, severity, message, remediation, and license identifier when applicable. It deliberately excludes source snippets, matched secret text, environment dumps, and credentials. A scanner that crashes, omits output, or emits invalid SARIF receives state `failed`; this is distinct from a completed scanner with zero findings.

The runner deletes previous output before each invocation. SARIF invocation failures and error notifications are rejected. Gosec also emits a native JSON summary from the same invocation: processing errors or zero analyzed files reject the scan because Gosec SARIF omits those errors. The runner accepts exit 1 with findings only for Gosec and OSV; Gitleaks and Trivy use explicitly configured finding exit code 10. Govulncheck and zizmor must return 0 in SARIF mode. Nonzero finding codes with empty results are failures. `make security-test` exercises these paths without Docker or network access.

Unknown finding severity blocks under the repository policy. Advisory timestamps extracted from SARIF survive normalization unless an explicit valid timestamp overrides them. A recorded timestamp alone does not establish freshness or authenticity.

## Policy and exceptions

[`policy/security-policy.json`](../../policy/security-policy.json) defines:

- required scanners;
- blocking severities;
- approved and prohibited SPDX license identifiers; and
- exact, time-bounded exceptions.

An exception requires all fields below:

```json
{
  "id": "EX-001",
  "owner": "security-maintainers",
  "reason": "Temporary mitigation is independently verified.",
  "scanner": "gosec",
  "rule": "G000",
  "artifact": "internal/example.go",
  "expiresOn": "2026-08-21"
}
```

Wildcard scope is rejected. Expired exceptions make the complete gate ineligible, even when their original finding is absent, so stale risk acceptance cannot remain unnoticed.

Stable M02 reason codes are `required_scanner_missing`, `scanner_failed`, `blocking_finding`, `prohibited_license`, `exception_invalid`, `exception_expired`, and `report_invalid`.

## Advisory data and review cadence

Live vulnerability results change as advisory databases are updated. The scan records available database timestamps, while deterministic fixtures test policy behavior without a live database. Review scanner references, policy, and exceptions with every update proposal and at least monthly. Never disable TLS verification, module authenticity, transparency checks, or scanner failure handling to make a gate pass.
