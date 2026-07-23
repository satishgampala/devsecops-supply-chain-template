# Security Exception Process

Exceptions are temporary, exact risk decisions. They do not turn a failed or missing scanner into success and do not permit wildcard scope.

## Required fields

Every exception in `policy/security-policy.json` must include:

- a stable identifier;
- one owner;
- an explicit UTC expiry;
- one scanner and one rule;
- the exact affected artifact path;
- a concrete technical reason; and
- scope narrow enough that an unrelated finding cannot match.

The security policy caps accepted exceptions, and the M05 release policy independently enforces that cap.

## Review procedure

1. Reproduce the finding from the original normalized report.
2. Confirm the tool completed successfully and the result is not a scanner failure.
3. Determine whether code, dependency, workflow, or configuration remediation is practical.
4. If temporary acceptance is necessary, document exploitability, compensating controls, owner, removal work, and the shortest useful expiry.
5. Add one exact policy entry and a negative test proving it cannot match another scanner, rule, or file.
6. Run:

```sh
make security-test
make security-fixtures
make security-scan
make release-policy-test
```

7. Require code-owner review for both the policy and any source-level suppression.

## Current governed exception

`release-cosign-argv-g204` accepts only Gosec rule `G204` in `internal/releasepolicy/cosign.go` until 2026-10-19. The executable is the literal `cosign`, arguments bypass shell parsing, and `--` terminates options before the artifact path. A changed executable, rule, scanner, or path does not match.

## Expiry and removal

Expired exceptions are blocking. The owner must remove the exception and any source suppression, replace the implementation, or submit a newly reviewed exception before expiry. Extending an expiry without new analysis is not renewal.

When scanner behavior or rule identity changes, treat the result as a new finding. Never broaden the old exception to absorb it.

## Emergency handling

Do not create an exception for a suspected active compromise, credential leak, invalid signature, wrong workflow identity, tampered evidence, failed tool, or missing required report. Stop release processing, preserve evidence, rotate affected trust material, and follow the security reporting and release rollback procedures.
