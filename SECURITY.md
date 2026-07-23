# Security Policy

## Supported versions

No versioned release has been published. Security fixes currently target the latest `main` revision. This table must be updated when the first version is released.

| Version | Supported |
| --- | --- |
| Unreleased `main` | Yes |
| Older revisions | No |

## Report a vulnerability

Use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Choose **Report a vulnerability**.

Include the affected revision, entry point, impact, reproduction steps, and any proposed mitigation. Do not include credentials, tokens, personal data, or live exploit data beyond what is necessary to reproduce the issue.

If private reporting is unavailable, open a public issue that requests a private contact channel without disclosing vulnerability details.

Maintainers aim to acknowledge a report within five business days and provide an initial triage result within ten business days. Complex reports may require more time. Disclosure timing is coordinated with the reporter after a fix or documented mitigation is available.

## Scope

Reports are welcome for:

- the Go service and command-line verifiers;
- evidence path, schema, digest, policy, and exception handling;
- Docker build and runtime boundaries;
- GitHub Actions permissions, triggers, artifacts, OIDC, and action dependencies; and
- template initialization that can silently weaken or misbind a control.

Scanner disagreements without a concrete security impact, unsupported historical revisions, and attacks requiring an already trusted maintainer to intentionally remove controls may be closed with an explanation.

## Handling

Do not publish a proof of concept before coordinated disclosure. Maintainers will preserve reporter credit unless anonymity is requested. Security fixes must add a regression check where practical and must pass the complete verification gate before release.
