# Repository Settings Baseline

Source files cannot prove remote repository settings. Apply and independently inspect these controls before treating hosted results as protected release evidence.

## Actions

- Set the default `GITHUB_TOKEN` permission to read-only.
- Allow only required actions and reusable workflows.
- Require actions to be pinned by policy where the hosting plan supports it.
- Do not allow untrusted public pull requests on persistent self-hosted runners.
- Enable artifact attestations and private vulnerability reporting where available.

## Rules for `main`

- require changes through pull requests;
- require at least one approval and code-owner review;
- dismiss stale approvals and require approval of the most recent reviewable push;
- require branches to be current before merge;
- require candidate validation, policy contracts, workflow/documentation checks, CodeQL, and consumer initialization;
- block force pushes and branch deletion;
- require conversation resolution; and
- restrict bypass to documented emergency operators.

Select the exact check names emitted by a successful pull-request run. With the current workflow job names, expect:

- `Supply-chain validation / Candidate validation`;
- `Supply-chain validation / Policy contracts`;
- `Supply-chain validation / Workflow and documentation checks`;
- `CodeQL`; and
- `Consumer initialization`.

Confirm these names on GitHub before configuring them; a required name that never runs blocks merges. Do not require Scorecard, Provenance, or Signing on pull requests: those workflows run after trusted default-branch pushes or on their scheduled/manual triggers.

Rules for release tags should prevent update and deletion after creation.

## Security features

- enable Dependabot alerts and security updates;
- enable secret scanning and push protection;
- enable CodeQL or code scanning;
- review Scorecard findings as heuristics, not certification; and
- review the repository security overview after every workflow or policy change.

## Evidence

Record screenshots or API output showing the applied rules, required check names, allowed bypass actors, Actions policy, and security-feature status. Store no access token or raw credential-bearing response. Recheck settings before the first release and after administrative changes.
