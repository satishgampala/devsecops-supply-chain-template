# M05 - Release Policy and Deployment Eligibility

- **Status:** Implemented Locally
- **Depends on:** M04
- **Implementation plan:** [2026-07-21 M05 release policy](../implementation-plans/2026-07-21-M05-release-policy.md)

## Outcome

A single local and CI verifier evaluates tests, scans, exceptions, SBOM, provenance, signature, and artifact identity and produces an explainable deployment-eligibility decision.

## Scope and non-goals

This milestone defines a release contract and decision engine. It does not deploy to a production cluster or replace organizational risk acceptance.

## Deliverables

- Versioned release-evidence and deployment-eligibility contracts.
- Local and CI verifier with stable decisions and evidence-linked reasons.
- Positive, missing-evidence, expired-exception, identity, and tampering tests.

## Tasks and subtasks

- [x] **T1: Define the release evidence contract.**
  - [x] Require artifact digest, test summary, scanner results, exception state, SBOM, provenance, signature, and identity constraints.
  - [x] Version the contract and define missing, malformed, failed, and accepted states.
  - [x] Keep original tool evidence available rather than reducing it to an unexplained boolean.
- [x] **T2: Implement the eligibility verifier.**
  - [x] Verify evidence schema and digest consistency before policy evaluation.
  - [x] Apply blocking severity, exception expiry, signer identity, provenance, and required-test rules.
  - [x] Emit eligible or ineligible with stable reason codes and evidence references.
- [x] **T3: Integrate admission-ready output.**
  - [x] Produce a machine-readable decision that a future deployment or admission control can consume.
  - [x] Keep the decision bound to one immutable artifact digest.
  - [x] Reject mutable references and artifact digest mismatches.
- [x] **T4: Build end-to-end negative scenarios.**
  - [x] Test blocking vulnerability, expired exception, missing SBOM, invalid provenance, unsigned artifact, and wrong workflow identity.
  - [x] Confirm each scenario fails for its primary expected reason.
  - [x] Test a complete synthetic release candidate through the full decision path.

## Verification and evidence

- Local contract command: `make release-policy-test` runs the complete synthetic path and exits nonzero on unexpected eligibility behavior.
- Verification results, the reason-code matrix, and the tested digest are retained in [M05 evidence](../evidence/M05/verification.md). Hosted runs retain original evidence and decisions as explicit workflow artifacts.

## Exit criteria

- [x] One verifier can reproduce release eligibility locally and is integrated into the protected signing workflow.
- [x] Every decision identifies the exact artifact digest and source evidence.
- [x] All defined negative scenarios fail with stable reason codes.
- [x] The eligible path passes only when every required control is satisfied.

The real hosted eligible path remains pending because local fixtures do not create or validate a GitHub OIDC certificate, Rekor entry, or public signature.

## Risks and controls

- **Risk:** Aggregation hides scanner failures. **Control:** Treat missing or failed tools as explicit ineligible states.
- **Risk:** Policy is bound to a mutable tag. **Control:** Evaluate and output only immutable digests.
