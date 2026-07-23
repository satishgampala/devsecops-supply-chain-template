# M05 - Release Policy and Deployment Eligibility

- **Status:** Not Started
- **Depends on:** M04
- **Implementation plan:** Not written; planned after the dependency milestone.

## Outcome

A single local and CI verifier evaluates tests, scans, exceptions, SBOM, provenance, signature, and artifact identity and produces an explainable deployment-eligibility decision.

## Scope and non-goals

This milestone defines a release contract and decision engine. It does not deploy to a production cluster or replace organizational risk acceptance.

## Deliverables

- Versioned release-evidence and deployment-eligibility contracts.
- Local and CI verifier with stable decisions and evidence-linked reasons.
- Positive, missing-evidence, expired-exception, identity, and tampering tests.

## Tasks and subtasks

- [ ] **T1: Define the release evidence contract.**
  - [ ] Require artifact digest, test summary, scanner results, exception state, SBOM, provenance, signature, and identity constraints.
  - [ ] Version the contract and define missing, malformed, failed, and accepted states.
  - [ ] Keep original tool evidence available rather than reducing it to an unexplained boolean.
- [ ] **T2: Implement the eligibility verifier.**
  - [ ] Verify evidence schema and digest consistency before policy evaluation.
  - [ ] Apply blocking severity, exception expiry, signer identity, provenance, and required-test rules.
  - [ ] Emit eligible or ineligible with stable reason codes and evidence references.
- [ ] **T3: Integrate admission-ready output.**
  - [ ] Produce a machine-readable decision that a future deployment or admission control can consume.
  - [ ] Keep the decision bound to one immutable artifact digest.
  - [ ] Demonstrate rejection when an approved tag points to a different digest.
- [ ] **T4: Build end-to-end negative scenarios.**
  - [ ] Test blocking vulnerability, expired exception, missing SBOM, invalid provenance, unsigned artifact, and wrong workflow identity.
  - [ ] Confirm each scenario fails for its primary expected reason.
  - [ ] Test a clean release candidate through the full decision path.

## Verification and evidence

- Required future command: a single `make verify-release ARTIFACT=<immutable-reference>` or equivalent that runs every gate and exits nonzero on ineligibility.
- Retain the evidence contract, clean decision, each negative decision, reason-code matrix, and tested digest under `docs/roadmap/evidence/M05/`.

## Exit criteria

- [ ] One verifier can reproduce release eligibility locally and in CI.
- [ ] Every decision identifies the exact artifact digest and source evidence.
- [ ] All defined negative scenarios fail with stable reason codes.
- [ ] The eligible path passes only when every required control is satisfied.

## Risks and controls

- **Risk:** Aggregation hides scanner failures. **Control:** Treat missing or failed tools as explicit ineligible states.
- **Risk:** Policy is bound to a mutable tag. **Control:** Evaluate and output only immutable digests.
