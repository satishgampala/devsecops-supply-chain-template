# Release Runbook

This runbook publishes one immutable source revision and its complete evidence set. It does not deploy the reference service. Commands that change remote state require explicit repository-owner authorization.

## Roles

- **Release owner:** selects the revision, records the evaluation time, and operates the release.
- **Reviewer:** independently checks source revision, policy, hosted runs, artifact digest, and eligibility decision.
- **Security contact:** resolves blocking findings or approves a narrowly scoped exception before expiry.

One person may hold multiple roles in a small project, but the final evidence review should be independent whenever possible.

## Preconditions

1. The release revision is the current protected `main` head.
2. Required repository rules and code-owner review are active.
3. CI, Security, Provenance, Signing, Template Self-Test, and Scorecard have completed for the exact source SHA.
4. No accepted security exception expires before the planned support window without a tracked removal plan.
5. The final Signing workflow decision is `eligible: true` for the intended immutable OCI digest.

Local fixtures that use the test-only Cosign substitute never satisfy preconditions 3 or 5.

## 1. Fix the candidate

```sh
git fetch --tags origin
git switch main
git pull --ff-only
test -z "$(git status --porcelain --untracked-files=all)"
source_sha="$(git rev-parse HEAD)"
test "$source_sha" = "$(git rev-parse origin/main)"
```

Choose a SemVer value that does not already exist:

```sh
version=v0.1.0
git rev-parse --verify "refs/tags/$version" >/dev/null 2>&1 && exit 1
```

## 2. Reproduce local controls

```sh
make verify
make container-build
make container-smoke
make security-fixtures
make security-scan
make integrity-repro
make signing-test
make release-policy-test
make template-test
```

Record tool database timestamps, accepted exceptions, OCI manifest digest, archive hash, and policy hashes. The local eligible fixture demonstrates policy composition only.

## 3. Verify hosted evidence

Open each required workflow run and confirm its head SHA equals `$source_sha`. Download artifacts by exact run ID into separate directories:

```sh
gh run download <provenance-run-id> --dir release-review/provenance
gh run download <signing-run-id> --dir release-review/signing
gh run download <scorecard-run-id> --dir release-review/scorecard
```

For the Signing run:

1. verify `checksums.sha256`;
2. inspect the signing observation and signing-policy decision;
3. rerun `cosign verify-blob` for the OCI archive, raw SPDX document, and local provenance using every exact issuer and GitHub workflow flag from `policy/signing-identity.json`;
4. rerun `cmd/releaseverify` against the retained evidence root and recorded evaluation time; and
5. confirm the final decision names the expected source SHA, artifact, manifest digest, release-policy hash, and no reason codes.

For the Provenance run, independently verify the platform attestation bundles against the same subject. Do not substitute a mutable tag for the manifest digest.

## 4. Create the immutable source tag

After reviewer approval:

```sh
git tag --annotate "$version" "$source_sha" \
  --message "$version: verified supply-chain release"
git show --no-patch --format=fuller "$version"
git push origin "refs/tags/$version"
```

Never move or reuse a published tag. Correct a release with a new patch version.

## 5. Publish the release record

Prepare release notes containing:

- source SHA and immutable OCI manifest digest;
- release-policy SHA-256 and final decision SHA-256;
- SPDX, provenance, Sigstore bundle, and checksum filenames;
- exact verification commands;
- accepted exception IDs and expirations, if any; and
- known limitations.

Create the release only from the verified tag and upload the bounded evidence set:

```sh
gh release create "$version" \
  --verify-tag \
  --title "$version" \
  --notes-file release-notes.md \
  release-review/evidence/*
```

Do not upload temporary credentials, raw environment output, scanner caches, or unreviewed files.

## 6. Post-release verification

In a clean directory:

1. download the release assets;
2. verify checksums and three Sigstore bundles;
3. compare the release tag SHA, decision source SHA, provenance source digest, and OCI subject;
4. inspect the SPDX subject and package inventory; and
5. record the release URL, workflow URLs, Rekor entries, decision hash, and independent verification result.

## Failure and rollback

Stop before tagging when any source, workflow, scanner, identity, hash, signature, provenance, SBOM, test, or decision check fails.

If a published release is later found unsafe:

- mark the release as affected and remove it from normal consumption without moving the tag;
- publish a security advisory when appropriate;
- revoke or rotate any compromised credential or trust relationship;
- fix the issue with a regression test;
- produce a new patch release with a complete new evidence set; and
- retain the original incident evidence according to project policy.
