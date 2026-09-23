# Repository Working Agreement

This file defines the rules for human-led and agent-assisted work in this repository.
The roadmap and milestone implementation plans remain the technical source of truth.

## Communication protocol

- Use the repository-local [caveman skill](.agents/skills/caveman/SKILL.md) in `ultra` mode for all responses, progress updates, plans, reviews, research summaries, and handoffs.
- Apply the repository-local [karpathy-guidelines skill](.agents/skills/karpathy-guidelines/SKILL.md) when writing, reviewing, or refactoring code.
- Remove filler, repeated summaries, decorative formatting, and routine tool narration while preserving technical substance, evidence, paths, commands, and exact errors.
- Use normal clear prose for security warnings, destructive actions, ambiguous ordering, or any case where compression could cause a mistake.
- Keep source code, configuration, repository documentation, commit messages, and pull-request content conventional and professional.
- Keep this protocol active until the repository owner explicitly requests normal mode.

## Project scope

- Keep the reference service deliberately small so delivery controls remain visible.
- Implement milestones in dependency order from `docs/roadmap/ROADMAP.md`.
- Do not describe a planned control as implemented until its verification evidence exists.
- Avoid unrelated refactors, speculative abstractions, and dependencies without a demonstrated need.

## Human ownership and Git

- Use the repository's configured human author identity. Never substitute an automated-tool identity.
- Do not add assistant attribution, tool branding, or automated co-author trailers to commits.
- Let Git record the genuine current author and committer timestamps. Never override or backdate them.
- Use purpose-based branches such as `feat/<scope>`, `fix/<scope>`, `docs/<scope>`, or `chore/<scope>`.
- Do not use an assistant, model, tool, or vendor name in branch names or commit messages.
- Only the coordinating worker creates commits. Implementation and review workers return uncommitted diffs.
- Stage explicit paths with `git add <path>`; do not use broad staging that can capture unrelated work.
- Do not push, open a pull request, merge, or publish a release without the repository owner's direction.

## Parallel-work protocol

- Record every parallel task in the ignored `.local/coordination/` ledger before delegation.
- Each task declares an owner, dependencies, exclusive write paths, required checks, and a handoff state.
- Use a separate Git worktree and branch for each write-capable worker. Read-only reviewers may share a checkout.
- Limit this small repository to two concurrent writers plus one coordinator. Additional workers should be read-only.
- A worker must not edit outside its exclusive scope or modify another worker's partial output.
- Valid handoff states are `working`, `waiting`, `ready`, and `error`. Only `ready` work may enter integration review.
- The coordinator reviews every diff and reruns the full integration gate; worker reports are not completion evidence.

## Protected files

Only the coordinator may modify these paths during a parallel milestone:

- `AGENTS.md`
- the active file under `docs/roadmap/implementation-plans/`
- `.local/coordination/`
- milestone verification evidence under `docs/roadmap/evidence/`

## Security rules

- Never commit credentials, tokens, private keys, `.env` files, raw environment dumps, or credential-bearing URLs.
- Coordination records contain neutral worker IDs, paths, commands, statuses, and evidence references only. They must not contain prompts, private reasoning, secrets, or raw environment values.
- Keep GitHub Actions permissions explicit and least-privilege.
- Pin every action to a full 40-character commit SHA and retain its release tag in a comment.
- Never execute untrusted pull-request code in a privileged trigger or with repository secrets.
- Keep pull-request jobs on ephemeral GitHub-hosted runners unless an approved threat model says otherwise.
- Keep container runtime defaults non-root, read-only where practical, capability-free, and protected by `no-new-privileges` and a PID limit.
- Do not weaken Go module authenticity, TLS verification, or scanner failures to make a check pass.

## Required verification

Run the smallest relevant checks during implementation, then run the full gate before staging a milestone:

```sh
make verify
go test -race -count=1 ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/ci.yml
make container-build
make container-smoke
git diff --check
```

Also verify:

- local Markdown links and Mermaid syntax;
- workflow triggers, permissions, action pins, and untrusted-input handling;
- tracked and proposed files for high-confidence secret patterns;
- container user, entrypoint, health check, image contents, and smoke-test restrictions;
- documentation claims against observed command output.

If a required check cannot run, record it as unverified. Never replace evidence with an assumption.

## Commit discipline

- One commit represents one coherent, reviewed capability.
- Include its tests and directly related documentation in the same commit when that makes the change independently understandable.
- Do not create empty, filler, mechanically split, or activity-pattern commits.
- Before every commit, inspect the exact staged diff, run `git diff --cached --check`, and confirm the configured author identity.
