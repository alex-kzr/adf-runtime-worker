# Sealed shared Codex project policy

This is an opt-in source implementation of [umbrella ADR 007](../../../docs/adr/007-sealed-shared-profile-policy.md). Native queued acceptance and MVP readiness remain pending. No ordinary worker startup writes or repairs the provider configuration.

## Operator input

Only `provider-server` accepts `--shared-profile-policy`; jobs, API requests and consumer configuration cannot select or extend it. Omission preserves the default refusal of every `config.toml` and policy layer. Put the manifest below the runtime's `tools` directory, outside repositories/worktrees:

```json
{
  "version": 1,
  "project_roots": [
    "/home/adf-worker/ai-factory/projects/shared-acceptance-resumed-20261011"
  ]
}
```

The manifest must be a canonical same-UID regular file, mode 0600, one link, at most 64 KiB. Its closed schema permits 1–32 distinct exact main Git roots under `ROOT/projects`; directory-wide/wildcard trust, linked-worktree roots, aliases, extra keys and duplicates are rejected. Main directories and `.git` directories must be owned, canonical and not writable by group/others. Root inode/ownership/mode identities are sealed. Existing Git configuration/hook checks still apply.

The profile remains a separate canonical owned 0700 directory. An absent `config.toml` is accepted and its absence is sealed. An existing file must satisfy the same private-file checks and parse to **exactly** the declared project table:

```toml
[projects."/home/adf-worker/ai-factory/projects/shared-acceptance-resumed-20261011"]
trust_level = "trusted"
```

No model/provider, environment, MCP, hook, feature, include, notice or profile setting is accepted. Comments/formatting can differ at initial validation, but bytes and file identity become immutable for the generation. Rules, skills, AGENTS and environment layers remain refused, including dangling or cyclic links. This validator reads only policy/configuration and runtime allocation evidence; it never reads authentication files or emits raw values. Nested parser exhaustion is classified as a fixed permission failure.

## Dispatch and fencing

Validation precedes any CLI version/auth probe. The owner injects `projects` from the manifest into both its fixed CLI overrides and native thread config **after** validating the client's unchanged fixed baseline. The pinned upstream no-model experiments show this avoids the automatic trust write. A job-supplied `projects` field is refused even if identical.

The durable dispatch journal selects the allocation target, including a review's separate dispatch ID. SCM_RIGHTS must carry that target's actual execution-lock inode. The allocator records `repository_root`; policy checks its canonical worktree, factory branch and real Git common directory against the declared main root. Worktree and main-root ancestor `.codex` layers are refused. The worktree `.git` pointer is bounded/no-follow/read-stable and sealed before/after binding; later dispatch cannot renew a changed seal.

Thread setup is serialized. Checks run before `thread/start`, between thread and turn start, after turn start, during active turns and before final success. An independent 50 ms polling monitor does not wait for a slow dispatch RPC; its polling interval is not a guaranteed detection latency. File I/O and OS scheduling still apply.

Drift irreversibly blocks the generation and health, interrupts/closes active siblings and denies new turns. A closed thread can return a failed terminal result; missing `thread/closed` remains uncertain with retained locks/config/skills and no unsafe cleanup/ACK. Recorded whole-server session death is the fallback quiescence proof. Accepted IDs remain tombstones across restart and are never replayed.

Operator generation/seal and immutable worktree marker receipts are stored in allocation journals, without config contents. Later Git operations check them; a stopped/replaced/blocked generation cannot authorize commits. Receipt inheritance follows trusted local worker evidence for repair, predecessor and integration copies. It validates source eligibility and actual target Git binding, preserves an existing marker seal and carries the fence into descendants. Source scans use bounded private reads under existing journal writer locks (one-second per-file wait, at most 8,192 records of 8 MiB each). This is a conservative local implementation: uncertain or invalid evidence fails closed rather than being repaired automatically.

The socket/profile/runtime share one trusted UID. These snapshots do not provide an atomic barrier against hostile same-UID filesystem mutation between a check and native access. Untrusted code still requires a future execution sandbox. Policy/profile changes require a drained operator restart and fresh executions; old receipts are not silently reauthorized.

## Startup example and rollback

After approval of the exact worker release, drained runtime, existing profile classification and manifest:

```sh
adf-worker provider-server --root /home/adf-worker/ai-factory \
  --node /absolute/pinned/node --codex /absolute/pinned/codex \
  --codex-home /home/adf-worker/ai-factory/provider-profiles/codex \
  --shared-profile-policy /home/adf-worker/ai-factory/tools/shared-profile-policy.json
```

The consumer keeps its existing settings and `--codex-backend shared`. Keep a verified immutable previous worker source and dependency inventory before replacing its venv. Invalid existing config stops deployment and is preserved; this scope does not authorize deleting, renaming, merging or overwriting it. Roll back only after writers drain or recorded ownership proves them stopped. A previously rejecting profile stays rejecting under the old release; a stopped, verified old worker is a valid safe rollback state.

## Verification

Offline tests use temporary synthetic Git repositories/profiles and real fake-provider subprocesses, sockets, FDs and locks, with zero model calls. They cover closed schemas, aliases/links/modes/quotas/read replacement, parser exhaustion, owner-only trust, three allocations, review target locks, all dispatch drift windows, delayed starts, sibling closure/uncertainty, no replay, immutable receipts, coordinated journal replacement and transitive Git fencing. Ruff, strict mypy, Bandit and the complete Linux pytest suite are required. [The concrete umbrella deployment scope](../../../docs/shared-policy-deployment.md) records the exact release and remaining native acceptance.
