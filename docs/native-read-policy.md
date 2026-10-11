# Mandatory shared native read policy

Both `shared` and `shared-patch` require a separately started owner with the sealed trust policy and native-read manifest. There is no production unsealed or legacy-sandbox opt-out. A new consumer rejects an older owner lacking `native_read_policy=restricted` before materialization; that marker is a protocol gate, not full MVP readiness.

## Operator manifest

Private canonical file under runtime `tools`, owned by the current Linux UID, single-link regular file, mode 0600, at most 64 KiB. Duplicate keys/unknown fields are rejected:

```json
{"version": 1, "read_tool_roots": ["/absolute/runtime/tools/public-codex-vendor"]}
```

Runtime root, selected profile and operator HOME beneath public/denied system trees (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/etc`, `/nix`, `/run`, `/mnt`) or `/` are rejected before manifest reads. This prevents platform grants exposing private sibling state; use ordinary private home/temp locations.

One to eight unique canonical owned directories below `tools`; `tools` itself, wildcard paths, aliases and overlaps with profiles or either private manifest are forbidden. Group/other writes are forbidden. Inventory every descendant as public before approving a root. Only manifest bytes and root identities are sealed; descendant contents are trusted operator inputs. A job cannot modify this list.

Owner startup keeps existing selections and adds the new manifest:

```sh
adf-worker provider-server --root /home/adf-worker/ai-factory \
  --node /absolute/pinned/node --codex /absolute/pinned/codex \
  --codex-home /home/adf-worker/ai-factory/provider-profiles/codex \
  --shared-profile-policy /home/adf-worker/ai-factory/tools/shared-profile-policy.json \
  --shared-native-read-policy /home/adf-worker/ai-factory/tools/shared-native-read-policy.json
```

This is documentation, not an installation/restart authorization. Preserve existing authentication and trust-manifest bytes. A drained coordinated release of owner/consumer and a verified stopped rollback are required. [Exact future deployment and acceptance scope](../../../docs/shared-native-read-policy.md) has not been executed.

## Native binding

The fixed `adf_shared_read` profile starts with `:root=deny`, pinned `:minimal=read`, public tool grants and explicit private/control masks. `/etc`, `/usr/local`, `/nix`, `/run` and `/mnt` are denied; ungranted homes/worktrees are absent. Only an allocator/seal-verified literal worktree is added. There are no writable/network grants or inherited profiles. The bounded 50,000-entry metadata scan masks private names at any depth and all multiply-linked regular files without reading contents or following links. Approved hash-checked SKILL.md leaves retain only their needed ancestor paths; private siblings stay masked. More entries fail closed.

The owner validates the closed legacy client frame first, then removes its `sandbox` override and supplies named config. It disables `exec_permission_approvals` and `request_permissions_tool`, uses experimental response witnesses from the pinned generated schema and sets `allowProviderModelFallback=false`. Actual active profile, exact runtime workspace roots, cwd, approval policy, read-only/network and OpenAI provider must match before a native turn. Account metadata must report `chatgpt`, not API key or another backend. This account gate does not prove billing beyond the selected backend.

Approved skills/MCP are reconstructed from the durable dispatch journal using the executor's shared approval routine, including tool narrowing. Skill selectors, instruction hash/mode and host-discovery setting must match. Only the existing owned credential-free stdio scoped-files implementation is permitted; its exact private launch/config, worktree read paths, tools, quotas and empty inherited env list must match. Generic MCP processes are not protected by the native command sandbox.

Manifest/root drift irreversibly blocks the generation, interrupts siblings and fences descendant Git operations. Quiescence, lock ownership and no-replay rules are retained. Missing native receipts or conflicting inherited receipts fail closed. Policy checks do not provide an atomic barrier against hostile same-UID changes; private masks and public platform grants retain the limits documented in the umbrella.

## Verification and limits

The complete Linux suite includes a real Unix IPC/SCM_RIGHTS synthetic canary using exact-hash Codex 0.157.0/bwrap public copies. Actual native thread metadata and standalone command sandbox run in a further synthetic namespace without real homes, profiles, configuration or sockets. Actual requests/responses validate against the generated experimental fixture. Three protocol-double jobs include one cancellation; assigned reads/selected skill pass, external/private/sibling/hardlink/alias reads and writes/network fail. Actual native skills/list and thread MCP inventory confirm selected instruction and only narrowed `read_marker`. Fake-owner tests prove lifecycle refresh ownership, drift, no replay and forged inputs; native model turns remain zero.

Set `ADF_TEST_CODEX_PATH` and `ADF_TEST_BWRAP_PATH` to the explicitly approved pinned public binaries to run the native canary locally; CI prepares the same hashes. No login, setup-token, API key or model is required. Run Ruff, mypy, Bandit and the full pytest suite. An unset native fixture skips only that canary and cannot support the native evidence claim.

The legacy preflight FAILED on host reads. The new source canary passes its defined metadata/command boundary; installed subscription/queue acceptance, all built-in tool routes, actual refresh and model-selected tools remain open. Public OS/tool files remain readable, tool descendants are not recursively sealed, Node/build checking is still unsupported by checker v1, and whole readiness stays false. See [shared trust fencing](shared-profile-policy.md), [source shared-patch phases](../../../docs/shared-patch-source.md), [ADR 009](../../../docs/adr/009-operator-owned-native-read-policy.md) and [sanitized evidence](../../../docs/evidence/shared-native-read-source-2026-10-11.json).
