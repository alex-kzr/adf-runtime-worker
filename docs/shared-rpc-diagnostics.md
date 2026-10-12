# Shared RPC diagnostics and persistent-owner metadata verification

October 12, 2026. Source-only repair. This release does not install a package, change operator manifests/authentication or reconcile/replay pending executions. Installed worker remains `f5a713a3df44ffdad58aaa80fc3a36157e6c2736`; the dedicated runtime remains stopped. The umbrella [source checkpoint](../../../docs/shared-rpc-source-checkpoint.md) and [installed runtime checkpoint](../../../docs/shared-patch-runtime-checkpoint.md) describe separate states.

## Closed diagnostic contract

`RpcError` retains the original transport/protocol outcome while existing public `WorkerError` codes and conservative terminal/quiescence handling remain intact. Only fixed metadata may be persisted:

| Outcome | Meaning | Public code before quiescence fencing |
| --- | --- | --- |
| `provider_error` | An explicit JSON-RPC error envelope with a valid integer code and string message | `PROVIDER_FAILED` |
| `malformed_response` | Invalid framing/JSON/envelope/result/native identity shape | `PROVIDER_FAILED` |
| `transport_closed` | A local EOF/transport failure sentinel, separate from an upstream error | `EXECUTION_UNCERTAIN` |
| `response_timeout` | No correlated response before the bounded request deadline | `EXECUTION_UNCERTAIN` |
| `write_uncertain` | Outbound transport failed; partial delivery is possible | `EXECUTION_UNCERTAIN` |

Receipts contain only a fixed allowlisted RPC method (otherwise `other`), fixed outcome, bounded integer `elapsed_ms` (0РІР‚вЂњ86,400,000), and a recognized numeric `provider_error_code` or null. Recognized codes are `-32700`, `-32600`, `-32601`, `-32602`, `-32603`, `-32000`. Unknown codes, boolean codes and arbitrary method strings cannot become free-form diagnostic channels. Raw provider message/data, reply payload, stderr, prompt, environment values and exception descriptions are excluded.

A typed local failure sentinel replaces synthetic `error.code=-1` wakeups. An actual upstream `-1` remains an explicit provider error with an unrecognized numeric code; it cannot impersonate local EOF. Malformed thread/turn identity values are rejected rather than string-coerced. Pending request entries are removed on every outcome. Wire/frame, request/thread and notification queues retain their existing bounds.

Owner job journals save `rpc_failure` with the last fixed RPC phase before any auth or uncertainty mapping. A separate `cleanup_rpc_failure` cannot overwrite the original failure. Initialize failures are recorded in the owner state; new generations clear stale diagnostic attribution. For example:

```json
{"rpc_failure":{"method":"thread/start","outcome":"provider_error","elapsed_ms":18,"provider_error_code":-32602,"phase":"thread_start"}}
```

That receipt does not imply no upstream side effect. After thread-spawn intent without a recorded native thread ID, the final execution remains `EXECUTION_UNCERTAIN`, retaining locks until thread/session quiescence is proved. No error becomes success and no automatic retry/replay is introduced.

## Production-parity no-model fixture

The new actual-native fixture uses the production `server_command` flags/configuration factory with the exact verified native Rust binary, baseline empty skills/MCP catalog and exact `providers/codex` startup cwd. Its profile is an empty synthetic private directory. Only the startup auth probe is replaced by an inert test witness; no authentication is loaded and subscription readiness is not claimed.

One pinned Codex 0.157.0 app-server handles three sequential and three parallel `thread/start` requests. Each request is assembled from the actual adapter configuration, durable capability validation and allocator-bound policy, then validated against the pinned generated schema. The fixture checks the default model and native-catalog model selectors, named active permissions, literal workspace roots, cwd, approval/network/provider metadata and separate skill/MCP catalogs: no capabilities, `scoped`/`files.read_marker`, and `alternate`/`alternatefiles.read_file`.

Actual RPC methods are limited to initialize, model/list, thread/start, skills/list, mcpServerStatus/list and thread/unsubscribe; turn/auth methods are refused by the fixture. Its outer namespace mounts only synthetic roots and verified public runtimes. Network is unshared, real homes/auth/service configuration are absent, and no native model turn is possible through its method allowlist.

Parity limits are explicit: the fixture invokes the verified Rust binary directly rather than the installed npm/Node launcher. Its public QA PATH/interpreter and fully unshared network differ from the pinned Node 24.21.0 launcher PATH and authenticated owner environment. The profile is empty; real account, refresh, account-specific model catalog/cloud policy and subscription routing are not reproduced. These differences remain candidates for future diagnostic comparison, not established causes. The pinned [model metadata protocol](https://github.com/openai/codex/blob/rust-v0.157.0/codex-rs/app-server-protocol/src/protocol/v2/model.rs) supports a default/catalog witness without a turn.

Unsubscribe response alone is insufficient quiescence. Native thread closure and owner shutdown are bounded and verified before skill contexts or allocation locks are released; failed proof retains the synthetic resources. The older per-job metadata/standalone-command canary remains a separate filesystem/IPC regression and does not claim persistent-owner startup parity. Offline protocol doubles still exercise turn mechanics without invoking native models.

## What the result establishes

The empty-profile native owner accepts different job overrides after baseline startup, including distinct skills/MCP and active workspace policies, in sequential and concurrent requests. The pinned upstream [configuration manager](https://github.com/openai/codex/blob/rust-v0.157.0/codex-rs/app-server/src/config_manager.rs) appends request overrides after CLI overrides; the claim that startup CLI baseline always wins is unsupported by source and contradicted by this reproduction.

This does not recover the discarded original RPC response from the three installed-runtime uncertain jobs. Their exact upstream cause remains unknown. Authentication/profile-specific behavior, real subscription/model execution and live queue acceptance are separate gates. Do not ACK, replay, rewrite terminal states or restart the consumer to obtain new diagnostics.
