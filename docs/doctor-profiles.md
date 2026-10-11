# Explicit operator profiles in diagnostics

`adf-worker doctor` accepts `--codex-home` and `--claude-config-dir`, using the same `ProviderProfile` validation and sanitized adapter environment as operator-selected runtime profiles. The selected `CODEX_HOME` or `CLAUDE_CONFIG_DIR` reaches both the pinned version check and the official read-only auth-status command. The other provider's selector and credential/API-key variables are excluded. No login, token generation, credential copy, model call or profile provisioning is performed.

An omitted native profile produces `health: blocked`, `auth: unknown`, `installed: null`, `probe_performed: false` and `error_code: PROFILE_REQUIRED`. The CLI is not invoked for that provider, even if the operator shell contains profile variables. Null installation state means not probed. Select an existing private directory explicitly rather than silently checking a different auth store. Missing, public, symlinked, relative or outside-home directories fail through the existing validation before a CLI child is launched. The diagnostic does not create a missing profile or change permissions.

```bash
adf-worker doctor \
  --root /home/your-user/ai-factory \
  --node /absolute/path/to/pinned/node \
  --codex /absolute/path/to/pinned/codex \
  --claude /absolute/path/to/pinned/claude \
  --codex-home /home/your-user/ai-factory/provider-profiles/codex \
  --claude-config-dir /home/your-user/ai-factory/provider-profiles/claude
```

The matching umbrella `scripts/doctor.sh` and `scripts/bootstrap-wsl.sh` forward those flags and `--node` as separate argv entries. Bootstrap still prepares only the worker and explicitly supplied ADF service files; it does not create or populate provider authentication. Diagnostics remain separate from an authorization to start provider services or agents. For an already active shared owner, use its read-only shared health preflight; diagnostic login status does not establish active refresh ownership.

These are trusted operator CLI options. They do not add fields to job input, permit per-job selectors/OAuth variables, or change `restricted_env` or the shared ancestor `.codex` guard. Subscription usage does not enable paid API fallback. Global runtime/MVP readiness remains false until matching umbrella acceptance gates pass.

Regression tests use empty temporary homes and private profiles with executable CLI fixtures that record the actual child environment and only accept the version/status verbs. They verify selectors, no default `.codex` creation, absent-profile skipping, independent provider selection, rejected invalid paths and unchanged job-environment refusals. These offline tests do not claim native authentication or model acceptance.

The repair is a source change. It is not automatically installed in any previously prepared runtime. Consult the matching umbrella release and installed-source evidence before using the new flags. The October 11 dedicated runtime remains pinned to `a8bb1cc` until a separately authorized update; use its existing shared preflight rather than invoking its old unprofiled doctor. See [runtime development](development.md), [shared migration](shared-provider.md) and the matching [umbrella checkpoint](../../../docs/fixed-worker-checkpoint.md).
