# adf-runtime-worker

ADF's Ubuntu WSL2 host execution service. It runs pinned Codex and Claude Code CLIs under the authenticated Linux user, consumes Redis Streams through a scoped API lease, supervises process groups, and owns task worktrees, checks, reviewed commits and serial integration. Provider authentication stays in the host home; this package has no Docker service.

The runtime is implemented. **Whole MVP readiness still requires the matching umbrella acceptance report**, including live provider authorization, three parallel CLI jobs, restart/lease fault scenarios and external network isolation. Mock tests prove mechanics without claiming subscription execution.

## Run in Ubuntu WSL2

Python 3.12.9 and uv 0.12.18 are the verified local tooling. Install the exact dependency lock in a virtual environment; the source checkout may be read from Windows, but target repositories, worktrees and runtime journals must be on Linux ext4.

```sh
uv venv --python 3.12.9 .venv
uv pip install --python .venv/bin/python -r requirements.lock
uv pip install --python .venv/bin/python --no-deps -e .
.venv/bin/adf-worker doctor --root /home/your-user/ai-factory --node /absolute/path/to/node
.venv/bin/adf-worker serve \
  --root /home/your-user/ai-factory \
  --project-root /home/your-user/ai-factory/projects \
  --api-url http://127.0.0.1:8080 \
  --token-file /home/your-user/ai-factory/config/worker-token \
  --redis-url redis://adf_worker@127.0.0.1:6380/0 \
  --redis-password-file /home/your-user/ai-factory/config/redis-worker-password \
  --node /absolute/path/to/node \
  --codex /absolute/path/to/codex --claude /absolute/path/to/claude
```

CLI version pins: Codex 0.157.0, Claude Code 2.1.296; the Codex JavaScript launcher also requires verified Node 24.21.0. `--node` adds only that configured executable directory to the sanitized Linux PATH. A mismatch blocks execution. Authenticate interactively using each provider's official CLI under the same regular Linux user; the worker does not log in, copy credentials or fall back to paid API access. Flags were checked against installed help on 2026-10-10. `doctor` uses official read-only auth status and emits only installation/auth readiness metadata. It also reports supplemental groups and Docker socket exposure without changing permissions. `execution_capabilities_available` is separate from `ready_for_real_execution`, which remains false until dedicated-account and umbrella acceptance gates are proved.

## Development and evidence

The default provider profile is the worker Linux user's stable home, independent of job worktrees. An operator can select existing private profiles with `serve --codex-home /home/your-user/.codex --claude-config-dir /home/your-user/.claude`. Explicit directories must be owned, canonical Linux paths below that home, mode 0700 and outside worktrees. The worker passes only the corresponding directory selector, never OAuth values. It does not create a login/token, copy Windows auth, or log in per job. Job `env_allowlist` cannot select profiles or inject secret variables. Missing explicit directories fail with `AUTH_REQUIRED`. These profile flags do not themselves make concurrent Codex refresh safe; shared app-server ownership is a separate backend change.

```sh
uv pip install --python .venv/bin/python -r requirements-dev.lock
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests
.venv/bin/mypy src
.venv/bin/bandit -r src -ll
```

Linux tests exercise real process groups and Git in temporary dedicated repositories. They cover output/time/lease quotas, stubborn descendants, redaction, path escape, exclusive locks, independent review, tree-bound checks, commit intent recovery, dependency snapshots, fresh repair attempts and integration conflict preservation. Live provider smoke belongs to umbrella acceptance, uses a dedicated trusted test repository and consumes the user's subscription only when authorized.

Read [host runtime design and limitations](docs/development.md). The public origin is [adf-runtime-worker](https://github.com/alex-kzr/adf-runtime-worker).

## Shared design

- [Architecture](../../docs/architecture.md)
- [Product and acceptance](../../docs/product.md)
- [Contracts](../../docs/contracts.md)
- [Security](../../docs/security.md)
- [Local development](../../docs/local-development.md)
- [Delivery status](../../docs/delivery-status.md)

Relative links resolve in the initialized umbrella. A standalone clone must obtain the matching [adf-meta](https://github.com/alex-kzr/adf-meta) release for authoritative contracts and shared documentation.
