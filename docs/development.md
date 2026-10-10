# Host worker development

Implemented: offline MockAdapter that emits metadata-only started/completed JSONL and a doctor that checks Linux/ext4 expectations plus CLI/Git executable versions. Doctor never logs in or reads credentials; auth is reported unknown. There is no Redis consumer, API client, real CLI adapter, process supervisor, worktree creation, test runner or Git commit behavior yet.

`src/adf_runtime_worker/adapters.py` defines the typed contract and mock. `cli.py` reads a draft request and emits safe normalized events without echoing task prompt/environment. Mock does not launch subprocesses or modify files. Version probes use argv arrays, restricted environment, timeout and no shell; probes are not proof of auth or permission safety. Windows doctor correctly reports unsupported real runtime; mock is portable.

E2 must implement Linux process groups/journals/OS locks, scoped internal API and Redis transport, quotas/redaction/path enforcement, registered Git operations and real pinned Codex/Claude adapters. Host credentials stay with the logged-in WSL user. This package has no Dockerfile/Compose service by design. No financial cap is promised for subscription usage. Use trusted scratch repositories for opt-in live tests only after permission/terms gates.
