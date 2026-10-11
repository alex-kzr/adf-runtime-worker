"""Opt-in shared Codex adapter preserving existing detached supervision."""
from __future__ import annotations

import json
import socket
import sys
from dataclasses import replace
from pathlib import Path
from threading import Event

from .adapters import CODEX_VERSION, CodexAdapter, _mcp_launch_configs
from .journal import Journal
from .models import AdapterResult, EventSink, Json, Request, WorkerError
from .process import ProcessRunner
from .shared_server import baseline, recv_frame, send_frame, shared_stopped


class SharedCodexAdapter(CodexAdapter):
    def __init__(self, root: Path) -> None:
        super().__init__()
        self.root = root
        # Thread shutdown timeout is 10s in the pin; leave bounded RPC margin.
        self.runner = ProcessRunner(grace_sec=35)

    def probe(self, deadline: float | None = None) -> Json:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect(str(self.root / "providers" / "codex" / "server.sock"))
                send_frame(connection, {"op": "health"})
                health = recv_frame(connection)
            return {**health, "provider": "codex", "installed": True, "pin_matches": True, "pinned_version": CODEX_VERSION,
                    "backend": "shared", "login_per_job": False, "readiness": "native_acceptance_pending"}
        except (OSError, ValueError, WorkerError):
            return {"provider": "codex", "installed": False, "health": "blocked", "auth": "unknown", "backend": "shared"}

    @staticmethod
    def _fixed_environment_request(request: Request) -> Request:
        # The legacy orchestrator sends selectors, not environment values.
        # This exact baseline uses the owner's fixed sanitized environment.
        if request.env_allowlist == ("PATH", "HOME", "LANG", "TERM"):
            return replace(request, env_allowlist=())
        if request.env_allowlist:
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Shared Codex cannot apply per-job environment overrides")
        return request

    def argv(self, request: Request, config_dir: Path) -> list[str]:
        request = self._fixed_environment_request(request)
        # Reuse the existing coarse sandbox and assigned-tool validation.
        super().argv(request, config_dir)
        if request.journal_path is None or request.lock_fd is None or request.workspace_path is None:
            raise WorkerError("PERMISSION_DENIED", "Shared jobs need a durable journal and inherited worktree lock")
        config = baseline()
        config["mcp_servers"] = _mcp_launch_configs(request, config_dir)
        config["skills"] = request.native_skill_config or {"bundled": {"enabled": False}, "config": []}
        config["features.skip_host_skill_discovery"] = not bool(request.native_skill_config)
        start: Json = {"cwd": str(request.workspace_path), "approvalPolicy": "never", "ephemeral": True,
                       "sandbox": "workspace-write" if request.permission_profile == "trusted-development" else "read-only", "config": config}
        if request.model:
            start["model"] = request.model
        path = config_dir / "shared-job.json"
        path.write_text(json.dumps({"root": str(self.root), "execution_id": request.execution_id, "start": start,
                                    "schema": request.structured_schema or None, "timeout": request.timeout_sec}), encoding="utf-8")
        path.chmod(0o600)
        return [sys.executable, "-I", "-m", "adf_runtime_worker.shared_job", "--config", str(path),
                "--journal", str(request.journal_path), "--lock-fd", str(request.lock_fd)]

    def execute(self, request: Request, event_sink: EventSink, cancellation: Event) -> AdapterResult:
        request = self._fixed_environment_request(request)
        if request.permission_profile == "trusted-development":
            health = self.probe(request.wall_deadline)
            if health.get("policy") == "blocked":
                raise WorkerError("PERMISSION_DENIED", "Shared operator policy generation is blocked")
            if health.get("write_capability", {}).get("supported") is False:
                # Refuse before session config/skills materialization. The owner
                # independently validates forged/direct IPC requests as well.
                raise WorkerError("CAPABILITY_UNSUPPORTED", "Sealed shared policy does not support workspace-write")
        result = super().execute(request, event_sink, cancellation)
        data = Journal(request.journal_path).read() if request.journal_path else {}
        reference = data.get("shared_session")
        if reference and not shared_stopped(reference):
            return replace(result, status="uncertain", error_code="EXECUTION_UNCERTAIN", process_stopped=False)
        if reference:
            from .shared_server import job_path
            job = Journal(job_path(self.root, request.execution_id)).read()
            if job.get("status") == "uncertain":
                return replace(result, status="uncertain", error_code="EXECUTION_UNCERTAIN")
            if job.get("status") == "failed" and result.status == "failed":
                return replace(result, error_code=str(job.get("code") or "PROVIDER_FAILED"))
        if result.status == "succeeded" and request.workspace_path:
            from .profile_policy import check_receipt
            try:
                check_receipt(self.root, Journal(self.root / "journals" / (request.workspace_path.name + ".json")).read())
            except WorkerError:
                return replace(result, status="failed", error_code="PERMISSION_DENIED", output="")
        return result
