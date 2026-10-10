"""Pinned subprocess adapters. Provider output is untrusted bounded input."""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from threading import Event
from .models import Adapter, AdapterResult, EventSink, Json, Request, Usage, WorkerError
from .process import ProcessRunner
from .security import restricted_env

__all__ = ["Adapter", "Request", "Usage", "MockAdapter", "CodexAdapter", "ClaudeAdapter", "provider_adapter"]
CODEX_VERSION = "0.157.0"
CLAUDE_VERSION = "2.1.296"
NODE_VERSION = "24.21.0"

def _tokens(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None

def _estimate(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 else None

class JsonNormalizer:
    def __init__(self, provider: str, sink: EventSink, max_steps: int, correlation: Json | None = None) -> None:
        self.provider = provider
        self.correlation = correlation or {}
        self.sink = sink
        self.max_steps = max_steps
        self.steps = 0
        self.terminal = False
        self.failed = False
        self.final_text = ""
        self.usage = Usage()

    def _tool_span(self) -> None:
        from .telemetry import span
        with span("tool.call", {**self.correlation, "provider": self.provider}):
            pass

    def line(self, stream: str, text: str) -> None:
        if stream == "stderr":
            self.sink("warning", {"provider": self.provider, "message": text[:4096]})
            return
        try:
            event: Json = json.loads(text)
        except (json.JSONDecodeError, TypeError) as exc:
            raise WorkerError("INVALID_PROVIDER_EVENT", "Provider stdout is not JSONL") from exc
        if not isinstance(event, dict):
            raise WorkerError("INVALID_PROVIDER_EVENT", "Provider event must be an object")
        kind = event.get("type")
        if self.provider == "codex":
            if kind == "thread.started":
                self.sink("started", {"provider": self.provider, "session_id": event.get("thread_id")})
            elif kind in {"item.started", "item.completed", "item.updated"}:
                item = event.get("item", {})
                item_kind = item.get("type")
                if item_kind in {"command_execution", "mcp_tool_call", "web_search"}:
                    if kind == "item.started":
                        self.steps += 1
                    if self.steps > self.max_steps:
                        raise WorkerError("STEP_QUOTA_EXCEEDED", "Observed provider tool limit exceeded")
                    if kind == "item.completed":
                        self._tool_span()
                    self.sink("tool_started" if kind == "item.started" else "tool_finished", {"provider": self.provider, "tool_id": item_kind, "item_id": item.get("id"), "status": item.get("status"), "exit_code": item.get("exit_code")})
                elif item_kind == "agent_message" and kind == "item.completed":
                    self.final_text = str(item.get("text", ""))[:65536]
                    self.sink("output", {"provider": self.provider, "text": self.final_text})
                elif item_kind == "reasoning":
                    # Private reasoning is never persisted or exported.
                    return
                else:
                    self.sink("warning", {"provider": self.provider, "event_type": str(kind), "item_type": str(item_kind)})
            elif kind == "turn.completed":
                usage = event.get("usage", {})
                self.usage = Usage("provider", _tokens(usage.get("input_tokens")), _tokens(usage.get("output_tokens")), None)
                self.terminal = True
                self.sink("usage_reported", {"source": self.usage.source, "input_tokens": self.usage.input_tokens, "output_tokens": self.usage.output_tokens, "cost": None, "provider_estimated_cost_usd": self.usage.provider_estimated_cost_usd})
            elif kind in {"turn.failed", "error"}:
                self.failed = True
                self.sink("failed", {"provider": self.provider, "code": "PROVIDER_FAILED"})
            elif kind != "turn.started":
                self.sink("warning", {"provider": self.provider, "event_type": str(kind)[:100]})
        else:
            if kind == "system" and event.get("subtype") == "init":
                self.sink("started", {"provider": self.provider, "session_id": event.get("session_id")})
            elif kind == "assistant":
                message = event.get("message", {})
                for content in message.get("content", []):
                    if content.get("type") == "tool_use":
                        self.steps += 1
                        if self.steps > self.max_steps:
                            raise WorkerError("STEP_QUOTA_EXCEEDED", "Observed provider tool limit exceeded")
                        self.sink("tool_started", {"provider": self.provider, "tool_id": content.get("name"), "item_id": content.get("id")})
                    elif content.get("type") == "text":
                        self.final_text = str(content.get("text", ""))[:65536]
                        self.sink("output", {"provider": self.provider, "text": self.final_text})
            elif kind == "user":
                for content in event.get("message", {}).get("content", []):
                    if content.get("type") == "tool_result":
                        self._tool_span()
                        self.sink("tool_finished", {"provider": self.provider, "item_id": content.get("tool_use_id"), "is_error": bool(content.get("is_error"))})
            elif kind == "result":
                self.terminal = event.get("subtype") == "success" and not bool(event.get("is_error"))
                self.failed = not self.terminal
                self.final_text = json.dumps(event["structured_output"]) if isinstance(event.get("structured_output"), dict) else str(event.get("result", self.final_text))[:65536]
                usage = event.get("usage", {})
                # Costs are not treated as guaranteed subscription expenditure.
                self.usage = Usage("provider" if usage else "unknown", _tokens(usage.get("input_tokens")), _tokens(usage.get("output_tokens")), None, _estimate(event.get("total_cost_usd")))
                self.sink("usage_reported", {"source": self.usage.source, "input_tokens": self.usage.input_tokens, "output_tokens": self.usage.output_tokens, "cost": None, "provider_estimated_cost_usd": self.usage.provider_estimated_cost_usd})
            elif kind != "stream_event":
                self.sink("warning", {"provider": self.provider, "event_type": str(kind)[:100]})

class SubprocessAdapter:
    provider = "unknown"
    pinned_version = ""
    executable_name = ""

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or shutil.which(self.executable_name)
        self.runner = ProcessRunner()
        self.usage = Usage()

    def probe(self, deadline: float | None = None) -> Json:
        if not self.executable:
            return {"provider": self.provider, "installed": False, "health": "unavailable", "auth": "unknown"}
        runtime: Json = {}
        try:
            with Path(self.executable).open("rb") as executable_file:
                uses_node = executable_file.read(64).startswith(b"#!/usr/bin/env node")
            if self.provider == "codex" and uses_node:
                node = Path(os.getenv("ADF_NODE_PATH", str(Path.home() / ".local" / "bin" / "node")))
                node_version = subprocess.run([str(node), "--version"], capture_output=True, text=True, timeout=5, shell=False, env=restricted_env()).stdout.strip()
                runtime = {"node_path": str(node), "node_version": node_version, "node_pin_matches": node_version == "v" + NODE_VERSION}
                if not runtime["node_pin_matches"]:
                    return {"provider": self.provider, "installed": True, "health": "blocked", "auth": "unknown", "runtime": runtime, "error_code": "RUNTIME_VERSION_MISMATCH"}
            version = subprocess.run([self.executable, "--version"], capture_output=True, text=True, timeout=max(0.1, min(5.0, deadline - time.monotonic())) if deadline else 5, shell=False, env=restricted_env()).stdout.strip()
            pin_matches = bool(re.search(r"(?<![\d.])" + re.escape(self.pinned_version) + r"(?![\d.])", version))
            auth_argv = [self.executable, "login", "status"] if self.provider == "codex" else [self.executable, "auth", "status"]
            auth = subprocess.run(auth_argv, capture_output=True, text=True, timeout=max(0.1, min(10.0, deadline - time.monotonic())) if deadline else 10, shell=False, env=restricted_env())
            auth_ok = auth.returncode == 0
            if self.provider == "claude":
                auth_ok = auth_ok and bool(json.loads(auth.stdout).get("loggedIn"))
            return {"provider": self.provider, "installed": True, "version": version[:160], "pinned_version": self.pinned_version, "pin_matches": pin_matches, "runtime": runtime, "auth": "ready" if auth_ok else "required", "health": "ready" if auth_ok and pin_matches else "blocked", "capabilities": {"streaming": True, "cancellation": True, "structured_output": True, "resume": False, "usage": "reported_tokens_or_unknown", "financial_cap": False, "observed_tool_limit": True, "narrow_tool_scope": self.provider == "claude", "mcp_scope_verified": False}}
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return {"provider": self.provider, "installed": True, "health": "blocked", "auth": "unknown"}

    def argv(self, request: Request, config_dir: Path) -> list[str]:
        raise NotImplementedError

    def execute(self, request: Request, event_sink: EventSink, cancellation: Event) -> AdapterResult:
        health = self.probe(request.wall_deadline)
        if health.get("health") != "ready":
            code = "CLI_VERSION_MISMATCH" if health.get("pin_matches") is False else "AUTH_REQUIRED"
            raise WorkerError(code, "Pinned provider must be installed and authenticated locally")
        if request.wall_deadline is not None and time.monotonic() >= request.wall_deadline:
            raise WorkerError("EXECUTION_TIMEOUT", "Deadline exhausted during provider probe")
        if request.cli_version and request.cli_version != self.pinned_version:
            raise WorkerError("CLI_VERSION_MISMATCH", "Snapshot CLI version differs from adapter fixtures")
        with tempfile.TemporaryDirectory(prefix="adf-cli-config-", dir=request.journal_path.parent if request.journal_path else None) as directory:
            config_dir = Path(directory)
            os.chmod(config_dir, 0o700)
            argv = self.argv(request, config_dir)
            normalizer = JsonNormalizer(self.provider, event_sink, request.max_steps, request.correlation)
            from .telemetry import span
            with span("cli.session", {**request.correlation, "execution_id": request.execution_id, "run_id": request.run_id, "provider": self.provider}):
                result = self.runner.run(argv, request, normalizer.line, cancellation, stdin_text=request.task_prompt)
            self.usage = normalizer.usage
            if result.status == "succeeded" and (not normalizer.terminal or normalizer.failed):
                result = replace(result, status="failed", error_code="MISSING_PROVIDER_SUCCESS")
            event_sink("completed" if result.status == "succeeded" else "cancelled" if result.status == "cancelled" else "failed", {"provider": self.provider, "exit_code": result.exit_code, "error_code": result.error_code})
            return replace(result, output=normalizer.final_text, usage=self.usage)

    def cancel(self) -> None:
        self.runner.cancel()

    def collect_usage(self) -> Usage:
        return self.usage

class CodexAdapter(SubprocessAdapter):
    provider = "codex"
    pinned_version = CODEX_VERSION
    executable_name = "codex"

    def argv(self, request: Request, config_dir: Path) -> list[str]:
        if request.permission_profile not in {"read_only", "observe", "trusted-development"}:
            raise WorkerError("PERMISSION_DENIED", "Unsupported Codex permission profile")
        if request.allowed_tools:
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Codex cannot enforce a narrow configured tool registry; an explicit coarse worktree profile is required")
        if request.mcp_config:
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Codex MCP scope is not yet fixture-verified; choose Claude for scoped MCP")
        sandbox = "workspace-write" if request.permission_profile == "trusted-development" else "read-only"
        argv = [str(self.executable), "-a", "never", "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral", "--json", "--color", "never", "--sandbox", sandbox, "-c", "sandbox_workspace_write.network_access=false", "-c", "features.multi_agent=false"]
        for feature in ("apps", "browser_use", "browser_use_external", "browser_use_full_cdp_access", "computer_use", "image_generation", "in_app_browser", "hooks", "plugins", "remote_plugin", "skill_search", "skill_mcp_dependency_install", "workspace_dependencies", "daemon_auto_start", "auth_elicitation"):
            argv += ["-c", "features." + feature + "=false"]
        argv += ["-c", "features.skip_host_skill_discovery=true", "-c", 'web_search="disabled"']
        if request.model:
            argv += ["--model", request.model]
        if request.structured_schema:
            schema = config_dir / "response.schema.json"
            schema.write_text(json.dumps(request.structured_schema), encoding="utf-8")
            argv += ["--output-schema", str(schema)]
        return argv + ["-"]

class ClaudeAdapter(SubprocessAdapter):
    provider = "claude"
    pinned_version = CLAUDE_VERSION
    executable_name = "claude"

    def argv(self, request: Request, config_dir: Path) -> list[str]:
        if request.permission_profile not in {"read_only", "observe", "trusted-development"}:
            raise WorkerError("PERMISSION_DENIED", "Unsupported Claude permission profile")
        writing = request.permission_profile == "trusted-development"
        defaults = ["Read", "Glob", "Grep", "Edit", "Write"] if writing else ["Read", "Glob", "Grep"]
        tools = list(request.allowed_tools) or defaults
        if any(tool in {"Bash", "Agent", "Task", "WebFetch", "WebSearch"} for tool in tools):
            raise WorkerError("PERMISSION_DENIED", "Unscoped shell, agents and network tools are forbidden")
        builtin = sorted({tool.split("(", 1)[0] for tool in tools if not tool.startswith("mcp__")})
        if not writing and any(tool in {"Edit", "Write", "NotebookEdit"} for tool in builtin):
            raise WorkerError("PERMISSION_DENIED", "Read-only role cannot use write tools")
        mcp = config_dir / "mcp.json"
        mcp.write_text(json.dumps({"mcpServers": request.mcp_config}), encoding="utf-8")
        settings = {"disableAllHooks": True, "enableAllProjectMcpServers": False, "permissions": {"deny": ["Bash(git commit*)", "Bash(git push*)", "Bash(sudo*)", "Bash(docker*)"]}}
        argv = [str(self.executable), "--safe-mode", "--restricted", "--disable-slash-commands", "--no-chrome", "-p", "--output-format", "stream-json", "--verbose", "--no-session-persistence", "--setting-sources", "", "--settings", json.dumps(settings), "--strict-mcp-config", "--mcp-config", str(mcp), "--permission-prompts", "none", "--permission-mode", "manual", "--tools", ",".join(builtin), "--allowedTools", ",".join(tools), "--max-turns", str(request.max_steps)]
        if request.model:
            argv += ["--model", request.model]
        if request.structured_schema:
            argv += ["--json-schema", json.dumps(request.structured_schema)]
        return argv

class MockAdapter:
    def probe(self) -> Json:
        return {"provider": "mock", "health": "ready", "auth": "offline", "implementation": "deterministic offline adapter"}

    def execute(self, request: Request, event_sink: EventSink, cancellation: Event) -> AdapterResult:
        if cancellation.is_set():
            event_sink("cancelled", {"reason": "requested"})
            return AdapterResult("cancelled", None)
        event_sink("started", {"provider": "mock"})
        try:
            body = json.loads(request.task_prompt)
        except json.JSONDecodeError:
            body = {"result": "mock completed; no provider call"}
        if request.workspace_path and isinstance(body, dict):
            from .security import validate_relative, within_root
            files = body.get("mock_files", {})
            if files and request.permission_profile != "trusted-development":
                raise WorkerError("PERMISSION_DENIED", "Read-only mock cannot modify files")
            for name, content in files.items():
                path = request.workspace_path / validate_relative(name)
                within_root(path, request.workspace_path.resolve(), must_exist=False)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(str(content), encoding="utf-8")
        result_text = json.dumps(body.get("plan", body.get("review", body.get("result", body)))) if isinstance(body, dict) else json.dumps(body)
        event_sink("completed", {"provider": "mock"})
        return AdapterResult("succeeded", 0, output=result_text)

    def cancel(self) -> None:
        pass

    def collect_usage(self) -> Usage:
        return Usage()

def provider_adapter(provider: str, executable: str | None = None) -> Adapter:
    if provider == "codex":
        return CodexAdapter(executable)
    if provider == "claude":
        return ClaudeAdapter(executable)
    if provider == "mock":
        return MockAdapter()
    raise WorkerError("CAPABILITY_UNSUPPORTED", "Unknown CLI provider")
