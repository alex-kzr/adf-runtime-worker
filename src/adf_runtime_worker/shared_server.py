"""Single operator-owned Codex process, independent bounded job threads.

The Unix endpoint is for trusted same-UID supervisors, not a hostile-code boundary.
"""
from __future__ import annotations

import array
import json
import os
import queue
import socket
import stat
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from .journal import FileLock, Journal, process_identity, process_stopped, stop_owned_session
from .models import WorkerError
from .profiles import ProviderProfile
from .profile_policy import SealedProfilePolicy
from .security import restricted_env
from .shared_rpc import FRAME_LIMIT, Rpc

UNSAFE_FEATURES = ("multi_agent", "apps", "browser_use", "browser_use_external", "browser_use_full_cdp_access",
                   "computer_use", "image_generation", "in_app_browser", "hooks", "plugins", "remote_plugin",
                   "skill_search", "skill_mcp_dependency_install", "workspace_dependencies", "daemon_auto_start", "auth_elicitation")


def baseline() -> dict[str, Any]:
    return {**{"features." + name: False for name in UNSAFE_FEATURES}, "features.code_mode_host": True,
            "features.skip_host_skill_discovery": True, "skills": {"bundled": {"enabled": False}, "config": []},
            "mcp_servers": {}, "web_search": "disabled", "allow_login_shell": False,
            "sandbox_workspace_write.network_access": False, "thread_unload_delay_secs": 0}


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WorkerError("PERMISSION_DENIED", "Shared provider directory must be owned canonical mode 0700")


def job_path(root: Path, execution_id: str) -> Path:
    if str(UUID(execution_id)) != execution_id:
        raise WorkerError("INVALID_REQUEST", "Shared execution ID must be a canonical UUID")
    return root / "providers" / "codex" / "jobs" / (execution_id + ".json")


def shared_stopped(reference: dict[str, Any]) -> bool:
    try:
        path = job_path(Path(reference["root"]), reference["execution_id"])
        data = Journal(path).read()
        return (data.get("execution_id") == reference["execution_id"] and data.get("generation") == reference["generation"]
                and data.get("quiesced") is True and data.get("proof") in {"thread_closed", "no_thread", "server_session_dead"})
    except (OSError, ValueError, KeyError, TypeError):
        return False


def send_frame(connection: socket.socket, value: dict[str, Any]) -> None:
    data = json.dumps(value, separators=(",", ":")).encode() + b"\n"
    if len(data) > FRAME_LIMIT:
        raise WorkerError("QUOTA_EXCEEDED", "Shared provider frame exceeds its quota")
    connection.sendall(data)


def recv_frame(connection: socket.socket) -> dict[str, Any]:
    # One byte reads avoid buffering a later SCM_RIGHTS handoff accidentally.
    data = bytearray()
    while len(data) <= FRAME_LIMIT:
        chunk = connection.recv(1)
        if not chunk:
            raise WorkerError("EXECUTION_UNCERTAIN", "Shared provider connection closed")
        if chunk == b"\n":
            value = json.loads(data)
            if not isinstance(value, dict):
                break
            return dict(value)
        data.extend(chunk)
    raise WorkerError("INVALID_PROVIDER_EVENT", "Shared provider frame is invalid")


def peer_uid(connection: socket.socket) -> int:
    return int(struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1])


def clean_config(profile: Path, workspace: Path | None = None) -> None:
    # app-server 0.157 has no exec --ignore-user-config/--ignore-rules switches.
    # Reject those layers instead of pretending equivalent isolation exists.
    if any(os.path.lexists(profile / name) for name in ("config.toml", "rules", "skills", "AGENTS.md", "environments.toml")):
        raise WorkerError("PERMISSION_DENIED", "Shared Codex requires an operator profile without configuration or policy layers")
    if workspace:
        for ancestor in (workspace, *workspace.parents):
            if os.path.lexists(ancestor / ".codex") and ancestor / ".codex" != profile:
                raise WorkerError("PERMISSION_DENIED", "Shared job cannot inherit project or ancestor Codex configuration")


def native_event(message: dict[str, Any]) -> dict[str, Any] | None:
    method, params = message.get("method"), message.get("params", {})
    if method in {"item/started", "item/completed"}:
        item = params.get("item", {})
        kinds = {"agentMessage": "agent_message", "commandExecution": "command_execution", "mcpToolCall": "mcp_tool_call"}
        kind = kinds.get(item.get("type"))
        if kind is None:
            return None
        value = {"type": kind, "id": item.get("id"), "status": item.get("status")}
        if kind == "agent_message":
            value["text"] = str(item.get("text", ""))[:65536]
        elif kind == "command_execution":
            value["exit_code"] = item.get("exitCode")
        else:
            value.update(server=item.get("server"), tool=item.get("tool"))
        return {"type": "item.started" if method == "item/started" else "item.completed", "item": value}
    return None


class SharedServer:
    def __init__(self, root: Path, argv: list[str], environment: dict[str, str], *, profile: Path | None = None,
                 cleanup_timeout: float = 20, policy: SealedProfilePolicy | None = None) -> None:
        self.root, self.argv, self.environment = root, argv, environment
        self.profile = profile
        self.policy = policy
        self.dispatch_lock = policy.lock if policy else threading.RLock()
        self.policy_blocked = threading.Event()
        self.directory = root / "providers" / "codex"
        self.socket_path = self.directory / "server.sock"
        self.state = Journal(self.directory / "server.json")
        self.generation = str(uuid4())
        self.cleanup_timeout = cleanup_timeout
        self.stopping = threading.Event()
        self.auth_blocked = threading.Event()
        self.slots = threading.BoundedSemaphore(3)
        self.connections = threading.BoundedSemaphore(8)
        self.handlers: list[threading.Thread] = []
        self.retained: list[int] = []
        self.retained_lock = threading.Lock()
        self.process: subprocess.Popen[bytes] | None = None
        self.rpc: Rpc | None = None

    def _check_policy(self) -> None:
        if self.policy_blocked.is_set():
            raise WorkerError("PERMISSION_DENIED", "Shared operator policy generation is blocked")
        if self.policy:
            try:
                self.policy.check()
            except WorkerError:
                self.policy_blocked.set()
                self.state.update(policy_blocked=True)
                raise

    def _monitor_policy(self) -> None:
        while not self.stopping.wait(0.05):
            # Do not wait for a slow native start: running siblings must fence.
            try:
                self._check_policy()
            except WorkerError:
                return

    def _recover(self) -> None:
        old = self.state.read()
        if not old or old.get("stopped") is True:
            return
        if not process_stopped(old.get("owner", {})) or not old.get("server"):
            raise WorkerError("EXECUTION_UNCERTAIN", "Previous shared provider ownership is not proven stopped")
        if not stop_owned_session(old["server"], grace_sec=1):
            raise WorkerError("EXECUTION_UNCERTAIN", "Previous shared provider session cannot be proven stopped")
        for path in (self.directory / "jobs").glob("*.json"):
            journal = Journal(path)
            data = journal.read()
            if data.get("generation") == old.get("generation") and data.get("quiesced") is not True:
                journal.update(status="uncertain", quiesced=True, proof="server_session_dead")

    def run(self) -> None:
        private_directory(self.directory)
        private_directory(self.directory / "jobs")
        with FileLock(self.root / "locks" / "provider-codex.lock"):
            self._recover()
            if self.policy:
                self.policy.check()
            elif self.profile:
                clean_config(self.profile)
            self.state.update(generation=self.generation, owner=process_identity(os.getpid()), server=None, stopped=False, policy_blocked=False)
            monitor: threading.Thread | None = None
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                self.process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                cwd=self.directory, env=self.environment, shell=False, start_new_session=True)
                identity = process_identity(self.process.pid)
                self.state.update(server=identity)
                self.rpc = Rpc(self.process)
                self.rpc.call("initialize", {"clientInfo": {"name": "adf-worker", "version": "0.1.0"}})
                self.rpc.send({"method": "initialized", "params": {}})
                if self.policy:
                    with self.dispatch_lock:
                        self._check_policy()
                    monitor = threading.Thread(target=self._monitor_policy, daemon=True)
                    monitor.start()
                if self.socket_path.exists():
                    if not stat.S_ISSOCK(self.socket_path.lstat().st_mode):
                        raise WorkerError("PERMISSION_DENIED", "Shared provider socket path is occupied")
                    self.socket_path.unlink()
                listener.bind(str(self.socket_path))
                self.socket_path.chmod(0o600)
                listener.listen(3)
                listener.settimeout(0.2)
                while not self.stopping.is_set() and not self.rpc.failed.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    if peer_uid(connection) != os.geteuid() or not self.connections.acquire(blocking=False):
                        connection.close()
                        continue
                    handler = threading.Thread(target=self._handle, args=(connection,), daemon=True)
                    self.handlers = [item for item in self.handlers if item.is_alive()]
                    self.handlers.append(handler)
                    handler.start()
            finally:
                self.stopping.set()
                if monitor:
                    monitor.join(timeout=3)
                listener.close()
                for handler in self.handlers:
                    handler.join(timeout=self.cleanup_timeout + 2)
                stopped = False
                if self.process is not None:
                    identity = self.state.read().get("server", {})
                    stopped = bool(identity) and stop_owned_session(identity, grace_sec=1)
                    if stopped:
                        self.process.wait(timeout=3)
                        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                            if stream:
                                stream.close()
                        for path in (self.directory / "jobs").glob("*.json"):
                            journal = Journal(path)
                            data = journal.read()
                            if data.get("generation") == self.generation and data.get("quiesced") is not True:
                                journal.update(status="uncertain", quiesced=True, proof="server_session_dead")
                        with self.retained_lock:
                            for fd in self.retained:
                                os.close(fd)
                            self.retained.clear()
                self.state.update(stopped=stopped)
                if self.socket_path.exists():
                    self.socket_path.unlink()

    def _handle(self, connection: socket.socket) -> None:
        fd: int | None = None
        thread_id = ""
        turn_id = ""
        journal: Journal | None = None
        closed = False
        events: queue.Queue[dict[str, Any]] | None = None
        status = "failed"
        code = "PROVIDER_FAILED"
        slot = False
        try:
            if self.rpc is None:
                raise WorkerError("EXECUTION_UNCERTAIN", "Shared provider is unavailable")
            connection.settimeout(3)
            frame = recv_frame(connection)
            if frame.get("op") == "health":
                auth = self.rpc.call("account/read", {"refreshToken": False})
                authenticated = bool(auth.get("account")) and not self.auth_blocked.is_set()
                with self.dispatch_lock:
                    try:
                        self._check_policy()
                    except WorkerError:
                        pass
                ready = authenticated and not self.policy_blocked.is_set()
                send_frame(connection, {"health": "ready" if ready else "blocked", "auth": "ready" if authenticated else "required",
                                        "generation": self.generation, "policy": "blocked" if self.policy_blocked.is_set() else "sealed" if self.policy else "default",
                                        "permission_profiles": ["observe", "read_only"] if self.policy else ["observe", "read_only", "trusted-development"],
                                        "write_capability": {"supported": self.policy is None,
                                                             "error_code": "CAPABILITY_UNSUPPORTED" if self.policy else None},
                                        "ready_for_real_execution": False})
                return
            if frame.get("op") != "job":
                raise WorkerError("INVALID_REQUEST", "Unknown shared operation")
            slot = self.slots.acquire(blocking=False)
            if not slot:
                raise WorkerError("QUOTA_EXCEEDED", "Shared job quota exceeded")
            path = job_path(self.root, frame["execution_id"])
            with FileLock(path.with_suffix(".claim.lock")):
                if path.exists():
                    raise WorkerError("EXECUTION_UNCERTAIN", "Shared execution IDs are never replayed")
                journal = Journal(path)
                journal.update(execution_id=frame["execution_id"], generation=self.generation, status="accepted", quiesced=False)
            send_frame(connection, {"accepted": True, "generation": self.generation})
            # Client fsyncs the execution's shared reference BEFORE begin/FD.
            payload, ancillary, flags, _ = connection.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize))
            descriptors: list[int] = []
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    received = array.array("i")
                    received.frombytes(data[:len(data) - len(data) % received.itemsize])
                    descriptors.extend(received)
            if payload != b"B" or flags & socket.MSG_CTRUNC or len(descriptors) != 1:
                for descriptor in descriptors:
                    os.close(descriptor)
                raise WorkerError("PERMISSION_DENIED", "Shared job requires its inherited worktree lock")
            fd = descriptors[0]
            os.set_inheritable(fd, False)
            lock_id = self.policy.target(frame["execution_id"]) if self.policy else frame["execution_id"]
            try:
                expected = (self.root / "locks" / ("execution-" + lock_id + ".lock")).lstat()
            except OSError as exc:
                raise WorkerError("PERMISSION_DENIED", "Shared job allocation lock is unavailable") from exc
            received_info = os.fstat(fd)
            if (not stat.S_ISREG(expected.st_mode) or received_info.st_ino != expected.st_ino or received_info.st_dev != expected.st_dev
                    or received_info.st_uid != os.geteuid() or received_info.st_nlink != 1):
                raise WorkerError("PERMISSION_DENIED", "Shared job FD is not its recorded execution lock")
            if self.auth_blocked.is_set():
                raise WorkerError("AUTH_REQUIRED", "Persistent provider dispatch is blocked until operator recovery")
            try:
                auth = self.rpc.call("account/read", {"refreshToken": False})
            except WorkerError as exc:
                raise WorkerError("AUTH_REQUIRED", "Persistent provider account is unavailable") from exc
            if not auth.get("account"):
                raise WorkerError("AUTH_REQUIRED", "Persistent provider profile is not authenticated")
            params = frame["start"]
            workspace = Path(params["cwd"])
            if (not workspace.is_absolute() or workspace.resolve() != workspace or str(workspace).startswith("/mnt/")
                    or not workspace.is_relative_to(self.root / "worktrees") or (self.policy is None and workspace.name != frame["execution_id"])):
                raise WorkerError("PERMISSION_DENIED", "Shared job needs a canonical Linux worktree")
            if self.profile and self.policy is None:
                clean_config(self.profile, workspace)
            if params.get("approvalPolicy") != "never" or params.get("ephemeral") is not True or params.get("sandbox") not in {"workspace-write", "read-only"}:
                raise WorkerError("PERMISSION_DENIED", "Shared thread permissions are invalid")
            fixed = baseline()
            config = params.get("config", {})
            dynamic = {"skills", "mcp_servers", "features.skip_host_skill_discovery"}
            if (set(params) - {"cwd", "approvalPolicy", "ephemeral", "sandbox", "config", "model"}
                    or set(config) != set(fixed) or any(config.get(key) != value for key, value in fixed.items() if key not in dynamic)
                    or config.get("skills", {}).get("bundled", {}).get("enabled") is not False):
                raise WorkerError("PERMISSION_DENIED", "Shared thread cannot override fixed operator permissions")
            for launch in config["mcp_servers"].values():
                import sys
                args = launch.get("args", [])
                if (launch.get("command") != sys.executable or len(args) != 5
                        or args[:4] != ["-I", "-m", "adf_runtime_worker.scoped_mcp", "--config"]):
                    raise WorkerError("PERMISSION_DENIED", "Shared thread only accepts the owned scoped MCP launcher")
                source = Path(args[4])
                info = source.lstat()
                if (source.resolve() != source or not source.is_relative_to(self.root / "journals") or not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
                    raise WorkerError("PERMISSION_DENIED", "Shared MCP configuration is not a private journal-scoped file")
            with self.dispatch_lock:
                self._check_policy()
                if self.policy and params["sandbox"] == "workspace-write":
                    # Pinned Linux sandbox creates a transient host .codex mount
                    # target. Strict no_layers cannot authorize that write mode.
                    raise WorkerError("CAPABILITY_UNSUPPORTED", "Sealed shared policy does not support workspace-write")
                if self.policy:
                    self.policy.bind(frame["execution_id"], workspace, self.generation)
                    # The client was validated above; only the owner adds trust.
                    params = {**params, "config": {**config, "projects": self.policy.projects}}
                self._check_policy()
                journal.update(status="thread_spawn_intent")
                started = self.rpc.call("thread/start", params)
                thread_id = str(started["thread"]["id"])
                journal.update(thread_id=thread_id, status="starting")
                events = self.rpc.subscribe(thread_id)
                self._check_policy()
                turn = self.rpc.call("turn/start", {"threadId": thread_id, "input": [{"type": "text", "text": frame["prompt"]}], "outputSchema": frame.get("schema")})
                turn_id = str(turn["turn"]["id"])
                journal.update(turn_id=turn_id, status="running")
                self._check_policy()
            send_frame(connection, {"event": {"type": "thread.started", "thread_id": thread_id}})
            connection.settimeout(0.1)
            disconnected = False
            cancelled = False
            finished = False
            deadline = time.monotonic() + min(86400, max(1, float(frame["timeout"])))
            cancel_deadline = float("inf")
            usage: dict[str, Any] = {}
            while not finished and not self.rpc.failed.is_set():
                self._check_policy()
                try:
                    command = connection.recv(1)
                    if not command or command == b"C":
                        disconnected = not command
                        cancelled = True
                except socket.timeout:
                    pass
                except OSError:
                    disconnected, cancelled = True, True
                if self.stopping.is_set() or time.monotonic() >= deadline:
                    cancelled = True
                if cancelled and cancel_deadline == float("inf"):
                    self.rpc.call("turn/interrupt", {"threadId": thread_id, "turnId": turn_id})
                    cancel_deadline = time.monotonic() + self.cleanup_timeout
                if time.monotonic() >= cancel_deadline:
                    break
                try:
                    message = events.get(timeout=0.1)
                except queue.Empty:
                    continue
                if message.get("params", {}).get("turnId") not in {None, turn_id}:
                    raise WorkerError("EXECUTION_UNCERTAIN", "Provider turn correlation failed")
                event = native_event(message)
                if event and not disconnected:
                    try:
                        send_frame(connection, {"event": event})
                    except OSError:
                        disconnected, cancelled = True, True
                if message.get("method") == "turn/completed":
                    if message["params"]["turn"].get("id") != turn_id:
                        raise WorkerError("EXECUTION_UNCERTAIN", "Provider completed another turn")
                    finished = True
                    state = message["params"]["turn"]["status"]
                    status = "cancelled" if cancelled or state == "interrupted" else "succeeded" if state == "completed" else "failed"
                    code = "CANCEL_REQUESTED" if status == "cancelled" else "PROVIDER_FAILED"
                    if (message["params"]["turn"].get("error") or {}).get("codexErrorInfo") == "unauthorized":
                        self.auth_blocked.set()
                        status, code = "failed", "AUTH_REQUIRED"
                elif message.get("method") == "thread/tokenUsage/updated":
                    tokens = message["params"].get("tokenUsage", {}).get("last", {})
                    usage = {"input_tokens": tokens.get("inputTokens"), "output_tokens": tokens.get("outputTokens")}
            if not finished:
                raise WorkerError("EXECUTION_UNCERTAIN", "Provider turn did not close")
        except (WorkerError, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            code = exc.code if isinstance(exc, WorkerError) else "EXECUTION_UNCERTAIN"
            if code == "AUTH_REQUIRED":
                self.auth_blocked.set()
            status = "uncertain" if code == "EXECUTION_UNCERTAIN" else "failed"
        finally:
            if journal is not None and journal.read().get("generation") == self.generation:
                # Even failures after thread/start must close the owned thread.
                if thread_id and self.rpc and not self.rpc.failed.is_set():
                    try:
                        if turn_id and (status == "uncertain" or self.policy_blocked.is_set()):
                            self.rpc.call("turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=3)
                        self.rpc.call("thread/unsubscribe", {"threadId": thread_id}, timeout=3)
                        until = time.monotonic() + self.cleanup_timeout
                        while events is not None and time.monotonic() < until and not self.rpc.failed.is_set():
                            try:
                                if events.get(timeout=0.1).get("method") == "thread/closed":
                                    closed = True
                                    break
                            except queue.Empty:
                                continue
                    except WorkerError:
                        pass
                elif not thread_id:
                    # A timed-out thread/start might still create a thread. Its
                    # response uncertainty cannot produce a no-thread proof.
                    closed = journal.read().get("status") == "accepted"
                if not closed:
                    status, code = "uncertain", "EXECUTION_UNCERTAIN"
                with self.dispatch_lock:
                    try:
                        self._check_policy()
                    except WorkerError:
                        if closed:
                            status, code = "failed", "PERMISSION_DENIED"
                    journal.update(status=status, code=None if status == "succeeded" else code, quiesced=closed,
                                   proof="thread_closed" if closed and thread_id else "no_thread" if closed else None)
                if thread_id and self.rpc:
                    self.rpc.forget(thread_id)
                if fd is not None:
                    if closed:
                        os.close(fd)
                    else:
                        with self.retained_lock:
                            self.retained.append(fd)
                    fd = None
                try:
                    if status == "succeeded" and closed:
                        send_frame(connection, {"event": {"type": "turn.completed", "usage": usage}})
                    send_frame(connection, {"done": True, "status": status, "code": None if status == "succeeded" else code, "quiesced": closed})
                except OSError:
                    pass
            if fd is not None:
                os.close(fd)
            connection.close()
            if slot:
                self.slots.release()
            self.connections.release()


def server_command(executable: str, profile: ProviderProfile, policy: SealedProfilePolicy | None = None) -> tuple[list[str], dict[str, str], Path]:
    from .adapters import CodexAdapter
    from .capabilities import toml_value
    if profile.directory is None:
        raise WorkerError("PERMISSION_DENIED", "Shared backend requires an explicit private operator profile")
    environment = {**restricted_env(), **profile.environment()}
    if policy:
        if policy.profile != profile.directory:
            raise WorkerError("PERMISSION_DENIED", "Shared policy profile differs from the operator profile")
        policy.check()
    else:
        clean_config(profile.directory)
    health = CodexAdapter(executable, profile).probe()
    if health.get("health") != "ready":
        raise WorkerError("AUTH_REQUIRED" if health.get("pin_matches") is not False else "CLI_VERSION_MISMATCH", "Pinned shared provider must be authenticated by its operator")
    argv = [executable, "app-server", "--strict-config", "--listen", "stdio://"]
    for name, value in baseline().items():
        argv += ["-c", name + "=" + toml_value(value)]
    if policy:
        policy.check()
        argv += ["-c", "projects=" + toml_value(policy.projects)]
    return argv, environment, profile.directory
