"""At-least-once Redis consumer. Execution ownership lives in detached supervisors."""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from threading import Event
from urllib.parse import urlparse
from uuid import UUID, uuid4
from typing import cast
import redis
from .adapters import provider_adapter
from .client import ApiClient
from .executor import Executor
from .journal import FileLock, Journal, process_identity, same_process
from .models import Json, WorkerError
from .security import canonical_root
from .supervisor import stopped_proof

STREAM = "adf:executions"
GROUP = "adf-workers"

class WorkerService:
    def __init__(self, root: Path, api_url: str, token_file: Path, redis_url: str, redis_password_file: Path, *, worker_id: str | None = None, max_parallel: int = 3, provider_paths: dict[str, str] | None = None, provider_profiles: dict[str, str] | None = None, codex_backend: str = "subprocess", project_ids: list[str] | None = None, project_roots: list[Path] | None = None, recovery_only: bool = False) -> None:
        self.root = canonical_root(root)
        self.executor = Executor(self.root, provider_paths=provider_paths, provider_profiles=provider_profiles, codex_backend=codex_backend)
        if max_parallel < 1 or max_parallel > 3:
            raise WorkerError("QUOTA_EXCEEDED", "Worker concurrency must be between one and three")
        self.max_parallel = max_parallel
        self.recovery_only = recovery_only
        self.project_roots = [canonical_root(path) for path in (project_roots or [self.root / "projects"])]
        if any(not path.is_relative_to(self.root) or path == self.root for path in self.project_roots):
            raise WorkerError("INVALID_PATH", "Registered project roots must be inside runtime root")
        config_dir = self.root / "config"
        config_dir.mkdir(exist_ok=True)
        identity_file = config_dir / "worker-id.json"
        if worker_id is None:
            if not identity_file.exists():
                if recovery_only:
                    raise WorkerError("EXECUTION_UNCERTAIN", "Recovery requires the existing worker identity")
                Journal(identity_file).update(worker_id=str(uuid4()))
            worker_id = str(Journal(identity_file).read()["worker_id"])
        UUID(worker_id)
        self.worker_id = worker_id
        parsed = urlparse(redis_url)
        if parsed.scheme != "redis" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"} or parsed.password:
            raise WorkerError("PERMISSION_DENIED", "Redis requires loopback and a separate password file")
        self.redis = redis.Redis(host=parsed.hostname, port=parsed.port or 6380, username=parsed.username or "adf_worker", password=redis_password_file.read_text().strip(), db=int(parsed.path.strip("/") or 0), decode_responses=True, socket_timeout=3, socket_connect_timeout=3)
        self.api = ApiClient(api_url, token_file, self.worker_id)
        self.config: Json = {"root": str(self.root), "api_url": api_url, "token_file": str(token_file.resolve()), "worker_id": worker_id, "provider_paths": provider_paths or {}, "provider_profiles": provider_profiles or {}, "codex_backend": codex_backend, "redis_password_file": str(redis_password_file.resolve())}
        self.project_ids = project_ids or []
        self.stopping = Event()
        self.children: dict[str, subprocess.Popen[bytes]] = {}

    def _active(self) -> list[Journal]:
        active: list[Journal] = []
        for path in (self.root / "journals").glob("*.json"):
            journal = Journal(path)
            saved = journal.read()
            if saved.get("worker_config", {}).get("worker_id") == self.worker_id and same_process(saved.get("supervisor", {})):
                active.append(journal)
        return active

    def _reconcile(self, execution_id: str) -> None:
        journal = self.executor.workspaces.journal_for(execution_id)
        saved = journal.read()
        if not saved.get("epoch") or saved.get("worker_config", {}).get("worker_id") != self.worker_id:
            raise WorkerError("EXECUTION_UNCERTAIN", "No locally owned supervisor journal")
        proof = stopped_proof(journal, self.executor)
        terminal = saved.get("terminal_result")
        if terminal and terminal.get("status") != "uncertain" and not saved.get("result_persisted"):
            try:
                self._replay_events(journal, execution_id, int(saved["epoch"]))
                response = self.api.result(execution_id, int(saved["epoch"]), terminal["status"], terminal)
                journal.update(result_persisted=True, terminal_persisted=response.get("terminal", True), phase="result_persisted")
                return
            except WorkerError as exc:
                if exc.code not in {"LEASE_STALE", "EXECUTION_UNCERTAIN"}:
                    raise
        response = self.api.reconcile(execution_id, int(saved["epoch"]), proof)
        if not response.get("terminal"):
            raise WorkerError("EXECUTION_UNCERTAIN", "API did not confirm terminal reconciliation")
        journal.update(reconciled=True, process_stopped=True, terminal_persisted=True, result_persisted=True)

    def _replay_events(self, journal: Journal, execution_id: str, epoch: int) -> None:
        import json
        path = journal.path.with_suffix(".events.jsonl")
        if not path.exists():
            return
        sequence = int(journal.read().get("events_persisted_sequence", 0))
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if len(line.encode()) > 65537:
                    raise WorkerError("INVALID_JOURNAL", "Durable event is too large")
                event = json.loads(line)
                if int(event["sequence"]) > sequence:
                    self.api.events(execution_id, epoch, [event])
                    sequence = int(event["sequence"])
                    journal.update(events_persisted_sequence=sequence)

    def _delivery(self, message_id: str, fields: dict[str, str]) -> None:
        try:
            if set(fields) - {"execution_id", "dispatch_id"}:
                raise WorkerError("INVALID_TRANSPORT", "Unknown Redis job fields")
            execution_id = str(UUID(fields["execution_id"]))
            if "dispatch_id" not in fields:
                raise WorkerError("INVALID_TRANSPORT", "Missing durable dispatch identifier")
        except (ValueError, KeyError, WorkerError):
            self.api.request("POST", f"/internal/workers/{self.worker_id}/dead-letter", {"message_id": message_id, "stream": STREAM, "reason": "INVALID_TRANSPORT", "field_names": sorted(fields)[:20]})
            self.redis.xack(STREAM, GROUP, message_id)
            return
        if any(item.read().get("execution_id") == execution_id for item in self._active()):
            return
        local = self.executor.workspaces.journal_for(execution_id).read()
        if self.recovery_only:
            if not local.get("epoch") or local.get("worker_config", {}).get("worker_id") != self.worker_id:
                return  # Unknown deliveries stay pending; never claim or spawn.
            self._reconcile(execution_id)
            reconciled = self.executor.workspaces.journal_for(execution_id).read()
            if reconciled.get("terminal_persisted") and reconciled.get("result_persisted"):
                self.redis.xack(STREAM, GROUP, message_id)
            return
        if local.get("epoch") and local.get("worker_config", {}).get("worker_id") == self.worker_id:
            # A consumed execution is never relaunched: replay durable intent or prove death.
            self._reconcile(execution_id)
        try:
            claim = self.api.claim(execution_id)
        except WorkerError as exc:
            if exc.code in {"EXECUTION_UNCERTAIN", "LEASE_STALE"}:
                self._reconcile(execution_id)
                claim = self.api.claim(execution_id)
            else:
                raise
        if claim.get("terminal"):
            self.redis.xack(STREAM, GROUP, message_id)
            return
        active = self._active()
        used = {item.read().get("worker_config", {}).get("slot") for item in active}
        slot = next((number for number in range(self.max_parallel) if number not in used), None)
        if slot is None:
            return
        journal = self.executor.workspaces.journal_for(execution_id)
        saved = journal.read()
        if saved.get("process") and not saved.get("result_persisted"):
            # Claiming an epoch cannot make a live filesystem writer safe.
            stopped_proof(journal, self.executor)
        config = {**self.config, "slot": slot}
        journal.update(execution_id=execution_id, epoch=claim["epoch"], claim=claim, request=claim["request"], worker_config=config, redis_message_id=message_id, phase="supervisor_spawn_intent")
        child = subprocess.Popen([sys.executable, "-m", "adf_runtime_worker.cli", "supervise", "--ticket", str(journal.path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False, start_new_session=True)
        journal.update(supervisor=process_identity(child.pid))
        self.children[execution_id] = child

    def _ack_completed(self) -> None:
        for path in (self.root / "journals").glob("*.json"):
            saved = Journal(path).read()
            if saved.get("worker_config", {}).get("worker_id") != self.worker_id:
                continue
            if saved.get("terminal_persisted") and saved.get("result_persisted") and saved.get("redis_message_id") and not saved.get("redis_acked"):
                if self.recovery_only:
                    if not saved.get("epoch"):
                        continue
                    try:
                        stopped_proof(Journal(path), self.executor)
                    except WorkerError:
                        continue
                self.redis.xack(STREAM, GROUP, saved["redis_message_id"])
                Journal(path).update(redis_acked=True)
        for execution_id, child in list(self.children.items()):
            if child.poll() is not None:
                child.wait()
                del self.children[execution_id]

    def _recover_local(self) -> None:
        # Recovery does not depend on provider health, generation replacement,
        # authentication probes or any new API lease claim.
        for path in (self.root / "journals").glob("*.json"):
            saved = Journal(path).read()
            if (not saved.get("epoch") or saved.get("worker_config", {}).get("worker_id") != self.worker_id
                    or saved.get("terminal_persisted") and saved.get("result_persisted")):
                continue
            try:
                self._reconcile(str(saved["execution_id"]))
            except WorkerError:
                continue  # Live/uncertain writers remain pending, without ACK.

    def run(self) -> None:
        with FileLock(self.root / "locks" / "consumer.lock"):
            try:
                self.redis.ping()
                try:
                    self.redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
                except redis.ResponseError as exc:
                    if "BUSYGROUP" not in str(exc):
                        raise
                names = () if self.recovery_only else ("claude", "mock") if self.config["codex_backend"] == "shared" else ("codex", "claude", "mock")
                providers = {name: provider_adapter(name, self.config["provider_paths"].get(name), Path(self.config["provider_profiles"][name]) if name in self.config["provider_profiles"] else None).probe() for name in names}
                if not self.recovery_only and self.config["codex_backend"] == "shared":
                    from .shared_adapter import SharedCodexAdapter
                    providers["codex"] = SharedCodexAdapter(self.root).probe()
                operations = [] if self.recovery_only else ["repo_inspect", "planner", "agent_task", "test", "review", "git_commit", "integrate"]
                self.api.register(self.root, {"providers": providers, "hostname": socket.gethostname(), "contract_version": "1", "operations": operations,
                                             "recovery_only": self.recovery_only}, self.project_ids, self.project_roots)
                if os.name == "posix":
                    signal.signal(signal.SIGTERM, lambda *_: self.stopping.set())
                    signal.signal(signal.SIGINT, lambda *_: self.stopping.set())
                last_heartbeat = 0.0
                claim_cursor = "0-0"
                while not self.stopping.is_set():
                    try:
                        if self.recovery_only:
                            self._recover_local()
                        self._ack_completed()
                        active = self._active()
                        if time.monotonic() - last_heartbeat >= 10:
                            self.api.worker_heartbeat([str(item.read()["execution_id"]) for item in active])
                            last_heartbeat = time.monotonic()
                        if self.recovery_only:
                            # Journal message IDs suffice for recovery. Do not
                            # reassign any unknown/foreign Redis pending work.
                            self.stopping.wait(0.5)
                            continue
                        capacity = self.max_parallel - len(active)
                        if capacity <= 0:
                            self.stopping.wait(0.5)
                            continue
                        reclaimed = cast(tuple[str, list[tuple[str, dict[str, str]]], list[str]], self.redis.xautoclaim(STREAM, GROUP, self.worker_id, min_idle_time=45000, start_id=claim_cursor, count=capacity))
                        claim_cursor = reclaimed[0]
                        messages = reclaimed[1]
                        if not messages:
                            batches = cast(list[tuple[str, list[tuple[str, dict[str, str]]]]], self.redis.xreadgroup(GROUP, self.worker_id, {STREAM: ">"}, count=capacity, block=1000))
                            messages = [item for _, batch in batches for item in batch]
                        for message_id, fields in messages:
                            self._delivery(message_id, fields)
                    except (WorkerError, redis.RedisError):
                        # Supervisor owns active leases independently; transport failures do not restart jobs.
                        self.stopping.wait(1.0)
            finally:
                # Drain-owned supervisors continue renewing/reporting after a consumer stop.
                self.api.__exit__(None, None, None)
                self.redis.close()
