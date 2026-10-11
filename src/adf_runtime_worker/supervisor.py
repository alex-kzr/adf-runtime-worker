"""Detached execution owner. Consumer restarts cannot orphan a writing CLI."""
from __future__ import annotations
import json
import os
import signal
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from uuid import uuid4
from typing import cast
from .client import ApiClient, Ledger
from .executor import Executor
from .journal import FileLock, Journal, owned_sessions_stopped, process_identity, process_stopped
from .models import Json, WorkerError
from .security import Redactor

class LeaseMonitor:
    def __init__(self, ledger: Ledger, execution_id: str, epoch: int, expires_at: str, cancellation: Event, journal: Journal) -> None:
        self.ledger = ledger
        self.execution_id = execution_id
        self.epoch = epoch
        self.cancellation = cancellation
        self.journal = journal
        saved = journal.read().get("supervisor", {})
        self.supervisor_identity = {key: saved.get(key) for key in ("pid", "start_ticks", "pgid", "session_id")}
        self.supervisor_identity["journal_id"] = journal.path.name
        self.stop = Event()
        self.deadline = self._deadline(expires_at)
        self.failure: str | None = None
        self.thread = threading.Thread(target=self._poll, daemon=True)

    @staticmethod
    def _deadline(value: str) -> float:
        expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
        remaining = (expires - datetime.now(timezone.utc)).total_seconds()
        return time.monotonic() + max(0, remaining)

    def __enter__(self) -> LeaseMonitor:
        # An inherited dispatch does not authorize writing after terminal reconciliation.
        heartbeat = self.ledger.heartbeat(self.execution_id, self.epoch, self.supervisor_identity)
        self.deadline = self._deadline(heartbeat["lease_expires_at"])
        if heartbeat.get("cancel_requested"):
            self.cancellation.set()
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop.set()
        self.thread.join(timeout=12)

    def _poll(self) -> None:
        last_renewal = 0.0
        while not self.stop.is_set():
            try:
                control = self.ledger.control(self.execution_id, self.epoch)
                if control.get("status") in {"succeeded", "failed", "cancelled", "uncertain"}:
                    self.failure = "EXECUTION_NOT_ACTIVE"
                    self.deadline = time.monotonic()
                    self.cancellation.set()
                    return
                if control.get("cancel_requested"):
                    self.cancellation.set()
                if time.monotonic() - last_renewal >= 10:
                    heartbeat = self.ledger.heartbeat(self.execution_id, self.epoch, self.supervisor_identity)
                    self.deadline = self._deadline(heartbeat["lease_expires_at"])
                    last_renewal = time.monotonic()
            except WorkerError as exc:
                if exc.code in {"LEASE_STALE", "EXECUTION_UNCERTAIN", "AUTH_REQUIRED", "PERMISSION_DENIED"}:
                    self.failure = exc.code
                    self.deadline = time.monotonic()
                    return
                if time.monotonic() >= self.deadline - 5:
                    self.failure = "LEASE_LOST"
                    return
            self.stop.wait(1.0)

class ExecutionSupervisor:
    def __init__(self, ledger: Ledger, executor: Executor, journal: Journal, *, secret_values: tuple[str, ...] = ()) -> None:
        self.ledger = ledger
        self.executor = executor
        self.journal = journal
        self.cancellation = Event()
        self.redactor = Redactor(secret_values + tuple(getattr(ledger, "redaction_values", ())))
        executor.secret_values = tuple(self.redactor.values)
        executor.workspaces.secret_values = executor.secret_values

    def run(self, claim: Json) -> Json:
        execution_id = str(claim["execution_id"])
        epoch = int(claim["epoch"])
        job = {**claim["request"], "execution_id": execution_id, "lease_epoch": epoch}
        self.journal.update(supervisor=process_identity(os.getpid()), epoch=epoch, execution_id=execution_id, phase="supervising")
        sequence = int(self.journal.read().get("event_sequence", 0))
        event_file = self.journal.path.with_suffix(".events.jsonl")
        def sink(kind: str, payload: Json) -> None:
            nonlocal sequence
            safe = self.redactor.data(payload)
            sequence += 1
            event = {"event_id": str(uuid4()), "sequence": sequence, "type": kind, "time": datetime.now(timezone.utc).isoformat(), "payload": safe}
            encoded = json.dumps(event).encode()
            if len(encoded) > 65536:
                raise WorkerError("EVENT_TOO_LARGE", "Normalized event exceeds 64KiB")
            with event_file.open("ab") as stream:
                os.chmod(event_file, 0o600)
                stream.write(encoded + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            self.journal.update(event_sequence=sequence)
            self.ledger.events(execution_id, epoch, [event])
            self.journal.update(events_persisted_sequence=sequence)
        with LeaseMonitor(self.ledger, execution_id, epoch, claim["lease_expires_at"], self.cancellation, self.journal) as monitor:
            try:
                result = self.executor.run(job, sink, self.cancellation, lease_deadline=lambda: monitor.deadline)
            except WorkerError as exc:
                result = {"status": "uncertain" if exc.code in {"EXECUTION_UNCERTAIN", "LEASE_STALE", "LEASE_LOST", "GIT_TIMEOUT"} else "cancelled" if exc.code == "CANCEL_REQUESTED" else "failed", "error_code": exc.code, "process_stopped": owned_sessions_stopped(self.journal.read())}
                if exc.code in {"CANCEL_REQUESTED", "LEASE_LOST", "LEASE_STALE", "GIT_TIMEOUT", "EXECUTION_TIMEOUT"}:
                    try:
                        target = str(job.get("target_execution_id") or execution_id)
                        result.update(self.executor.workspaces.reconcile_git_evidence(target))
                    except WorkerError:
                        pass
                if exc.code == "INTEGRATION_CONFLICT":
                    result["integration_status"] = "needs_resolution"
                    target = str(job.get("target_execution_id") or execution_id)
                    data = self.executor.workspaces.journal_for(target).read()
                    result.update(branch=data.get("workspace", {}).get("branch"), worktree_key=target, conflicting_paths=[path for intent in data.get("delta_intents", {}).values() for path in intent.get("conflicting_paths", [])])
            except Exception:
                # Exception descriptions can contain paths, prompts or secrets.
                result = {"status": "uncertain", "error_code": "SUPERVISOR_FAILED", "process_stopped": owned_sessions_stopped(self.journal.read())}
            if not result.get("process_stopped", True):
                result["status"] = "uncertain"
            if monitor.failure:
                result.update(status="uncertain", error_code=monitor.failure)
            if self.cancellation.is_set() and result.get("process_stopped"):
                result["status"] = "cancelled"
            result = self.redactor.data(result)
            if result.get("status") != "uncertain" and (result.get("status") == "succeeded" or any(key in result for key in ("test_results", "review", "plan"))):
                try:
                    result["artifacts"] = self._artifacts(job, result, execution_id, epoch)
                except WorkerError as exc:
                    result.update(status="failed", error_code=exc.code)
            if not owned_sessions_stopped(self.journal.read()):
                result.update(status="uncertain", process_stopped=False, error_code="EXECUTION_UNCERTAIN")
            self.journal.update(terminal_result=result, phase="result_intent")
            try:
                response = self.ledger.result(execution_id, epoch, result["status"], result)
                self.journal.update(result_persisted=True, terminal_persisted=response.get("terminal", result["status"] in {"succeeded", "failed", "cancelled"}), phase="result_persisted")
            except WorkerError as exc:
                self.journal.update(result_persisted=False, result_error=exc.code)
            return cast(Json, result)

    def _artifacts(self, job: Json, result: Json, execution_id: str, epoch: int) -> list[Json]:
        artifacts: list[Json] = []
        kinds = {"test_results": "test_results", "review": "review_result", "plan": "plan"}
        for field, kind in kinds.items():
            if field in result:
                content = json.dumps(self.redactor.data(result[field]), sort_keys=True).encode()
                artifacts.append(self.ledger.artifact(execution_id, epoch, kind, content))
        if job["operation"] == "agent_task" and result.get("status") == "succeeded" or job["operation"] == "git_commit" and result.get("commit_sha"):
            target = str(job.get("target_execution_id") or execution_id)
            with self.executor.workspaces.worktree_lock(target) as lock:
                self.executor.workspaces.worktree_lock_fd = lock.fd
                try:
                    workspace = self.executor.workspaces.load(target)
                    diff = self.executor.workspaces.git(workspace.path, "diff", "--cached", "--binary") if job["operation"] == "agent_task" else self.executor.workspaces.git(workspace.path, "show", "--format=", "--binary", str(result["commit_sha"]))
                    content = self.redactor.text(diff).encode()
                    artifacts.append(self.ledger.artifact(execution_id, epoch, "change_diff", content, "text/x-diff"))
                finally:
                    self.executor.workspaces.worktree_lock_fd = None
        return artifacts

def stopped_proof(journal: Journal, executor: Executor) -> Json:
    saved = journal.read()
    if not process_stopped(saved.get("supervisor", {})) or not owned_sessions_stopped(saved):
        raise WorkerError("EXECUTION_UNCERTAIN", "Supervisor or owned CLI/Git session still alive")
    target = str(saved.get("request", {}).get("target_execution_id") or saved["execution_id"])
    with executor.workspaces.worktree_lock(target):
        identity = saved.get("supervisor", {})
        return {"journal_id": journal.path.name, "pid": identity.get("pid"), "start_ticks": identity.get("start_ticks"), "pgid": identity.get("pgid"), "session_id": identity.get("session_id"), "child_process": saved.get("process", {}), "child_group_stopped": True, "worktree_lock_reacquired": True, "terminal_evidence": saved.get("terminal_result", {})}

def supervise_ticket(ticket: Path) -> None:
    saved = Journal(ticket).read()
    config = saved["worker_config"]
    root = Path(config["root"])
    executor = Executor(root, provider_paths=config.get("provider_paths", {}), provider_profiles=config.get("provider_profiles", {}))
    journal = Journal(ticket)
    with FileLock(root / "locks" / f"slot-{config['slot']}.lock"):
        with ApiClient(config["api_url"], Path(config["token_file"]), config["worker_id"]) as ledger:
            infra_secrets = (Path(config["redis_password_file"]).read_text().strip(),) if config.get("redis_password_file") else ()
            supervisor = ExecutionSupervisor(ledger, executor, journal, secret_values=infra_secrets)
            if os.name == "posix":
                for sig in (signal.SIGTERM, signal.SIGINT):
                    signal.signal(sig, lambda *_: supervisor.cancellation.set())
            supervisor.run(saved["claim"])
