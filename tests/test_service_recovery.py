"""At-least-once Redis deliveries never relaunch a consumed execution."""
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from adf_runtime_worker.executor import Executor
from adf_runtime_worker.models import WorkerError
from adf_runtime_worker.service import WorkerService
from adf_runtime_worker.supervisor import ExecutionSupervisor
from test_client_supervisor import FakeLedger

class RedisFixture:
    def __init__(self):
        self.acks = []
    def xack(self, stream, group, message):
        self.acks.append(message)

class RecoveryLedger(FakeLedger):
    def __init__(self):
        super().__init__()
        self.calls = []
    def claim(self, execution_id):
        self.calls.append("claim")
        return {"terminal": True}
    def events(self, execution_id, epoch, events):
        self.calls.append("events")
        return super().events(execution_id, epoch, events)
    def result(self, execution_id, epoch, status, result):
        self.calls.append("result")
        return {"persisted": True, "terminal": True}
    def reconcile(self, execution_id, epoch, evidence):
        self.calls.append("reconcile")
        assert evidence["child_group_stopped"] is True
        return {"persisted": True, "terminal": True, "status": "failed"}


def service_fixture(repository):
    service = object.__new__(WorkerService)
    service.root = repository[0]
    service.executor = Executor(service.root, require_ext4=False)
    service.worker_id = str(uuid4())
    service.api = RecoveryLedger()
    service.redis = RedisFixture()
    service.children = {}
    service.max_parallel = 3
    return service


def journal_fixture(service, status="succeeded", persisted=False):
    execution_id = str(uuid4())
    journal = service.executor.workspaces.journal_for(execution_id)
    journal.update(execution_id=execution_id, epoch=1, worker_config={"worker_id": service.worker_id}, redis_message_id="1-0", supervisor={"pid": 999999999, "start_ticks": 1, "pgid": 999999999, "session_id": 999999999}, terminal_result={"status": status, "process_stopped": True}, result_persisted=persisted, terminal_persisted=False)
    return journal


def test_delivery_replays_exact_event_and_terminal_intent_without_respawn(repository):
    service = service_fixture(repository)
    journal = journal_fixture(service)
    event = {"event_id": "stable-id", "sequence": 1, "type": "output", "payload": {"text": "bounded"}}
    journal.path.with_suffix(".events.jsonl").write_text(json.dumps(event) + "\n")
    service._delivery("1-0", {"execution_id": journal.read()["execution_id"], "dispatch_id": "dispatch"})
    assert service.api.calls == ["events", "result", "claim"]
    assert service.api.recorded_events == [event]
    assert service.redis.acks == ["1-0"]
    assert journal.read()["terminal_persisted"] is True
    assert not service.children


def test_uncertain_persist_is_not_ack_safe_until_death_reconciliation(repository):
    service = service_fixture(repository)
    journal = journal_fixture(service, status="uncertain", persisted=True)
    service._ack_completed()
    assert service.redis.acks == []
    service._delivery("1-0", {"execution_id": journal.read()["execution_id"], "dispatch_id": "dispatch"})
    assert service.api.calls == ["reconcile", "claim"]
    assert service.redis.acks == ["1-0"]
    assert journal.read()["reconciled"] is True


def test_dead_supervisor_without_result_is_reconciled_not_reexecuted(repository):
    service = service_fixture(repository)
    journal = journal_fixture(service)
    saved = journal.read()
    saved.pop("terminal_result")
    journal.path.write_text(json.dumps(saved))
    service._delivery("1-0", {"execution_id": saved["execution_id"], "dispatch_id": "dispatch"})
    assert service.api.calls == ["reconcile", "claim"]
    assert not service.children


def test_initial_lease_binding_failure_prevents_git_and_provider(repository, job, monkeypatch):
    executor = Executor(repository[0], require_ext4=False)
    ledger = FakeLedger()
    def stale(*_):
        raise WorkerError("LEASE_STALE", "already reconciled")
    ledger.heartbeat = stale
    monkeypatch.setattr(executor, "run", lambda *_args, **_kwargs: pytest.fail("stale owner executed"))
    claim = {"execution_id": job["execution_id"], "epoch": 1, "request": job, "lease_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=45)).isoformat()}
    with pytest.raises(WorkerError, match="already reconciled"):
        ExecutionSupervisor(ledger, executor, executor.workspaces.journal_for(job["execution_id"])).run(claim)
    assert not (repository[0] / "worktrees").exists()
