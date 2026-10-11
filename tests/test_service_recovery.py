"""At-least-once Redis deliveries never relaunch a consumed execution."""
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from adf_runtime_worker.executor import Executor
from adf_runtime_worker.models import WorkerError
from adf_runtime_worker.journal import Journal, process_identity
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
    service.recovery_only = False
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


@pytest.mark.parametrize("local", ["absent", "foreign", "no-epoch"])
def test_recovery_only_unknown_delivery_stays_pending_without_claim(repository, monkeypatch, local):
    service = service_fixture(repository)
    service.recovery_only = True
    journal = journal_fixture(service)
    saved = journal.read()
    if local == "absent":
        journal.path.unlink()
    elif local == "foreign":
        journal.update(worker_config={"worker_id": str(uuid4())})
    else:
        journal.update(epoch=None)
    monkeypatch.setattr(service.api, "claim", lambda *_: pytest.fail("Recovery claimed a lease"))
    monkeypatch.setattr("adf_runtime_worker.service.subprocess.Popen", lambda *_args, **_kwargs: pytest.fail("Recovery spawned a supervisor"))
    service._delivery("1-0", {"execution_id": saved["execution_id"], "dispatch_id": "dispatch"})
    assert service.api.calls == [] and service.redis.acks == [] and not service.children


def test_recovery_only_stopped_local_intent_reconciles_and_acks_without_claim(repository, monkeypatch):
    service = service_fixture(repository)
    service.recovery_only = True
    journal = journal_fixture(service)
    monkeypatch.setattr(service.api, "claim", lambda *_: pytest.fail("Recovery claimed a lease"))
    service._recover_local()
    service._ack_completed()
    assert service.api.calls == ["result"] and service.redis.acks == ["1-0"]
    assert journal.read()["redis_acked"] is True
    service._delivery("2-0", {"execution_id": journal.read()["execution_id"], "dispatch_id": "dispatch"})
    assert service.api.calls == ["result", "reconcile"] and service.redis.acks == ["1-0", "2-0"]
    assert not service.children


@pytest.mark.skipif(os.name != "posix", reason="Linux process identity proof")
@pytest.mark.parametrize("live_field", ["supervisor", "process"])
def test_recovery_only_live_writer_is_not_ack_safe_even_with_terminal_flags(repository, live_field):
    service = service_fixture(repository)
    service.recovery_only = True
    journal = journal_fixture(service, persisted=True)
    journal.update(**{live_field: process_identity(os.getpid()), "terminal_persisted": True})
    service._recover_local()
    service._ack_completed()
    if live_field == "supervisor":
        service._delivery("1-0", {"execution_id": journal.read()["execution_id"], "dispatch_id": "dispatch"})
    else:
        with pytest.raises(WorkerError) as error:
            service._delivery("1-0", {"execution_id": journal.read()["execution_id"], "dispatch_id": "dispatch"})
        assert error.value.code == "EXECUTION_UNCERTAIN"
    assert not service.api.calls and not service.redis.acks and not service.children


def test_recovery_only_nonterminal_response_keeps_message_pending(repository):
    service = service_fixture(repository)
    service.recovery_only = True
    journal = journal_fixture(service)
    service.api.result = lambda *_: {"persisted": True, "terminal": False}
    service._delivery("1-0", {"execution_id": journal.read()["execution_id"], "dispatch_id": "dispatch"})
    assert not service.redis.acks and not service.children


def test_recovery_only_invalid_transport_retains_fixed_dead_letter(repository):
    service = service_fixture(repository)
    service.recovery_only = True
    calls = []
    service.api.request = lambda *args: calls.append(args)
    service._delivery("9-0", {"execution_id": "invalid", "unexpected": "synthetic"})
    assert calls[0][2]["reason"] == "INVALID_TRANSPORT"
    assert "synthetic" not in json.dumps(calls)
    assert service.redis.acks == ["9-0"] and not service.api.calls


def test_recovery_only_run_skips_all_provider_health_and_stream_claims(repository, monkeypatch):
    from threading import Event
    service = service_fixture(repository)
    service.recovery_only = True
    service.config = {"codex_backend": "shared", "provider_paths": {}, "provider_profiles": {}}
    service.project_ids, service.project_roots = [], []
    service.stopping = Event()
    state = Journal(service.root / "providers/codex/server.json")
    state.update(generation="retained-generation", stopped=True, policy_blocked=True)
    before = state.path.read_bytes()
    monkeypatch.setattr("adf_runtime_worker.service.provider_adapter", lambda *_: pytest.fail("Recovery probed auth"))
    monkeypatch.setattr("adf_runtime_worker.shared_adapter.SharedCodexAdapter.probe", lambda *_: pytest.fail("Recovery required provider readiness"))
    monkeypatch.setattr("adf_runtime_worker.service.signal.signal", lambda *_: None)
    registrations = []
    service.api.register = lambda *args: registrations.append(args)
    service.api.worker_heartbeat = lambda *_: service.stopping.set()
    service.api.__exit__ = lambda *_: None
    service.redis.ping = lambda: True
    service.redis.xgroup_create = lambda *_args, **_kwargs: None
    service.redis.close = lambda: None
    service.redis.xreadgroup = lambda *_args, **_kwargs: pytest.fail("Recovery read new queue work")
    service.redis.xautoclaim = lambda *_args, **_kwargs: pytest.fail("Recovery reassigned pending queue work")
    service.run()
    assert registrations[0][1]["providers"] == {} and registrations[0][1]["operations"] == []
    assert registrations[0][1]["recovery_only"] is True
    assert not service.api.calls and not service.redis.acks and not service.children
    assert state.path.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="Linux worktree locks")
@pytest.mark.parametrize("unproved", ["shared-thread", "held-lock"])
def test_recovery_only_unproved_shared_writer_or_lock_never_acks(repository, unproved):
    from adf_runtime_worker.journal import FileLock
    service = service_fixture(repository)
    service.recovery_only = True
    journal = journal_fixture(service, persisted=True)
    execution_id = journal.read()["execution_id"]
    journal.update(terminal_persisted=True)
    if unproved == "shared-thread":
        journal.update(shared_session={"root": str(service.root), "execution_id": execution_id, "generation": "unproved"})
        service._ack_completed()
        with pytest.raises(WorkerError):
            service._delivery("1-0", {"execution_id": execution_id, "dispatch_id": "dispatch"})
    else:
        with FileLock(service.root / "locks" / ("execution-" + execution_id + ".lock")):
            service._ack_completed()
            with pytest.raises(WorkerError):
                service._delivery("1-0", {"execution_id": execution_id, "dispatch_id": "dispatch"})
    assert not service.api.calls and not service.redis.acks and not service.children
