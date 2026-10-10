from datetime import datetime, timedelta, timezone
import httpx
import pytest
from adf_runtime_worker.client import ApiClient
from adf_runtime_worker.executor import Executor
from adf_runtime_worker.journal import process_identity
from adf_runtime_worker.models import WorkerError
from adf_runtime_worker.supervisor import ExecutionSupervisor, stopped_proof

def test_api_retry_reuses_exact_event_body_and_auth_is_not_retried(tmp_path):
    token_file = tmp_path / "worker-token"
    token_file.write_text("x" * 32)
    requests = []
    def response(request):
        requests.append(request)
        return httpx.Response(503 if len(requests) < 2 else 200, json={"ok": True})
    with ApiClient("http://127.0.0.1:8080", token_file, "worker", transport=httpx.MockTransport(response)) as client:
        client.events("execution", 1, [{"event_id": "stable", "sequence": 1, "type": "started"}])
    assert len(requests) == 2
    assert requests[0].content == requests[1].content
    requests.clear()
    def denied(request):
        requests.append(request)
        return httpx.Response(401, json={"code": "AUTH_REQUIRED"})
    with ApiClient("http://127.0.0.1:8080", token_file, "worker", transport=httpx.MockTransport(denied)) as client:
        with pytest.raises(WorkerError):
            client.claim("execution")
    assert len(requests) == 1

def test_api_rejects_nonloopback_or_embedded_credentials(tmp_path):
    with pytest.raises(WorkerError, match="loopback"):
        ApiClient("http://example.com", tmp_path / "absent", "worker")

class FakeLedger:
    def __init__(self):
        self.recorded_events = []
        self.results = []
        self.fail_results = False
    def claim(self, execution_id):
        return {}
    def heartbeat(self, execution_id, epoch, process=None):
        return {"lease_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=45)).isoformat()}
    def control(self, execution_id, epoch):
        return {"cancel_requested": False}
    def events(self, execution_id, epoch, events):
        self.recorded_events.extend(events)
        return {"persisted": True}
    def result(self, execution_id, epoch, status, result):
        if self.fail_results:
            raise WorkerError("BACKEND_UNAVAILABLE", "unavailable")
        self.results.append(result)
        return {"persisted": True}
    def reconcile(self, execution_id, epoch, evidence):
        return {}
    def artifact(self, execution_id, epoch, kind, content, media_type="application/json"):
        return {"id": "artifact", "kind": kind}

def test_terminal_intent_is_durable_before_persist_and_events_are_ordered(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    ledger = FakeLedger()
    journal = executor.workspaces.journal_for(job["execution_id"])
    claim = {"execution_id": job["execution_id"], "epoch": 1, "request": job, "lease_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=45)).isoformat()}
    result = ExecutionSupervisor(ledger, executor, journal).run(claim)
    assert result["status"] == "succeeded"
    assert journal.read()["result_persisted"] is True
    assert journal.read()["terminal_result"] == ledger.results[0]
    assert [event["sequence"] for event in ledger.recorded_events] == [1, 2]
    assert journal.path.with_suffix(".events.jsonl").exists()

def test_result_transport_failure_never_claims_persistence(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    ledger = FakeLedger()
    ledger.fail_results = True
    journal = executor.workspaces.journal_for(job["execution_id"])
    claim = {"execution_id": job["execution_id"], "epoch": 1, "request": job, "lease_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=45)).isoformat()}
    ExecutionSupervisor(ledger, executor, journal).run(claim)
    assert journal.read()["result_persisted"] is False
    assert journal.read()["phase"] == "result_intent"
    assert journal.read()["terminal_result"]["status"] == "succeeded"

def test_reconcile_refuses_a_live_supervisor(repository, job):
    import os
    executor = Executor(repository[0], require_ext4=False)
    journal = executor.workspaces.journal_for(job["execution_id"])
    journal.update(execution_id=job["execution_id"], supervisor=process_identity(os.getpid()))
    with pytest.raises(WorkerError, match="still alive"):
        stopped_proof(journal, executor)

def test_reconcile_accepts_dead_identity_with_reacquired_worktree_lock(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    journal = executor.workspaces.journal_for(job["execution_id"])
    journal.update(execution_id=job["execution_id"], supervisor={"pid": 999999999, "start_ticks": 1})
    proof = stopped_proof(journal, executor)
    assert proof["worktree_lock_reacquired"] is True
