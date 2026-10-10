"""Regressions for review findings at actual wire/process/Git boundaries."""
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from threading import Event
import pytest
from adf_runtime_worker.adapters import CodexAdapter, MockAdapter
from adf_runtime_worker.executor import Executor
from adf_runtime_worker.journal import group_alive
from adf_runtime_worker.models import Request, WorkerError
from adf_runtime_worker.security import Redactor, restricted_env
from adf_runtime_worker.supervisor import ExecutionSupervisor, LeaseMonitor
from test_git_workspace import commit_fixture
from test_client_supervisor import FakeLedger


def task_delta(manager, job, suffix, filename):
    candidate = {**job, "execution_id": "writer-" + suffix, "task_id": "writer-" + suffix, "allowed_write_paths": [filename]}
    workspace = manager.allocate(candidate)
    (workspace.path / filename).write_text(suffix + "\n")
    result, _ = commit_fixture(manager, workspace, candidate)
    return result["commit_sha"]


def test_integrate_wire_predecessors_are_applied_only_once(manager, repository, job):
    commits = [task_delta(manager, job, "a", "a.txt"), task_delta(manager, job, "b", "b.txt")]
    wire = {**job, "operation": "integrate", "execution_id": "integration", "predecessor_commits": commits, "integration_commits": commits}
    workspace = manager.allocate(wire)
    assert workspace.base_sha == repository[2]
    assert not (workspace.path / "a.txt").exists()
    result = manager.integrate(workspace, wire)
    assert result["integration_status"] == "passed"
    assert manager.git(workspace.path, "rev-list", "--count", repository[2] + "..HEAD") == "2"
    assert manager.git(repository[1], "rev-parse", "main") == repository[2]


def test_partial_dependency_allocation_replays_remaining_delta(manager, job, monkeypatch):
    commits = [task_delta(manager, job, "a", "a.txt"), task_delta(manager, job, "b", "b.txt")]
    dependent = {**job, "execution_id": "dependent", "predecessor_commits": commits}
    original = manager._apply_delta
    def fault(workspace, sha, key):
        if key == "dependency-1":
            raise WorkerError("BACKEND_UNAVAILABLE", "injected allocation crash")
        return original(workspace, sha, key)
    monkeypatch.setattr(manager, "_apply_delta", fault)
    with pytest.raises(WorkerError):
        manager.allocate(dependent)
    assert manager.journal_for("dependent").read()["dependency_snapshot_complete"] is False
    monkeypatch.setattr(manager, "_apply_delta", original)
    workspace = manager.allocate(dependent)
    assert (workspace.path / "a.txt").exists() and (workspace.path / "b.txt").exists()
    assert manager.git(workspace.path, "rev-list", "--count", job["root_base_sha"] + "..HEAD") == "2"
    assert workspace.journal.read()["dependency_snapshot_complete"] is True


def test_lease_loss_gates_next_integration_delta_and_preserves_prefix(manager, job):
    commits = [task_delta(manager, job, "a", "a.txt"), task_delta(manager, job, "b", "b.txt")]
    wire = {**job, "operation": "integrate", "execution_id": "integration", "integration_commits": commits}
    workspace = manager.allocate(wire)
    def guard():
        if any(item.get("phase") == "committed" for item in workspace.journal.read().get("delta_intents", {}).values()):
            raise WorkerError("LEASE_LOST", "injected lease loss")
    manager.control_guard = guard
    with pytest.raises(WorkerError, match="lease loss"):
        manager.integrate(workspace, wire)
    evidence = manager.reconcile_git_evidence("integration")
    assert len(evidence["commit_sha"]) == 40
    assert evidence["applied_source_commits"] == commits[:1]
    assert not (workspace.path / "b.txt").exists()
    assert "integration-1" not in workspace.journal.read()["delta_intents"]


def test_project_lock_wait_observes_cancellation(manager):
    calls = 0
    with manager.project_lock("project"):
        def guard():
            nonlocal calls
            calls += 1
            if calls == 3:
                raise WorkerError("CANCEL_REQUESTED", "cancelled while waiting")
        manager.control_guard = guard
        started = time.monotonic()
        with pytest.raises(WorkerError, match="cancelled while waiting"):
            with manager.project_lock("project"):
                pytest.fail("lock unexpectedly acquired")
        assert time.monotonic() - started < 1


def test_git_output_is_bounded_during_streaming(manager):
    manager.execution_journal = manager.journal_for("output-fault")
    with pytest.raises(WorkerError, match="output exceeds"):
        manager._command([sys.executable, "-c", "import os; [os.write(1,b'x'*8192) for _ in range(20000)]"])
    assert not group_alive(manager.execution_journal.read()["process"])


def test_local_include_cannot_enable_git_hooks(manager, repository):
    root, repo, _, project = repository
    included = root / "hook-config"
    included.write_text("[core]\n    hooksPath = /tmp/untrusted-hooks\n")
    manager.git(repo, "config", "include.path", str(included))
    with pytest.raises(WorkerError, match="includes"):
        manager.validate_repo(project)


def test_authoritative_expired_deadline_allocates_nothing(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    deadline = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with pytest.raises(WorkerError, match="deadline"):
        executor.run({**job, "deadline_at": deadline}, lambda *_: None, Event())
    assert not (repository[0] / "worktrees").exists()


def test_registry_wire_check_timeout_is_consumed(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    executor.run(job, lambda *_: None, Event())
    project = {**job["project"], "check_registry": {"slow": ["python", "-c", "import time;time.sleep(5)"]}, "check_timeouts": {"slow": 1}}
    started = time.monotonic()
    result = executor.run({**job, "execution_id": "slow-check", "target_execution_id": job["execution_id"], "operation": "test", "project": project, "check_ids": ["slow"]}, lambda *_: None, Event())
    assert result["test_results"][0]["error_code"] == "EXECUTION_TIMEOUT"
    assert time.monotonic() - started < 4


def test_mock_refuses_readonly_writes_and_symlink_parent_escape(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "src").symlink_to(outside, target_is_directory=True)
    for profile in ("read_only", "trusted-development"):
        request = Request("execution", "run", 1, workspace, '{"mock_files":{"src/file.txt":"blocked"}}', permission_profile=profile)
        with pytest.raises(WorkerError):
            MockAdapter().execute(request, lambda *_: None, Event())
    assert not (outside / "file.txt").exists()


def test_codex_refuses_narrow_builtin_tool_scope(tmp_path):
    with pytest.raises(WorkerError, match="built-in shell scope remains coarse"):
        CodexAdapter("codex").argv(Request("execution", "run", 1, allowed_tools=("Read",)), tmp_path)


def test_usage_counts_remain_numeric_next_to_credentials():
    data = Redactor(("private-sentinel",)).data({"usage": {"input_tokens": 12, "output_tokens": 3}, "token": "private-sentinel", "authorization": "Bearer private-sentinel"})
    assert data["usage"] == {"input_tokens": 12, "output_tokens": 3}
    assert data["token"] == data["authorization"] == "[REDACTED]"  # noqa: S105 - expected redaction marker


def test_file_loaded_token_redacted_before_local_event_journal(repository, job, monkeypatch):
    token = "opaque-loaded-worker-sentinel-value"  # noqa: S105 - deliberate non-secret fixture
    ledger = FakeLedger()
    ledger.redaction_values = (token,)
    executor = Executor(repository[0], require_ext4=False)
    def execute(_job, sink, _cancel, **_kwargs):
        sink("output", {"text": token, "input_tokens": 17})
        return {"status": "succeeded", "process_stopped": True, "usage": {"source": "provider", "input_tokens": 17, "output_tokens": 2}, "text": token}
    monkeypatch.setattr(executor, "run", execute)
    journal = executor.workspaces.journal_for(job["execution_id"])
    claim = {"execution_id": job["execution_id"], "epoch": 1, "request": {**job, "operation": "repo_inspect"}, "lease_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=45)).isoformat()}
    result = ExecutionSupervisor(ledger, executor, journal).run(claim)
    assert result["usage"]["input_tokens"] == 17
    assert token not in journal.path.read_text()
    assert token not in journal.path.with_suffix(".events.jsonl").read_text()
    assert ledger.recorded_events[0]["payload"]["text"] == "[REDACTED]"  # noqa: S105 - expected redaction marker


def test_sequential_child_pid_changes_do_not_change_lease_identity(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    journal = executor.workspaces.journal_for(job["execution_id"])
    journal.update(supervisor={"pid": os.getpid(), "start_ticks": 123, "pgid": 42, "session_id": 42})
    ledger = FakeLedger()
    identities = []
    def heartbeat(_id, _epoch, identity):
        identities.append(dict(identity))
        return {"lease_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=45)).isoformat()}
    ledger.heartbeat = heartbeat
    monitor = LeaseMonitor(ledger, job["execution_id"], 1, (datetime.now(timezone.utc) + timedelta(seconds=45)).isoformat(), Event(), journal)
    for pid in (12, 99):
        journal.update(process={"pid": pid, "start_ticks": pid})
        # One deterministic poll iteration; no ten-second test sleeps.
        ledger.control = lambda *_: (monitor.stop.set() or {"cancel_requested": False})
        monitor.stop.clear()
        monitor._poll()
    assert identities[0] == identities[1]
    assert identities[0]["pid"] == os.getpid()
    assert identities[0]["journal_id"] == journal.path.name


def test_configured_node_path_is_added_without_windows_path(tmp_path, monkeypatch):
    node = tmp_path / "node"
    node.write_text("fixture")
    monkeypatch.setenv("ADF_NODE_PATH", str(node))
    monkeypatch.setenv("PATH", "/usr/bin:/mnt/c/Windows/System32")
    env = restricted_env()
    assert env["PATH"].split(os.pathsep)[0] == str(tmp_path)
    assert "/mnt/c" not in env["PATH"]
    assert "ADF_NODE_PATH" not in env


def test_staged_whitespace_filename_is_never_normalized_into_approved_path(manager, job):
    workspace = manager.allocate(job)
    (workspace.path / "feature.py").write_text("approved file\n")
    (workspace.path / " feature.py").write_text("outside scope\n")
    manager.git(workspace.path, "add", "--", "feature.py", " feature.py")
    with pytest.raises(WorkerError, match="relative path"):
        manager.changes(workspace, ["feature.py"])
