import copy
import os
import threading
from threading import Event
from uuid import uuid4

import pytest

from adf_runtime_worker.executor import Executor
from adf_runtime_worker.journal import Journal
from adf_runtime_worker.models import WorkerError
from adf_runtime_worker.profile_policy import SealedProfilePolicy, inherit_receipt
from adf_runtime_worker.git_workspace import GitWorkspaceManager

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux sealed profile checks")


def approved_commit(executor, job):
    executor.run(job, lambda *_: None, Event())
    executor.workspaces.journal_for(job["execution_id"]).update(request=copy.deepcopy(job))
    common = {**job, "target_execution_id": job["execution_id"]}
    executor.run({**common, "execution_id": "checked", "operation": "test"}, lambda *_: None, Event())
    executor.run({**common, "execution_id": "reviewed", "operation": "review", "agent": {"id": "reviewer", "provider": "mock"},
                  "task_prompt": '{"review":{"approved":true,"findings":[]}}'}, lambda *_: None, Event())
    return common


def commit_and_publish(executor, common):
    writer = executor.workspaces.journal_for(common["target_execution_id"]).read()
    request = {**common, "execution_id": "committed", "operation": "git_commit",
               "review": writer["review"], "test_results": writer["test_results"]}
    result = executor.run(request, lambda *_: None, Event())
    executor.workspaces.journal_for(request["execution_id"]).update(execution_id=request["execution_id"], request=request,
                                                                  terminal_result=result, result_persisted=True, terminal_persisted=True)
    return result["commit_sha"]


@pytest.mark.parametrize("operation", ["commit", "repair", "predecessor", "integrate"])
def test_drift_fences_commit_and_consumption_of_trusted_source(sealed_policy, job, operation):
    policy = sealed_policy
    executor = Executor(policy.root, require_ext4=False)
    generation = str(uuid4())
    state = Journal(policy.root / "providers" / "codex" / "server.json")
    state.update(generation=generation, stopped=False, policy_blocked=False)
    common = approved_commit(executor, job)
    source = executor.workspaces.journal_for(job["execution_id"])
    identity = SealedProfilePolicy._workspace_identity(executor.workspaces.load(job["execution_id"]).path)
    source.update(shared_profile_policy=policy.receipt(generation), shared_workspace_seal=[list(identity[0]), identity[1]])
    sha = None
    if operation in {"predecessor", "integrate"}:
        sha = commit_and_publish(executor, common)
    state.update(policy_blocked=True)
    next_job = {**job, "execution_id": "fresh", "task_prompt": '{"mock_files":{"feature.py":"value = 43\\n"}}'}
    if operation == "commit":
        next_job = {**common, "execution_id": "commit-after-drift", "operation": "git_commit"}
    elif operation == "repair":
        next_job["repair_source_execution_id"] = job["execution_id"]
    elif operation == "predecessor":
        next_job["predecessor_commits"] = [sha]
    else:
        next_job.update(operation="integrate", integration_commits=[sha])
    with pytest.raises(WorkerError) as error:
        executor.run(next_job, lambda *_: None, Event())
    assert error.value.code == "PERMISSION_DENIED"
    assert GitWorkspaceManager(policy.root, require_ext4=False).git(policy.repositories[0], "rev-parse", "main") == job["root_base_sha"]


@pytest.mark.parametrize("operation", ["repair", "predecessor", "integrate"])
def test_valid_receipt_follows_copies_and_blocks_after_retirement(sealed_policy, job, operation):
    policy = sealed_policy
    executor = Executor(policy.root, require_ext4=False)
    generation = str(uuid4())
    state = Journal(policy.root / "providers" / "codex" / "server.json")
    state.update(generation=generation, stopped=False, policy_blocked=False)
    common = approved_commit(executor, job)
    source = executor.workspaces.journal_for(job["execution_id"])
    identity = SealedProfilePolicy._workspace_identity(executor.workspaces.load(job["execution_id"]).path)
    source.update(shared_profile_policy=policy.receipt(generation), shared_workspace_seal=[list(identity[0]), identity[1]])
    fresh = {**job, "execution_id": "fresh-copy", "task_prompt": '{}'}
    if operation == "repair":
        fresh["repair_source_execution_id"] = job["execution_id"]
    else:
        sha = commit_and_publish(executor, common)
        if operation == "predecessor":
            fresh["predecessor_commits"] = [sha]
        else:
            fresh.update(operation="integrate", integration_commits=[sha])
    executor.run(fresh, lambda *_: None, Event())
    assert executor.workspaces.journal_for(fresh["execution_id"]).read()["shared_profile_policy"] == policy.receipt(generation)
    state.update(generation=str(uuid4()))
    with pytest.raises(WorkerError):
        executor.run({**fresh, "execution_id": "test-retired", "target_execution_id": fresh["execution_id"], "operation": "test"}, lambda *_: None, Event())


def test_repeated_inheritance_cannot_reseal_changed_target_marker(sealed_policy, job):
    policy = sealed_policy
    manager = GitWorkspaceManager(policy.root, require_ext4=False)
    source = manager.allocate(job)
    target = manager.allocate({**job, "execution_id": str(uuid4())})
    generation = str(uuid4())
    Journal(policy.root / "providers" / "codex" / "server.json").update(generation=generation, stopped=False, policy_blocked=False)
    identity = SealedProfilePolicy._workspace_identity(source.path)
    source.journal.update(shared_profile_policy=policy.receipt(generation), shared_workspace_seal=[list(identity[0]), identity[1]])
    inherit_receipt(policy.root, target.journal, source_id=job["execution_id"])
    old = target.journal.read()["shared_workspace_seal"]
    marker = target.path / ".git"
    replacement = marker.with_suffix(".replacement")
    replacement.write_bytes(marker.read_bytes())
    replacement.replace(marker)
    with pytest.raises(WorkerError):
        inherit_receipt(policy.root, target.journal, source_id=job["execution_id"])
    with pytest.raises(WorkerError):
        policy.bind(target.execution_id, target.path, generation)
    assert target.journal.read()["shared_workspace_seal"] == old


def test_unrelated_atomic_journal_writer_is_serialized_during_source_scan(sealed_policy, job, monkeypatch):
    import adf_runtime_worker.profile_policy as module
    policy = sealed_policy
    manager = GitWorkspaceManager(policy.root, require_ext4=False)
    source, target = manager.allocate(job), manager.allocate({**job, "execution_id": "fresh-copy"})
    generation = str(uuid4())
    Journal(policy.root / "providers" / "codex" / "server.json").update(generation=generation, stopped=False, policy_blocked=False)
    identity = policy._workspace_identity(source.path)
    sha = "1" * 40
    source.journal.update(commit_sha=sha, shared_profile_policy=policy.receipt(generation), shared_workspace_seal=[list(identity[0]), identity[1]])
    unrelated = Journal(policy.root / "journals" / "unrelated.json")
    unrelated.update(phase="running")
    attempted, done = Event(), Event()
    errors = []
    def writer():
        try:
            assert attempted.wait(timeout=3)
            unrelated.update(phase="atomic-replacement")
        except Exception as exc:
            errors.append(exc)
        finally:
            done.set()
    original = module.private_bytes
    def read(path, **kwargs):
        if path == unrelated.path:
            attempted.set()
            assert not done.wait(timeout=0.1)
        return original(path, **kwargs)
    monkeypatch.setattr(module, "private_bytes", read)
    runner = threading.Thread(target=writer)
    runner.start()
    try:
        inherit_receipt(policy.root, target.journal, source_sha=sha)
    finally:
        runner.join(timeout=4)
    assert not runner.is_alive() and not errors
    assert unrelated.read()["phase"] == "atomic-replacement"
    assert target.journal.read()["shared_profile_policy"] == policy.receipt(generation)


def test_binding_inherited_receipt_cannot_reseal_marker_changed_after_validation(sealed_policy, job, monkeypatch):
    policy = sealed_policy
    manager = GitWorkspaceManager(policy.root, require_ext4=False)
    source, target = manager.allocate(job), manager.allocate({**job, "execution_id": str(uuid4())})
    generation = str(uuid4())
    Journal(policy.root / "providers" / "codex" / "server.json").update(generation=generation, stopped=False, policy_blocked=False)
    identity = policy._workspace_identity(source.path)
    source.journal.update(shared_profile_policy=policy.receipt(generation), shared_workspace_seal=[list(identity[0]), identity[1]])
    inherit_receipt(policy.root, target.journal, source_id=job["execution_id"])
    old = target.journal.read()["shared_workspace_seal"]
    original = policy.allocation_identity
    def changed(target_id, saved):
        marker = target.path / ".git"
        replacement = marker.with_suffix(".replacement")
        replacement.write_bytes(marker.read_bytes())
        replacement.replace(marker)
        return original(target_id, saved)
    monkeypatch.setattr(policy, "allocation_identity", changed)
    with pytest.raises(WorkerError):
        policy.bind(target.execution_id, target.path, generation)
    assert target.journal.read()["shared_workspace_seal"] == old
