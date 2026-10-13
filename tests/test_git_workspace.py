import copy
import json
from concurrent.futures import ThreadPoolExecutor
import pytest
from adf_runtime_worker.models import WorkerError

def commit_fixture(manager, workspace, job):
    evidence = manager.changes(workspace, job["allowed_write_paths"])
    request = {**job, "review": {"approved": True, "reviewer_id": "reviewer", "developer_id": "developer", "tree_sha": evidence["tree_sha"]}, "test_results": [{"check_id": "python", "status": "passed", "exit_code": 0, "tree_sha": evidence["tree_sha"]}]}
    workspace.journal.update(request=copy.deepcopy(job), allowed_write_paths=job["allowed_write_paths"],
                             developer_id="developer", review=request["review"], test_results=request["test_results"])
    result = manager.commit(workspace, request)
    dispatch_id = "published-" + workspace.execution_id
    dispatch = {**request, "execution_id": dispatch_id, "operation": "git_commit", "target_execution_id": workspace.execution_id}
    manager.journal_for(dispatch_id).update(execution_id=dispatch_id, request=dispatch, terminal_result={**result, "status": "succeeded"},
                                            result_persisted=True, terminal_persisted=True)
    return result, request

def test_three_allocations_are_unique_and_preserve_main(manager, job, repository):
    _, repo, base, _ = repository
    (repo / "user-dirty.txt").write_text("preserve user work")
    jobs = [{**job, "execution_id": f"execution-{number}", "task_id": f"task-{number}"} for number in range(3)]
    with ThreadPoolExecutor(max_workers=3) as pool:
        workspaces = list(pool.map(manager.allocate, jobs))
    assert len({workspace.path for workspace in workspaces}) == 3
    assert len({workspace.branch for workspace in workspaces}) == 3
    assert manager.git(repo, "rev-parse", "main") == base
    assert (repo / "user-dirty.txt").read_text() == "preserve user work"
    assert all(workspace.base_sha == base for workspace in workspaces)

def test_dependency_snapshot_contains_predecessor_delta(manager, job):
    first = manager.allocate(job)
    (first.path / "feature.py").write_text("value = 42\n")
    result, _ = commit_fixture(manager, first, job)
    dependent_job = {**job, "execution_id": "dependent", "task_id": "dependent", "predecessor_commits": [result["commit_sha"]]}
    dependent = manager.allocate(dependent_job)
    assert dependent.base_sha != dependent.root_base_sha
    assert (dependent.path / "feature.py").read_text() == "value = 42\n"

def test_commit_requires_exact_independent_review_and_tests(manager, job):
    workspace = manager.allocate(job)
    (workspace.path / "feature.py").write_text("value = 42\n")
    with pytest.raises(WorkerError, match="review"):
        manager.commit(workspace, job)
    evidence = manager.changes(workspace, job["allowed_write_paths"])
    invalid = {**job, "review": {"approved": True, "reviewer_id": "developer", "developer_id": "developer", "tree_sha": evidence["tree_sha"]}}
    with pytest.raises(WorkerError, match="Independent"):
        manager.commit(workspace, invalid)

def test_commit_crash_after_git_recovers_one_commit(manager, job):
    workspace = manager.allocate(job)
    (workspace.path / "feature.py").write_text("value = 42\n")
    result, request = commit_fixture(manager, workspace, job)
    saved = workspace.journal.read()
    saved.pop("commit_sha")
    workspace.journal.path.write_text(json.dumps(saved))
    recovered = manager.commit(workspace, request)
    assert recovered["commit_sha"] == result["commit_sha"]
    assert manager.git(workspace.path, "rev-list", "--count", workspace.base_sha + "..HEAD") == "1"

def test_serial_integration_and_conflict_preserve_default_branch(manager, job, repository):
    _, repo, base, _ = repository
    commits = []
    for number, text in enumerate(("first\n", "second\n")):
        task_job = {**job, "execution_id": f"writer-{number}", "task_id": f"task-{number}"}
        workspace = manager.allocate(task_job)
        (workspace.path / "feature.py").write_text(text)
        result, _ = commit_fixture(manager, workspace, task_job)
        commits.append(result["commit_sha"])
    integration_job = {**job, "execution_id": "integration", "operation": "integrate", "integration_commits": commits}
    integration = manager.allocate(integration_job)
    with pytest.raises(WorkerError, match="conflicts"):
        manager.integrate(integration, integration_job)
    assert manager.git(repo, "rev-parse", "main") == base
    assert manager.git(integration.path, "diff", "--name-only", "--diff-filter=U") == "feature.py"
    assert any(intent["phase"] == "needs_resolution" for intent in integration.journal.read()["delta_intents"].values())

def test_unapproved_paths_and_active_hooks_fail_closed(manager, job, repository):
    workspace = manager.allocate(job)
    (workspace.path / "unexpected.txt").write_text("denied")
    with pytest.raises(WorkerError, match="approved"):
        manager.changes(workspace, job["allowed_write_paths"])
    _, repo, _, project = repository
    (repo / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\nexit 0\n")
    with pytest.raises(WorkerError, match="hook"):
        manager.validate_repo(project)
