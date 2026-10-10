import json
from threading import Event
import pytest
from adf_runtime_worker.executor import Executor
from adf_runtime_worker.models import WorkerError

def test_split_develop_test_review_commit_pipeline(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    def sink(*_):
        pass
    developed = executor.run(job, sink, Event())
    assert developed["status"] == "succeeded"
    assert "commit_sha" not in developed
    assert developed["changed_paths"] == ["feature.py"]
    common = {**job, "target_execution_id": job["execution_id"]}
    with pytest.raises(WorkerError, match="review"):
        executor.run({**common, "execution_id": "early-commit", "operation": "git_commit"}, sink, Event())
    tested = executor.run({**common, "execution_id": "test-1", "operation": "test"}, sink, Event())
    assert tested["test_results"][0]["status"] == "passed"
    reviewed = executor.run({**common, "execution_id": "review-1", "operation": "review", "agent": {"id": "reviewer", "provider": "mock"}, "task_prompt": '{"review":{"approved":true,"findings":[]}}'}, sink, Event())
    assert reviewed["review"]["tree_sha"] == developed["tree_sha"]
    committed = executor.run({**common, "execution_id": "commit-1", "operation": "git_commit"}, sink, Event())
    assert committed["status"] == "succeeded"
    assert len(committed["commit_sha"]) == 40
    assert executor.workspaces.git(repository[1], "rev-parse", "main") == repository[2]

def test_self_review_and_tree_changed_after_review_rejected(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    def sink(*_):
        pass
    executor.run(job, sink, Event())
    common = {**job, "target_execution_id": job["execution_id"]}
    executor.run({**common, "execution_id": "test", "operation": "test"}, sink, Event())
    with pytest.raises(WorkerError, match="independent"):
        executor.run({**common, "execution_id": "review", "operation": "review"}, sink, Event())
    executor.run({**common, "execution_id": "review", "operation": "review", "agent": {"id": "reviewer", "provider": "mock"}, "task_prompt": '{"review":{"approved":true,"findings":[]}}'}, sink, Event())
    workspace = executor.workspaces.load(job["execution_id"])
    (workspace.path / "feature.py").write_text("value = 99\n")
    with pytest.raises(WorkerError, match="exact staged tree"):
        executor.run({**common, "execution_id": "commit", "operation": "git_commit"}, sink, Event())

def test_planner_schema_and_dependency_cycle_fail_closed(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    plan = {"tasks": [{"id": "a", "title": "task", "description": "goal", "acceptance_criteria": ["test"], "expected_files": ["feature.py"], "dependency_ids": ["a"]}], "unknowns": []}
    with pytest.raises(WorkerError, match="cycle"):
        executor.run({**job, "operation": "planner", "task_prompt": json.dumps({"plan": plan})}, lambda *_: None, Event())

def test_repo_inspect_never_creates_a_worktree(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    result = executor.run({**job, "operation": "repo_inspect"}, lambda *_: None, Event())
    assert result["root_base_sha"] == repository[2]
    assert not (repository[0] / "worktrees").exists()

def test_repair_uses_fresh_scoped_attempt_snapshot(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    executor.run(job, lambda *_: None, Event())
    repaired_job = {**job, "execution_id": "repair-1", "repair_source_execution_id": job["execution_id"], "repair_feedback": "fix test failure", "task_prompt": '{"mock_files":{"feature.py":"value = 43\\n"}}'}
    repaired = executor.run(repaired_job, lambda *_: None, Event())
    old = executor.workspaces.load(job["execution_id"])
    fresh = executor.workspaces.load("repair-1")
    assert old.path != fresh.path
    assert old.branch != fresh.branch
    assert "42" in (old.path / "feature.py").read_text()
    assert "43" in (fresh.path / "feature.py").read_text()
    assert repaired["status"] == "succeeded"
