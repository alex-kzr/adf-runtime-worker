"""Accepted immutable deltas do not carry retired execution grants."""
import copy
import json
from threading import Event
from uuid import uuid4

import pytest

from adf_runtime_worker.commit_lineage import validation
from adf_runtime_worker.executor import Executor
from adf_runtime_worker.git_workspace import GitWorkspaceManager
from adf_runtime_worker.journal import Journal
from adf_runtime_worker.models import WorkerError


@pytest.fixture(params=["historical", "v1"])
def lineage(sealed_policy, job, request):
    policy = sealed_policy
    job = copy.deepcopy(job)
    job["project"]["checks"].append({"id": "second", "argv": ["python", "-c", "pass"], "timeout_sec": 10})
    job["check_ids"].append("second")
    executor = Executor(policy.root, require_ext4=False)
    generation = str(uuid4())
    state = Journal(policy.root / "providers/codex/server.json")
    state.update(generation=generation, stopped=False, policy_blocked=False)
    developed = executor.run(job, lambda *_: None, Event())
    source = executor.workspaces.journal_for(job["execution_id"])
    source.update(request=copy.deepcopy(job), terminal_result=developed,
                  result_persisted=True, terminal_persisted=True)
    common = {**job, "target_execution_id": job["execution_id"]}
    executor.run({**common, "execution_id": "checked", "operation": "test"}, lambda *_: None, Event())
    executor.run({**common, "execution_id": "reviewed", "operation": "review", "agent": {"id": "reviewer", "provider": "mock"},
                  "task_prompt": '{"review":{"approved":true,"findings":[]}}'}, lambda *_: None, Event())
    workspace = executor.workspaces.load(job["execution_id"])
    identity = policy._workspace_identity(workspace.path)
    source.update(shared_profile_policy=policy.receipt(generation), shared_workspace_seal=[list(identity[0]), identity[1]])
    saved = source.read()
    commit_job = {**common, "execution_id": "committed", "operation": "git_commit",
                  "review": saved["review"], "test_results": saved["test_results"]}
    result = executor.run(commit_job, lambda *_: None, Event())
    # The writer owns the Git intent; the separate dispatch owns API publication.
    publication = executor.workspaces.journal_for(commit_job["execution_id"])
    publication.update(execution_id=commit_job["execution_id"], request=copy.deepcopy(commit_job),
                       terminal_result=result, result_persisted=True, terminal_persisted=True)
    if request.param == "historical":
        saved = source.read()
        saved.pop("commit_validation")
        source.path.write_text(json.dumps(saved))
        source.path.chmod(0o600)
    state.update(generation=str(uuid4()))
    fresh = {**job, "execution_id": "fresh-generation", "task_id": "fresh-task", "run_id": "fresh-run",
             "predecessor_commits": [result["commit_sha"]], "task_prompt": '{}'}
    return policy, executor, state, source, fresh, result


def publication_for(executor):
    return executor.workspaces.journal_for("committed")


def test_accepted_historical_delta_imports_without_retired_grant(lineage):
    policy, executor, state, source, fresh, result = lineage
    executor.run(fresh, lambda *_: None, Event())
    workspace = executor.workspaces.load(fresh["execution_id"])
    assert (workspace.path / "feature.py").read_text() == "value = 42\n"
    assert "shared_profile_policy" not in workspace.journal.read()
    assert source.read()["shared_profile_policy"]["generation"] != state.read()["generation"]
    assert executor.workspaces.git(policy.repositories[0], "rev-parse", "main") == fresh["root_base_sha"]


@pytest.mark.parametrize("mutation", ["unconfirmed", "commit_sha", "tree", "parent", "project", "repo", "review", "checks", "unapproved"])
def test_invalid_historical_provenance_is_rejected_before_copy(lineage, mutation):
    policy, executor, state, source, fresh, result = lineage
    saved = source.read()
    if mutation == "unconfirmed":
        publication_for(executor).update(result_persisted=False)
    elif mutation == "commit_sha":
        saved["commit_sha"] = "f" * 40
    elif mutation in {"tree", "parent"}:
        saved["commit_intent"][mutation + "_sha"] = "f" * 40
    elif mutation == "project":
        saved["project_id"] = "foreign-project"
    elif mutation == "repo":
        saved["repository_root"] = str(policy.root / "projects/other")
    elif mutation == "review":
        saved["review"]["approved"] = False
    elif mutation == "checks":
        saved["test_results"][0]["status"] = "failed"
    else:
        fresh["policy"] = {**fresh["policy"], "approved": False}
    source.update(**saved)
    with pytest.raises(WorkerError):
        executor.run(fresh, lambda *_: None, Event())
    assert executor.workspaces.git(policy.repositories[0], "rev-parse", "main") == fresh["root_base_sha"]


@pytest.mark.parametrize("mutation", ["missing", "unpublished", "not_terminal", "cancelled", "rejected", "failed",
                                     "commit", "tree", "operation", "target", "project", "run", "task", "repo",
                                     "unapproved", "commit_denied", "execution"])
def test_commit_requires_separate_successful_publication(lineage, mutation):
    policy, executor, state, source, fresh, result = lineage
    publication = publication_for(executor)
    if mutation == "missing":
        publication.path.unlink()
    else:
        saved = publication.read()
        if mutation == "unpublished":
            saved["result_persisted"] = False
        elif mutation == "not_terminal":
            saved["terminal_persisted"] = False
        elif mutation in {"cancelled", "rejected", "failed"}:
            saved["terminal_result"]["status"] = mutation
        elif mutation in {"commit", "tree"}:
            saved["terminal_result"][mutation + "_sha"] = "f" * 40
        elif mutation == "operation":
            saved["request"]["operation"] = "agent_task"
        elif mutation == "target":
            saved["request"]["target_execution_id"] = "other-writer"
        elif mutation in {"project", "run", "task"}:
            saved["request"][mutation + "_id"] = "foreign"
        elif mutation == "repo":
            saved["request"]["project"]["repo_path"] = str(policy.root / "projects/foreign")
        elif mutation == "unapproved":
            saved["request"]["policy"]["approved"] = False
        elif mutation == "commit_denied":
            saved["request"]["policy"]["allow_commit"] = False
        else:
            saved["request"]["execution_id"] = "other-dispatch"
        publication.update(**saved)
    with pytest.raises(WorkerError):
        executor.run(fresh, lambda *_: None, Event())
    assert not (policy.root / "worktrees" / fresh["project_id"] / fresh["run_id"] / fresh["execution_id"] / "feature.py").exists()


@pytest.mark.parametrize("mutation", ["drop_check", "broaden_paths", "reviewer", "developer", "grant", "source_request", "version_bool"])
def test_v1_coherent_proof_tampering_is_rejected(lineage, mutation):
    policy, executor, state, source, fresh, result = lineage
    saved = source.read()
    proof = copy.deepcopy(validation(saved, {**saved["request"], "review": saved["review"], "test_results": saved["test_results"]}, result["tree_sha"]))
    if mutation == "drop_check":
        proof["check_ids"].pop()
        proof["test_results"].pop()
    elif mutation == "broaden_paths":
        proof["allowed_write_paths"] = ["**"]
    elif mutation in {"reviewer", "developer"}:
        proof["review"][mutation + "_id"] = "replacement-identity"
    elif mutation == "version_bool":
        proof["version"] = True
    elif mutation == "grant":
        saved["request"]["policy"]["allow_commit"] = False
    else:
        saved.pop("request")
    source.path.write_text(json.dumps({**saved, "commit_validation": proof}))
    source.path.chmod(0o600)
    with pytest.raises(WorkerError):
        executor.run(fresh, lambda *_: None, Event())


def test_writer_terminal_success_does_not_substitute_for_publication(lineage):
    policy, executor, state, source, fresh, result = lineage
    source.update(terminal_result=result, result_persisted=True, terminal_persisted=True)
    publication_for(executor).update(result_persisted=False)
    with pytest.raises(WorkerError):
        executor.run(fresh, lambda *_: None, Event())


def test_publication_may_retain_original_repair_check_provenance(lineage):
    policy, executor, state, source, fresh, result = lineage
    publication = publication_for(executor)
    saved = publication.read()
    saved["request"]["test_results"][0]["source_execution_id"] = "original-repair-check"
    publication.update(**saved)
    executor.run(fresh, lambda *_: None, Event())


def test_historical_delta_does_not_authorize_old_execution_or_new_drift(lineage):
    policy, executor, state, source, fresh, result = lineage
    from adf_runtime_worker.profile_policy import check_receipt
    with pytest.raises(WorkerError):
        check_receipt(policy.root, source.read())
    state.update(policy_blocked=True)
    with pytest.raises(WorkerError):
        executor.run(fresh, lambda *_: None, Event())


def test_sha_outside_current_selection_is_rejected(lineage):
    policy, executor, state, source, fresh, result = lineage
    manager = GitWorkspaceManager(policy.root, require_ext4=False)
    clean = {**fresh, "predecessor_commits": []}
    workspace = manager.allocate(clean)
    with pytest.raises(WorkerError):
        manager._apply_delta(workspace, result["commit_sha"], "dependency-0")


@pytest.mark.parametrize("fence", [None, {}, {"shared_profile_policy": None, "shared_workspace_seal": []},
                                   {"shared_profile_policy": {}, "shared_workspace_seal": None},
                                   {"shared_profile_policy": {}, "shared_workspace_seal": [], "artifact_import_fence": {}},
                                   {"shared_profile_policy": {}, "shared_workspace_seal": [], "workspace": {}},
                                   {"shared_profile_policy": {}, "shared_workspace_seal": [], "shared_native_read_policy": None}])
def test_malformed_import_fence_is_rejected(tmp_path, fence):
    from adf_runtime_worker.commit_lineage import check_import_fence
    with pytest.raises(WorkerError):
        check_import_fence(tmp_path, {"artifact_import_fence": fence})


def test_import_fence_preserves_original_live_receipt_check(lineage):
    from adf_runtime_worker.profile_policy import check_receipt
    policy, executor, state, source, fresh, result = lineage
    executor.run(fresh, lambda *_: None, Event())
    saved = executor.workspaces.journal_for(fresh["execution_id"]).read()
    assert "artifact_import_fence" in saved
    check_receipt(policy.root, saved)
    saved["shared_profile_policy"] = source.read()["shared_profile_policy"]
    with pytest.raises(WorkerError):
        check_receipt(policy.root, saved)


@pytest.mark.parametrize("mutation", ["review_bool", "exit_bool", "duplicate_check", "blank_check", "empty_checks"])
def test_validation_rejects_malformed_acceptance_fields(job, mutation):
    tree = "a" * 40
    request = copy.deepcopy(job)
    request.update(review={"approved": True, "tree_sha": tree, "developer_id": "developer", "reviewer_id": "reviewer"},
                   test_results=[{"check_id": "python", "status": "passed", "exit_code": 0, "tree_sha": tree}])
    if mutation == "review_bool":
        request["review"]["approved"] = 1
    elif mutation == "exit_bool":
        request["test_results"][0]["exit_code"] = False
    elif mutation == "duplicate_check":
        request["project"]["checks"].append(copy.deepcopy(request["project"]["checks"][0]))
        request["test_results"].append(copy.deepcopy(request["test_results"][0]))
    elif mutation == "blank_check":
        request["project"]["checks"][0]["id"] = ""
        request["test_results"][0]["check_id"] = ""
    else:
        request["project"]["checks"] = []
    saved = {**job, "repository_root": job["project"]["repo_path"]}
    with pytest.raises(WorkerError):
        validation(saved, request, tree)
