import json
import hashlib
import os
import sys
import subprocess
import threading
import time
from dataclasses import replace
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
import jsonschema

from adf_runtime_worker.journal import FileLock, Journal, owned_sessions_stopped, process_identity, group_alive
from adf_runtime_worker.models import Request, SkillSnapshot, WorkerError
from adf_runtime_worker.security import restricted_env
from adf_runtime_worker.shared_adapter import SharedCodexAdapter
from adf_runtime_worker.shared_job import bridge
from adf_runtime_worker.shared_server import SharedServer, baseline, clean_config, job_path, native_event, shared_stopped, server_command
from adf_runtime_worker.profile_policy import SealedProfilePolicy, check_receipt
from adf_runtime_worker.git_workspace import GitWorkspaceManager

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux Unix sockets, FD handoff and session proof")
FAKE = Path(__file__).parent / "fixtures" / "shared_app_server.py"


@pytest.fixture
def server(tmp_path, monkeypatch):
    running = []
    inert_roots = set()
    owner_check = SharedServer._require_native_policy
    adapter_check = SharedCodexAdapter._require_native_owner
    # Explicitly inert protocol doubles only; production entry points have no
    # opt-out for legacy native permissions. Native-policy tests keep the gate.
    def check_owner(runtime):
        if runtime.root not in inert_roots:
            owner_check(runtime)
    def check_adapter(adapter, request):
        if adapter.root not in inert_roots:
            adapter_check(adapter, request)
    monkeypatch.setattr(SharedServer, "_require_native_policy", check_owner)
    monkeypatch.setattr(SharedCodexAdapter, "_require_native_owner", check_adapter)
    def start(mode="ready", root=None, environment=None, profile=None, policy=None, native_policy=None):
        root = root or tmp_path / ("root-" + str(len(running)))
        # The durable stopped receipt precedes socket unlink. Join the owned
        # offline thread before replacement so a stale socket is not readiness.
        for previous, previous_owner, _ in running:
            if previous.root == root:
                assert previous.state.read().get("stopped") is True
                previous_owner.join(timeout=6)
                assert not previous_owner.is_alive()
        root.mkdir(exist_ok=True)
        root.chmod(0o700)
        capture = tmp_path / ("wire-" + str(len(running)) + ".jsonl")
        runtime = SharedServer(root, [sys.executable, str(FAKE), str(capture), mode],
                               restricted_env() if environment is None else environment, profile=profile, cleanup_timeout=0.7, policy=policy, native_policy=native_policy)
        if native_policy is None:
            inert_roots.add(root)
        errors = []
        def run():
            try:
                runtime.run()
            except Exception as exc:
                errors.append(exc)
        owner = threading.Thread(target=run)
        owner.start()
        running.append((runtime, owner, errors))
        until = time.monotonic() + 5
        while not runtime.socket_path.exists() and owner.is_alive() and time.monotonic() < until:
            time.sleep(0.02)
        assert runtime.socket_path.exists(), errors
        return runtime, capture
    yield start
    for runtime, owner, errors in running:
        runtime.stopping.set()
        owner.join(timeout=6)
        assert not owner.is_alive()
        assert not errors, errors


def request(root, tmp_path, number):
    execution_id = str(uuid4())
    workspace = root / "worktrees" / ("test-project-" + str(number)) / execution_id
    workspace.mkdir(parents=True)
    journal = root / "journals" / (str(uuid4()) + ".json")
    Journal(journal).update(phase="test_allocated")
    return Request(execution_id, str(uuid4()), 1, workspace_path=workspace, task_prompt="offline job",
                   timeout_sec=4, journal_path=journal, permission_profile="trusted-development", model="model-" + str(number))


def policy_request(policy, job, number=0):
    allocation = {**job, "execution_id": str(uuid4()), "run_id": str(uuid4()), "task_id": str(uuid4()), "project_id": str(uuid4())}
    workspace = GitWorkspaceManager(policy.root, require_ext4=False).allocate(allocation)
    workspace.journal.update(request=allocation)
    return Request(allocation["execution_id"], allocation["run_id"], 1, workspace.path, "synthetic policy job", 8,
                   # Sealed policy supports read-only only: fake providers must
                   # not claim compatibility with native synthetic mount writes.
                   journal_path=workspace.journal.path, permission_profile="observe", model="model-" + str(number))


def policy_execute(runtime, job, cancellation=None):
    target = job.workspace_path.name
    with FileLock(runtime.root / "locks" / ("execution-" + target + ".lock")) as lock:
        return SharedCodexAdapter(runtime.root).execute(replace(job, lock_fd=lock.fd), lambda *_: None, cancellation or Event())


def wire_methods(capture, method):
    return [json.loads(line) for line in capture.read_text().splitlines() if json.loads(line)["method"] == method]


def test_policy_three_allocations_use_owner_trust_without_config_write(server, sealed_policy, job):
    policy = sealed_policy
    runtime, capture = server(root=policy.root, profile=policy.profile, policy=policy)
    jobs = [policy_request(policy, job, number) for number in range(3)]
    results = {}
    runners = [threading.Thread(target=lambda n=n: results.update({n: policy_execute(runtime, jobs[n])})) for n in range(3)]
    for runner in runners:
        runner.start()
    for runner in runners:
        runner.join(timeout=12)
        assert not runner.is_alive()
    assert [results[n].status for n in range(3)] == ["succeeded"] * 3
    starts = wire_methods(capture, "thread/start")
    assert len(starts) == 3
    assert len({start["params"]["cwd"] for start in starts}) == 3
    assert all(start["params"]["config"]["projects"] == policy.projects for start in starts)
    assert all(start["params"]["sandbox"] == "read-only" for start in starts)
    assert not (policy.profile / "config.toml").exists()
    policy.check()
    for request in jobs:
        check_receipt(policy.root, Journal(request.journal_path).read())


def test_sealed_write_preflight_has_no_materialization_or_generation_block(server, sealed_policy, job, monkeypatch):
    policy = sealed_policy
    runtime, capture = server(root=policy.root, profile=policy.profile, policy=policy)
    request = replace(policy_request(policy, job), permission_profile="trusted-development")
    adapter = SharedCodexAdapter(runtime.root)
    monkeypatch.setattr(adapter.runner, "run", lambda *_args, **_kwargs: pytest.fail("Unsupported write launched a bridge"))
    events = []
    before = Journal(request.journal_path).read()
    with FileLock(runtime.root / "locks" / ("execution-" + request.execution_id + ".lock")) as lock:
        with pytest.raises(WorkerError) as error:
            adapter.execute(replace(request, lock_fd=lock.fd), lambda *args: events.append(args), Event())
    assert error.value.code == "CAPABILITY_UNSUPPORTED"
    assert Journal(request.journal_path).read() == before
    assert not events and not (request.workspace_path / ".agents").exists()
    assert not wire_methods(capture, "thread/start") and not wire_methods(capture, "turn/start")
    assert not runtime.policy_blocked.is_set()
    for _ in range(3):
        health = adapter.probe()
        assert health["health"] == "ready" and health["auth"] == "ready"
        assert health["generation"] == runtime.generation and health["policy"] == "sealed"
        assert health["permission_profiles"] == ["observe", "read_only"]
        assert health["write_capability"] == {"supported": False, "error_code": "CAPABILITY_UNSUPPORTED"}
        assert health["ready_for_real_execution"] is False
    assert policy_execute(runtime, policy_request(policy, job, 1)).status == "succeeded"


def test_sealed_owner_rejects_direct_write_ipc_with_no_thread_tombstone(server, sealed_policy, job, tmp_path, capsys):
    policy = sealed_policy
    runtime, capture = server(root=policy.root, profile=policy.profile, policy=policy)
    request = replace(policy_request(policy, job), permission_profile="trusted-development")
    generated = tmp_path / "direct-bridge"
    generated.mkdir(mode=0o700)
    with FileLock(runtime.root / "locks" / ("execution-" + request.execution_id + ".lock")) as lock:
        SharedCodexAdapter(runtime.root).argv(replace(request, lock_fd=lock.fd), generated)
        config = json.loads((generated / "shared-job.json").read_text())
        assert bridge(config, "no native turn", lock.fd, request.journal_path, Event()) == 1
    capsys.readouterr()
    saved = Journal(job_path(runtime.root, request.execution_id)).read()
    assert saved["status"] == "failed" and saved["code"] == "CAPABILITY_UNSUPPORTED"
    assert saved["quiesced"] is True and saved["proof"] == "no_thread"
    assert not wire_methods(capture, "thread/start") and not wire_methods(capture, "turn/start")
    assert not runtime.policy_blocked.is_set()
    assert shared_stopped(Journal(request.journal_path).read()["shared_session"])
    assert policy_execute(runtime, policy_request(policy, job, 1)).status == "succeeded"
    assert len(wire_methods(capture, "turn/start")) == 1


def test_policy_review_dispatch_uses_target_allocator_and_target_lock(server, sealed_policy, job):
    policy = sealed_policy
    runtime, capture = server(root=policy.root, profile=policy.profile, policy=policy)
    target = policy_request(policy, job)
    dispatch_id = str(uuid4())
    journal = policy.root / "journals" / (dispatch_id + ".json")
    Journal(journal).update(execution_id=dispatch_id, request={"target_execution_id": target.execution_id})
    review = replace(target, execution_id=dispatch_id, journal_path=journal, permission_profile="observe")
    assert policy_execute(runtime, review).status == "succeeded"
    assert wire_methods(capture, "thread/start")[0]["params"]["cwd"] == str(target.workspace_path)
    assert wire_methods(capture, "thread/start")[0]["params"]["sandbox"] == "read-only"


@pytest.mark.parametrize("fault", ["allocator", "main-root", "ancestor", "worktree-layer", "dispatch-target"])
def test_policy_binding_faults_fail_before_native_start(server, sealed_policy, job, fault):
    policy = sealed_policy
    runtime, capture = server(root=policy.root, profile=policy.profile, policy=policy)
    request = policy_request(policy, job)
    journal = Journal(request.journal_path)
    if fault == "allocator":
        journal.update(workspace={**journal.read()["workspace"], "path": str(policy.repositories[0])})
    elif fault == "main-root":
        journal.update(repository_root=str(policy.root / "projects"))
    elif fault == "ancestor":
        (policy.repositories[0].parent / ".codex").mkdir()
    elif fault == "worktree-layer":
        (request.workspace_path / ".codex").symlink_to("missing")
    else:
        journal.update(request={"target_execution_id": str(uuid4())})
    try:
        result = policy_execute(runtime, request)
        assert result.status == "failed"
    except WorkerError:
        assert runtime.policy_blocked.is_set()
    assert not wire_methods(capture, "thread/start")


def test_job_cannot_inject_operator_projects(server, sealed_policy, job, tmp_path):
    policy = sealed_policy
    runtime, capture = server(root=policy.root, profile=policy.profile, policy=policy)
    request = policy_request(policy, job)
    directory = tmp_path / "job-config"
    directory.mkdir()
    with FileLock(policy.root / "locks" / ("execution-" + request.execution_id + ".lock")) as lock:
        SharedCodexAdapter(policy.root).argv(replace(request, lock_fd=lock.fd), directory)
        frame = json.loads((directory / "shared-job.json").read_text())
        frame["start"]["config"]["projects"] = policy.projects
        result = bridge(frame, "synthetic", lock.fd, request.journal_path, Event())
    assert result != 0
    assert Journal(job_path(policy.root, request.execution_id)).read()["code"] == "PERMISSION_DENIED"
    assert not wire_methods(capture, "thread/start")


@pytest.mark.parametrize("point", ["before-start", "after-thread", "after-turn", "before-success", "git-marker"])
def test_drift_windows_fence_native_turn_or_success(server, sealed_policy, job, monkeypatch, point):
    policy = sealed_policy
    runtime, capture = server(root=policy.root, profile=policy.profile, policy=policy)
    request = policy_request(policy, job)
    path = policy.profile / "config.toml"
    def mutate():
        if point == "git-marker":
            (request.workspace_path / ".git").write_text("gitdir: /unapproved-root/.git\n")
            return
        path.write_text('model = "SYNTHETIC_POLICY_SECRET"')
        path.chmod(0o600)
    original = runtime.rpc.call
    def call(method, params, **kwargs):
        value = original(method, params, **kwargs)
        if method == {"after-thread": "thread/start", "git-marker": "thread/start", "after-turn": "turn/start", "before-success": "thread/unsubscribe"}.get(point):
            mutate()
        return value
    monkeypatch.setattr(runtime.rpc, "call", call)
    if point == "before-start":
        mutate()
    try:
        result = policy_execute(runtime, request)
        assert result.status == "failed" and result.error_code == "PERMISSION_DENIED"
    except WorkerError:
        assert point == "before-start"
    assert runtime.policy_blocked.is_set()
    assert runtime.state.read()["policy_blocked"] is True
    assert SharedCodexAdapter(policy.root).probe()["health"] == "blocked"
    assert len(wire_methods(capture, "turn/start")) == (0 if point in {"before-start", "after-thread", "git-marker"} else 1)
    if point != "before-start":
        assert Journal(job_path(policy.root, request.execution_id)).read()["proof"] == "thread_closed"
    if point != "before-start":
        with pytest.raises(WorkerError):
            check_receipt(policy.root, Journal(request.journal_path).read())
    else:
        assert Journal(request.journal_path).read().get("shared_profile_policy") is None
    assert "SYNTHETIC_POLICY_SECRET" not in json.dumps(runtime.state.read())


@pytest.mark.parametrize("mode,mutation", [("slow", "manifest"), ("slow", "loop"), ("slow", "deep"), ("slow-no-close", "manifest")])
def test_drift_interrupts_all_siblings_and_keeps_unproved_locks(server, sealed_policy, job, mode, mutation):
    policy = sealed_policy
    runtime, capture = server(mode, root=policy.root, profile=policy.profile, policy=policy)
    jobs = [policy_request(policy, job, number) for number in range(3)]
    results, errors = {}, []
    def execute(number):
        try:
            results[number] = policy_execute(runtime, jobs[number])
        except Exception as exc:
            errors.append(exc)
    runners = [threading.Thread(target=execute, args=(number,)) for number in range(3)]
    for runner in runners:
        runner.start()
    until = time.monotonic() + 8
    while time.monotonic() < until:
        if all(Journal(job_path(policy.root, request.execution_id)).read().get("status") == "running" for request in jobs):
            break
        time.sleep(0.01)
    assert len(wire_methods(capture, "turn/start")) == 3
    if mutation == "manifest":
        policy.manifest.write_text('{"version":1,"project_roots":[]}')
    elif mutation == "loop":
        (policy.profile / "config.toml").symlink_to("config.toml")
    else:
        path = policy.profile / "config.toml"
        path.write_text('x=' + '{a=' * 2000 + '1' + '}' * 2000)
        path.chmod(0o600)
    for runner in runners:
        runner.join(timeout=12)
        assert not runner.is_alive()
    assert not errors, errors
    assert len(wire_methods(capture, "turn/interrupt")) == 3
    expected = "failed" if mode == "slow" else "uncertain"
    assert [results[n].status for n in range(3)] == [expected] * 3
    assert runtime.policy_blocked.is_set()
    for request in jobs:
        lock = FileLock(policy.root / "locks" / ("execution-" + request.execution_id + ".lock"))
        if mode == "slow":
            with lock:
                pass
        else:
            with pytest.raises(WorkerError):
                with lock:
                    pass
            assert not results[jobs.index(request)].process_stopped
    old = Journal(job_path(policy.root, jobs[0].execution_id)).read()
    runtime.stopping.set()
    until = time.monotonic() + 6
    while runtime.state.read().get("stopped") is not True and time.monotonic() < until:
        time.sleep(0.05)
    assert runtime.state.read()["stopped"] is True
    policy.manifest.write_text(json.dumps({"version": 1, "project_roots": [str(policy.repositories[0])]}))
    if mutation in {"loop", "deep"}:
        (policy.profile / "config.toml").unlink()
    replacement_policy = SealedProfilePolicy(policy.root, policy.profile, policy.manifest)
    replacement, new_capture = server(root=policy.root, profile=policy.profile, policy=replacement_policy)
    with FileLock(policy.root / "locks" / ("execution-" + jobs[0].execution_id + ".lock")) as lock:
        with pytest.raises(WorkerError):
            bridge({"root": str(policy.root), "execution_id": jobs[0].execution_id, "start": {}, "timeout": 1},
                   "never replay", lock.fd, jobs[0].journal_path, Event())
    assert Journal(job_path(policy.root, jobs[0].execution_id)).read()["generation"] == old["generation"]
    assert not wire_methods(new_capture, "thread/start")
    with pytest.raises(WorkerError):
        check_receipt(policy.root, Journal(jobs[0].journal_path).read())
    fresh = policy_request(replacement_policy, job, 4)
    assert policy_execute(replacement, fresh).status == "succeeded"


def test_delayed_start_does_not_delay_drift_interrupt_of_running_sibling(server, sealed_policy, job, monkeypatch):
    policy = sealed_policy
    runtime, capture = server("slow", root=policy.root, profile=policy.profile, policy=policy)
    first, second = policy_request(policy, job, 0), policy_request(policy, job, 1)
    blocked, release = Event(), Event()
    original = runtime.rpc.call
    def call(method, params, **kwargs):
        if method == "thread/start" and params.get("model") == "model-1":
            blocked.set()
            assert release.wait(timeout=4)
        return original(method, params, **kwargs)
    monkeypatch.setattr(runtime.rpc, "call", call)
    results = {}
    first_runner = threading.Thread(target=lambda: results.update(first=policy_execute(runtime, first)))
    second_runner = threading.Thread(target=lambda: results.update(second=policy_execute(runtime, second)))
    first_runner.start()
    until = time.monotonic() + 5
    while Journal(job_path(policy.root, first.execution_id)).read().get("status") != "running" and time.monotonic() < until:
        time.sleep(0.01)
    second_runner.start()
    assert blocked.wait(timeout=5)
    try:
        policy.manifest.write_text('{"version":1,"project_roots":[]}')
        until = time.monotonic() + 1.5
        while not wire_methods(capture, "turn/interrupt") and time.monotonic() < until:
            time.sleep(0.01)
        assert runtime.policy_blocked.is_set()
        assert len(wire_methods(capture, "turn/interrupt")) == 1
        assert not release.is_set()
    finally:
        release.set()
        first_runner.join(timeout=10)
        second_runner.join(timeout=10)
    assert not first_runner.is_alive() and not second_runner.is_alive()
    assert results["first"].status == results["second"].status == "failed"
    assert len(wire_methods(capture, "turn/start")) == 1


def test_three_jobs_share_one_server_and_cancel_only_one(server, tmp_path):
    runtime, capture = server()
    cancellations = [Event() for _ in range(3)]
    jobs = [request(runtime.root, tmp_path, number) for number in range(3)]
    for number, job in enumerate(jobs):
        name = "files" + str(number)
        content = "---\nname: skill" + str(number) + "\ndescription: isolated test\n---\nOnly job " + str(number)
        jobs[number] = replace(job, approved_skills=(SkillSnapshot("skill" + str(number), hashlib.sha256(content.encode()).hexdigest(), content),),
                               mcp_config={name: {"command": sys.executable, "args": ["-I", "-m", "adf_runtime_worker.scoped_mcp"],
                                                 "scope": {"contract": "adf.scoped-files.v1"}, "enabled_tools": ["read_marker"],
                                                 "startup_timeout_sec": 2, "tool_timeout_sec": 2, "required": True, "env_vars": []}},
                               allowed_tools=("mcp__" + name + "__read_marker",))
    results, outputs, errors = {}, {}, []
    def execute(number):
        try:
            with FileLock(runtime.root / "locks" / ("execution-" + jobs[number].execution_id + ".lock")) as lock:
                adapter = SharedCodexAdapter(runtime.root)
                results[number] = adapter.execute(replace(jobs[number], lock_fd=lock.fd), lambda *_: None, cancellations[number])
                outputs[number] = results[number].output
        except Exception as exc:
            errors.append(exc)
    runners = [threading.Thread(target=execute, args=(number,)) for number in range(3)]
    for runner in runners:
        runner.start()
    until = time.monotonic() + 5
    while time.monotonic() < until:
        states = list((runtime.directory / "jobs").glob("*.json"))
        if len(states) == 3 and all(Journal(path).read().get("status") == "running" for path in states):
            break
        time.sleep(0.01)
    assert len(states) == 3
    assert SharedCodexAdapter(runtime.root).probe()["health"] == "ready"
    cancellations[0].set()
    for runner in runners:
        runner.join(timeout=10)
        assert not runner.is_alive()
    assert not errors, errors
    assert results[0].status == "cancelled"
    assert [results[n].status for n in (1, 2)] == ["succeeded", "succeeded"]
    assert outputs[1] == str(jobs[1].workspace_path)
    assert outputs[2] == str(jobs[2].workspace_path)
    assert results[1].usage.input_tokens == 4 and results[1].usage.output_tokens == 2
    wire = [json.loads(line) for line in capture.read_text().splitlines()]
    assert len({frame["pid"] for frame in wire}) == 1
    starts = [frame["params"] for frame in wire if frame["method"] == "thread/start"]
    assert len(starts) == 3
    assert len({start["cwd"] for start in starts}) == 3
    assert {start["model"] for start in starts} == {"model-0", "model-1", "model-2"}
    for start in starts:
        number = int(start["model"][-1])
        assert set(start["config"]["mcp_servers"]) == {"files" + str(number)}
        enabled = [rule["path"] for rule in start["config"]["skills"]["config"] if rule["enabled"]]
        assert enabled == [str(jobs[number].workspace_path / ".agents" / "skills" / ("skill" + str(number)) / "SKILL.md")]
        assert start["approvalPolicy"] == "never"
        assert not (jobs[number].workspace_path / ".agents").exists()
    assert len([frame for frame in wire if frame["method"] == "turn/interrupt"]) == 1
    assert all(owned_sessions_stopped(Journal(job.journal_path).read()) for job in jobs)
    assert all(Journal(job_path(runtime.root, job.execution_id)).read()["proof"] == "thread_closed" for job in jobs)
    assert "private reasoning" not in json.dumps(outputs)


def test_unsubscribe_without_closed_is_uncertain_and_retains_worktree_lock(server, tmp_path):
    runtime, _ = server("no-close")
    job = request(runtime.root, tmp_path, 0)
    content = "---\nname: retained\ndescription: test\n---\nRetain until dead proof"
    job = replace(job, approved_skills=(SkillSnapshot("retained", hashlib.sha256(content.encode()).hexdigest(), content),))
    lock_path = runtime.root / "locks" / ("execution-" + job.execution_id + ".lock")
    with FileLock(lock_path) as lock:
        result = SharedCodexAdapter(runtime.root).execute(replace(job, lock_fd=lock.fd), lambda *_: None, Event())
    assert result.status == "uncertain"
    assert not result.process_stopped
    assert not owned_sessions_stopped(Journal(job.journal_path).read())
    assert (job.workspace_path / ".agents" / "skills" / "retained" / "SKILL.md").exists()
    assert Path(Journal(job.journal_path).read()["retained_provider_config"]).is_dir()
    with pytest.raises(WorkerError):
        with FileLock(lock_path):
            pass
    runtime.stopping.set()
    until = time.monotonic() + 4
    while runtime.state.read().get("stopped") is not True and time.monotonic() < until:
        time.sleep(0.05)
    assert shared_stopped(Journal(job.journal_path).read()["shared_session"])
    assert Journal(job_path(runtime.root, job.execution_id)).read()["status"] == "uncertain"
    with FileLock(lock_path):
        pass


def test_crash_is_quiesced_without_replay_and_new_generation_accepts_new_id(server, tmp_path):
    runtime, capture = server("crash")
    job = request(runtime.root, tmp_path, 0)
    with FileLock(runtime.root / "locks" / ("execution-" + job.execution_id + ".lock")) as lock:
        result = SharedCodexAdapter(runtime.root).execute(replace(job, lock_fd=lock.fd), lambda *_: None, Event())
    assert result.status == "uncertain"
    until = time.monotonic() + 5
    while runtime.state.read().get("stopped") is not True and time.monotonic() < until:
        time.sleep(0.05)
    old = Journal(job_path(runtime.root, job.execution_id)).read()
    assert old["proof"] == "server_session_dead"
    replacement, new_capture = server(root=runtime.root)
    assert replacement.generation != runtime.generation
    with FileLock(runtime.root / "locks" / "workspace.lock") as lock:
        with pytest.raises((WorkerError, OSError)):
            config = {"root": str(runtime.root), "execution_id": job.execution_id, "start": {}, "timeout": 1}
            bridge(config, "do not replay", lock.fd, job.journal_path, Event())
    assert Journal(job_path(runtime.root, job.execution_id)).read() == old
    next_job = request(runtime.root, tmp_path, 1)
    with FileLock(runtime.root / "locks" / ("execution-" + next_job.execution_id + ".lock")) as lock:
        assert SharedCodexAdapter(runtime.root).execute(replace(next_job, lock_fd=lock.fd), lambda *_: None, Event()).status == "succeeded"
    assert len([line for line in capture.read_text().splitlines() if json.loads(line)["method"] == "turn/start"]) == 1
    assert len([line for line in new_capture.read_text().splitlines() if json.loads(line)["method"] == "turn/start"]) == 1


@pytest.mark.parametrize("mode", ["missing", "expired"])
def test_auth_failure_never_logs_in_or_leaks_raw_error(server, tmp_path, capsys, mode):
    runtime, capture = server(mode)
    job = request(runtime.root, tmp_path, 0)
    with FileLock(runtime.root / "locks" / ("execution-" + job.execution_id + ".lock")) as lock:
        config = {"root": str(runtime.root), "execution_id": job.execution_id, "start": {}, "timeout": 1}
        assert bridge(config, "offline", lock.fd, job.journal_path, Event()) == 1
    record = Journal(job_path(runtime.root, job.execution_id)).read()
    assert record["code"] == "AUTH_REQUIRED"
    assert record["proof"] == "no_thread"
    wire = capture.read_text()
    assert "login" not in wire and "thread/start" not in wire and "refreshToken\": true" not in wire
    assert "AUTH_SECRET" not in capsys.readouterr().out
    assert "AUTH_SECRET" not in json.dumps(record)


def test_config_guard_and_normalization_do_not_leak_permissions_or_reasoning(tmp_path):
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "config.toml").write_text('secret = "private"')
    with pytest.raises(WorkerError, match="configuration"):
        clean_config(profile)
    assert native_event({"method": "item/completed", "params": {"item": {"type": "reasoning", "text": "private"}}}) is None
    assert native_event({"method": "item/completed", "params": {"item": {"type": "commandExecution", "command": "secret", "aggregatedOutput": "secret", "exitCode": 0}}}) == {
        "type": "item.completed", "item": {"type": "command_execution", "id": None, "status": None, "exit_code": 0}}
    config = baseline()
    assert config["thread_unload_delay_secs"] == 0
    assert not config["features.auth_elicitation"]
    assert not config["sandbox_workspace_write.network_access"]


def test_bridge_requires_canonical_execution_ids_and_real_shared_proof(tmp_path):
    with pytest.raises(ValueError):
        job_path(tmp_path, "../../auth.json")
    assert not shared_stopped({"root": str(tmp_path), "execution_id": str(uuid4()), "generation": "missing"})
    assert not owned_sessions_stopped({"shared_session": {"root": str(tmp_path), "execution_id": str(uuid4()), "generation": "missing"}})


def test_recover_orphan_server_before_new_generation_without_job_replay(server, tmp_path):
    root = tmp_path / "orphan-root"
    directory = root / "providers" / "codex"
    (directory / "jobs").mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    owner = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(0.1)"], start_new_session=True)
    owner_identity = process_identity(owner.pid)
    owner.wait(timeout=3)
    orphan = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], start_new_session=True)
    identity = process_identity(orphan.pid)
    generation, execution_id = str(uuid4()), str(uuid4())
    Journal(directory / "server.json").update(owner=owner_identity, server=identity, generation=generation, stopped=False)
    old_job = Journal(job_path(root, execution_id))
    old_job.update(execution_id=execution_id, generation=generation, status="running", quiesced=False)
    try:
        runtime, capture = server(root=root)
        assert not group_alive(identity)
        orphan.wait(timeout=3)
        assert old_job.read()["proof"] == "server_session_dead"
        assert old_job.read()["status"] == "uncertain"
        assert not any(json.loads(line)["method"] == "turn/start" for line in capture.read_text().splitlines())
        assert runtime.generation != generation
    finally:
        if orphan.poll() is None:
            orphan.terminate()
        orphan.wait(timeout=3)


def test_shared_job_environment_and_permission_override_are_rejected(tmp_path):
    adapter = SharedCodexAdapter(tmp_path)
    with pytest.raises(WorkerError, match="environment"):
        adapter.argv(Request(str(uuid4()), str(uuid4()), 1, env_allowlist=("LANG",)), tmp_path)


@pytest.mark.parametrize("names", [
    ("HOME",), ("PATH", "HOME", "LANG"), ("HOME", "PATH", "LANG", "TERM"),
    ("PATH", "HOME", "LANG", "TERM", "TERM"), ("PATH", "HOME", "LANG", "TERM", "TMPDIR"),
    ("PATH", "HOME", "LANG", "TERM", "OPENAI_API_KEY"), ("CODEX_HOME",), ("CLAUDE_CONFIG_DIR",),
    ("ADF_WORKER_TOKEN",), ("LANG=job-value",), ("path", "HOME", "LANG", "TERM"),
])
def test_shared_nonbaseline_environment_is_refused_before_probe_or_dispatch(tmp_path, monkeypatch, names):
    adapter = SharedCodexAdapter(tmp_path)
    def unexpected_probe(*_):
        pytest.fail("Rejected job must not probe or launch the provider")
    monkeypatch.setattr(adapter, "probe", unexpected_probe)
    job = Request(str(uuid4()), str(uuid4()), 1, env_allowlist=names)
    with pytest.raises(WorkerError) as error:
        adapter.execute(job, lambda *_: None, Event())
    assert error.value.code == "CAPABILITY_UNSUPPORTED"
    with pytest.raises(WorkerError):
        adapter.argv(job, tmp_path)
    assert not list(tmp_path.iterdir())


def test_actual_orchestrator_baseline_uses_fixed_operator_environment(server, tmp_path, monkeypatch):
    from adf_runtime_worker.adapters import CodexAdapter
    from adf_runtime_worker.profiles import ProviderProfile
    fixture = json.loads((FAKE.parent / "orchestrator-shared-envelope.json").read_text())
    names = tuple(fixture["request"]["env_allowlist"])
    home = tmp_path / "adf-worker"
    profile = home / "ai-factory/provider-profiles/codex"
    profile.mkdir(parents=True, mode=0o700)
    node = home / "ai-factory/tools/node/bin/node"
    node.parent.mkdir(parents=True)
    node.write_text("synthetic executable; never invoked")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", "/mnt/c/unapproved:/usr/bin:/bin")
    monkeypatch.setenv("ADF_NODE_PATH", str(node))
    monkeypatch.setenv("CODEX_HOME", "/mnt/c/unapproved-profile")
    for name in ("OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ADF_WORKER_TOKEN", "ADF_REDIS_PASSWORD"):
        monkeypatch.setenv(name, "synthetic-private-value")
    monkeypatch.setattr(CodexAdapter, "probe", lambda *_: {"health": "ready"})
    environment = {**restricted_env(), **ProviderProfile("codex", profile).environment()}
    selected_profile = profile
    runtime, capture = server(environment=environment, profile=selected_profile)
    adapter = SharedCodexAdapter(runtime.root)
    job = replace(request(runtime.root, tmp_path, 0), env_allowlist=names)
    observed_requests = []
    original_run = adapter.runner.run
    def bridge_run(argv, effective, *args, **kwargs):
        observed_requests.append(effective)
        return original_run(argv, effective, *args, **kwargs)
    monkeypatch.setattr(adapter.runner, "run", bridge_run)
    with FileLock(runtime.root / "locks" / ("execution-" + job.execution_id + ".lock")) as lock:
        result = adapter.execute(replace(job, lock_fd=lock.fd), lambda *_: None, Event())
    assert result.status == "succeeded"
    assert job.env_allowlist == names
    assert len(observed_requests) == 1 and observed_requests[0].env_allowlist == ()
    wire = [json.loads(line) for line in capture.read_text().splitlines()]
    assert len([frame for frame in wire if frame["method"] == "turn/start"]) == 1
    for frame in wire:
        assert frame["environment"] == {"HOME": str(home), "PATH": str(node.parent) + ":/usr/bin:/bin", "CODEX_HOME": str(profile)}
        assert not {"OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ADF_WORKER_TOKEN", "ADF_REDIS_PASSWORD"}.intersection(frame["environment_names"])
        assert not {"env", "environment", "env_allowlist", "CODEX_HOME"}.intersection(frame["params"])
    assert Journal(job_path(runtime.root, job.execution_id)).read()["proof"] == "thread_closed"


def test_pinned_public_schema_accepts_generated_thread_and_turn_configuration(tmp_path):
    fixture = json.loads((FAKE.parent / "codex-0.157.0-shared-schema.json").read_text())
    assert fixture["tag"] == "rust-v0.157.0"
    assert fixture["schemas"]["ThreadStartParams"]["full_source_sha256"] == "e9c6d3cc18d049bfbc0249add3808fb8e5a27e1a0b5a423767aafbc3859a9428"
    root = tmp_path / "root"
    root.mkdir()
    job = request(root, tmp_path, 0)
    config_dir = root / "journals" / "generated"
    config_dir.mkdir()
    with FileLock(root / "locks" / ("execution-" + job.execution_id + ".lock")) as lock:
        SharedCodexAdapter(root).argv(replace(job, lock_fd=lock.fd), config_dir)
    config = json.loads((config_dir / "shared-job.json").read_text())
    cases = {"ThreadStartParams": config["start"], "TurnStartParams": {"threadId": "thread", "input": [{"type": "text", "text": "test"}], "outputSchema": None},
             "TurnInterruptParams": {"threadId": "thread", "turnId": "turn"}, "ThreadUnsubscribeParams": {"threadId": "thread"},
             "ThreadClosedNotification": {"threadId": "thread"}}
    for name, value in cases.items():
        jsonschema.validate(value, fixture["schemas"][name]["schema"])


def test_revoked_auth_stops_further_dispatch_without_login_or_raw_error(server, tmp_path):
    runtime, capture = server("revoked")
    job = request(runtime.root, tmp_path, 0)
    events = []
    with FileLock(runtime.root / "locks" / ("execution-" + job.execution_id + ".lock")) as lock:
        result = SharedCodexAdapter(runtime.root).execute(replace(job, lock_fd=lock.fd), lambda kind, value: events.append((kind, value)), Event())
    assert result.status == "failed" and result.error_code == "AUTH_REQUIRED"
    assert SharedCodexAdapter(runtime.root).probe()["auth"] == "required"
    next_job = request(runtime.root, tmp_path, 1)
    with FileLock(runtime.root / "locks" / ("execution-" + next_job.execution_id + ".lock")) as lock:
        with pytest.raises(WorkerError) as error:
            SharedCodexAdapter(runtime.root).execute(replace(next_job, lock_fd=lock.fd), lambda *_: None, Event())
    assert error.value.code == "AUTH_REQUIRED"
    wire = [json.loads(line) for line in capture.read_text().splitlines()]
    assert len([item for item in wire if item["method"] == "turn/start"]) == 1
    assert all("login" not in str(item["method"]) for item in wire)
    assert "AUTH_SECRET" not in json.dumps(events)
    assert "AUTH_SECRET" not in json.dumps(Journal(job_path(runtime.root, job.execution_id)).read())

# Source regressions for the new owner-bound native policy. The generic fixture
# above retains legacy transport tests; provider-server cannot start in that mode.
@pytest.fixture
def native_policy(sealed_policy):
    from adf_runtime_worker.native_read_policy import NativeReadPolicy
    tool = sealed_policy.root / "tools" / "public-bin"
    tool.mkdir(mode=0o700)
    manifest = sealed_policy.root / "tools" / "native-read-policy.json"
    manifest.write_text(json.dumps({"version": 1, "read_tool_roots": [str(tool)]}))
    manifest.chmod(0o600)
    return NativeReadPolicy(sealed_policy, manifest)


def native_server(server, native_policy, mode="ready"):
    policy = native_policy.policy
    return server(mode=mode, root=policy.root, profile=policy.profile, policy=policy, native_policy=native_policy,
                  environment={**restricted_env(), "CODEX_HOME": str(policy.profile)})


def test_native_startup_requires_both_operator_policies_before_probe(monkeypatch, native_policy):
    from adf_runtime_worker.adapters import CodexAdapter
    from adf_runtime_worker.profiles import ProviderProfile
    monkeypatch.setenv("HOME", str(native_policy.policy.root.parent))
    profile = ProviderProfile("codex", native_policy.policy.profile)
    monkeypatch.setattr(CodexAdapter, "probe", lambda *_: pytest.fail("Invalid policy reached provider probe"))
    for policy, native in ((None, None), (native_policy.policy, None), (None, native_policy)):
        with pytest.raises(WorkerError, match="requires sealed trust"):
            server_command("synthetic-codex", profile, policy, native)


def test_native_command_contains_owner_only_default_deny_without_workspace(monkeypatch, native_policy):
    from adf_runtime_worker.adapters import CodexAdapter
    from adf_runtime_worker.profiles import ProviderProfile
    monkeypatch.setattr(CodexAdapter, "probe", lambda *_: {"health": "ready"})
    monkeypatch.setenv("HOME", str(native_policy.policy.root.parent))
    argv, _, _ = server_command("synthetic-codex", ProviderProfile("codex", native_policy.policy.profile), native_policy.policy, native_policy)
    assert not any("sandbox_mode" in arg for arg in argv)
    assert 'default_permissions="adf_shared_read"' in argv
    assert 'features.request_permissions_tool=false' in argv
    fs = native_policy.overrides(None)["permissions"]["adf_shared_read"]["filesystem"]
    assert fs[":root"] == "deny" and ":workspace_roots" not in fs and ":read-only" not in fs
    assert set(fs.values()) <= {"read", "deny"}
    assert not any(str(native_policy.policy.root / "worktrees") in key and value == "read" for key, value in fs.items())


@pytest.mark.parametrize("fault", ["extra", "duplicate", "broad", "alias", "wrong-mode", "profile-overlap", "trust-manifest-overlap"])
def test_native_operator_manifest_rejects_expansion(native_policy, fault):
    from adf_runtime_worker.native_read_policy import NativeReadPolicy
    policy = native_policy.policy
    data = {"version": 1, "read_tool_roots": [str(native_policy.tool_roots[0])]}
    if fault == "extra":
        data["network"] = True
    elif fault == "duplicate":
        data["read_tool_roots"] *= 2
    elif fault == "broad":
        data["read_tool_roots"] = [str(policy.root / "tools")]
    elif fault == "alias":
        alias = policy.root / "tools" / "alias"
        alias.symlink_to(native_policy.tool_roots[0])
        data["read_tool_roots"] = [str(alias)]
    elif fault == "profile-overlap":
        profile = policy.root / "tools" / "profile"
        profile.mkdir(mode=0o700)
        policy = SealedProfilePolicy(policy.root, profile, policy.manifest)
        data["read_tool_roots"] = [str(profile)]
    elif fault == "trust-manifest-overlap":
        directory = policy.root / "tools" / "trust"
        directory.mkdir(mode=0o700)
        new_manifest = directory / "trust.json"
        new_manifest.write_bytes(policy.manifest.read_bytes())
        new_manifest.chmod(0o600)
        policy = SealedProfilePolicy(policy.root, policy.profile, new_manifest)
        data["read_tool_roots"] = [str(directory)]
    native_policy.manifest.write_text(json.dumps(data))
    native_policy.manifest.chmod(0o644 if fault == "wrong-mode" else 0o600)
    with pytest.raises(WorkerError):
        NativeReadPolicy(policy, native_policy.manifest)


def test_native_three_jobs_cancel_only_one_and_auth_refresh_is_owner_only(server, native_policy, job):
    policy = native_policy.policy
    runtime, capture = native_server(server, native_policy, "fake-refresh")
    # This is a synthetic auth canary. Native policy never reads its contents.
    auth = policy.profile / "auth.json"
    auth.write_text('{"ADF_SYNTHETIC_AUTH": "initial"}')
    auth.chmod(0o600)
    jobs = [policy_request(policy, job, number) for number in range(3)]
    cancels = [Event() for _ in jobs]
    results = {}
    runners = [threading.Thread(target=lambda n=n: results.update({n: policy_execute(runtime, jobs[n], cancels[n])})) for n in range(3)]
    for runner in runners:
        runner.start()
    until = time.monotonic() + 5
    while len(wire_methods(capture, "turn/start")) < 3 and time.monotonic() < until:
        time.sleep(0.01)
    assert len(wire_methods(capture, "turn/start")) == 3
    cancels[0].set()
    for runner in runners:
        runner.join(timeout=12)
        assert not runner.is_alive()
    assert results[0].status == "cancelled"
    assert results[1].status == results[2].status == "succeeded"
    assert len(wire_methods(capture, "turn/interrupt")) == 1
    assert json.loads(auth.read_text()).get("ADF_SYNTHETIC_OWNER_REFRESH") is not None
    for item in wire_methods(capture, "thread/start"):
        params = item["params"]
        workspace = Path(params["cwd"])
        assert "sandbox" not in params and params["allowProviderModelFallback"] is False
        fs = params["config"]["permissions"]["adf_shared_read"]["filesystem"]
        assert fs[str(workspace)] == "read"
        assert not any(fs.get(str(other.workspace_path)) == "read" for other in jobs if other.workspace_path != workspace)
        assert params["config"]["permissions"]["adf_shared_read"]["network"] == {"enabled": False}
    for request in jobs:
        check_receipt(policy.root, Journal(request.journal_path).read())
    assert not (policy.profile / "config.toml").exists()


@pytest.mark.parametrize("mode", ["native-wrong-profile", "native-wrong-roots", "native-network", "native-wrong-provider"])
def test_native_effective_policy_mismatch_closes_without_turn(server, native_policy, job, mode):
    runtime, capture = native_server(server, native_policy, mode)
    request = policy_request(native_policy.policy, job)
    result = policy_execute(runtime, request)
    assert result.status == "failed" and result.error_code == "PERMISSION_DENIED"
    assert not wire_methods(capture, "turn/start")
    assert len(wire_methods(capture, "thread/unsubscribe")) == 1
    assert Journal(job_path(runtime.root, request.execution_id)).read()["quiesced"] is True


def test_native_api_key_account_is_blocked_without_turn(server, native_policy, job):
    runtime, capture = native_server(server, native_policy, "api-key")
    assert SharedCodexAdapter(runtime.root).probe()["auth"] == "required"
    with pytest.raises(WorkerError) as denied:
        policy_execute(runtime, policy_request(native_policy.policy, job))
    assert denied.value.code == "AUTH_REQUIRED"
    assert not wire_methods(capture, "thread/start")


@pytest.mark.parametrize("fault", ["default_permissions", "permissions", "runtimeWorkspaceRoots", "projects"])
def test_native_client_cannot_supply_permission_authority(server, native_policy, job, tmp_path, fault, capsys):
    runtime, capture = native_server(server, native_policy)
    request = policy_request(native_policy.policy, job)
    generated = runtime.root / "journals" / "direct-native"
    generated.mkdir(mode=0o700)
    with FileLock(runtime.root / "locks" / ("execution-" + request.execution_id + ".lock")) as lock:
        SharedCodexAdapter(runtime.root).argv(replace(request, lock_fd=lock.fd), generated)
        config = json.loads((generated / "shared-job.json").read_text())
        config["start"]["config"][fault] = {"/": "read"}
        assert bridge(config, "synthetic", lock.fd, request.journal_path, Event()) == 1
    capsys.readouterr()
    assert not wire_methods(capture, "thread/start")
    assert Journal(job_path(runtime.root, request.execution_id)).read()["code"] == "PERMISSION_DENIED"


def test_native_manifest_drift_cancels_siblings_and_fences_descendants(server, native_policy, job):
    from adf_runtime_worker.profile_policy import inherit_receipt
    runtime, capture = native_server(server, native_policy, "slow")
    request = policy_request(native_policy.policy, job)
    results = {}
    runner = threading.Thread(target=lambda: results.update(result=policy_execute(runtime, request)))
    runner.start()
    until = time.monotonic() + 5
    while not wire_methods(capture, "turn/start") and time.monotonic() < until:
        time.sleep(0.01)
    native_policy.manifest.write_bytes(native_policy.manifest.read_bytes() + b"\n")
    runner.join(timeout=10)
    assert not runner.is_alive()
    assert results["result"].status == "failed" and runtime.policy_blocked.is_set()
    assert len(wire_methods(capture, "turn/interrupt")) == 1
    with pytest.raises(WorkerError):
        check_receipt(runtime.root, Journal(request.journal_path).read())
    target = policy_request(native_policy.policy, job, 1)
    with pytest.raises(WorkerError):
        inherit_receipt(runtime.root, Journal(target.journal_path), source_id=request.execution_id)


def test_native_crash_proof_restarts_without_replaying_execution(server, native_policy, job):
    runtime, capture = native_server(server, native_policy, "crash")
    request = policy_request(native_policy.policy, job)
    result = policy_execute(runtime, request)
    assert result.status == "uncertain"
    until = time.monotonic() + 6
    while runtime.state.read().get("stopped") is not True and time.monotonic() < until:
        time.sleep(0.02)
    assert runtime.state.read()["stopped"] is True
    assert shared_stopped(Journal(request.journal_path).read()["shared_session"])
    replacement, _ = native_server(server, native_policy)
    assert policy_execute(replacement, request).error_code == "EXECUTION_UNCERTAIN"
    assert policy_execute(replacement, policy_request(native_policy.policy, job, 1)).status == "succeeded"
    assert len(wire_methods(capture, "turn/start")) == 1

@pytest.mark.parametrize("marker", [None, "legacy_unverified", "default"])
def test_new_consumer_refuses_legacy_owner_before_materialization(tmp_path, monkeypatch, marker):
    adapter = SharedCodexAdapter(tmp_path)
    monkeypatch.setattr(adapter, "probe", lambda *_: {"health": "ready", "auth": "ready", "native_read_policy": marker})
    monkeypatch.setattr(adapter.runner, "run", lambda *_: pytest.fail("Legacy owner reached provider bridge"))
    request = Request(str(uuid4()), str(uuid4()), 1, permission_profile="observe")
    with pytest.raises(WorkerError) as error:
        adapter.execute(request, lambda *_: None, Event())
    assert error.value.code == "CAPABILITY_UNSUPPORTED"


def test_direct_shared_owner_requires_native_policy_before_spawn(tmp_path):
    runtime = SharedServer(tmp_path, ["never-launch"], {})
    with pytest.raises(WorkerError) as error:
        runtime.run()
    assert error.value.code == "CAPABILITY_UNSUPPORTED" and not runtime.directory.exists()


def capability_job(native_policy, job, number=0, maximum=8, *, skill_name="scoped", server_name="files", tool_name="read_marker"):
    from adf_runtime_worker.capabilities import approved_capabilities
    root = native_policy.policy.root
    skill = root / "skills" / skill_name / "SKILL.md"
    skill.parent.mkdir(parents=True, mode=0o700)
    content = "---\nname: " + skill_name + "\ndescription: synthetic approved skill\n---\nRead the assigned marker.\n"
    skill.write_text(content)
    skill.chmod(0o600)
    mcp = {"name": server_name, "trusted": True, "transport": "stdio",
           "argv": ["python3", "-m", "adf_runtime_worker.scoped_mcp"], "allowed_tools": ["read_file", "read_marker"],
           "scope": {"contract": "adf.scoped-files.v1", "root": "$WORKTREE", "read_paths": ["README.md"], "max_bytes": 4096}, "timeout_sec": 8}
    body = {**job, "timeout_sec": maximum, "agent": {"provider": "codex", "permission_profile": "observe",
            "skills": [{"path": str(skill), "sha256": hashlib.sha256(content.encode()).hexdigest()}],
            "mcp_servers": [mcp], "tools": [{"permission": "read", "provider_mappings": {"codex": ["mcp__" + server_name + "__" + tool_name]}}]}}
    request = policy_request(native_policy.policy, body, number)
    skills, configs, tools = approved_capabilities(body["agent"], root, request.workspace_path, maximum, "observe")
    return replace(request, approved_skills=skills, mcp_config=configs, allowed_tools=tuple(tools))


def test_native_scoped_skills_and_mcp_use_same_durable_narrowing(server, native_policy, job):
    runtime, capture = native_server(server, native_policy)
    request = capability_job(native_policy, job)
    assert policy_execute(runtime, request).status == "succeeded"
    params = wire_methods(capture, "thread/start")[0]["params"]
    launch = params["config"]["mcp_servers"]["files"]
    assert launch["enabled_tools"] == ["read_marker"] and launch["env_vars"] == []
    fs = params["config"]["permissions"]["adf_shared_read"]["filesystem"]
    assert fs[str(request.workspace_path / ".agents" / "skills" / "scoped" / "SKILL.md")] == "read"
    assert fs[str(request.workspace_path / ".codex")] == "deny"
    assert not (request.workspace_path / ".agents").exists()


@pytest.mark.parametrize("fault", ["env", "env_vars", "extra-launch", "outside-scope", "extra-config", "extra-tool", "outside-skill", "host-discovery"])
def test_native_direct_capability_forgery_never_starts_thread(server, native_policy, job, fault, capsys):
    from adf_runtime_worker.native_skills import native_skills
    runtime, capture = native_server(server, native_policy)
    request = capability_job(native_policy, job)
    generated = runtime.root / "journals" / "direct-native-caps"
    generated.mkdir(mode=0o700)
    with FileLock(runtime.root / "locks" / ("execution-" + request.execution_id + ".lock")) as lock:
        with native_skills(request) as (skill_config, prompt):
            effective = replace(request, lock_fd=lock.fd, native_skill_config=skill_config)
            SharedCodexAdapter(runtime.root).argv(effective, generated)
            config = json.loads((generated / "shared-job.json").read_text())
            dynamic = config["start"]["config"]
            launch = dynamic["mcp_servers"]["files"]
            stored_path = Path(launch["args"][-1])
            stored = json.loads(stored_path.read_text())
            if fault == "env":
                launch["env"] = {"LD_PRELOAD": "synthetic"}
            elif fault == "env_vars":
                launch["env_vars"] = ["CODEX_HOME"]
            elif fault == "extra-launch":
                launch["url"] = "http://synthetic.invalid"
            elif fault == "outside-scope":
                stored["scope"]["root"] = str(runtime.root)
                stored_path.write_text(json.dumps(stored))
            elif fault == "extra-config":
                stored["env"] = {"HOME": "synthetic"}
                stored_path.write_text(json.dumps(stored))
            elif fault == "extra-tool":
                launch["enabled_tools"].append("read_file")
                stored["enabled_tools"].append("read_file")
                stored_path.write_text(json.dumps(stored))
            elif fault == "outside-skill":
                dynamic["skills"]["config"].append({"path": str(runtime.root / "outside/SKILL.md"), "enabled": True})
            elif fault == "host-discovery":
                dynamic["features.skip_host_skill_discovery"] = True
            assert bridge(config, prompt, lock.fd, request.journal_path, Event()) == 1
    capsys.readouterr()
    assert not wire_methods(capture, "thread/start")
    assert Journal(job_path(runtime.root, request.execution_id)).read()["code"] == "PERMISSION_DENIED"

@pytest.mark.skipif(not os.environ.get("ADF_TEST_CODEX_PATH"), reason="Pinned public native fixture must be explicitly supplied")
@pytest.mark.parametrize("nix_alias", [False, True])
def test_real_native_permissions_through_shared_ipc_without_model(server, native_policy, job, nix_alias, persistent_metadata_fixture, monkeypatch):
    """Actual metadata + command sandbox; fake turns, never model acceptance."""
    import stat
    from adf_runtime_worker.native_read_policy import NativeReadPolicy
    policy = native_policy.policy
    source = Path(os.environ["ADF_TEST_CODEX_PATH"])
    vendor = policy.root / "tools" / "native-vendor"
    fingerprints = {"bin/codex": "1a822376d4634ac32dddc030e5117c63359f7f8cd4b1b64382c68190287d0258",
                    "codex-resources/bwrap": "77360cb751ccedc5971391444ac86a8a33c15b04d6b4a6fe45f5d25496e62c4c"}
    for relative, expected in fingerprints.items():
        original = source.parent.parent / relative
        before = original.stat(follow_symlinks=False)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        target = vendor / relative
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb") as incoming, target.open("xb") as output:
            while chunk := incoming.read(1024 * 1024):
                digest.update(chunk)
                output.write(chunk)
        target.chmod(0o700)
        assert digest.hexdigest() == expected
        after = original.stat(follow_symlinks=False)
        assert (before.st_atime_ns, before.st_mtime_ns, before.st_ctime_ns) == (after.st_atime_ns, after.st_mtime_ns, after.st_ctime_ns)
    native_policy.manifest.write_text(json.dumps({"version": 1, "read_tool_roots": [str(vendor)]}))
    selected = NativeReadPolicy(policy, native_policy.manifest)
    jobs = [replace(policy_request(policy, {**job, "timeout_sec": 30}, number), timeout_sec=30) for number in (0, 2)]
    jobs.insert(1, capability_job(selected, job, 1, 30))
    canaries = persistent_metadata_fixture.synthetic_platform(policy.root, nix_alias=nix_alias)
    for label, path in (("outside", policy.root / "outside/canary"),
                        ("codex_auth", policy.profile / "auth.json"),
                        ("claude_auth", policy.root / "provider-profiles/claude/.credentials.json"),
                        ("worker_config", policy.root / "config/worker-token"),
                        ("redis_config", policy.root / "config/redis-worker-password")):
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_text("ADF synthetic canary " + label)
        path.chmod(0o600)
        canaries.append((label, str(path)))
    for request in jobs:
        workspace = request.workspace_path
        (workspace / "inside-canary").write_text("ADF synthetic project canary")
        for name in ("src/.codex/auth.json", "src/.ssh/id_ed25519", "src/.envrc", ".env", "src/auth.json"):
            path = workspace / name
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            path.write_text("ADF synthetic nested private canary")
            canaries.append((request.execution_id + ":" + name, str(path)))
        (workspace / "run-alias").symlink_to("/run/current-system/sw")
        (workspace / "auth-link").symlink_to(policy.profile / "auth.json")
        os.link(policy.root / "outside/canary", workspace / "auth-hardlink")
        canaries.append((request.execution_id + ":hardlink", str(workspace / "auth-hardlink")))
        unapproved = workspace / ".agents/skills/unapproved/SKILL.md"
        unapproved.parent.mkdir(parents=True, mode=0o700)
        unapproved.write_text("---\nname: unapproved\ndescription: synthetic unapproved\n---\nNever enable.\n")
        canaries.append((request.execution_id + ":unapproved-skill", str(unapproved)))
    for request in jobs:
        workspace = request.workspace_path
        cases = canaries + [("run_alias", str(workspace / "run-alias/canary")),
                            ("auth_alias", str(workspace / "auth-link")),
                            ("parent_alias", str(workspace) + "/../../../outside/canary"),
                            ("proc_self_auth", "/proc/self/root" + str(policy.profile / "auth.json")),
                            ("proc_init_auth", "/proc/1/root" + str(policy.profile / "auth.json"))]
        cases += [("sibling_" + other.execution_id, str(other.workspace_path / "inside-canary")) for other in jobs if other != request]
        probe = """import json,pathlib,socket
cases=CASES
results={}
for label,path in cases:
    try:
        pathlib.Path(path).read_bytes()
        results[label]={'denied':False}
    except OSError as error:
        results[label]={'denied':True,'errno':error.errno}
inside=pathlib.Path('inside-canary').read_text()=='ADF synthetic project canary'
selected=SELECTED
skill_read=(not selected or pathlib.Path(selected).read_text().endswith('Read the assigned marker.\\n'))
try:
    pathlib.Path('forbidden-write').write_text('synthetic')
    write_denied=False
except OSError:
    write_denied=True
try:
    with socket.socket() as s:
        s.settimeout(1)
        s.connect(('127.0.0.1',9))
    network_errno=None
except OSError as error:
    network_errno=error.errno
print(json.dumps({'canaries':results,'inside_read':inside,'write_denied':write_denied,
                  'network_errno':network_errno,'selected_skill_read':skill_read,'gate_passed':inside and skill_read and write_denied and all(v['denied'] for v in results.values()) and network_errno in (1,13)}))
""".replace("CASES", repr(cases)).replace("SELECTED", repr(str(workspace / ".agents/skills/scoped/SKILL.md") if request.approved_skills else None))
        (workspace / "native-probe.py").write_text(probe)
    environment = {**restricted_env(), "CODEX_HOME": str(policy.profile), "ADF_TEST_NATIVE_ROOT": str(policy.root),
                   "ADF_TEST_NATIVE_CODEX": str(vendor / "bin/codex")}
    runtime, capture = server(mode="native-canary", root=policy.root, profile=policy.profile, policy=policy,
                              native_policy=selected, environment=environment)
    policy.bind(jobs[0].execution_id, jobs[0].workspace_path, runtime.generation)
    selected.bind(jobs[0].execution_id, jobs[0].workspace_path, runtime.generation)
    monkeypatch.setenv("ADF_TEST_NATIVE_ROOT", str(policy.root))
    monkeypatch.setenv("ADF_TEST_NATIVE_CODEX", str(vendor / "bin/codex"))
    late = persistent_metadata_fixture.late_run_probe({"cwd": str(jobs[0].workspace_path),
                                                     "config": selected.overrides(jobs[0].workspace_path)})
    assert late == {"late_reads_denied": True, "cases": 5, "inside_read": True}
    # The old parent mask must fail under the same synthetic WSL mount, while
    # the reviewed named profile above has actually entered the sandbox.
    previous = selected.overrides(jobs[0].workspace_path)
    previous_fs = previous["permissions"]["adf_shared_read"]["filesystem"]
    previous_fs.pop("/run/current-system/sw")
    previous_fs.pop("/run/WSL")
    previous_fs["/run"] = "deny"
    refused = persistent_metadata_fixture.probe({"cwd": str(jobs[0].workspace_path), "config": previous})
    assert refused == {"gate_passed": False, "native_exit_code": 1}
    cancels = [Event() for _ in jobs]
    results, errors = {}, []
    def run(number):
        try:
            results[number] = policy_execute(runtime, jobs[number], cancels[number])
        except Exception as error:
            errors.append(error)
    runners = [threading.Thread(target=run, args=(number,)) for number in range(3)]
    for runner in runners:
        runner.start()
    until = time.monotonic() + 12
    while len(wire_methods(capture, "turn/start")) < 3 and time.monotonic() < until:
        time.sleep(0.02)
    assert len(wire_methods(capture, "turn/start")) == 3
    cancels[0].set()
    for runner in runners:
        runner.join(timeout=25)
        assert not runner.is_alive()
    assert not errors, errors
    assert results[0].status == "cancelled"
    for number in (1, 2):
        assert results[number].status == "succeeded"
        observed = json.loads(results[number].output)
        assert observed["gate_passed"] is True, observed
        assert observed["inside_read"] and observed["write_denied"] and observed["selected_skill_read"]
        assert all(case["denied"] for case in observed["canaries"].values())
    assert not any((request.workspace_path / "forbidden-write").exists() for request in jobs)
    assert len(wire_methods(capture, "turn/interrupt")) == 1
    for request in jobs:
        check_receipt(runtime.root, Journal(request.journal_path).read())

    observations = [row["summary"] for row in wire_methods(capture, "adf-test/native-metadata")]
    assert len(observations) == 3
    assert all(row["schema_validated"] and row["native_turn_calls"] == 0 for row in observations)
    scoped = next(row for row in observations if row["cwd"] == str(jobs[1].workspace_path))
    assert scoped["selected_skill_enabled"] and scoped["unapproved_skill_disabled"]
    assert scoped["mcp_tools"] == ["read_marker"]


@pytest.mark.parametrize("boundary", ["root", "profile", "home"])
@pytest.mark.parametrize("system", ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/nix", "/run", "/mnt", "/"])
def test_native_private_boundaries_cannot_overlap_system_grants(native_policy, monkeypatch, boundary, system):
    from types import SimpleNamespace
    from adf_runtime_worker import native_read_policy as module
    original = native_policy.policy
    values = {"root": original.root, "profile": original.profile, "manifest": original.manifest}
    candidate = Path(system) / "synthetic-private" if system != "/" else Path("/")
    if boundary == "home":
        monkeypatch.setattr(Path, "home", lambda: candidate)
    else:
        values[boundary] = candidate
    monkeypatch.setattr(module, "private_bytes", lambda *_: pytest.fail("Unsafe boundary read operator manifest"))
    with pytest.raises(WorkerError) as error:
        module.NativeReadPolicy(SimpleNamespace(**values), native_policy.manifest)
    assert error.value.code == "PERMISSION_DENIED"


@pytest.mark.skipif(not os.environ.get("ADF_TEST_CODEX_PATH"), reason="Pinned public native fixture must be explicitly supplied")
@pytest.mark.parametrize("launcher_mode", ["native", "node"])
def test_real_persistent_native_owner_configuration_without_turns(native_policy, job, monkeypatch, launcher_mode):
    """Production baseline -> multiple job overrides; actual metadata only."""
    import stat
    from contextlib import ExitStack
    from concurrent.futures import ThreadPoolExecutor
    from adf_runtime_worker.adapters import CodexAdapter
    from adf_runtime_worker.profiles import ProviderProfile
    from adf_runtime_worker.native_skills import native_skills
    from adf_runtime_worker.native_read_policy import NativeReadPolicy
    from adf_runtime_worker.shared_rpc import RpcError
    import importlib.util
    fixture = Path(__file__).parent / "fixtures/native_read_canary.py"
    spec = importlib.util.spec_from_file_location(f"adf_native_metadata_canary_{launcher_mode}", fixture)
    module = importlib.util.module_from_spec(spec)
    # Retained owners/resources stay rooted even after a failed test traceback.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    policy = native_policy.policy
    module.synthetic_platform(policy.root)
    source = Path(os.environ["ADF_TEST_CODEX_PATH"])
    vendor = policy.root / "tools" / "native-vendor"
    if launcher_mode == "node":
        if not os.environ.get("ADF_TEST_NODE_PATH") or not os.environ.get("ADF_TEST_CODEX_PACKAGE"):
            pytest.skip("Pinned public Node and npm launcher fixture must be explicitly supplied")
        package_root = policy.root / "tools/provider-cli/lib/node_modules/@openai/codex"
        vendor = package_root / "node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl"
    fingerprints = {"bin/codex": "1a822376d4634ac32dddc030e5117c63359f7f8cd4b1b64382c68190287d0258",
                    "codex-resources/bwrap": "77360cb751ccedc5971391444ac86a8a33c15b04d6b4a6fe45f5d25496e62c4c"}
    for relative, expected in fingerprints.items():
        original = source.parent.parent / relative
        before = original.stat(follow_symlinks=False)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        target = vendor / relative
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb") as incoming, target.open("xb") as output:
            while chunk := incoming.read(1024 * 1024):
                digest.update(chunk)
                output.write(chunk)
        target.chmod(0o700)
        assert digest.hexdigest() == expected
        after = original.stat(follow_symlinks=False)
        assert (before.st_atime_ns, before.st_mtime_ns, before.st_ctime_ns) == (after.st_atime_ns, after.st_mtime_ns, after.st_ctime_ns)

    launcher = vendor / "bin/codex"
    environment = None
    if launcher_mode == "node":
        originals = Path(os.environ["ADF_TEST_CODEX_PACKAGE"])
        node = policy.root / "tools/node-24.21.0/node-v24.21.0-linux-x64/bin/node"
        public_files = [
            (Path(os.environ["ADF_TEST_NODE_PATH"]), node, "7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c", 0o700),
            (originals / "bin/codex.js", package_root / "bin/codex.js", "61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70", 0o700),
            (originals / "package.json", package_root / "package.json", "3d6d5d41091c12d2e32c7d9866c9f1fcdd8a0904eafcf3c4e15f445fb497f853", 0o600),
            (source.parents[3] / "package.json", vendor.parent.parent / "package.json", "fc7f7d7ee9011189bd48e934f6af2527def360405021eebf30fbd89e1964834a", 0o600)]
        for original, target, expected, mode in public_files:
            before = original.stat(follow_symlinks=False)
            assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
            digest = hashlib.sha256()
            with os.fdopen(fd, "rb") as incoming, target.open("xb") as output:
                while chunk := incoming.read(1024 * 1024):
                    digest.update(chunk)
                    output.write(chunk)
            target.chmod(mode)
            assert digest.hexdigest() == expected
            after = original.stat(follow_symlinks=False)
            assert (before.st_atime_ns, before.st_mtime_ns, before.st_ctime_ns) == (after.st_atime_ns, after.st_mtime_ns, after.st_ctime_ns)
        launcher = policy.root / "tools/provider-cli/bin/codex"
        launcher.parent.mkdir(mode=0o700)
        launcher.symlink_to("../lib/node_modules/@openai/codex/bin/codex.js")
        worker_bin = policy.root / "tools/worker-venv/bin"
        worker_bin.mkdir(parents=True, mode=0o700)
        # Only synthetic/public values: never read an installed process environ.
        production_input = {"HOME": str(policy.root.parent), "USER": "adf-worker", "LOGNAME": "adf-worker", "LANG": "C.UTF-8",
                            "PATH": str(node.parent) + ":" + str(worker_bin) + ":/usr/bin:/bin", "ADF_NODE_PATH": str(node),
                            "DISABLE_UPDATES": "1", "DISABLE_AUTOUPDATER": "1", "NODE_OPTIONS": "ADF_SYNTHETIC_DENIED",
                            "OPENAI_API_KEY": "ADF_SYNTHETIC_DENIED", "CODEX_MANAGED_BY_NPM": "ADF_SYNTHETIC_DENIED"}
    native_policy.manifest.write_text(json.dumps({"version": 1, "read_tool_roots": [str(vendor)]}))
    selected = NativeReadPolicy(policy, native_policy.manifest)
    monkeypatch.setenv("ADF_TEST_NATIVE_ROOT", str(policy.root))
    monkeypatch.setenv("ADF_TEST_NATIVE_CODEX", str(vendor / "bin/codex"))
    monkeypatch.setenv("HOME", str(policy.root.parent))
    # Empty-profile metadata reproduction only. No auth check/login/refresh.
    monkeypatch.setattr(CodexAdapter, "probe", lambda *_: {"health": "ready"})
    if launcher_mode == "node":
        from unittest.mock import patch
        with patch.dict(os.environ, production_input, clear=True):
            argv, environment, profile = server_command(str(launcher), ProviderProfile("codex", policy.profile), policy, selected)
        assert environment == {"HOME": str(policy.root.parent), "USER": "adf-worker", "LOGNAME": "adf-worker", "LANG": "C.UTF-8",
                               "PATH": production_input["PATH"], "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                               "GIT_CONFIG_GLOBAL": "/dev/null", "CODEX_HOME": str(profile)}
        version = subprocess.run([str(node), "--version"], env=environment, capture_output=True, timeout=5, check=True)
        assert version.stdout.strip() == b"v24.21.0"
        version = subprocess.run([str(launcher), "--version"], env=environment, capture_output=True, timeout=5, check=True)
        assert version.stdout.strip() == b"codex-cli 0.157.0"
        direct_argv, _, _ = server_command(str(vendor / "bin/codex"), ProviderProfile("codex", policy.profile), policy, selected)
        assert argv[1:] == direct_argv[1:]
    else:
        argv, _, profile = server_command(str(launcher), ProviderProfile("codex", policy.profile), policy, selected)
    assert 'mcp_servers={}' in argv and 'features.skip_host_skill_discovery=true' in argv
    assert not (profile / "auth.json").exists()
    requests = [policy_request(policy, job, 0), capability_job(selected, job, 1, 30),
                capability_job(selected, job, 2, 30, skill_name="alternate", server_name="alternatefiles", tool_name="read_file")]
    owner = module.PersistentMetadataOwner(argv, policy.root, profile, environment=environment)
    params = []
    summaries = []
    thread_ids = []
    expected_models = {}
    stack = ExitStack()
    try:
        models = owner.call("model/list", {"limit": 100})["data"]
        defaults = [item["model"] for item in models if item["isDefault"]]
        alternatives = [item["model"] for item in models if not item["isDefault"]]
        assert len(defaults) == 1 and alternatives
        for number, request in enumerate(requests):
            lock = stack.enter_context(FileLock(policy.root / "locks" / ("execution-" + request.execution_id + ".lock")))
            config_dir = policy.root / "journals" / ("metadata-" + str(number))
            config_dir.mkdir(mode=0o700)
            skill_config, _ = stack.enter_context(native_skills(request))
            SharedCodexAdapter(policy.root).argv(replace(request, lock_fd=lock.fd, native_skill_config=skill_config), config_dir)
            frame = json.loads((config_dir / "shared-job.json").read_text())
            policy.bind(request.execution_id, request.workspace_path, "synthetic-metadata")
            skill_paths = selected.validate_capabilities(request.execution_id, request.workspace_path, frame["start"]["config"])
            selected.bind(request.execution_id, request.workspace_path, "synthetic-metadata")
            effective = {**frame["start"], "allowProviderModelFallback": False,
                         "config": {**frame["start"]["config"], "projects": policy.projects,
                                    **selected.overrides(request.workspace_path, skill_paths)}}
            effective.pop("sandbox")
            # Exercise the real default route as well as catalog model overrides.
            if number == 0:
                effective.pop("model")
            else:
                effective["model"] = defaults[0] if number == 1 else alternatives[0]
            expected_models[effective["cwd"]] = defaults[0] if number < 2 else alternatives[0]
            params.append(effective)
        for values in params:
            result, summary = owner.metadata(values)
            selected.verify_response(result, Path(values["cwd"]))
            assert result["model"] == expected_models[values["cwd"]]
            thread_ids.append(result["thread"]["id"])
            summaries.append(summary)
        with ThreadPoolExecutor(max_workers=3) as pool:
            for values, (result, summary) in zip(params, pool.map(owner.metadata, params), strict=True):
                selected.verify_response(result, Path(values["cwd"]))
                assert result["model"] == expected_models[values["cwd"]]
                thread_ids.append(result["thread"]["id"])
                summaries.append(summary)
        assert len(summaries) == len(set(thread_ids)) == 6
        for summary in summaries:
            number = next(n for n, request in enumerate(requests) if summary["cwd"] == str(request.workspace_path))
            assert summary["quiescence_proof"] == "thread_closed"
            assert summary["mcp_servers"] == ([], ["files"], ["alternatefiles"])[number]
            assert summary["mcp_tools"] == ([], ["read_marker"], ["read_file"])[number]
            expected_skill = (None, "scoped", "alternate")[number]
            enabled = [item["path"] for item in summary["skill_catalog"] if item["enabled"]]
            assert enabled == ([summary["cwd"] + "/.agents/skills/" + expected_skill + "/SKILL.md"] if expected_skill else [])
        policy.check()
        selected.check()
        assert owner.methods.count("thread/start") == owner.methods.count("thread/unsubscribe") == 6
        assert not any(method.startswith("turn/") for method in owner.methods)
        print(json.dumps({"persistent_metadata_owner": True, "launcher_mode": launcher_mode,
                          "production_env_names": sorted(environment) if environment else [],
                          "sequential_threads": 3, "parallel_threads": 3,
                          "native_turn_calls": 0, "summaries": summaries}))
    except RpcError as error:
        pytest.fail("Persistent native metadata failed: " + json.dumps(error.receipt()), pytrace=False)
    finally:
        try:
            owner.close()
        except BaseException:
            # Keep materialized skills and lock FDs if owner death is unknown.
            module.RETAINED_METADATA_RESOURCES.append((owner, stack))
            raise
        stack.close()
    assert owner.process.poll() is not None and not (profile / "auth.json").exists()


@pytest.mark.parametrize(("mode", "outcome"), [("rpc-provider-error", "provider_error"),
                                               ("rpc-malformed", "malformed_response"), ("rpc-closure", "transport_closed")])
def test_rpc_failure_receipt_survives_uncertain_fence_without_turn(server, native_policy, job, mode, outcome):
    runtime, capture = native_server(server, native_policy, mode)
    target = policy_request(native_policy.policy, job)
    result = policy_execute(runtime, target)
    assert result.status == "uncertain" and result.error_code == "EXECUTION_UNCERTAIN"
    journal = Journal(job_path(runtime.root, target.execution_id)).read()
    assert journal["rpc_failure"]["outcome"] == outcome
    assert journal["rpc_failure"]["method"] == "thread/start" and journal["rpc_failure"]["phase"] == "thread_start"
    assert journal["failure_phase"] == "thread_start"
    assert "PRIVATE_SYNTHETIC_SECRET" not in json.dumps(journal)
    assert not wire_methods(capture, "turn/start")
    assert len(wire_methods(capture, "thread/start")) == 1
    # Explicit errors still cannot prove no upstream side effect after intent.
    if mode != "rpc-closure":
        assert journal["quiesced"] is False and journal["proof"] is None
        with pytest.raises(WorkerError, match="lock is held"):
            with FileLock(runtime.root / "locks" / ("execution-" + target.execution_id + ".lock")):
                pytest.fail("Uncertain allocation lock was released")
        with pytest.raises(WorkerError, match="lock is held"):
            policy_execute(runtime, target)
        assert len(wire_methods(capture, "thread/start")) == 1


@pytest.fixture
def persistent_metadata_fixture():
    import importlib.util
    fixture = Path(__file__).parent / "fixtures/native_read_canary.py"
    spec = importlib.util.spec_from_file_location("adf_fake_metadata_canary", fixture)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("mode", ["closed", "missing-close", "wrong-thread", "transport-closed",
                                  "unacknowledged", "metadata-failed", "start-failed", "invalid-schema"])
def test_persistent_metadata_waits_for_closed_or_stops_owner(persistent_metadata_fixture, monkeypatch, mode):
    """In-memory RPC only: an unsubscribe response is not quiescence."""
    import queue
    from adf_runtime_worker.shared_rpc import RpcError
    module = persistent_metadata_fixture
    trace = []

    class FakeRpc:
        def __init__(self):
            self.failed = Event()
            self.events = queue.Queue()

        def call(self, method, _params, timeout):
            assert timeout == 12
            trace.append(method)
            if method == "thread/start":
                if mode == "start-failed":
                    raise RpcError(method, "response_timeout", 12)
                return {"thread": {"id": "metadata-thread"}}
            if method == "mcpServerStatus/list":
                if mode == "metadata-failed":
                    raise RpcError(method, "provider_error", 1, -32602)
                return {"data": []}
            if method == "skills/list":
                return {"data": []}
            assert method == "thread/unsubscribe"
            if mode == "closed":
                self.events.put({"method": "thread/status/changed", "params": {"threadId": "metadata-thread"}})
                self.events.put({"method": "thread/closed", "params": {"threadId": "metadata-thread"}})
            elif mode == "wrong-thread":
                self.events.put({"method": "thread/closed", "params": {"threadId": "another-thread"}})
            elif mode == "transport-closed":
                self.failed.set()
            return {"status": "PRIVATE_SYNTHETIC_SECRET" if mode == "unacknowledged" else "unsubscribed"}

        def subscribe(self, thread_id):
            assert thread_id == "metadata-thread"
            trace.append("subscribe")
            return self.events

        def forget(self, thread_id):
            assert thread_id == "metadata-thread"
            trace.append("forget")

    owner = module.PersistentMetadataOwner.__new__(module.PersistentMetadataOwner)
    owner.methods = []
    owner.lock = threading.Lock()
    owner.cleanup_timeout = 0.02
    owner.rpc = FakeRpc()
    owner.close = lambda: trace.append("owner_stopped")

    def validate(value, _schema):
        if mode == "invalid-schema" and "thread" in value:
            raise jsonschema.ValidationError("PRIVATE_SYNTHETIC_SECRET")
    monkeypatch.setattr(module.jsonschema, "validate", validate)
    if mode == "closed":
        _, summary = owner.metadata({"cwd": "/synthetic-worktree"})
        assert summary["quiescence_proof"] == "thread_closed"
        assert "owner_stopped" not in trace
        assert trace.index("subscribe") < trace.index("forget")
    else:
        with pytest.raises((RuntimeError, WorkerError)) as error:
            owner.metadata({"cwd": "/synthetic-worktree"})
        if mode == "start-failed":
            assert "subscribe" not in trace and "forget" not in trace
            assert trace[-1] == "owner_stopped"
        else:
            assert trace.index("subscribe") < trace.index("forget")
            assert trace.index("owner_stopped") < trace.index("forget")
        assert "PRIVATE_SYNTHETIC_SECRET" not in str(error.value)
    assert not any(method.startswith("turn/") for method in owner.methods)


@pytest.mark.parametrize("phase", ["transport", "initialize", "initialized"])
def test_persistent_metadata_initialization_failure_stops_owner(persistent_metadata_fixture, tmp_path, monkeypatch, phase):
    import io
    from types import SimpleNamespace
    from adf_runtime_worker import shared_rpc
    module = persistent_metadata_fixture
    trace = []

    class FakeProcess:
        stdin, stdout, stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
        stopped = False

        def poll(self):
            return 0 if self.stopped else None

        def terminate(self):
            trace.append("terminate")
            self.stopped = True

        def wait(self, timeout):
            assert timeout == 3 and self.stopped
            trace.append("wait")
            return 0

    process = FakeProcess()

    class FakeRpc:
        def __init__(self, _process):
            if phase == "transport":
                raise WorkerError("EXECUTION_UNCERTAIN", "Synthetic transport setup failed")
            self.reader = SimpleNamespace(join=lambda timeout: trace.append("reader_join"), is_alive=lambda: False)

        def call(self, method, _params, timeout):
            assert method == "initialize" and timeout == 12
            if phase == "initialize":
                raise shared_rpc.RpcError(method, "provider_error", 1, -32602)
            return {}

        def send(self, value):
            assert value["method"] == "initialized"
            raise WorkerError("EXECUTION_UNCERTAIN", "Synthetic initialized write failed")

    monkeypatch.setattr(module, "command", lambda *_args, **_kwargs: ["synthetic-native"])
    monkeypatch.setattr(module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(shared_rpc, "Rpc", FakeRpc)
    with pytest.raises(WorkerError):
        module.PersistentMetadataOwner(["synthetic-native"], tmp_path, tmp_path / "empty-profile")
    assert trace[:2] == ["terminate", "wait"]
    assert process.poll() == 0
    assert all(stream.closed for stream in (process.stdin, process.stdout, process.stderr))


def test_persistent_metadata_owner_unproved_shutdown_keeps_streams(persistent_metadata_fixture):
    import io
    module = persistent_metadata_fixture
    trace = []

    class UnstoppedProcess:
        stdin, stdout, stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()

        def poll(self):
            return None

        def terminate(self):
            trace.append("terminate")

        def kill(self):
            trace.append("kill")

        def wait(self, timeout):
            assert timeout == 3
            trace.append("wait")
            raise subprocess.TimeoutExpired("PRIVATE_SYNTHETIC_SECRET", timeout)

    owner = module.PersistentMetadataOwner.__new__(module.PersistentMetadataOwner)
    owner.process = UnstoppedProcess()
    owner.rpc = None
    owner.close_lock = threading.Lock()
    with pytest.raises(RuntimeError, match="shutdown was not proved") as error:
        owner.close()
    assert "PRIVATE_SYNTHETIC_SECRET" not in str(error.value)
    assert trace == ["terminate", "wait", "kill", "wait"]
    assert not any(stream.closed for stream in (owner.process.stdin, owner.process.stdout, owner.process.stderr))


def test_new_shared_generation_clears_prior_initialize_failure(server, tmp_path):
    root = tmp_path / "r"
    previous_generation = str(uuid4())
    state = Journal(root / "providers" / "codex" / "server.json")
    state.path.parent.mkdir(parents=True, mode=0o700)
    state.update(generation=previous_generation, stopped=True,
                 rpc_failure={"method": "initialize", "outcome": "provider_error", "elapsed_ms": 1,
                              "provider_error_code": -32602, "phase": "initialize"})
    runtime, capture = server(root=root)
    current = state.read()
    assert current["generation"] == runtime.generation != previous_generation
    assert current["rpc_failure"] is None and current["stopped"] is False
    assert len(wire_methods(capture, "initialize")) == 1
    assert not wire_methods(capture, "thread/start") and not wire_methods(capture, "turn/start")


@pytest.mark.skipif(not all(os.environ.get(name) for name in ("ADF_TEST_CODEX_PATH", "ADF_TEST_NODE_PATH", "ADF_TEST_CODEX_PACKAGE")),
                    reason="Checksum-pinned public Node/npm fixtures must be supplied")
@pytest.mark.parametrize("profile_mode", ["read_only", "sqlite_redirect", "writable"])
def test_public_initialize_profile_write_contract(native_policy, persistent_metadata_fixture, monkeypatch, profile_mode):
    """Initialize only: RO home fails; private SQLite alone still needs installation_id."""
    import selectors
    import signal
    from unittest.mock import patch
    from adf_runtime_worker.adapters import CodexAdapter
    from adf_runtime_worker.profiles import ProviderProfile
    from adf_runtime_worker.journal import stop_owned_session

    policy = native_policy.policy
    root, profile = policy.root, policy.profile
    node = Path(os.environ["ADF_TEST_NODE_PATH"])
    package = Path(os.environ["ADF_TEST_CODEX_PACKAGE"])
    executable = Path(os.environ["ADF_TEST_CODEX_PATH"])
    bwrap = executable.parent.parent / "codex-resources/bwrap"
    public = {node: "7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c",
              package / "bin/codex.js": "61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70",
              executable: "1a822376d4634ac32dddc030e5117c63359f7f8cd4b1b64382c68190287d0258",
              bwrap: "77360cb751ccedc5971391444ac86a8a33c15b04d6b4a6fe45f5d25496e62c4c"}
    for path, expected in public.items():
        assert path.resolve() == path and path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    assert not list(profile.iterdir())
    directory = root / "providers/codex"
    directory.mkdir(parents=True, mode=0o700)
    launcher = root / "tools/public-entry/bin/codex"
    launcher.parent.mkdir(parents=True, mode=0o700)
    launcher.symlink_to(package / "bin/codex.js")
    alias = launcher.parent.parent / "codex-resources/bwrap"
    alias.parent.mkdir(mode=0o700)
    alias.symlink_to(bwrap)
    worker_bin = root / "tools/worker-venv/bin"
    worker_bin.mkdir(parents=True, mode=0o700)
    production = {"HOME": str(root.parent), "USER": "adf-worker", "LOGNAME": "adf-worker", "LANG": "C.UTF-8",
                  "PATH": str(node.parent) + ":" + str(worker_bin) + ":/usr/bin:/bin", "ADF_NODE_PATH": str(node)}
    with patch.dict(os.environ, production, clear=True), patch.object(CodexAdapter, "probe", lambda *_: {"health": "ready"}):
        argv, environment, selected = server_command(str(launcher), ProviderProfile("codex", profile), policy, native_policy)
    assert selected == profile and set(environment) == {
        "HOME", "USER", "LOGNAME", "LANG", "PATH", "CODEX_HOME", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"}
    monkeypatch.setenv("ADF_TEST_NATIVE_ROOT", str(root))
    monkeypatch.setenv("ADF_TEST_NATIVE_CODEX", str(launcher))
    outer = persistent_metadata_fixture.command({"cwd": str(directory), "config": {}}, profile_path=profile, environment=environment)
    # Keep every initialize-only child in the Popen-owned SID; no model/tool starts.
    outer.remove("--new-session")
    binds = ["--disable-userns"]
    for public_root in sorted({node.parent.parent, package, executable.parents[3]}):
        binds += ["--ro-bind", str(public_root), str(public_root)]
    if profile_mode != "writable":
        binds += ["--ro-bind", str(profile), str(profile)]
    index = outer.index("--")
    outer[index:index] = binds
    outer += argv[1:]
    if profile_mode == "sqlite_redirect":
        outer += ["-c", 'sqlite_home="/tmp/adf-initialize-private-sqlite"']
    # The pinned standalone Python build lacks these APIs; exercise its existing ABI fallback.
    monkeypatch.delattr(os, "pidfd_open", raising=False)
    monkeypatch.delattr(signal, "pidfd_send_signal", raising=False)
    process = subprocess.Popen(outer, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"LANG": "C.UTF-8"}, start_new_session=True, close_fds=True)
    identity = process_identity(process.pid)
    output, errors, received, succeeded = bytearray(), bytearray(), 0, False
    started = time.monotonic()
    try:
        process.stdin.write(json.dumps({"id": 1, "method": "initialize", "params": {
            "clientInfo": {"name": "adf-worker", "version": "0.1.0"}, "capabilities": {"experimentalApi": True}}}).encode() + b"\n")
        process.stdin.flush()
        with selectors.DefaultSelector() as streams:
            streams.register(process.stdout, selectors.EVENT_READ, "out")
            streams.register(process.stderr, selectors.EVENT_READ, "err")
            while streams.get_map() and not succeeded and time.monotonic() - started < 12:
                for event, _ in streams.select(timeout=0.1):
                    data = os.read(event.fd, 4096)
                    if not data:
                        streams.unregister(event.fileobj)
                        continue
                    received += len(data)
                    assert received <= 65536
                    buffer = errors if event.data == "err" else output
                    buffer.extend(data)
                    if event.data == "out":
                        while (end := output.find(b"\n")) >= 0:
                            reply = json.loads(bytes(output[:end]))
                            del output[:end + 1]
                            if reply.get("id") == 1:
                                succeeded = "result" in reply
        if profile_mode == "writable":
            assert succeeded
        else:
            assert not succeeded and process.wait(timeout=3) == 1
            expected = b"failed to initialize sqlite state runtime" if profile_mode == "read_only" else b"Read-only file system"
            assert expected in errors
    finally:
        assert stop_owned_session(identity, grace_sec=0.5, kill_wait_sec=1)
        process.wait(timeout=3)
        assert not group_alive(identity)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        assert time.monotonic() - started < 20
    assert not (profile / "auth.json").exists()
