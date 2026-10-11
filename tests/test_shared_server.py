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
def server(tmp_path):
    running = []
    def start(mode="ready", root=None, environment=None, profile=None, policy=None):
        root = root or tmp_path / ("root-" + str(len(running)))
        root.mkdir(exist_ok=True)
        root.chmod(0o700)
        capture = tmp_path / ("wire-" + str(len(running)) + ".jsonl")
        runtime = SharedServer(root, [sys.executable, str(FAKE), str(capture), mode],
                               restricted_env() if environment is None else environment, profile=profile, cleanup_timeout=0.7, policy=policy)
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
    return Request(allocation["execution_id"], allocation["run_id"], 1, workspace.path, "synthetic policy job", 8,
                   journal_path=workspace.journal.path, permission_profile="trusted-development", model="model-" + str(number))


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
    assert not (policy.profile / "config.toml").exists()
    policy.check()
    for request in jobs:
        check_receipt(policy.root, Journal(request.journal_path).read())


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
    fixture = json.loads((FAKE.parent / "orchestrator-6fe7c14-shared-envelope.json").read_text())
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
    _, environment, selected_profile = server_command("synthetic-codex", ProviderProfile("codex", profile))
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
