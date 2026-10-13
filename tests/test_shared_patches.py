"""Offline patch safety, stopped proofs and complete repair/integration cycle."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from adf_runtime_worker.check_sandbox import CheckSandbox
from adf_runtime_worker.executor import Executor
from adf_runtime_worker.journal import FileLock, Journal
from adf_runtime_worker.models import AdapterResult, Request, WorkerError
from adf_runtime_worker.patches import PatchWriter, baseline, mutation_resolved, parse_patch
from adf_runtime_worker.security import digest
from adf_runtime_worker.supervisor import stopped_proof


def edit(name, content, before=None):
    return {"path": name, "action": "delete" if content is None else "replace" if before else "create", "preimage": before, "content": content}


def patch(*edits):
    return {"version": 1, "edits": list(edits)}


@pytest.fixture
def writer_factory(tmp_path):
    root = tmp_path / "worktree"
    root.mkdir()
    journal = Journal(tmp_path / "journal.json")
    lock = FileLock(tmp_path / "allocation.lock")
    with lock:
        def make(names, guard=lambda: None):
            binding = {"execution_id": "developer", "run_id": "run", "project_id": "project", "epoch": 1,
                       "approved": True, "role": "trusted-development", "scopes": names,
                       "policy_sha256": digest({"approved": True}), "baseline": baseline(root, names, names), "lock_path": str(lock.path)}
            return PatchWriter(root, journal, guard, lock_fd=lock.fd, binding=binding)
        yield root, journal, make


def test_create_replace_delete_modes_and_exact_delivery(writer_factory):
    root, journal, make = writer_factory
    (root / "old.py").write_text("old\n")
    (root / "old.py").chmod(0o755)
    (root / "gone.py").write_text("gone\n")
    writer = make(["new.py", "old.py", "gone.py"])
    value = patch(edit("new.py", "new\n"), edit("old.py", "replacement\n", writer.binding["baseline"]["old.py"]),
                  edit("gone.py", None, writer.binding["baseline"]["gone.py"]))
    result = writer.apply(value)
    assert result["patch_phase"] == "applied"
    assert (root / "old.py").stat().st_mode & 0o777 == 0o755
    assert (root / "new.py").stat().st_mode & 0o777 == 0o644
    assert not (root / "gone.py").exists()
    before = (root / "new.py").stat().st_ino
    assert writer.apply(value)["patch_replayed"] is False
    assert (root / "new.py").stat().st_ino == before
    assert mutation_resolved(journal, root)
    with pytest.raises(WorkerError) as failure:
        writer.apply(patch(edit("new.py", "changed\n")))
    assert failure.value.code == "IDEMPOTENCY_CONFLICT"


@pytest.mark.parametrize("name", ["../external", "/etc/passwd", "a/../external", "a//alias.py", ".codex/config.toml",
                                        ".agents/skills/evil", ".claude/settings.json", ".git/config", "AGENTS.md",
                                        ".env", "auth.json", "worker-token", ".adf-patch-owned", ".github/workflows/run.yml"])
def test_closed_writer_rejects_unsafe_paths(writer_factory, name):
    root, _, make = writer_factory
    writer = make(["safe.py"])
    with pytest.raises(WorkerError):
        writer.apply(patch(edit(name, "unsafe\n")))
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("payload", [
    '{"version":1,"version":1,"edits":[]}',
    '{"version":1,"edits":[],"command":"anything"}',
    json.dumps(patch(edit("safe.py", "x\n"), edit("safe.py", "x\n"))),
    json.dumps(patch(edit("safe.py", "password = 'synthetic-value'\n"))),
    json.dumps(patch(edit("safe.py", "\x00"))),
    json.dumps(patch(edit("safe.py", "🙂" * 10000))),
])
def test_schema_secrets_duplicates_binary_and_utf8_bounds(payload):
    with pytest.raises(WorkerError):
        parse_patch(payload, ["safe.py"], {})


def test_symlink_hardlink_and_missing_parent_are_rejected(writer_factory, tmp_path):
    root, journal, make = writer_factory
    outside = tmp_path / "outside"
    outside.write_text("unchanged\n")
    (root / "linked.py").symlink_to(outside)
    os.link(outside, root / "hard.py")
    for name in ["linked.py", "hard.py", "missing/new.py"]:
        with pytest.raises(WorkerError):
            make([name])
    assert outside.read_text() == "unchanged\n"
    assert not journal.read().get("patch_intents")


def test_preimage_conflict_preserves_existing_changes(writer_factory):
    root, _, make = writer_factory
    (root / "file.py").write_text("original\n")
    writer = make(["file.py"])
    value = patch(edit("file.py", "agent\n", writer.binding["baseline"]["file.py"]))
    (root / "file.py").write_text("user change\n")
    with pytest.raises(WorkerError) as failure:
        writer.apply(value)
    assert failure.value.code == "VERSION_CONFLICT"
    assert (root / "file.py").read_text() == "user change\n"


def test_atomic_exchange_race_preserves_unknown_preimage(writer_factory, monkeypatch):
    import adf_runtime_worker.patches as module
    root, journal, make = writer_factory
    (root / "file.py").write_text("original\n")
    writer = make(["file.py"])
    rename = module._rename
    def race(fd, source, target, flags):
        (root / "file.py").write_text("concurrent host change\n")
        rename(fd, source, target, flags)
    monkeypatch.setattr(module, "_rename", race)
    with pytest.raises(WorkerError) as failure:
        writer.apply(patch(edit("file.py", "agent\n", writer.binding["baseline"]["file.py"])))
    assert failure.value.code == "EXECUTION_UNCERTAIN"
    assert any(item.read_text() == "concurrent host change\n" for item in root.glob(".adf-patch-*"))
    assert not mutation_resolved(journal, root)


def test_cancellation_before_application_has_no_mutations(writer_factory):
    root, journal, make = writer_factory
    def cancelled():
        raise WorkerError("CANCEL_REQUESTED", "synthetic cancellation")
    with pytest.raises(WorkerError) as failure:
        make(["file.py"], cancelled).apply(patch(edit("file.py", "agent\n")))
    assert failure.value.code == "CANCEL_REQUESTED"
    assert list(root.iterdir()) == []
    assert mutation_resolved(journal, root)


def test_proven_no_mutation_io_failure_has_nonretryable_code(writer_factory, monkeypatch):
    root, journal, make = writer_factory
    (root / "file.py").write_text("original\n")
    writer = make(["file.py"])
    def fail(*_):
        raise OSError("synthetic I/O failure")
    monkeypatch.setattr("adf_runtime_worker.patches._rename", fail)
    with pytest.raises(WorkerError) as failure:
        writer.apply(patch(edit("file.py", None, writer.binding["baseline"]["file.py"])))
    assert failure.value.code == "PATCH_IO_FAILED"
    assert (root / "file.py").read_text() == "original\n"
    assert mutation_resolved(journal, root)


def test_cancel_between_files_classifies_partial_without_more_writes(writer_factory):
    root, journal, make = writer_factory
    def guard():
        if (root / "one.py").exists():
            raise WorkerError("CANCEL_REQUESTED", "stop before second mutation")
    with pytest.raises(WorkerError) as failure:
        make(["one.py", "two.py"], guard).apply(patch(edit("one.py", "one\n"), edit("two.py", "two\n")))
    assert failure.value.code == "CANCEL_REQUESTED"
    assert (root / "one.py").exists() and not (root / "two.py").exists()
    assert mutation_resolved(journal, root)


@pytest.mark.parametrize("code", ["CANCEL_REQUESTED", "LEASE_LOST", "PERMISSION_DENIED"])
def test_control_change_after_exchange_retains_backup_and_fences_ack(writer_factory, code):
    root, journal, make = writer_factory
    (root / "file.py").write_text("original\n")
    def guard():
        records = journal.read().get("patch_intents", {}).get("development", {}).get("files", [])
        if records and records[0]["phase"] == "mutated":
            raise WorkerError(code, "stop before destructive backup cleanup")
    writer = make(["file.py"], guard)
    with pytest.raises(WorkerError) as failure:
        writer.apply(patch(edit("file.py", "agent\n", writer.binding["baseline"]["file.py"])))
    assert failure.value.code == "EXECUTION_UNCERTAIN"
    assert any(item.read_text() == "original\n" for item in root.glob(".adf-patch-*"))
    assert not mutation_resolved(journal, root)


@pytest.mark.parametrize("phase", ["preparing", "prepared", "mutated", "applied"])
def test_crash_windows_classify_without_replay(writer_factory, monkeypatch, phase):
    root, journal, make = writer_factory
    writer = make(["file.py"])
    update = journal.update
    def crash(**fields):
        result = update(**fields)
        records = fields.get("patch_intents", {}).get("development", {}).get("files", [])
        if records and records[0]["phase"] == phase:
            raise RuntimeError("synthetic process crash")
        return result
    monkeypatch.setattr(journal, "update", crash)
    with pytest.raises(RuntimeError):
        writer.apply(patch(edit("file.py", "agent\n")))
    assert mutation_resolved(journal, root) is (phase != "prepared")
    before = journal.read()
    mutation_resolved(journal, root)
    assert journal.read() == before  # No automatic writes/model retry in recovery.


def test_repair_and_development_form_verified_image_chain(writer_factory):
    root, journal, make = writer_factory
    make(["file.py"]).apply(patch(edit("file.py", "bad\n")), key="repair")
    writer = make(["file.py"])
    writer.apply(patch(edit("file.py", "fixed\n", writer.binding["baseline"]["file.py"])))
    assert mutation_resolved(journal, root)


def test_unresolved_intent_prevents_reconciliation_even_without_live_process(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    workspace = executor.workspaces.allocate(job)
    workspace.journal.update(patch_intents={"development": {"sequence": 1, "files": [
        {"path": "feature.py", "aux": ".adf-patch-preserved", "pre": None, "post": None, "phase": "prepared"}]}})
    (workspace.path / ".adf-patch-preserved").write_text("owned incomplete mutation\n")
    with pytest.raises(WorkerError) as failure:
        stopped_proof(workspace.journal, executor)
    assert failure.value.code == "EXECUTION_UNCERTAIN"


def test_shared_patch_rejects_missing_lease_or_checker_before_native(repository, job, monkeypatch):
    from adf_runtime_worker.shared_patch_adapter import SharedPatchAdapter
    monkeypatch.setattr(SharedPatchAdapter, "execute", lambda *_: pytest.fail("native generation must not start"))
    executor = Executor(repository[0], require_ext4=False, codex_backend="shared-patch")
    job = {**job, "agent": {**job["agent"], "provider": "codex"}}
    with pytest.raises(WorkerError) as failure:
        executor.run(job, lambda *_: None, Event())
    assert failure.value.code == "PERMISSION_DENIED"
    with pytest.raises(WorkerError) as failure:
        executor.run(job, lambda *_: None, Event(), lease_deadline=lambda: time.monotonic() + 120)
    assert failure.value.code == "CAPABILITY_UNSUPPORTED"


@pytest.mark.parametrize("stopped", [True, False])
def test_adapter_keeps_original_authority_and_requires_readonly_stopped_proof(tmp_path, monkeypatch, stopped):
    from adf_runtime_worker.patches import PATCH_SCHEMA
    from adf_runtime_worker.shared_adapter import SharedCodexAdapter
    from adf_runtime_worker.shared_patch_adapter import SharedPatchAdapter
    captured = []
    events = []
    def fake(self, request, sink, cancellation):
        captured.append(request)
        sink("output", {"text": "🙂" * 20000})
        return AdapterResult("succeeded", 0, output=json.dumps(patch()), process_stopped=stopped)
    monkeypatch.setattr(SharedCodexAdapter, "execute", fake)
    request = Request("developer", "run", 7, tmp_path, permission_profile="trusted-development",
                      structured_schema=PATCH_SCHEMA, journal_path=tmp_path / "job.json")
    adapter = SharedPatchAdapter(tmp_path)
    if not stopped:
        with pytest.raises(WorkerError) as failure:
            adapter.execute(request, lambda kind, payload: events.append(payload), Event())
        assert failure.value.code == "EXECUTION_UNCERTAIN"
        assert not Journal(request.journal_path).read().get("patch_generation")
    else:
        outcome = adapter.execute(request, lambda kind, payload: events.append(payload), Event())
        assert outcome.status == "succeeded"
        assert Journal(request.journal_path).read()["phase"] == "patch_generated"
        assert "terminal_result" not in Journal(request.journal_path).read()
    assert request.permission_profile == "trusted-development"
    assert captured[0].permission_profile == "observe"
    assert captured[0].structured_schema == PATCH_SCHEMA
    assert captured[0].max_output_bytes == request.max_output_bytes
    assert len(json.dumps(events[0]).encode()) < 65536 and events[0]["truncated"]


@pytest.mark.parametrize("explicit_empty", [True, False])
def test_developer_preflights_registry_with_empty_or_missing_check_ids(repository, job, tmp_path, monkeypatch, explicit_empty):
    import shutil
    from adf_runtime_worker.shared_patch_adapter import SharedPatchAdapter
    node = tmp_path / "node"
    node.write_text("synthetic unsupported executable\n")
    node.chmod(0o700)
    which = shutil.which
    monkeypatch.setattr("adf_runtime_worker.executor.shutil.which", lambda name: str(node) if name == "node" else which(name))
    monkeypatch.setattr(CheckSandbox, "launcher", lambda _: Path("/synthetic/bwrap"))
    monkeypatch.setattr(SharedPatchAdapter, "execute", lambda *_: pytest.fail("unsupported check must fail before generation"))
    config = {"toolchain_roots": list(dict.fromkeys([str(Path(sys.prefix).resolve()), str(Path(sys.base_prefix).resolve())]))}
    executor = Executor(repository[0], require_ext4=False, codex_backend="shared-patch", check_sandbox=config)
    body = {**job, "agent": {**job["agent"], "provider": "codex"}, "project": {**job["project"], "check_registry": {"node": ["node", "check.js"]}}}
    if explicit_empty:
        body["check_ids"] = []
    else:
        body.pop("check_ids")
    with pytest.raises(WorkerError) as failure:
        executor.run(body, lambda *_: None, Event(), lease_deadline=lambda: time.monotonic() + 120)
    assert failure.value.code == "CAPABILITY_UNSUPPORTED"


@pytest.fixture
def checker_config():
    selected = os.environ.get("ADF_TEST_BWRAP_PATH")
    if not selected:
        pytest.skip("Standalone pinned bubblewrap is required for namespace integration tests")
    launcher = Path(selected).resolve(strict=True)
    roots = [str(Path(sys.prefix).resolve()), str(Path(sys.base_prefix).resolve()), "/usr/lib", "/usr/lib64"]
    return {"version": 1, "bwrap": str(launcher), "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
            "toolchain_roots": list(dict.fromkeys(roots))}


def test_checker_denies_external_auth_write_network_and_lock_fd(repository, job, checker_config):
    executor = Executor(repository[0], require_ext4=False)
    workspace = executor.workspaces.allocate(job)
    outside = repository[0] / "synthetic-auth"
    outside.write_text("never visible\n")
    (workspace.path / "probe.py").write_text(
        "import os, pathlib, socket\n"
        f"assert not pathlib.Path({str(outside)!r}).exists()\n"
        "assert not pathlib.Path('.git').exists()\n"
        "assert os.environ['HOME'] == '/home/checker'\n"
        "assert pathlib.Path('/proc').exists()\n"
        "assert len(list(pathlib.Path('/proc/self/fd').iterdir())) <= 4\n"
        "import resource\n"
        "assert resource.getrlimit(resource.RLIMIT_AS) == (128 * 1024 * 1024,) * 2\n"
        "assert resource.getrlimit(resource.RLIMIT_MEMLOCK) == (0, 0)\n"
        "import ctypes, errno\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "for number in [425, 248, 438, 319, 29, 41]:\n"
        " assert libc.syscall(number, 0, 0, 0, 0, 0, 0) == -1\n"
        " assert ctypes.get_errno() == errno.EPERM\n"
        "try:\n os.fork()\n"
        "except PermissionError:\n pass\n"
        "else:\n raise AssertionError('checker could create a process')\n"
        "import threading\n"
        "try:\n threading.Thread(target=lambda: None).start()\n"
        "except RuntimeError:\n pass\n"
        "else:\n raise AssertionError('checker could create a thread')\n"
        "for name in ['/root-file', '/dev/private-file']:\n"
        " try:\n  pathlib.Path(name).write_text('attack')\n"
        " except OSError:\n  pass\n"
        " else:\n  raise AssertionError('unbounded namespace root was writable')\n"
        "try:\n pathlib.Path('README.md').write_text('attack')\n"
        "except OSError:\n pass\n"
        "else:\n raise AssertionError('readonly snapshot was writable')\n"
        "try:\n socket.create_connection(('127.0.0.1', 8080), timeout=.1)\n"
        "except OSError:\n pass\n"
        "else:\n raise AssertionError('host network was reachable')\n"
        "pathlib.Path(os.environ['TMPDIR'], 'scratch').write_text('private')\n")
    with executor.workspaces.worktree_lock(job["execution_id"]) as lock:
        request = Request("check", "run", 1, workspace.path, journal_path=workspace.journal.path, lock_fd=lock.fd, timeout_sec=15)
        result = CheckSandbox(checker_config).run(Path(sys.executable), ["probe.py"], ["README.md", "probe.py"], request,
                                                  lambda *_: None, Event(), lambda: None)
    assert result.status == "succeeded", result.output
    assert (workspace.path / "README.md").read_text() == "test repository\n"
    assert outside.read_text() == "never visible\n"
    assert not list(workspace.path.glob(".adf-checks-*"))


def test_three_parallel_developers_failed_check_repair_review_commit_serial_integration(repository, job, checker_config, monkeypatch):
    from adf_runtime_worker.shared_adapter import SharedCodexAdapter
    from adf_runtime_worker.shared_patch_adapter import SharedPatchAdapter
    generated = []
    def fake_generation(self, request, sink, cancellation):
        assert request.structured_schema["properties"]["version"]["const"] == 1
        hashes = json.loads(request.task_prompt.split("\nBaseline: ")[1].split("\nSchema: ")[0])
        index = request.execution_id[-1]
        name = "feature" + index + ".py"
        generated.append(request.execution_id)
        value = 42 if request.execution_id.startswith("repair") or index != "1" else 0
        return AdapterResult("succeeded", 0, output=json.dumps(patch(edit(name, f"value = {value}\n", hashes.get(name)))))
    monkeypatch.setattr(SharedPatchAdapter, "execute", fake_generation)
    monkeypatch.setattr(SharedCodexAdapter, "execute", lambda *_: AdapterResult("succeeded", 0, output='{"approved":true,"findings":[]}'))
    def execute(body):
        runner = Executor(repository[0], require_ext4=False, codex_backend="shared-patch", check_sandbox=checker_config)
        journal = runner.workspaces.journal_for(body["execution_id"])
        if body["operation"] == "git_commit":
            writer = runner.workspaces.journal_for(body["target_execution_id"]).read()
            body = {**body, "review": writer["review"], "test_results": writer["test_results"]}
        journal.update(execution_id=body["execution_id"], request=body)
        result = runner.run(body, lambda *_: None, Event(), lease_deadline=lambda: time.monotonic() + 120)
        journal.update(terminal_result=result, result_persisted=True, terminal_persisted=True)
        return runner, result
    jobs = [{**job, "execution_id": f"develop{index}", "task_id": f"task{index}", "allowed_write_paths": [f"feature{index}.py"],
             "check_ids": ["value"],
             "project": {**job["project"], "checks": [{"id": "value", "argv": ["python", "-c", f"from feature{index} import value; assert value == 42"], "timeout_sec": 15}]},
             "agent": {"id": "developer", "provider": "codex", "permission_profile": "trusted-development"}}
            for index in range(1, 4)]
    with ThreadPoolExecutor(max_workers=3) as pool:
        developed = list(pool.map(execute, jobs))
    assert len({result[1]["workspace_path"] for result in developed}) == 3
    commits = []
    for index, body in enumerate(jobs, 1):
        target = body["execution_id"]
        project = {**body["project"], "checks": [{"id": "value", "argv": ["python", "-c", f"from feature{index} import value; assert value == 42"], "timeout_sec": 15}]}
        common = {**body, "project": project, "target_execution_id": target, "check_ids": ["value"]}
        _, tested = execute({**common, "operation": "test", "execution_id": f"check{index}"})
        if index == 1:
            assert tested["status"] == "failed" and tested["error_code"] == "TEST_FAILED"
            repair = {**body, "project": project, "check_ids": ["value"], "execution_id": "repair1", "repair_source_execution_id": target,
                      "repair_feedback": "value must be 42; assertion failed"}
            runner, fixed = execute(repair)
            assert fixed["status"] == "succeeded"
            assert (runner.workspaces.load(target).path / "feature1.py").read_text() == "value = 0\n"
            target = "repair1"
            common["target_execution_id"] = target
            _, tested = execute({**common, "operation": "test", "execution_id": "recheck1"})
        assert tested["status"] == "succeeded"
        _, reviewed = execute({**common, "operation": "review", "execution_id": f"review{index}",
                               "agent": {"id": "independent-reviewer", "provider": "codex", "permission_profile": "observe"}})
        assert reviewed["review"]["tree_sha"] == tested["tree_sha"]
        _, committed = execute({**common, "operation": "git_commit", "execution_id": f"commit{index}"})
        commits.append(committed["commit_sha"])
    integration = {**job, "operation": "integrate", "execution_id": "integration", "integration_commits": commits,
                   "allowed_write_paths": [f"feature{index}.py" for index in range(1, 4)], "check_ids": ["all"],
                   "project": {**job["project"], "checks": [{"id": "all", "argv": ["python", "-c", "from feature1 import value as a; from feature2 import value as b; from feature3 import value as c; assert a == b == c == 42"], "timeout_sec": 15}]}}
    runner, result = execute(integration)
    assert result["integration_status"] == "passed"
    assert runner.workspaces.git(repository[1], "rev-parse", "main") == repository[2]
    assert len(runner.workspaces.journal_for("integration").read()["delta_intents"]) == 3
    assert sorted(generated) == ["develop1", "develop2", "develop3", "repair1"]
