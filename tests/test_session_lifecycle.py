"""Actual Linux SID/pidfd faults; fixture subprocesses never use provider auth."""
import errno
import json
import os
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from threading import Event

import pytest

from adf_runtime_worker import journal as identities
from adf_runtime_worker import pidfd
from adf_runtime_worker.executor import Executor
from adf_runtime_worker.journal import Journal, group_alive, owned_sessions_stopped, process_identity, same_process, signal_owned_session, stop_owned_session
from adf_runtime_worker.models import WorkerError
from adf_runtime_worker.process import ProcessRunner
from adf_runtime_worker.supervisor import stopped_proof
from test_process import request

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Owned Linux sessions and pidfd ABI")


@contextmanager
def owned_child():
    child = subprocess.Popen([sys.executable, "-c", "import time;print('ready',flush=True);time.sleep(30)"], start_new_session=True, stdout=subprocess.PIPE)
    assert child.stdout.readline().strip() == b"ready"
    identity = process_identity(child.pid)
    try:
        yield child, identity
    finally:
        child.kill()
        child.wait(timeout=3)
        child.stdout.close()


def test_fixed_syscalls_work_without_stdlib_bindings_and_preserve_errno(monkeypatch):
    monkeypatch.delattr(os, "pidfd_open", raising=False)
    monkeypatch.delattr(signal, "pidfd_send_signal", raising=False)
    with owned_child() as (child, _):
        fd = pidfd.pidfd_open(child.pid)
        try:
            pidfd.pidfd_send_signal(fd, 0)
            assert child.poll() is None
        finally:
            os.close(fd)
        with pytest.raises(OSError) as error:
            pidfd.pidfd_send_signal(fd, 0)
        assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("machine,width", [("riscv64", 8), ("x86_64", 4), ("aarch64", 4)])
def test_unsupported_abi_never_calls_syscall(monkeypatch, machine, width):
    monkeypatch.setattr(pidfd.platform, "machine", lambda: machine)
    monkeypatch.setattr(pidfd.ctypes, "sizeof", lambda _: width)
    monkeypatch.setattr(pidfd, "_syscall", lambda: pytest.fail("Unsupported ABI executed syscall"))
    with pytest.raises(OSError) as error:
        pidfd.pidfd_open(1)
    assert error.value.errno == errno.ENOSYS


@pytest.mark.parametrize("missing", ["start_ticks", "session_id", "recycled"])
def test_invalid_identity_refuses_signal_and_dead_proof(repository, job, missing):
    executor = Executor(repository[0], require_ext4=False)
    journal = executor.workspaces.journal_for(job["execution_id"])
    with owned_child() as (child, identity):
        invalid = dict(identity)
        if missing == "recycled":
            invalid["start_ticks"] -= 1
        else:
            invalid.pop(missing)
        journal.update(execution_id=job["execution_id"], process=invalid)
        assert group_alive(invalid) and not owned_sessions_stopped(journal.read())
        assert signal_owned_session(invalid, signal.SIGTERM) is False
        with pytest.raises(WorkerError, match="still alive"):
            stopped_proof(journal, executor)
        assert child.poll() is None


def test_pidfd_identity_race_refuses_signal(monkeypatch):
    with owned_child() as (child, identity):
        original_open = identities.pidfd_open
        original_identity = identities.process_identity
        raced = False
        sends = []
        def open_then_recycle(pid):
            nonlocal raced
            fd = original_open(pid)
            raced = True
            return fd
        def raced_identity(pid):
            current = original_identity(pid)
            if raced and pid == child.pid:
                return {**current, "start_ticks": current["start_ticks"] + 1}
            return current
        monkeypatch.setattr(identities, "pidfd_open", open_then_recycle)
        monkeypatch.setattr(identities, "process_identity", raced_identity)
        monkeypatch.setattr(identities, "pidfd_send_signal", lambda *args: sends.append(args))
        assert not signal_owned_session(identity, signal.SIGTERM)
        assert sends == [] and child.poll() is None


def test_pidfd_refusal_is_bounded_uncertain_even_when_cancelled(tmp_path, monkeypatch):
    def unsupported(_):
        raise OSError(errno.ENOSYS, "Synthetic unavailable kernel")
    monkeypatch.setattr(identities, "pidfd_open", unsupported)
    cancel = Event()
    runner = ProcessRunner(grace_sec=0.1)
    started = time.monotonic()
    try:
        result = runner.run([sys.executable, "-c", "import time;print('ready',flush=True);time.sleep(30)"], request(tmp_path), lambda *_: cancel.set(), cancel)
        assert result.status == "uncertain" and not result.process_stopped
        assert time.monotonic() - started < 2
        assert Journal(tmp_path / "process.json").read()["phase"] == "uncertain"
    finally:
        runner.process.kill()
        runner.process.wait(timeout=3)


def test_normal_distinct_group_eof_shutdown_gets_bounded_grace(tmp_path):
    path = tmp_path / "host.json"
    child = "import json,os,time;open(" + repr(str(path)) + ",'w').write(json.dumps({'pid':os.getpid()}));time.sleep(.5)"
    parent = "import subprocess,sys,time,pathlib;subprocess.Popen([sys.executable,'-c'," + repr(child) + "],process_group=0,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);p=pathlib.Path(" + repr(str(path)) + ");\nwhile not p.exists():time.sleep(.01)\nprint('ready',flush=True)"
    found = {}
    def sink(*_):
        found.update(process_identity(json.loads(path.read_text())["pid"]))
    result = ProcessRunner(grace_sec=1).run([sys.executable, "-c", parent], request(tmp_path), sink, Event())
    assert found["pgid"] != result.process_identity["pgid"]
    assert found["session_id"] == result.process_identity["session_id"]
    assert result.status == "succeeded" and result.error_code is None
    assert result.process_stopped and not same_process(found)


@pytest.mark.parametrize("retained", ["owned_sessions", "terminal_result"])
def test_completed_git_does_not_erase_live_provider_session(repository, job, tmp_path, retained):
    path = tmp_path / "host.json"
    child = "import json,os,signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);open(" + repr(str(path)) + ",'w').write(json.dumps({'pid':os.getpid()}));time.sleep(30)"
    parent = "import subprocess,sys,time,pathlib;subprocess.Popen([sys.executable,'-c'," + repr(child) + "],process_group=0,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);p=pathlib.Path(" + repr(str(path)) + ");\nwhile not p.exists():time.sleep(.01)\nprint('ready',flush=True);time.sleep(30)"
    leader = subprocess.Popen([sys.executable, "-c", parent], start_new_session=True, stdout=subprocess.PIPE)
    assert leader.stdout.readline().strip() == b"ready"
    identity = process_identity(leader.pid)
    host = process_identity(json.loads(path.read_text())["pid"])
    executor = Executor(repository[0], require_ext4=False)
    journal = executor.workspaces.journal_for(job["execution_id"])
    journal.update(execution_id=job["execution_id"])
    journal.record_process(identity)
    if retained == "terminal_result":
        journal.update(owned_sessions=[], terminal_result={"process_identity": identity})
    leader.terminate()
    leader.wait(timeout=3)
    try:
        assert host["pgid"] != identity["pgid"] and host["session_id"] == identity["session_id"]
        executor.workspaces.execution_journal = journal
        executor.workspaces.git(repository[1], "rev-parse", "HEAD")
        assert journal.read()["process"]["pid"] != identity["pid"]
        assert not group_alive(journal.read()["process"])
        journal.update(supervisor={"pid": 999999999, "start_ticks": 1, "pgid": 999999999, "session_id": 999999999})
        with pytest.raises(WorkerError, match="still alive"):
            stopped_proof(journal, executor)
        assert stop_owned_session(identity, grace_sec=.1)
        assert stopped_proof(journal, executor)["child_group_stopped"]
    finally:
        if same_process(host):
            os.kill(host["pid"], signal.SIGKILL)
        leader.stdout.close()


def test_session_journal_quota_preserves_previous_identity(tmp_path):
    journal = Journal(tmp_path / "quota.json")
    journal.update(process={"pid": 1}, owned_sessions=[{"pid": 1}] * 4096)
    with pytest.raises(WorkerError, match="quota"):
        journal.ensure_process_capacity()
    with pytest.raises(WorkerError, match="quota"):
        journal.record_process({"pid": 2})
    assert journal.read()["process"] == {"pid": 1}


@pytest.mark.parametrize("missing", ["start_ticks", "session_id", "recycled"])
def test_incomplete_or_recycled_supervisor_is_not_dead_proof(repository, job, missing):
    executor = Executor(repository[0], require_ext4=False)
    journal = executor.workspaces.journal_for(job["execution_id"])
    with owned_child() as (child, identity):
        invalid = dict(identity)
        if missing == "recycled":
            invalid["start_ticks"] -= 1
        else:
            invalid.pop(missing)
        journal.update(execution_id=job["execution_id"], supervisor=invalid)
        with pytest.raises(WorkerError, match="still alive"):
            stopped_proof(journal, executor)
        assert child.poll() is None


@pytest.mark.parametrize("unknown", ["leader", "member"])
def test_unknown_existing_proc_metadata_refuses_signal_and_proof(repository, job, monkeypatch, unknown):
    executor = Executor(repository[0], require_ext4=False)
    journal = executor.workspaces.journal_for(job["execution_id"])
    original = identities.process_identity
    with owned_child() as (child, identity):
        def denied(pid):
            if pid == child.pid:
                return {"pid": pid, "start_ticks": None, "pgid": None, "session_id": None}
            return original(pid)
        if unknown == "member":
            original_sid = identity["session_id"]
            identity = {"pid": 999999999, "pgid": 999999999, "session_id": 999999999, "start_ticks": 1}
            assert original_sid == child.pid
        journal.update(execution_id=job["execution_id"], process=identity)
        monkeypatch.setattr(identities, "process_identity", denied)
        assert group_alive(identity)
        assert not signal_owned_session(identity, signal.SIGTERM)
        with pytest.raises(WorkerError, match="still alive"):
            stopped_proof(journal, executor)
        assert child.poll() is None
