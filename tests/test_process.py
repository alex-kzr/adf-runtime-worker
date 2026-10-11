import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from threading import Event
import pytest
from adf_runtime_worker.journal import group_alive
from adf_runtime_worker.models import Request, WorkerError
from adf_runtime_worker.process import ProcessRunner
from adf_runtime_worker.security import Redactor

def request(tmp_path: Path):
    return Request("execution", "run", 1, workspace_path=tmp_path, timeout_sec=5, max_output_bytes=10000, journal_path=tmp_path / "process.json")

def test_process_stdout_is_redacted_before_sink(tmp_path):
    seen = []
    runner = ProcessRunner(grace_sec=0.1, redactor=Redactor(("sentinel-private-value",)))
    result = runner.run([sys.executable, "-c", "print('sentinel-private-value')"], request(tmp_path), lambda _, text: seen.append(text), Event())
    assert result.status == "succeeded"
    assert seen == ["[REDACTED]"]
    assert "sentinel-private-value" not in result.output

@pytest.mark.skipif(os.name != "posix", reason="Linux process group acceptance")
def test_cancel_terminates_stubborn_descendants(tmp_path):
    child_script = "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)"
    script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c'," + repr(child_script) + "]); print('started',flush=True); time.sleep(30)"
    cancellation = Event()
    runner = ProcessRunner(grace_sec=0.2)
    def sink(_, text):
        if text == "started":
            cancellation.set()
    started = time.monotonic()
    result = runner.run([sys.executable, "-c", script], request(tmp_path), sink, cancellation)
    assert result.status == "cancelled"
    assert result.process_stopped
    assert not group_alive(result.process_identity)
    assert time.monotonic() - started < 3

def test_timeout_and_output_limit_stop_process(tmp_path):
    runner = ProcessRunner(grace_sec=0.1)
    timeout = runner.run([sys.executable, "-c", "import time; time.sleep(10)"], replace(request(tmp_path), timeout_sec=1), lambda *_: None, Event())
    assert timeout.error_code == "EXECUTION_TIMEOUT"
    quota = ProcessRunner(grace_sec=0.1).run([sys.executable, "-c", "print('x'*20000)"], replace(request(tmp_path), max_output_bytes=100), lambda *_: None, Event())
    assert quota.error_code == "OUTPUT_QUOTA_EXCEEDED"
    assert quota.process_stopped

def test_lease_loss_stops_before_expiry_and_is_uncertain(tmp_path):
    result = ProcessRunner(grace_sec=0.1).run([sys.executable, "-c", "import time; time.sleep(10)"], replace(request(tmp_path), lease_deadline=lambda: time.monotonic() + 2), lambda *_: None, Event())
    assert result.status == "uncertain"
    assert result.error_code == "LEASE_LOST"
    assert result.process_stopped

def test_sink_exception_does_not_leave_child_alive(tmp_path):
    def sink(*_):
        raise WorkerError("INVALID_PROVIDER_EVENT", "bad data")
    runner = ProcessRunner(grace_sec=0.1)
    result = runner.run([sys.executable, "-c", "import time; print('invalid',flush=True); time.sleep(20)"], request(tmp_path), sink, Event())
    assert result.status == "failed"
    assert result.error_code == "INVALID_PROVIDER_EVENT"
    assert not group_alive(result.process_identity)


@pytest.mark.skipif(sys.platform != "linux", reason="Dedicated Linux session containment")
@pytest.mark.parametrize("cancel", [True, False])
def test_stop_includes_stubborn_child_in_another_process_group(tmp_path, cancel):
    from adf_runtime_worker.journal import process_identity, same_process
    metadata = tmp_path / "child.json"
    child = "import json,os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); open(" + repr(str(metadata)) + ", 'w').write(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp(),'session_id':os.getsid(0)})); time.sleep(30)"
    parent = "import subprocess,sys,time,pathlib; subprocess.Popen([sys.executable,'-c'," + repr(child) + "],process_group=0,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); p=pathlib.Path(" + repr(str(metadata)) + ");\nwhile not p.exists(): time.sleep(.01)\nprint('started',flush=True)\n" + ("time.sleep(30)" if cancel else "")
    cancellation = Event()
    runner = ProcessRunner(grace_sec=0.2)
    identity = {}
    def sink(_, text):
        if text == "started":
            import json
            identity.update(process_identity(json.loads(metadata.read_text())["pid"]))
            if cancel:
                cancellation.set()
    started = time.monotonic()
    try:
        result = runner.run([sys.executable, "-c", parent], request(tmp_path), sink, cancellation)
        assert identity["pgid"] != result.process_identity["pgid"]
        assert identity["session_id"] == result.process_identity["session_id"]
        assert not same_process(identity), "Detached-PGID host survived the claimed stopped proof"
        assert result.process_stopped and not group_alive(result.process_identity)
        assert time.monotonic() - started < 3
    finally:
        if same_process(identity):
            os.kill(identity["pid"], 9)
