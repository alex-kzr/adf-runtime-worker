"""Bounded process groups with durable identity and fail-closed lease loss."""
from __future__ import annotations

import os
import queue
import subprocess
import threading
import time
from pathlib import Path
from threading import Event
from typing import BinaryIO, Callable
from .models import Json
from .journal import Journal, group_alive, process_identity, stop_owned_session
from .models import AdapterResult, Request, WorkerError
from .security import Redactor, restricted_env
from .profiles import ProviderProfile

LineSink = Callable[[str, str], None]

def disk_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                total += path.stat().st_size
            except OSError:
                pass
    return total

class ProcessRunner:
    def __init__(self, *, grace_sec: float = 10.0, redactor: Redactor | None = None) -> None:
        self.grace_sec = grace_sec
        self.redactor = redactor or Redactor()
        self.process: subprocess.Popen[bytes] | None = None
        self.identity: Json = {}
        self._cancel = Event()

    def cancel(self) -> None:
        self._cancel.set()

    def stop(self) -> bool:
        process = self.process
        if process is None:
            return True
        if os.name == "posix":
            if not stop_owned_session(self.identity, grace_sec=self.grace_sec):
                return False
        elif process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=self.grace_sec)
            except subprocess.TimeoutExpired:
                process.kill()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            return False
        return not group_alive(self.identity) if os.name == "posix" else process.poll() is not None

    def run(self, argv: list[str], request: Request, sink: LineSink, cancellation: Event, *, stdin_text: str = "", profile: ProviderProfile | None = None) -> AdapterResult:
        try:
            return self._run(argv, request, sink, cancellation, stdin_text=stdin_text, profile=profile)
        finally:
            if self.process is not None:
                self.stop()
                for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                    if stream and not stream.closed:
                        stream.close()

    def _run(self, argv: list[str], request: Request, sink: LineSink, cancellation: Event, *, stdin_text: str = "", profile: ProviderProfile | None = None) -> AdapterResult:
        self.redactor = Redactor(tuple(self.redactor.values) + request.redaction_values)
        if request.workspace_path is None:
            raise WorkerError("INVALID_PATH", "Process cwd must be an allocated worktree")
        if cancellation.is_set() or self._cancel.is_set():
            return AdapterResult("cancelled", None, error_code="CANCEL_REQUESTED")
        journal = Journal(request.journal_path) if request.journal_path else None
        started = time.monotonic()
        if journal:
            journal.ensure_process_capacity()
            journal.update(phase="spawn_intent", supervisor=process_identity(os.getpid()), argv_executable=Path(argv[0]).name)
        pass_fds = (request.lock_fd,) if os.name == "posix" and request.lock_fd is not None else ()
        environment = restricted_env(request.env_allowlist)
        if profile:
            environment.update(profile.environment(request.workspace_path))
        self.process = subprocess.Popen(argv, cwd=request.workspace_path, env=environment, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name == "posix", pass_fds=pass_fds)
        self.identity = process_identity(self.process.pid)
        if journal:
            journal.record_process(self.identity, phase="running", started_at=time.time())
        chunks: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=128)
        def reader(name: str, stream: BinaryIO) -> None:
            try:
                while True:
                    chunk = os.read(stream.fileno(), 8192)
                    if not chunk:
                        break
                    chunks.put((name, chunk))
            finally:
                chunks.put((name, None))
        for name, stream in (("stdout", self.process.stdout), ("stderr", self.process.stderr)):
            if stream is not None:
                threading.Thread(target=reader, args=(name, stream), daemon=True).start()
        def writer() -> None:
            try:
                if self.process and self.process.stdin:
                    self.process.stdin.write(stdin_text.encode())
                    self.process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        threading.Thread(target=writer, daemon=True).start()
        byte_count = 0
        buffers = {"stdout": b"", "stderr": b""}
        closed: set[str] = set()
        output: list[str] = []
        reason: str | None = None
        cleanup_failed = False
        last_disk_check = started
        exited_at: float | None = None
        while len(closed) < 2 or self.process.poll() is None or group_alive(self.identity):
            now = time.monotonic()
            if self.process.poll() is not None and group_alive(self.identity):
                exited_at = now if exited_at is None else exited_at
                if reason is None and now - exited_at >= self.grace_sec:
                    reason = "DESCENDANTS_REMAINING"
                    cleanup_failed = not self.stop()
            if reason is None:
                if cancellation.is_set() or self._cancel.is_set():
                    reason = "CANCEL_REQUESTED"
                elif now - started >= request.timeout_sec or request.wall_deadline is not None and now >= request.wall_deadline:
                    reason = "EXECUTION_TIMEOUT"
                elif request.lease_deadline and now >= request.lease_deadline() - 5:
                    reason = "LEASE_LOST"
                elif now - last_disk_check >= 1:
                    last_disk_check = now
                    if disk_bytes(request.workspace_path) > request.max_disk_bytes:
                        reason = "DISK_QUOTA_EXCEEDED"
                if reason:
                    cleanup_failed = not self.stop()
            if cleanup_failed:
                break
            try:
                name, chunk = chunks.get(timeout=0.2)
            except queue.Empty:
                continue
            if chunk is None:
                closed.add(name)
                if buffers[name]:
                    line = self.redactor.text(buffers[name].decode("utf-8", errors="replace"))
                    sink(name, line)
                    output.append(line)
                continue
            byte_count += len(chunk)
            if byte_count > request.max_output_bytes:
                if reason is None:
                    reason = "OUTPUT_QUOTA_EXCEEDED"
                    if not self.stop():
                        break
                continue
            buffers[name] += chunk
            if len(buffers[name]) > 65536 and b"\n" not in buffers[name]:
                reason = reason or "EVENT_TOO_LARGE"
                if not self.stop():
                    break
                buffers[name] = b""
            while b"\n" in buffers[name]:
                line_bytes, buffers[name] = buffers[name].split(b"\n", 1)
                text = self.redactor.text(line_bytes.decode("utf-8", errors="replace"))
                try:
                    sink(name, text)
                except WorkerError as exc:
                    reason = reason or exc.code
                    cleanup_failed = not self.stop()
                output.append(text)
                if cleanup_failed:
                    break
            if cleanup_failed:
                break
        stopped = self.stop()
        code = self.process.returncode
        status = "uncertain" if reason == "LEASE_LOST" or not stopped else "cancelled" if reason == "CANCEL_REQUESTED" else "failed" if reason or code != 0 else "succeeded"
        if journal:
            journal.update(phase="process_stopped" if stopped else "uncertain", exit_code=code, error_code=reason, process_stopped=stopped, finished_at=time.time())
        return AdapterResult(status, code, "\n".join(output), reason, process_stopped=stopped, process_identity=self.identity)
