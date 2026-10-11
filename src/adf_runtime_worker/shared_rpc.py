"""Bounded pinned app-server JSON-RPC transport. Never logs wire payloads."""
from __future__ import annotations

import json
import os
import queue
import select
import subprocess
import threading
import time
from typing import Any

from .models import WorkerError

FRAME_LIMIT = 512 * 1024


class Rpc:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.failed = threading.Event()
        self.lock = threading.Lock()
        self.pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self.threads: dict[str, queue.Queue[dict[str, Any]]] = {}
        self.sequence = 0
        if process.stdin is None:
            raise WorkerError("EXECUTION_UNCERTAIN", "Provider stdin is unavailable")
        os.set_blocking(process.stdin.fileno(), False)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        threading.Thread(target=self._discard_stderr, daemon=True).start()

    def send(self, value: dict[str, Any]) -> None:
        data = json.dumps(value, separators=(",", ":")).encode() + b"\n"
        if len(data) > FRAME_LIMIT or self.failed.is_set():
            raise WorkerError("EXECUTION_UNCERTAIN", "Provider transport is unavailable")
        with self.lock:
            try:
                if self.process.stdin is None:
                    raise OSError("Provider stdin is unavailable")
                fd = self.process.stdin.fileno()
                until = time.monotonic() + 5
                offset = 0
                while offset < len(data):
                    if time.monotonic() >= until or self.failed.is_set():
                        raise OSError("Provider pipe is not writable")
                    if select.select([], [fd], [], 0.1)[1]:
                        try:
                            offset += os.write(fd, data[offset:])
                        except BlockingIOError:
                            continue
            except (OSError, ValueError) as exc:
                self.failed.set()
                raise WorkerError("EXECUTION_UNCERTAIN", "Provider transport closed") from exc

    def call(self, method: str, params: dict[str, Any], timeout: float = 15) -> dict[str, Any]:
        with self.lock:
            if len(self.pending) >= 32:
                raise WorkerError("QUOTA_EXCEEDED", "Provider request quota exceeded")
            self.sequence += 1
            identifier = self.sequence
            result_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
            self.pending[identifier] = result_queue
        try:
            self.send({"id": identifier, "method": method, "params": params})
            try:
                result = result_queue.get(timeout=timeout)
            except queue.Empty as exc:
                raise WorkerError("EXECUTION_UNCERTAIN", "Provider response deadline exceeded") from exc
            if "error" in result or not isinstance(result.get("result"), dict):
                # Provider errors can contain secrets; only a fixed code escapes.
                raise WorkerError("PROVIDER_FAILED", "Provider request failed")
            return dict(result["result"])
        finally:
            with self.lock:
                self.pending.pop(identifier, None)

    def subscribe(self, thread_id: str) -> queue.Queue[dict[str, Any]]:
        events: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=128)
        with self.lock:
            if thread_id in self.threads or len(self.threads) >= 3:
                raise WorkerError("QUOTA_EXCEEDED", "Provider thread quota exceeded")
            self.threads[thread_id] = events
        return events

    def forget(self, thread_id: str) -> None:
        with self.lock:
            self.threads.pop(thread_id, None)

    def _read(self) -> None:
        try:
            if self.process.stdout is None:
                raise OSError("Provider stdout is unavailable")
            while not self.failed.is_set():
                line = self.process.stdout.readline(FRAME_LIMIT + 1)
                if not line or len(line) > FRAME_LIMIT or not line.endswith(b"\n"):
                    break
                message = json.loads(line)
                if not isinstance(message, dict):
                    break
                if "id" in message and "method" in message:
                    # No server-initiated approval, auth or permission operation.
                    self.send({"id": message["id"], "error": {"code": -32601, "message": "ADF denies server requests"}})
                elif "id" in message:
                    with self.lock:
                        target = self.pending.get(message["id"])
                    if target:
                        target.put_nowait(message)
                elif isinstance(message.get("params"), dict):
                    with self.lock:
                        target = self.threads.get(message["params"].get("threadId"))
                    if target:
                        target.put_nowait(message)
        except (OSError, ValueError, TypeError, queue.Full, WorkerError):
            pass
        finally:
            self.failed.set()
            with self.lock:
                for target in self.pending.values():
                    if target.empty():
                        target.put_nowait({"error": {"code": -1}})

    def _discard_stderr(self) -> None:
        # No raw stderr reaches worker logs. An unbounded stream fails closed.
        size = 0
        try:
            if self.process.stderr is None:
                raise OSError("Provider stderr is unavailable")
            while chunk := self.process.stderr.read(8192):
                size += len(chunk)
                if size > FRAME_LIMIT:
                    self.failed.set()
                    break
        except (OSError, ValueError):
            self.failed.set()
