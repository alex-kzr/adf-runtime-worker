"""Bounded pinned app-server JSON-RPC transport. Never logs wire payloads."""
from __future__ import annotations

import json
import os
import queue
import select
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any

from .models import WorkerError

FRAME_LIMIT = 512 * 1024
_METHODS = frozenset({"initialize", "model/list", "account/read", "thread/start", "turn/start", "turn/interrupt",
                      "thread/unsubscribe", "skills/list", "mcpServerStatus/list"})
_ERROR_CODES = frozenset({-32700, -32600, -32601, -32602, -32603, -32000})
_OUTCOMES = frozenset({"provider_error", "malformed_response", "transport_closed", "response_timeout", "write_uncertain"})


class RpcError(WorkerError):
    """Only closed diagnostic metadata escapes; provider text/data never does."""
    def __init__(self, method: str, outcome: str, elapsed_ms: int, provider_code: object = None) -> None:
        safe_outcome = outcome if outcome in _OUTCOMES else "write_uncertain"
        super().__init__("PROVIDER_FAILED" if safe_outcome in {"provider_error", "malformed_response"} else "EXECUTION_UNCERTAIN",
                         "Provider RPC " + safe_outcome)
        self.method = method if method in _METHODS else "other"
        self.outcome = safe_outcome
        self.elapsed_ms = max(0, min(86_400_000, elapsed_ms))
        self.provider_code = provider_code if type(provider_code) is int and provider_code in _ERROR_CODES else None

    def receipt(self) -> dict[str, Any]:
        return {"method": self.method, "outcome": self.outcome, "elapsed_ms": self.elapsed_ms,
                "provider_error_code": self.provider_code}


@dataclass(frozen=True)
class _Failure:
    # A typed local sentinel cannot be forged by upstream JSON error payloads.
    outcome: str


class Rpc:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.failed = threading.Event()
        self.failure_outcome = "transport_closed"
        self.lock = threading.Lock()
        self.pending: dict[int, queue.Queue[dict[str, Any] | _Failure]] = {}
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
        started = time.monotonic()
        def error(outcome: str, provider_code: object = None) -> RpcError:
            return RpcError(method, outcome, int((time.monotonic() - started) * 1000), provider_code)
        with self.lock:
            if len(self.pending) >= 32:
                raise WorkerError("QUOTA_EXCEEDED", "Provider request quota exceeded")
            self.sequence += 1
            identifier = self.sequence
            result_queue: queue.Queue[dict[str, Any] | _Failure] = queue.Queue(maxsize=1)
            self.pending[identifier] = result_queue
        try:
            if self.failed.is_set():
                raise error(self.failure_outcome)
            try:
                self.send({"id": identifier, "method": method, "params": params})
            except WorkerError:
                # Partial writes remain uncertain; never infer no native work.
                raise error("write_uncertain") from None
            try:
                result = result_queue.get(timeout=timeout)
            except queue.Empty:
                raise error("response_timeout") from None
            if isinstance(result, _Failure):
                raise error(result.outcome)
            if "error" in result:
                failure = result["error"]
                if ("result" in result or not isinstance(failure, dict) or type(failure.get("code")) is not int
                        or not isinstance(failure.get("message"), str)):
                    raise error("malformed_response")
                raise error("provider_error", failure["code"])
            value = result.get("result")
            if not isinstance(value, dict):
                raise error("malformed_response")
            # Do not coerce malformed native identity values into strings.
            key = {"thread/start": "thread", "turn/start": "turn"}.get(method)
            if key:
                identity = value.get(key)
                if (not isinstance(identity, dict) or not isinstance(identity.get("id"), str)
                        or not 1 <= len(identity["id"]) <= 128):
                    raise error("malformed_response")
            return dict(value)
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
        outcome = "transport_closed"
        try:
            if self.process.stdout is None:
                raise OSError("Provider stdout is unavailable")
            while not self.failed.is_set():
                line = self.process.stdout.readline(FRAME_LIMIT + 1)
                if not line:
                    break
                outcome = "malformed_response"
                if len(line) > FRAME_LIMIT or not line.endswith(b"\n"):
                    break
                message = json.loads(line)
                if not isinstance(message, dict):
                    break
                if "id" in message and "method" in message:
                    self.send({"id": message["id"], "error": {"code": -32601, "message": "ADF denies server requests"}})
                elif "id" in message:
                    if type(message["id"]) is not int:
                        break
                    with self.lock:
                        target = self.pending.get(message["id"])
                    if target:
                        target.put_nowait(message)
                elif isinstance(message.get("params"), dict):
                    with self.lock:
                        event_target = self.threads.get(message["params"].get("threadId"))
                    if event_target:
                        event_target.put_nowait(message)
                outcome = "transport_closed"
        except (OSError, ValueError, TypeError, RecursionError, queue.Full, WorkerError):
            pass
        finally:
            if not self.failed.is_set():
                self.failure_outcome = outcome
            self.failed.set()
            with self.lock:
                for target in self.pending.values():
                    try:
                        target.put_nowait(_Failure(self.failure_outcome))
                    except queue.Full:
                        pass

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
