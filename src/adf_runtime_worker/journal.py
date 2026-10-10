"""Fsynced supervisor/Git intents and advisory locks; no provider credentials."""
from __future__ import annotations
import json
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from .models import WorkerError

class Journal:
    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        return dict(json.loads(self.path.read_text(encoding="utf-8")))

    def update(self, **fields: Any) -> dict[str, Any]:
        with FileLock(self.path.with_suffix(".write.lock"), blocking=True):
            return self._update(fields)

    def _update(self, fields: dict[str, Any]) -> dict[str, Any]:
        data = self.read()
        data.update(fields)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, filename = tempfile.mkstemp(prefix=".journal-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(filename, 0o600)
            os.replace(filename, self.path)
            if os.name == "posix":
                directory = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)
        return data

class FileLock:
    def __init__(self, path: Path, *, blocking: bool = False, guard: Callable[[], None] | None = None, timeout: float | None = None) -> None:
        self.path = path
        self.blocking = blocking
        self.guard = guard
        self.timeout = timeout
        self.fd: int | None = None

    def __enter__(self) -> FileLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "posix":
                import fcntl
                started = time.monotonic()
                while True:
                    if self.guard:
                        self.guard()
                    try:
                        fcntl.flock(self.fd, fcntl.LOCK_EX | (0 if self.blocking and self.timeout is None and self.guard is None else fcntl.LOCK_NB))
                        break
                    except BlockingIOError:
                        if not self.blocking or (self.timeout is not None and time.monotonic() - started >= self.timeout):
                            raise
                        time.sleep(0.1)
            else:
                import msvcrt
                os.write(self.fd, b"0")
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_LOCK if self.blocking else msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
        except WorkerError:
            os.close(self.fd)
            self.fd = None
            raise
        except OSError as exc:
            os.close(self.fd)
            self.fd = None
            raise WorkerError("EXECUTION_UNCERTAIN", "Worktree or project lock is held") from exc
        return self

    def __exit__(self, *_: object) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

def process_identity(pid: int) -> dict[str, Any]:
    if os.name != "posix":
        return {"pid": pid, "start_ticks": None, "pgid": pid, "session_id": None}
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        parts = text[text.rfind(")") + 2:].split()
        return {"pid": pid, "start_ticks": int(parts[19]), "pgid": int(parts[2]), "session_id": int(parts[3]), "state": parts[0]}
    except (OSError, ValueError, IndexError):
        return {"pid": pid, "start_ticks": None, "pgid": None, "session_id": None}

def same_process(identity: dict[str, Any]) -> bool:
    if not identity.get("pid") or identity.get("start_ticks") is None:
        return False
    current = process_identity(int(identity["pid"]))
    return current.get("start_ticks") == identity["start_ticks"] and current.get("state") != "Z"

def group_alive(identity: dict[str, Any]) -> bool:
    if os.name != "posix" or not identity.get("pgid"):
        return same_process(identity)
    for stat in Path("/proc").glob("[0-9]*/stat"):
        try:
            parts = stat.read_text().rsplit(")", 1)[1].split()
            if parts[0] != "Z" and int(parts[2]) == identity["pgid"] and int(parts[3]) == identity["session_id"]:
                return True
        except (OSError, ValueError, IndexError):
            continue
    return False
