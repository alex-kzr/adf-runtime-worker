"""Fsynced supervisor/Git intents and advisory locks; no provider credentials."""
from __future__ import annotations
import errno
import json
import os
import signal
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from .models import WorkerError
from .pidfd import pidfd_open, pidfd_send_signal

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

    def ensure_process_capacity(self) -> None:
        if len(self.read().get("owned_sessions", [])) >= 4096:
            raise WorkerError("QUOTA_EXCEEDED", "Execution process identity journal exceeds its quota")

    def record_process(self, identity: dict[str, Any], **fields: Any) -> None:
        with FileLock(self.path.with_suffix(".write.lock"), blocking=True):
            data = self.read()
            sessions = list(data.get("owned_sessions", []))
            if len(sessions) >= 4096:
                raise WorkerError("QUOTA_EXCEEDED", "Execution process identity journal exceeds its quota")
            sessions.append(identity)
            self._update({**fields, "process": identity, "owned_sessions": sessions})

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

def process_stopped(identity: dict[str, Any]) -> bool:
    """A reused or incomplete recorded supervisor identity is not a dead proof."""
    if not identity:
        return True
    if any(type(identity.get(key)) is not int or identity[key] <= 0 for key in ("pid", "start_ticks", "pgid", "session_id")):
        return False
    current = process_identity(identity["pid"])
    if current.get("start_ticks") is None:
        return not Path(f"/proc/{identity['pid']}").exists()
    return current.get("start_ticks") == identity["start_ticks"] and current.get("state") == "Z"


def session_members(identity: dict[str, Any]) -> list[dict[str, Any]]:
    """Live owned SID members; missing/recycled ownership is unknown, never dead."""
    if not identity:
        return []
    sid = identity.get("session_id")
    ticks = identity.get("start_ticks")
    if os.name != "posix" or type(sid) is not int or sid <= 0 or sid != identity.get("pid") or sid != identity.get("pgid") or type(ticks) is not int or ticks < 0 or sid == os.getsid(0):
        raise OSError(errno.ESTALE, "Dedicated session ownership is unknown")
    leader = process_identity(sid)
    if leader.get("start_ticks") is None and Path(f"/proc/{sid}").exists():
        raise OSError(errno.ESTALE, "Recorded session leader metadata is unknown")
    if leader.get("start_ticks") is not None and leader.get("start_ticks") != ticks:
        raise OSError(errno.ESTALE, "Recorded session leader identity was recycled")
    members: list[dict[str, Any]] = []
    for process_dir in Path("/proc").iterdir():
        if not process_dir.name.isdecimal():
            continue
        current = process_identity(int(process_dir.name))
        if current.get("start_ticks") is None and process_dir.exists():
            raise OSError(errno.ESTALE, "Live process metadata is unknown")
        if current.get("session_id") == sid and current.get("state") != "Z":
            if current.get("start_ticks") is None or current["start_ticks"] < ticks:
                raise OSError(errno.ESTALE, "Session member identity is unknown")
            members.append(current)
    return members


def group_alive(identity: dict[str, Any]) -> bool:
    """Compatibility name: live OR unknown owned SID refuses a stopped proof."""
    try:
        return bool(session_members(identity))
    except OSError:
        return True


def owned_sessions_stopped(saved: dict[str, Any]) -> bool:
    identities = [saved.get("process", {}), saved.get("terminal_result", {}).get("process_identity", {}), *saved.get("owned_sessions", [])]
    if saved.get("shared_session"):
        from .shared_server import shared_stopped
        if not shared_stopped(saved["shared_session"]):
            return False
    return not any(group_alive(identity) for identity in identities)


def signal_owned_session(identity: dict[str, Any], signum: int) -> bool:
    """Signal only pinned PID identities in an execution-owned Linux session."""
    try:
        members = session_members(identity)
    except OSError:
        return False
    sid = identity.get("session_id")
    for member in members:
        try:
            fd = pidfd_open(int(member["pid"]))
        except ProcessLookupError:
            continue
        except OSError:
            return False
        try:
            current = process_identity(int(member["pid"]))
            if current.get("start_ticks") is None:
                continue
            if current.get("start_ticks") != member["start_ticks"] or current.get("session_id") != sid:
                return False
            pidfd_send_signal(fd, signum)
        except ProcessLookupError:
            continue
        except OSError:
            return False
        finally:
            os.close(fd)
    return True


def stop_owned_session(identity: dict[str, Any], *, grace_sec: float, kill_wait_sec: float = 3.0) -> bool:
    """Bounded TERM/KILL for same-SID descendants; no elapsed-time death inference."""
    if not group_alive(identity):
        return True
    if not signal_owned_session(identity, signal.SIGTERM):
        return False
    deadline = time.monotonic() + grace_sec
    while group_alive(identity) and time.monotonic() < deadline:
        time.sleep(0.05)
    if group_alive(identity):
        deadline = time.monotonic() + kill_wait_sec
        while group_alive(identity) and time.monotonic() < deadline:
            if not signal_owned_session(identity, signal.SIGKILL):
                return False
            time.sleep(0.05)
    return not group_alive(identity)
