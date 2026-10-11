"""Fail-closed path, environment, and data disclosure boundaries."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from .models import WorkerError

_SAFE_ENV = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR", "SYSTEMROOT", "TEMP", "TMP"}
_SECRET_NAMES = re.compile(r"TOKEN|SECRET|PASSWORD|API_KEY|CREDENTIAL|AUTH", re.I)
_CREDENTIAL_KEYS = re.compile(r"^(?:authorization|auth|credentials?|password|secret|api[_-]?key|(?:access|refresh|id|bearer|worker)[_-]?token|token)$|(?:[_-](?:password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token))$", re.I)
_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?)[^\s\"']+"),
    re.compile(r"(?i)((?:api[_-]?key|password|secret|token)\s*[:=]\s*[\"']?)[^\s\"',}]+"),
    re.compile(r"(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
_DENIED_NAMES = re.compile(r"(?:^|/)(?:\.env(?:\..*)?|auth\.json|credentials[^/]*|[^/]*\.(?:pem|key)|node_modules|\.venv|__pycache__)(?:/|$)", re.I)

class Redactor:
    def __init__(self, values: tuple[str, ...] = ()) -> None:
        env_values = tuple(value for key, value in os.environ.items() if _SECRET_NAMES.search(key) and len(value) >= 6)
        self.values = sorted(set(values + env_values), key=len, reverse=True)

    def text(self, value: str) -> str:
        for secret in self.values:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        for pattern in _SECRET_PATTERNS:
            value = pattern.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", value)
        return value

    def data(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {key: "[REDACTED]" if _CREDENTIAL_KEYS.search(str(key)) else self.data(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.data(item) for item in value]
        return value

def restricted_env(names: tuple[str, ...] = ()) -> dict[str, str]:
    if any(_SECRET_NAMES.search(name) or name not in _SAFE_ENV for name in names):
        raise WorkerError("PERMISSION_DENIED", "Environment allowlist contains a sensitive or unsupported variable")
    env = {name: value for name, value in os.environ.items() if name in _SAFE_ENV}
    if os.name == "posix":
        entries = [entry for entry in env.get("PATH", "").split(os.pathsep) if entry.startswith("/") and not entry.startswith("/mnt/") and Path(entry).is_dir()]
        node = Path(os.getenv("ADF_NODE_PATH", str(Path.home() / ".local" / "bin" / "node")))
        if node.is_absolute() and node.is_file() and not str(node.resolve()).startswith("/mnt/"):
            entries.insert(0, str(node.parent))
        env["PATH"] = os.pathsep.join(dict.fromkeys(entries))
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    return env

def canonical_root(path: Path, *, require_ext4: bool = True) -> Path:
    if not path.is_absolute() or not path.exists():
        raise WorkerError("INVALID_PATH", "Allowed root must exist and be absolute")
    canonical = path.resolve(strict=True)
    if canonical != path.absolute():
        raise WorkerError("INVALID_PATH", "Symlink roots are forbidden")
    if require_ext4:
        if platform.system() != "Linux" or str(canonical).startswith("/mnt/") or os.geteuid() == 0:
            raise WorkerError("UNSUPPORTED_RUNTIME", "Real execution requires an unprivileged Linux ext4 root")
        stat = shutil.which("stat")
        if stat is None:
            raise WorkerError("UNSUPPORTED_RUNTIME", "Filesystem probe unavailable")
        result = subprocess.run([stat, "-f", "-c", "%T", str(canonical)], capture_output=True, text=True, timeout=5, shell=False, check=True)
        if result.stdout.strip() not in {"ext2/ext3", "ext4"}:
            raise WorkerError("UNSUPPORTED_RUNTIME", "Worker root must be on ext4")
    return canonical

def within_root(path: Path, root: Path, *, must_exist: bool = True) -> Path:
    if not path.is_absolute():
        raise WorkerError("INVALID_PATH", "Absolute trusted path required")
    canonical = path.resolve(strict=must_exist)
    if not canonical.is_relative_to(root) or canonical == root:
        raise WorkerError("INVALID_PATH", "Path escapes worker root")
    current = path
    while current != root and current != current.parent:
        if current.is_symlink():
            raise WorkerError("INVALID_PATH", "Symlink path components are forbidden")
        current = current.parent
    return canonical

def validate_relative(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute() or not candidate.parts or not path or path != path.strip() or ".." in candidate.parts or "\\" in path or any(ord(char) < 32 for char in path):
        raise WorkerError("INVALID_PATH", "Unsafe relative path")
    if candidate.parts[0] == ".git" or _DENIED_NAMES.search(path):
        raise WorkerError("SECRET_DETECTED", "Generated or sensitive paths cannot be staged")
    return candidate.as_posix()

def inspect_content(path: Path, limit: int = 2 * 1024 * 1024, *, secret_values: tuple[str, ...] = ()) -> None:
    if path.is_symlink():
        raise WorkerError("INVALID_PATH", "Changed symlinks require explicit future policy support")
    if not path.exists():
        return
    if path.stat().st_size > limit:
        raise WorkerError("QUOTA_EXCEEDED", "Changed file exceeds scan limit")
    raw = path.read_bytes()
    inspect_bytes(raw, secret_values=secret_values)


def inspect_bytes(raw: bytes, *, secret_values: tuple[str, ...] = ()) -> None:
    """Scan already fd-verified content without reopening a mutable path."""
    if b"\x00" in raw:
        raise WorkerError("PERMISSION_DENIED", "Binary changes require explicit future scan policy")
    text = raw.decode("utf-8", errors="replace")
    if any(pattern.search(text) for pattern in _SECRET_PATTERNS):
        raise WorkerError("SECRET_DETECTED", "Potential credential material in changed content")
    if any(value in text for value in Redactor(secret_values).values):
        raise WorkerError("SECRET_DETECTED", "Known secret in changed content")

def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
