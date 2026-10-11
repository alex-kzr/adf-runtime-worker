"""Bounded agent-authored text edits, applied only by a leased trusted writer.

Linux renameat2 preserves raced preimages. Unresolved intents fence terminal/ACK
proofs; recovery classifies them without replaying generation or further writes.
Host administrators/editors must respect the allocation lock (see architecture).
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from uuid import uuid4

from .journal import Journal
from .models import Json, WorkerError
from .security import digest, inspect_bytes, validate_relative

MAX_FILES = 16
MAX_CONTENT = 32 * 1024
MAX_TOTAL = 48 * 1024
MAX_RESULT = 60 * 1024
_HASH = re.compile(r"[0-9a-f]{64}")
_RESERVED = {".git", ".agents", ".codex", ".claude", ".github", "AGENTS.md", "CLAUDE.md",
             ".gitignore", ".gitattributes", ".gitmodules", "shared-profile-policy.json",
             "worker-token", "redis-worker-password"}
PATCH_SCHEMA: Json = {"type": "object", "additionalProperties": False, "properties": {
    "version": {"type": "integer", "const": 1}, "edits": {"type": "array", "maxItems": MAX_FILES, "items": {
        "type": "object", "additionalProperties": False, "properties": {
            "path": {"type": "string", "maxLength": 512},
            "action": {"type": "string", "enum": ["create", "replace", "delete"]},
            "preimage": {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"},
            "content": {"type": ["string", "null"], "maxLength": MAX_CONTENT}},
        "required": ["path", "action", "preimage", "content"]}}}, "required": ["version", "edits"]}


def patch_path(name: str) -> str:
    relative = validate_relative(name)
    if relative != name or len(name) > 512 or any(part in _RESERVED or part.startswith(".adf-") for part in Path(name).parts):
        raise WorkerError("PERMISSION_DENIED", "Patch targets an execution/sensitive path or alias")
    return relative


def allowed(name: str, scopes: list[str]) -> bool:
    return any(scope == "**" or name == scope or name.startswith(scope.rstrip("/") + "/") or fnmatchcase(name, scope) for scope in scopes)


@contextmanager
def parent_fd(root: Path, name: str) -> Iterator[tuple[int, str]]:
    """Hold no-follow ancestors; new parent directories are unsupported in v1."""
    patch_path(name)
    descriptors: list[int] = []
    identities: list[tuple[Path, int, int]] = []
    current = root
    entered = False
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(fd)
        info = os.fstat(fd)
        identities.append((current, info.st_dev, info.st_ino))
        for part in Path(name).parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            descriptors.append(fd)
            current = current / part
            info = os.fstat(fd)
            identities.append((current, info.st_dev, info.st_ino))
        for path, device, inode in identities:
            info = path.stat(follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
                raise WorkerError("EXECUTION_UNCERTAIN", "Patch ancestor identity changed")
        entered = True
        yield fd, Path(name).name
        for path, device, inode in identities:
            info = path.stat(follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
                raise WorkerError("EXECUTION_UNCERTAIN", "Patch ancestor moved during mutation")
    except OSError as exc:
        if entered:
            raise  # Body I/O belongs to the durable writer's classification.
        raise WorkerError("INVALID_PATH", "Patch requires existing no-follow parent directories") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def image(fd: int, name: str) -> tuple[Json | None, bytes | None]:
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise WorkerError("INVALID_PATH", "Patch file must not be a symlink") from exc
        raise
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 2 * 1024 * 1024:
            raise WorkerError("PERMISSION_DENIED", "Patch requires bounded single-link regular files")
        chunks = bytearray()
        while len(chunks) <= 2 * 1024 * 1024:
            chunk = os.read(file_fd, 65536)
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(file_fd)
        visible = os.stat(name, dir_fd=fd, follow_symlinks=False)
        def identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
            return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns
        if identity(before) != identity(after) or identity(after) != identity(visible):
            raise WorkerError("EXECUTION_UNCERTAIN", "Patch file changed while reading")
        raw = bytes(chunks)
        return {"dev": after.st_dev, "ino": after.st_ino, "hash": hashlib.sha256(raw).hexdigest(),
                "mode": stat.S_IMODE(after.st_mode), "size": len(raw)}, raw
    finally:
        os.close(file_fd)


def same(actual: Json | None, expected: Json | None) -> bool:
    return actual == expected


def baseline(root: Path, names: list[str], scopes: list[str]) -> Json:
    result: Json = {}
    for name in sorted(set(names)):
        if not name or not allowed(name, scopes):
            continue
        patch_path(name)
        if len(result) >= 256:
            raise WorkerError("QUOTA_EXCEEDED", "Patch baseline file count exceeds v1 bound")
        with parent_fd(root, name) as (fd, leaf):
            item, _ = image(fd, leaf)
            result[name] = item["hash"] if item else None
    if len(json.dumps(result).encode()) > 48 * 1024:
        raise WorkerError("QUOTA_EXCEEDED", "Patch baseline exceeds v1 prompt bound")
    return result


def parse_patch(output: str, scopes: list[str], expected: Json, secrets: tuple[str, ...] = ()) -> Json:
    import jsonschema
    try:
        size = len(output.encode("utf-8"))
    except UnicodeError as exc:
        raise WorkerError("INVALID_PROVIDER_RESULT", "Patch result must be valid UTF-8") from exc
    if size > MAX_RESULT:
        raise WorkerError("OUTPUT_LIMIT", "Structured patch exceeds its UTF-8 frame bound")
    def pairs(items: list[tuple[str, Any]]) -> Json:
        value: Json = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value
    try:
        patch = json.loads(output, object_pairs_hook=pairs)
        jsonschema.validate(patch, PATCH_SCHEMA)
    except (ValueError, UnicodeError, jsonschema.ValidationError) as exc:
        raise WorkerError("INVALID_PROVIDER_RESULT", "Structured patch failed closed schema") from exc
    seen: set[str] = set()
    total = 0
    for edit in patch["edits"]:
        name = patch_path(edit["path"])
        if name in seen or not allowed(name, scopes):
            raise WorkerError("PERMISSION_DENIED", "Duplicate/out-of-scope patch path")
        seen.add(name)
        pre = edit["preimage"]
        if pre is not None and not _HASH.fullmatch(pre):
            raise WorkerError("INVALID_PROVIDER_RESULT", "Patch hash must be exact lowercase SHA-256")
        if expected.get(name) != pre or (edit["action"] == "create") != (pre is None):
            raise WorkerError("VERSION_CONFLICT", "Patch does not bind supplied baseline")
        content = edit["content"]
        if (edit["action"] == "delete") != (content is None):
            raise WorkerError("INVALID_PROVIDER_RESULT", "Patch action/content mismatch")
        if content is not None:
            try:
                raw = content.encode("utf-8")
            except UnicodeError as exc:
                raise WorkerError("INVALID_PROVIDER_RESULT", "Patch content must be valid UTF-8") from exc
            total += len(raw)
            if len(raw) > MAX_CONTENT or total > MAX_TOTAL:
                raise WorkerError("OUTPUT_LIMIT", "Patch content exceeds UTF-8 byte quotas")
            inspect_bytes(raw, secret_values=secrets)
    return dict(patch)


def _rename(fd: int, source: str, target: str, flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise WorkerError("CAPABILITY_UNSUPPORTED", "Atomic no-replace/exchange rename is required")
    if function(fd, os.fsencode(source), fd, os.fsencode(target), flags) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


class PatchWriter:
    def __init__(self, root: Path, journal: Journal, guard: Callable[[], None], *, lock_fd: int, binding: Json, secrets: tuple[str, ...] = ()) -> None:
        if os.name != "posix" or lock_fd < 0 or not binding.get("approved") or binding.get("role") != "trusted-development" or type(binding.get("epoch")) is not int or binding["epoch"] <= 0 or any(not binding.get(key) for key in ("execution_id", "run_id", "project_id", "scopes", "policy_sha256", "lock_path")):
            raise WorkerError("PERMISSION_DENIED", "Patch writer needs original approved developer lease/lock")
        info = os.fstat(lock_fd)
        visible = Path(binding["lock_path"]).stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (visible.st_dev, visible.st_ino):
            raise WorkerError("PERMISSION_DENIED", "Patch allocation lock identity changed")
        self.root, self.journal, self.guard = root, journal, guard
        self.binding = binding
        self.secrets = secrets

    def apply(self, patch: Json, *, key: str = "development") -> Json:
        """Apply once; exact repeats classify receipt, never replay a native turn."""
        self.guard()
        patch = parse_patch(json.dumps(patch), self.binding["scopes"], self.binding.get("baseline", {}), self.secrets)
        patch_hash = digest(patch)
        intents = self.journal.read().get("patch_intents", {})
        existing = intents.get(key)
        if existing:
            if existing["hash"] != patch_hash or existing["binding"] != self.binding:
                raise WorkerError("IDEMPOTENCY_CONFLICT", "Patch intent binding changed")
            if existing.get("phase") != "applied" or not mutation_resolved(self.journal, self.root):
                raise WorkerError("EXECUTION_UNCERTAIN", "Patch intent needs explicit reconciliation")
            return {"patch_sha256": patch_hash, "patch_phase": "applied", "patch_replayed": False}
        if not mutation_resolved(self.journal, self.root):
            raise WorkerError("EXECUTION_UNCERTAIN", "Previous patch mutation is unresolved")
        records: list[Json] = []
        # Validate the complete patch before the first mutation.
        for edit in patch["edits"]:
            with parent_fd(self.root, edit["path"]) as (fd, leaf):
                before, before_raw = image(fd, leaf)
                if (before["hash"] if before else None) != edit["preimage"]:
                    raise WorkerError("VERSION_CONFLICT", "Patch preimage changed before application")
                if before and before["mode"] not in {0o644, 0o755, 0o600, 0o700}:
                    raise WorkerError("PERMISSION_DENIED", "Patch cannot modify special file modes")
                if before_raw is not None:
                    try:
                        before_raw.decode("utf-8")
                    except UnicodeError as exc:
                        raise WorkerError("CAPABILITY_UNSUPPORTED", "Binary preimages are outside text-patch v1") from exc
                    inspect_bytes(before_raw, secret_values=self.secrets)
                records.append({"path": edit["path"], "action": edit["action"], "pre": before, "post": None,
                                "aux": ".adf-patch-" + uuid4().hex, "phase": "validated"})
        intent: Json = {"hash": patch_hash, "binding": self.binding, "phase": "validated", "files": records,
                        "sequence": max((item.get("sequence", 0) for item in intents.values()), default=0) + 1}
        intents[key] = intent
        self.journal.update(patch_intents=intents, phase="patch_validated")
        try:
            for edit, record in zip(patch["edits"], records, strict=True):
                self.guard()
                with parent_fd(self.root, record["path"]) as (fd, leaf):
                    actual, _ = image(fd, leaf)
                    if not same(actual, record["pre"]):
                        raise WorkerError("VERSION_CONFLICT", "Patch preimage identity changed")
                    record["phase"] = "preparing"
                    intent["phase"] = "applying"
                    self.journal.update(patch_intents=intents, phase="patch_applying")
                    if record["action"] != "delete":
                        temp_fd = os.open(record["aux"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
                        try:
                            raw = edit["content"].encode("utf-8")
                            view = memoryview(raw)
                            while view:
                                view = view[os.write(temp_fd, view):]
                            os.fchmod(temp_fd, record["pre"]["mode"] if record["pre"] else 0o644)
                            os.fsync(temp_fd)
                        finally:
                            os.close(temp_fd)
                        record["post"], _ = image(fd, record["aux"])
                        os.fsync(fd)
                    record["phase"] = "prepared"
                    self.journal.update(patch_intents=intents)
                    self.guard()
                    # Recheck immediately before an atomic operation. Preserve
                    # any raced old inode in aux rather than discarding it.
                    actual, _ = image(fd, leaf)
                    if not same(actual, record["pre"]):
                        raise WorkerError("VERSION_CONFLICT", "Patch target changed before atomic mutation")
                    if record["action"] == "create":
                        _rename(fd, record["aux"], leaf, 1)  # RENAME_NOREPLACE
                    elif record["action"] == "replace":
                        _rename(fd, record["aux"], leaf, 2)  # RENAME_EXCHANGE
                    else:
                        _rename(fd, leaf, record["aux"], 1)
                    os.fsync(fd)
                    if record["action"] != "create":
                        captured, _ = image(fd, record["aux"])
                        if not same(captured, record["pre"]):
                            raise WorkerError("EXECUTION_UNCERTAIN", "Atomic mutation captured a concurrent preimage; preserved")
                    current, _ = image(fd, leaf)
                    if not same(current, record["post"]):
                        raise WorkerError("EXECUTION_UNCERTAIN", "Atomic patch postimage changed; preserved")
                    record["phase"] = "mutated"
                    self.journal.update(patch_intents=intents)
                    if record["action"] != "create":
                        self.guard()
                        captured, _ = image(fd, record["aux"])
                        if not same(captured, record["pre"]):
                            raise WorkerError("EXECUTION_UNCERTAIN", "Patch backup changed before cleanup")
                        os.unlink(record["aux"], dir_fd=fd)
                        os.fsync(fd)
                    record["phase"] = "applied"
                    self.journal.update(patch_intents=intents)
            intent["phase"] = "applied"
            self.journal.update(patch_intents=intents, phase="patch_applied")
            self.guard()
        except (OSError, WorkerError) as exc:
            # No speculative rollback or remaining writes after lease loss.
            # Classify on-disk evidence. Ambiguous aux/mutation stays fenced.
            intent["error"] = exc.code if isinstance(exc, WorkerError) else "PATCH_IO_FAILED"
            self.journal.update(patch_intents=intents, phase="patch_interrupted")
            if not mutation_resolved(self.journal, self.root):
                raise WorkerError("EXECUTION_UNCERTAIN", "Unresolved patch mutation requires operator reconciliation") from exc
            if isinstance(exc, OSError):
                raise WorkerError("PATCH_IO_FAILED", "Patch I/O failed with a proven mutation state") from exc
            raise
        return {"patch_sha256": patch_hash, "patch_phase": "applied", "patch_replayed": False}


def mutation_resolved(journal: Journal, root: Path) -> bool:
    """Read-only recovery proof: every file is a proven preimage or postimage.

Aux leftovers or unknown images remain uncertain, even when all processes died.
No authority is inferred to finish/undo an interrupted mutation.
"""
    try:
        latest: dict[str, Json] = {}
        for intent in sorted(journal.read().get("patch_intents", {}).values(), key=lambda item: item["sequence"]):
            for record in intent["files"]:
                previous = latest.get(record["path"])
                if previous and (previous["phase"] != "applied" or not same(previous["post"], record["pre"])):
                    return False
                latest[record["path"]] = record
        for record in latest.values():
            with parent_fd(root, record["path"]) as (fd, leaf):
                current, _ = image(fd, leaf)
                aux, _ = image(fd, record["aux"])
                if aux is not None:
                    return False
                expected = record["post"] if record["phase"] in {"applied", "mutated"} else record["pre"]
                # Crash after create/cleanup before receipt is recognizable
                # from the journaled postimage inode and missing auxiliary.
                if not same(current, expected) and not (record["phase"] == "prepared" and record["action"] == "create" and same(current, record["post"])):
                    return False
        return True
    except (OSError, KeyError, TypeError, WorkerError):
        return False
