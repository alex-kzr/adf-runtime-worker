"""Opt-in operator trust, sealed without writing provider configuration.

Same-UID host code is trusted: snapshots detect drift, not hostile atomic races.
No authentication file is read here. Errors never contain policy values.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import tomllib
from pathlib import Path
from typing import Any
from uuid import UUID

from .git_workspace import GitWorkspaceManager
from .journal import FileLock, Journal
from .models import WorkerError

_LAYERS = ("rules", "skills", "AGENTS.md", "environments.toml")


def denied() -> WorkerError:
    return WorkerError("PERMISSION_DENIED", "Shared operator policy validation failed")


def canonical(path: Path) -> None:
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path or str(path).startswith("/mnt/"):
            raise denied()
    except (OSError, RuntimeError) as exc:
        raise denied() from exc


def private_bytes(path: Path, *, limit: int = 65536) -> tuple[bytes, tuple[int, ...]]:
    """Bounded no-follow read; inode/metadata and path must stay identical."""
    canonical(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > limit):
            raise denied()
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > limit:
            raise denied()
        after = os.fstat(fd)
        canonical(path)
        current = path.lstat()
        def identity(info: os.stat_result) -> tuple[int, ...]:
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        seal = identity(before)
        if seal != identity(after) or seal != identity(current) or len(raw) != before.st_size:
            raise denied()
        return bytes(raw), seal
    finally:
        os.close(fd)


def no_layers(profile: Path, workspace: Path | None = None) -> None:
    if any(os.path.lexists(profile / name) for name in _LAYERS):
        raise denied()
    if workspace:
        canonical(workspace)
        for ancestor in (workspace, *workspace.parents):
            layer = ancestor / ".codex"
            if layer != profile and os.path.lexists(layer):
                raise denied()


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise denied()
        value[name] = item
    return value


class SealedProfilePolicy:
    def __init__(self, root: Path, profile: Path, manifest: Path, *, validate_repositories: bool = True) -> None:
        self.root, self.profile, self.manifest = root, profile, manifest
        self.lock = threading.RLock()
        self.workspace_lock = threading.Lock()
        self.workspaces: dict[Path, tuple[Any, ...]] = {}
        try:
            canonical(root)
            canonical(profile)
            info = profile.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
                    or profile.is_relative_to(root / "projects") or profile.is_relative_to(root / "worktrees")
                    or not manifest.is_relative_to(root / "tools")):
                raise denied()
            self.profile_identity = (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
            raw, _ = private_bytes(manifest)
            data = json.loads(raw, object_pairs_hook=_closed_object)
            if (not isinstance(data, dict) or set(data) != {"version", "project_roots"}
                    or type(data["version"]) is not int or data["version"] != 1
                    or not isinstance(data["project_roots"], list) or not 1 <= len(data["project_roots"]) <= 32
                    or any(not isinstance(item, str) for item in data["project_roots"])):
                raise denied()
            self.projects = {name: {"trust_level": "trusted"} for name in data["project_roots"]}
            if len(self.projects) != len(data["project_roots"]):
                raise denied()
            self.repositories = tuple(Path(name) for name in self.projects)
            self.repository_identities: dict[Path, tuple[int, ...]] = {}
            manager = GitWorkspaceManager(root, require_ext4=False) if validate_repositories else None
            for name, repo in zip(data["project_roots"], self.repositories, strict=True):
                canonical(repo)
                canonical(repo / ".git")
                if (name != str(repo)
                        or any(char in str(repo) for char in "*?[]")
                        or not repo.is_relative_to(root / "projects") or repo == root / "projects" or not (repo / ".git").is_dir()):
                    raise denied()
                self.repository_identities[repo] = self._repository_identity(repo)
                if manager:
                    manager.validate_repo({"repo_path": str(repo), "allowed_root": str(root / "projects")})
            self.seal = self.snapshot()
            self.digest = hashlib.sha256(repr(self.seal).encode()).hexdigest()
        except (OSError, ValueError, TypeError, KeyError, RecursionError, WorkerError) as exc:
            raise denied() from exc

    @staticmethod
    def _repository_identity(repo: Path) -> tuple[int, ...]:
        values: list[int] = []
        for path in (repo, repo / ".git"):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise denied()
            values.extend((info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)))
        return tuple(values)

    @staticmethod
    def _workspace_identity(workspace: Path) -> tuple[Any, ...]:
        path = workspace / ".git"
        canonical(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) & 0o022 or before.st_size > 4096):
                raise denied()
            raw = os.read(fd, 4097)
            after = os.fstat(fd)
            canonical(path)
            current = path.lstat()
            def identity(info: os.stat_result) -> tuple[int, ...]:
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                        info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            seal = identity(before)
            if seal != identity(after) or seal != identity(current) or len(raw) != before.st_size:
                raise denied()
            return (seal, hashlib.sha256(raw).hexdigest())
        finally:
            os.close(fd)

    def snapshot(self) -> tuple[Any, ...]:
        canonical(self.profile)
        info = self.profile.lstat()
        if (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) != self.profile_identity:
            raise denied()
        no_layers(self.profile)
        for repo in self.repositories:
            canonical(repo / ".git")
            if self._repository_identity(repo) != self.repository_identities[repo]:
                raise denied()
            no_layers(self.profile, repo)
        with self.workspace_lock:
            workspaces = tuple(self.workspaces.items())
        for workspace, identity in workspaces:
            no_layers(self.profile, workspace)
            if self._workspace_identity(workspace) != identity:
                raise denied()
        manifest_raw, manifest_identity = private_bytes(self.manifest)
        path = self.profile / "config.toml"
        config_seal: tuple[Any, ...] | None = None
        if os.path.lexists(path):
            raw, identity = private_bytes(path)
            data = tomllib.loads(raw.decode("utf-8"))
            if data != {"projects": self.projects}:
                raise denied()
            config_seal = (hashlib.sha256(raw).hexdigest(), identity)
        return (hashlib.sha256(manifest_raw).hexdigest(), manifest_identity, config_seal, self.profile_identity,
                tuple(self.repository_identities.items()))

    def check(self) -> None:
        try:
            if self.snapshot() != self.seal:
                raise denied()
        except (OSError, ValueError, TypeError, RecursionError, WorkerError) as exc:
            raise denied() from exc

    def receipt(self, generation: str) -> dict[str, str]:
        return {"generation": generation, "manifest": str(self.manifest), "profile": str(self.profile), "seal": self.digest}

    def target(self, execution_id: str) -> str:
        try:
            raw, _ = private_bytes(self.root / "journals" / (execution_id + ".json"), limit=8 * 1024 * 1024)
            dispatch = json.loads(raw)
            target = str(dispatch.get("request", {}).get("target_execution_id") or execution_id)
            if dispatch.get("execution_id") != execution_id or str(UUID(target)) != target:
                raise denied()
            return target
        except (OSError, ValueError, TypeError, AttributeError, RecursionError, WorkerError) as exc:
            raise denied() from exc

    def allocation_identity(self, target: str, saved: dict[str, Any]) -> tuple[Any, ...]:
        workspace = Path(saved["workspace"]["path"])
        repo = Path(saved["repository_root"])
        if (saved.get("execution_id") != target or workspace.name != target
                or not workspace.is_relative_to(self.root / "worktrees") or str(repo) not in self.projects):
            raise denied()
        manager = GitWorkspaceManager(self.root, require_ext4=False)
        identity = self._workspace_identity(workspace)
        loaded = manager.load(target)
        if loaded.path != workspace:
            raise denied()
        common = Path(manager.git(workspace, "rev-parse", "--path-format=absolute", "--git-common-dir"))
        if common != repo / ".git":
            raise denied()
        canonical(common)
        no_layers(self.profile, workspace)
        if identity != self._workspace_identity(workspace):
            raise denied()
        return identity

    def bind(self, execution_id: str, workspace: Path, generation: str) -> None:
        """Use durable allocator identity and actual Git, never frame trust."""
        try:
            target = self.target(execution_id)
            if workspace.name != target:
                raise denied()
            allocation = self.root / "journals" / (target + ".json")
            raw, _ = private_bytes(allocation, limit=8 * 1024 * 1024)
            saved = json.loads(raw)
            repo = Path(saved["repository_root"])
            if (saved.get("execution_id") != target or saved["workspace"]["path"] != str(workspace)
                    or str(repo) not in self.projects or (saved.get("shared_profile_policy") not in (None, self.receipt(generation)))):
                raise denied()
            if saved.get("shared_profile_policy") is not None:
                check_receipt(self.root, saved)
            identity = self.allocation_identity(target, saved)
            if saved.get("shared_profile_policy") is not None and saved.get("shared_workspace_seal") != [list(identity[0]), identity[1]]:
                raise denied()
            with self.workspace_lock:
                if self.workspaces.get(workspace) not in (None, identity):
                    raise denied()
                self.workspaces[workspace] = identity
            self.check()
            Journal(allocation).update(shared_profile_policy=self.receipt(generation), shared_workspace_seal=[list(identity[0]), identity[1]])
        except (OSError, ValueError, TypeError, KeyError, RecursionError, WorkerError) as exc:
            raise denied() from exc


def check_receipt(root: Path, saved: dict[str, Any]) -> None:
    """Fence later checks/commits against a changed or retired generation."""
    from .commit_lineage import check_import_fence
    check_import_fence(root, saved)
    receipt = saved.get("shared_profile_policy")
    if receipt is None:
        return
    try:
        state = Journal(root / "providers" / "codex" / "server.json").read()
        if state.get("generation") != receipt["generation"] or state.get("policy_blocked") or state.get("stopped") is not False:
            raise denied()
        policy = SealedProfilePolicy(root, Path(receipt["profile"]), Path(receipt["manifest"]), validate_repositories=False)
        if policy.digest != receipt["seal"]:
            raise denied()
        native_receipt = saved.get("shared_native_read_policy")
        if native_receipt is not None:
            from .native_read_policy import NativeReadPolicy
            native = NativeReadPolicy(policy, Path(native_receipt["manifest"]))
            if native.receipt(receipt["generation"]) != native_receipt or state.get("native_read_policy") != native_receipt:
                raise denied()
        elif state.get("native_read_policy") is not None:
            raise denied()
        no_layers(policy.profile, Path(saved["workspace"]["path"]))
        identity = policy._workspace_identity(Path(saved["workspace"]["path"]))
        if saved.get("shared_workspace_seal") != [list(identity[0]), identity[1]]:
            raise denied()
    except (OSError, ValueError, TypeError, KeyError, RecursionError, WorkerError) as exc:
        raise denied() from exc


def inherit_receipt(root: Path, target: Journal, *, source_id: str | None = None, source_sha: str | None = None) -> None:
    """Local worker evidence follows repair/delta copies, not job claims."""
    try:
        if source_id is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", source_id):
            raise denied()
        paths = [root / "journals" / (source_id + ".json")] if source_id else list((root / "journals").glob("*.json"))
        if len(paths) > 8192:
            raise denied()
        for path in paths:
            # Atomic journal writers share this lock; do not misclassify their
            # unrelated replacement as policy drift during dependency copies.
            with FileLock(path.with_suffix(".write.lock"), blocking=True, timeout=1):
                raw, _ = private_bytes(path, limit=8 * 1024 * 1024)
            saved = json.loads(raw)
            if source_sha and saved.get("commit_sha") != source_sha:
                continue
            receipt = saved.get("shared_profile_policy")
            if receipt is None:
                continue
            check_receipt(root, saved)
            target_saved = target.read()
            previous = target_saved.get("shared_profile_policy")
            native_receipt = saved.get("shared_native_read_policy")
            if target_saved.get("shared_native_read_policy") not in (None, native_receipt):
                raise denied()
            if previous not in (None, receipt):
                raise denied()
            if previous is not None:
                check_receipt(root, target_saved)
            else:
                policy = SealedProfilePolicy(root, Path(receipt["profile"]), Path(receipt["manifest"]), validate_repositories=False)
                if policy.digest != receipt["seal"]:
                    raise denied()
                identity = policy.allocation_identity(target_saved["execution_id"], target_saved)
                target.update(shared_profile_policy=receipt, shared_workspace_seal=[list(identity[0]), identity[1]],
                              **({"shared_native_read_policy": native_receipt} if native_receipt is not None else {}))
    except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError, WorkerError) as exc:
        raise denied() from exc
