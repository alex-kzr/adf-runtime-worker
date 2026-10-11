"""Closed, opt-in checker namespace; never fall back to host execution.

The operator supplies a separate pinned launcher/toolchain manifest. This does
not change provider permissions, sealed profile policy or OS security settings.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from threading import Event
from uuid import uuid4

from .models import AdapterResult, Json, Request, WorkerError
from .patches import image, parent_fd, patch_path
from .process import LineSink, ProcessRunner
from .security import inspect_bytes


class CheckSandbox:
    def __init__(self, config: Json | None) -> None:
        self.config = config or {}

    def launcher(self) -> Path:
        config = self.config
        if os.name != "posix" or set(config) != {"version", "bwrap", "sha256", "toolchain_roots"} or config.get("version") != 1:
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Checks require a separate operator-pinned sandbox manifest")
        path = Path(config["bwrap"])
        if not path.is_absolute() or path.resolve(strict=True) != path or str(path).startswith("/mnt/"):
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Sandbox launcher must be a canonical Linux file")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o6022 or not os.access(path, os.X_OK):
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Sandbox launcher has unsafe permissions")
        if hashlib.sha256(path.read_bytes()).hexdigest() != config["sha256"]:
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Sandbox launcher pin changed")
        return path

    def command(self, executable: Path, args: list[str], snapshot: Path, request: Request) -> list[str]:
        launcher = self.launcher()
        if request.workspace_path is None:
            raise WorkerError("INVALID_PATH", "Sandbox needs an allocated workspace")
        root = request.workspace_path
        roots = self.config["toolchain_roots"]
        if not isinstance(roots, list) or not roots or len(roots) > 16:
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Sandbox needs bounded operator-selected toolchain roots")
        mounts: list[Path] = []
        eligible = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve(), executable.resolve(strict=True).parent,
                    Path("/usr/lib"), Path("/usr/lib64")}
        for name in roots:
            path = Path(name)
            if not path.is_absolute() or path.resolve(strict=True) != path or path not in eligible or str(path).startswith("/mnt/"):
                raise WorkerError("PERMISSION_DENIED", "Broad/external control roots are not checker toolchains")
            if path == root or path.is_relative_to(root) or root.is_relative_to(path) or any(part in {"provider-profiles", "projects", "journals", "config", "providers", ".codex", ".claude"} for part in path.parts):
                raise WorkerError("PERMISSION_DENIED", "Checker mount would expose project/control/auth state")
            mounts.append(path)
        selected = executable.resolve(strict=True)
        if selected != Path(sys.executable).resolve(strict=True):
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Checker v1 supports only pinned Python; Node/build checks need separate aggregate resource isolation")
        if not any(selected == path or selected.is_relative_to(path) for path in mounts):
            raise WorkerError("CHECK_UNAVAILABLE", "Registered executable is outside pinned checker toolchains")
        argv = [str(launcher), "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session", "--clearenv", "--cap-drop", "ALL"]
        # bubblewrap creates missing destination parents in the empty root.
        for path in mounts:
            argv += ["--ro-bind", str(path), str(path)]
        if Path("/usr/lib") in mounts:
            argv += ["--symlink", "usr/lib", "/lib"]
        if Path("/usr/lib64") in mounts:
            argv += ["--symlink", "usr/lib64", "/lib64"]
        quota = min(request.max_disk_bytes, 64 * 1024 * 1024)
        if quota < 8192:
            raise WorkerError("QUOTA_EXCEEDED", "Checker private filesystems require at least two pages")
        home_quota = max(4096, min(quota // 4, 8 * 1024 * 1024))
        argv += ["--ro-bind", str(snapshot), "/workspace", "--proc", "/proc", "--dev", "/dev",
                 "--ro-bind", str(Path(__file__).with_name("check_payload.py")), "/checker.py",
                 "--size", str(quota - home_quota), "--tmpfs", "/scratch", "--dir", "/home", "--size", str(home_quota), "--tmpfs", "/home/checker", "--chdir", "/workspace",
                 "--setenv", "HOME", "/home/checker", "--setenv", "TMPDIR", "/scratch",
                 "--setenv", "PATH", ":".join(dict.fromkeys(str(path.parent if path.is_file() else path / "bin") for path in mounts)),
                 "--setenv", "LANG", "C.UTF-8", "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
                 "--setenv", "PYTHONNOUSERSITE", "1", "--setenv", "npm_config_cache", "/scratch/npm-cache",
                 "--remount-ro", "/dev", "--remount-ro", "/",
                 "--", sys.executable, "-I", "-B", "/checker.py", json.dumps([str(executable), *args])]
        return argv

    def run(self, executable: Path, args: list[str], names: list[str], request: Request,
            sink: LineSink, cancellation: Event, guard: Callable[[], None]) -> AdapterResult:
        self.launcher()  # Reject unavailable capability before any spawn/copy.
        if request.workspace_path is None:
            raise WorkerError("INVALID_PATH", "Checker needs a worktree")
        root = request.workspace_path
        guard()
        snapshot = root / (".adf-checks-" + uuid4().hex)
        snapshot.mkdir(mode=0o700)
        ownership = snapshot.stat(follow_symlinks=False)
        stopped = True
        try:
            total = 0
            if len(names) > 4096:
                raise WorkerError("QUOTA_EXCEEDED", "Checker snapshot exceeds file-count quota")
            for name in sorted(set(names)):
                guard()
                # Exclude metadata/auth/control paths, never expose raw worktree
                # .git pointers, caches, ignored files or user-owned secrets.
                try:
                    patch_path(name)
                except WorkerError:
                    continue
                with parent_fd(root, name) as (fd, leaf):
                    item, raw = image(fd, leaf)
                    if item is None or raw is None:
                        continue
                    inspect_bytes(raw, secret_values=request.redaction_values)
                    total += len(raw)
                    if total > min(request.max_disk_bytes, 64 * 1024 * 1024):
                        raise WorkerError("QUOTA_EXCEEDED", "Checker snapshot exceeds byte quota")
                    destination = snapshot / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(raw)
                    destination.chmod(item["mode"] & 0o755)
            guard()
            argv = self.command(executable, args, snapshot, request)
            # No supervisor/allocation FDs, inherited HOME, secrets, profile or
            # caller-selected environment enters the namespace launcher.
            isolated = replace(request, lock_fd=None, env_allowlist=(), permission_profile="observe")
            runner = ProcessRunner()
            stopped = False
            try:
                bounded = [sys.executable, "-I", "-B", "-m", "adf_runtime_worker.check_bootstrap", json.dumps(argv), str(request.timeout_sec), str(request.max_disk_bytes)]
                outcome = runner.run(bounded, isolated, sink, cancellation, environment={"LANG": "C.UTF-8"})
            finally:
                stopped = runner.stop() if runner.process is not None else True
            stopped = outcome.process_stopped
            if not stopped:
                raise WorkerError("EXECUTION_UNCERTAIN", "Checker namespace process has not stopped")
            if outcome.status == "failed" and any(line.startswith("bwrap:") or line == "ADF_CHECKER_SETUP_FAILED" for line in outcome.output.splitlines()):
                raise WorkerError("CAPABILITY_UNSUPPORTED", "Checker namespace setup failed; host fallback is forbidden")
            guard()
            return outcome
        finally:
            if stopped:
                # Only this private, UUID-named directory, never caller paths.
                current = snapshot.stat(follow_symlinks=False)
                if snapshot.parent != root or snapshot.is_symlink() or (current.st_dev, current.st_ino) != (ownership.st_dev, ownership.st_ino) or not shutil.rmtree.avoids_symlink_attacks:
                    raise WorkerError("EXECUTION_UNCERTAIN", "Checker snapshot ownership changed")
                shutil.rmtree(snapshot)
