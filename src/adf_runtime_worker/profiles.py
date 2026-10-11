"""Operator-owned persistent provider paths; never credential readers or logins."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .models import WorkerError


@dataclass(frozen=True)
class ProviderProfile:
    provider: str
    directory: Path | None = None

    def environment(self, workspace: Path | None = None) -> dict[str, str]:
        if self.provider not in {"codex", "claude"}:
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Unknown persistent provider profile")
        if self.directory is None:
            # The stable Linux HOME is already retained by restricted_env.
            return {}
        path = self.directory
        home = Path.home().resolve()
        if (os.name != "posix" or not path.is_absolute() or str(path).startswith("/mnt/")
                or path.resolve() != path or not path.is_relative_to(home) or path == home):
            raise WorkerError("PERMISSION_DENIED", "Provider profile requires an owned canonical Linux home path")
        try:
            info = path.lstat()
        except OSError as exc:
            raise WorkerError("AUTH_REQUIRED", "Operator must provision the persistent profile directory") from exc
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise WorkerError("PERMISSION_DENIED", "Explicit provider profile must be owned and private mode 0700")
        if workspace and (path.is_relative_to(workspace) or workspace.is_relative_to(path)):
            raise WorkerError("PERMISSION_DENIED", "Provider profile must be separate from job worktrees")
        variable = "CODEX_HOME" if self.provider == "codex" else "CLAUDE_CONFIG_DIR"
        return {variable: str(path)}

    def metadata(self) -> dict[str, object]:
        default = ".codex" if self.provider == "codex" else ".claude"
        return {"profile_directory": str(self.directory or Path.home() / default), "login_per_job": False}
