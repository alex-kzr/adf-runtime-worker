"""Temporary approved-only native skill materialization without changing auth/config."""
from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import Json, Request, WorkerError
from .security import within_root


def discovery_documents(workspace: Path) -> set[Path]:
    roots = {Path.home() / ".agents" / "skills", Path.home() / ".codex" / "skills", Path("/etc/codex/skills")}
    # Project ancestry is conservatively disabled by exact path selectors, no skill bodies read.
    for parent in (workspace, *workspace.parents):
        roots.update({parent / ".agents" / "skills", parent / ".codex" / "skills"})
    documents: set[Path] = set()
    directories_seen = 0
    for root in roots:
        if root.is_symlink() or root.resolve() != root.absolute():
            raise WorkerError("PERMISSION_DENIED", "Symlinked native skill roots require operator review")
        if not root.is_dir():
            continue
        for directory, subdirs, files in os.walk(root, followlinks=False):
            directories_seen += 1
            if directories_seen > 4000:
                raise WorkerError("QUOTA_EXCEEDED", "Native skill exclusion directory quota exceeded")
            if Path(directory).is_symlink():
                subdirs.clear()
                continue
            if "SKILL.md" in files:
                documents.add((Path(directory) / "SKILL.md").resolve())
            # Unknown symlinked packs cannot enter the approved native catalog safely.
            if any((Path(directory) / name).is_symlink() for name in subdirs):
                raise WorkerError("PERMISSION_DENIED", "Symlinked unrelated native skill packs require operator review")
            if len(documents) > 2000:
                raise WorkerError("QUOTA_EXCEEDED", "Native skill discovery exclusion exceeds metadata quota")
    return documents


@contextmanager
def native_skills(request: Request) -> Iterator[tuple[Json, str]]:
    if not request.approved_skills:
        yield {}, request.task_prompt
        return
    if request.workspace_path is None:
        raise WorkerError("INVALID_PATH", "Native skills require an allocated workspace")
    workspace = request.workspace_path
    documents = discovery_documents(workspace)
    created_dirs: list[Path] = []
    created_files: list[tuple[Path, str]] = []
    base = workspace / ".agents" / "skills"
    within_root(base, workspace, must_exist=False)
    try:
        for directory in (workspace / ".agents", base):
            if not directory.exists():
                directory.mkdir(mode=0o700)
                created_dirs.append(directory)
        rules: list[Json] = [{"path": str(path), "enabled": False} for path in sorted(documents)]
        for skill in request.approved_skills:
            directory = base / skill.name
            if directory.exists() or directory.is_symlink():
                raise WorkerError("PERMISSION_DENIED", "Approved skill materialization cannot overwrite repository content")
            directory.mkdir(mode=0o700)
            created_dirs.append(directory)
            source = directory / "SKILL.md"
            if hashlib.sha256(skill.content.encode()).hexdigest() != skill.sha256:
                raise WorkerError("VERSION_CONFLICT", "Skill snapshot hash changed before materialization")
            source.write_text(skill.content, encoding="utf-8")
            source.chmod(0o400)
            created_files.append((source, skill.sha256))
            rules.append({"path": str(source), "enabled": True})
        prompt = "Use the approved native skills: " + " ".join("$" + skill.name for skill in request.approved_skills) + "\n" + request.task_prompt
        yield {"config": rules, "bundled": {"enabled": False}, "include_instructions": True}, prompt
    finally:
        changed = False
        for source, expected in reversed(created_files):
            try:
                within_root(source, workspace)
                with source.open("rb") as content:
                    changed |= source.is_symlink() or hashlib.sha256(content.read(32769)).hexdigest() != expected
                source.unlink()
            except (OSError, WorkerError):
                changed = True
        for directory in reversed(created_dirs):
            try:
                within_root(directory, workspace)
                directory.rmdir()
            except (OSError, WorkerError):
                changed = True
        if changed:
            raise WorkerError("PERMISSION_DENIED", "Provider modified approved skill materialization; retained residual evidence")
