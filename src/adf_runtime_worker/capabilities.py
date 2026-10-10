"""Versioned approved skill snapshots and owned scoped MCP configuration."""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import Any

from .models import Json, SkillSnapshot, WorkerError
from .security import inspect_content, validate_relative, within_root

_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
MCP_CONTRACT = "adf.scoped-files.v1"
MCP_TOOLS = frozenset({"read_file", "read_marker"})
MCP_DENIED_COMPONENTS = frozenset({".agents", ".codex", ".claude", ".git", ".ssh", ".aws", ".azure", ".kube", ".gnupg", ".config"})
MCP_DENIED_BASENAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})


def validate_mcp_path(path: str) -> None:
    validate_relative(path)
    if len(path) > 1024 or Path(path).as_posix() != path or any(char in path for char in "*?[\\:"):
        raise WorkerError("INVALID_PATH", "MCP paths must be bounded canonical relative names")
    if any(part.lower() in MCP_DENIED_COMPONENTS for part in Path(path).parts) or Path(path).name.lower() in MCP_DENIED_BASENAMES:
        raise WorkerError("PERMISSION_DENIED", "MCP cannot read credential or configuration paths")


def skill_snapshot(item: Json, root: Path, secret_values: tuple[str, ...] = ()) -> SkillSnapshot:
    manifest = item.get("manifest", item)
    path = within_root(Path(manifest["path"]), root / "skills")
    source = path / "SKILL.md" if path.is_dir() else path
    within_root(source, root / "skills")
    if source.name != "SKILL.md":
        raise WorkerError("INVALID_PATH", "Instruction skills require SKILL.md in the approved skills root")
    if source.stat().st_nlink != 1:
        raise WorkerError("INVALID_PATH", "Hardlinked skill documents are forbidden")
    inspect_content(source, 32768, secret_values=secret_values)
    raw = source.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != manifest.get("sha256", manifest.get("hash")):
        raise WorkerError("VERSION_CONFLICT", "Skill content differs from approved manifest")
    text = raw.decode("utf-8")
    # This bounded instruction-only contract does not load unapproved scripts or YAML dependencies.
    frontmatter = re.match(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|$)", text, re.S)
    name = re.search(r"^name:\s*([A-Za-z][A-Za-z0-9_-]{0,63})\s*$", frontmatter[1], re.M) if frontmatter else None
    description = re.search(r"^description:\s*\S.*$", frontmatter[1], re.M) if frontmatter else None
    if not name or not description:
        raise WorkerError("INVALID_REQUEST", "Native skills require bounded name and description frontmatter")
    return SkillSnapshot(name[1], sha, text)


def scoped_mcp(item: Json, workspace: Path, timeout: int) -> tuple[str, Json]:
    manifest = item.get("manifest", item)
    tools = manifest.get("allowed_tools", [])
    if manifest.get("trusted") is not True or manifest.get("transport", "stdio") != "stdio" or not isinstance(tools, list) or not tools:
        raise WorkerError("PERMISSION_DENIED", "MCP requires trusted stdio and explicit tools")
    if any(not isinstance(tool, str) or tool not in MCP_TOOLS for tool in tools) or len(set(tools)) != len(tools):
        raise WorkerError("PERMISSION_DENIED", "MCP tool outside the owned read-file contract")
    name = str(manifest.get("name", item.get("name", "")))
    if not _NAME.fullmatch(name) or "__" in name:
        raise WorkerError("INVALID_REQUEST", "MCP server name is unsafe")
    if manifest.get("argv") not in (["python3", "-m", "adf_runtime_worker.scoped_mcp"], ["python", "-m", "adf_runtime_worker.scoped_mcp"], [sys.executable, "-m", "adf_runtime_worker.scoped_mcp"]):
        raise WorkerError("CAPABILITY_UNSUPPORTED", "Scoped MCP requires the owned adf.scoped-files.v1 server")
    scope = manifest.get("scope", {})
    if not isinstance(scope, dict) or scope.get("contract") != MCP_CONTRACT or set(scope) - {"contract", "root", "read_paths", "max_bytes"}:
        raise WorkerError("CAPABILITY_UNSUPPORTED", "Unsupported MCP scope contract")
    if scope.get("root") not in {"$WORKTREE", str(workspace)}:
        raise WorkerError("PERMISSION_DENIED", "MCP root must be exactly the allocated worktree")
    if workspace.resolve() != workspace or workspace.is_symlink():
        raise WorkerError("INVALID_PATH", "MCP root must be canonical")
    paths = scope.get("read_paths")
    if not isinstance(paths, list) or not paths or len(paths) > 100 or any(not isinstance(path, str) for path in paths) or len(set(paths)) != len(paths):
        raise WorkerError("INVALID_REQUEST", "MCP requires exact read paths")
    for path in paths:
        validate_mcp_path(path)
        within_root(workspace / path, workspace, must_exist=False)
    maximum = scope.get("max_bytes", 4096)
    configured_timeout = manifest.get("timeout_sec", 30)
    if type(maximum) is not int or not 1 <= maximum <= 65536 or type(configured_timeout) is not int or not 1 <= configured_timeout <= 1800:
        raise WorkerError("INVALID_REQUEST", "MCP quotas must be bounded integers")
    limit = min(configured_timeout, timeout)
    return name, {"command": sys.executable, "args": ["-I", "-m", "adf_runtime_worker.scoped_mcp"], "enabled_tools": sorted(tools), "tool_timeout_sec": limit, "startup_timeout_sec": min(limit, 10), "required": True, "scope": {**scope, "root": str(workspace), "max_bytes": maximum}, "env_vars": []}


def toml_value(value: Any) -> str:
    import json
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(str(key)) + "=" + toml_value(item) for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(toml_value(item) for item in value) + "]"
    return json.dumps(value)
