"""Operator-owned named native permissions; never a job-selected grant.

Same-UID host mutation remains trusted. This seals operator inputs and binds
literal allocator worktrees; native tool-route acceptance is a separate gate.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from .capabilities import approved_capabilities
from .journal import Journal
from .native_skills import discovery_documents
from .profile_policy import SealedProfilePolicy, _closed_object, canonical, denied, private_bytes

PROFILE_ID = "adf_shared_read"
_SYSTEM_ROOTS = tuple(Path(name) for name in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/nix", "/run", "/mnt"))
_PRIVATE_DIRS = frozenset({".git", ".agents", ".codex", ".claude", ".ssh", ".aws", ".azure", ".kube", ".gnupg", ".config"})
_PRIVATE_FILES = frozenset({"auth.json", ".credentials.json", "worker-token", "redis-worker-password", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})


def private_workspace_paths(workspace: Path, selected_files: tuple[Path, ...] = ()) -> set[Path]:
    """Exact any-depth masks, with selected documents reopened by sibling masks.

    Never read file contents, follow links or use Linux glob snapshots. The
    command stage is read-only; hostile same-UID mutations remain out of scope.
    """
    pending, denied_paths, seen = [(workspace, False)], set(), 0
    while pending:
        directory, parent_private = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                seen += 1
                if seen > 50000:
                    raise denied()
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                private = (parent_private or entry.name.lower() in _PRIVATE_DIRS | _PRIVATE_FILES
                           or entry.name.lower().startswith(".env") or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1))
                selected = path in selected_files
                ancestor = stat.S_ISDIR(info.st_mode) and any(item.is_relative_to(path) for item in selected_files)
                if private and not selected and not ancestor:
                    denied_paths.add(path)
                elif stat.S_ISDIR(info.st_mode):
                    pending.append((path, private))
    return denied_paths


def minimal_deny_roots(filesystem: dict[str, str]) -> dict[str, str]:
    """Avoid redundant parent/child masks that pinned bwrap cannot create."""
    kept: list[Path] = []
    for key in sorted((key for key, value in filesystem.items() if value == "deny" and key.startswith("/")),
                      key=lambda key: (len(Path(key).parts), key)):
        path = Path(key)
        if any(path.is_relative_to(parent) for parent in kept):
            filesystem.pop(key)
        else:
            kept.append(path)
    return filesystem


class NativeReadPolicy:
    def __init__(self, policy: SealedProfilePolicy, manifest: Path) -> None:
        self.policy, self.manifest = policy, manifest
        try:
            # Private runtime/home beneath a platform grant would expose sibling
            # worktrees or auth; deny/read reopening also breaks pinned masks.
            for private in (policy.root, policy.profile, Path.home()):
                if private == Path("/") or any(private.is_relative_to(system) for system in _SYSTEM_ROOTS):
                    raise denied()
            if not manifest.is_relative_to(policy.root / "tools"):
                raise denied()
            raw, _ = private_bytes(manifest)
            data = json.loads(raw, object_pairs_hook=_closed_object)
            if (not isinstance(data, dict) or set(data) != {"version", "read_tool_roots"}
                    or type(data["version"]) is not int or data["version"] != 1
                    or not isinstance(data["read_tool_roots"], list) or not 1 <= len(data["read_tool_roots"]) <= 8
                    or any(not isinstance(item, str) for item in data["read_tool_roots"])):
                raise denied()
            self.tool_roots = tuple(Path(item) for item in data["read_tool_roots"])
            if len(set(self.tool_roots)) != len(self.tool_roots):
                raise denied()
            for name, path in zip(data["read_tool_roots"], self.tool_roots, strict=True):
                canonical(path)
                if (name != str(path) or any(char in name for char in "*?[]")
                        or not path.is_relative_to(policy.root / "tools") or path == policy.root / "tools"
                        or any(path.is_relative_to(private) or private.is_relative_to(path)
                               for private in (policy.profile, policy.manifest, manifest))):
                    raise denied()
            self.seal = self.snapshot()
            self.digest = hashlib.sha256(repr(self.seal).encode()).hexdigest()
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            raise denied() from exc

    def snapshot(self) -> tuple[Any, ...]:
        raw, identity = private_bytes(self.manifest)
        roots = []
        for path in self.tool_roots:
            canonical(path)
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise denied()
            roots.append((str(path), info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)))
        return (hashlib.sha256(raw).hexdigest(), identity, tuple(roots))

    def check(self) -> None:
        try:
            if self.snapshot() != self.seal:
                raise denied()
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            raise denied() from exc

    def receipt(self, generation: str) -> dict[str, str]:
        return {"generation": generation, "manifest": str(self.manifest), "seal": self.digest}

    def bind(self, execution_id: str, workspace: Path, generation: str) -> None:
        self.check()
        target = self.policy.target(execution_id)
        journal = Journal(self.policy.root / "journals" / (target + ".json"))
        saved = journal.read()
        if saved.get("shared_native_read_policy") not in (None, self.receipt(generation)):
            raise denied()
        if workspace not in self.policy.workspaces:
            raise denied()
        journal.update(shared_native_read_policy=self.receipt(generation))

    def overrides(self, workspace: Path | None, skill_paths: tuple[Path, ...] = ()) -> dict[str, Any]:
        """No inherited built-in profile, workspace expansion or writable grant."""
        self.check()
        # Empty-root policy hides ungranted paths. Explicit deny ancestors of
        # read grants break the pinned Linux helper; mask only private siblings.
        filesystem = {":root": "deny", ":minimal": "read", "/etc": "deny", "/usr/local": "deny",
                      # The pinned SDK adds a /run/WSL tmpfs after filesystem masks.
                      # A read-only /run ancestor prevents that mount. Root deny
                      # hides other /run paths; mask its sole :minimal grant.
                      "/nix": "deny", "/run/current-system/sw": "deny", "/run/WSL": "deny",
                      "/mnt": "deny", str(self.policy.profile): "deny",
                      str(self.policy.manifest): "deny", str(self.manifest): "deny"}
        filesystem.update({str(self.policy.root / name): "deny"
                           for name in ("config", "providers", "provider-profiles", "journals", "locks", "projects", "skills")})
        filesystem.update({str(path): "read" for path in self.tool_roots})
        if workspace is not None:
            if workspace not in self.policy.workspaces:
                raise denied()
            filesystem[str(workspace)] = "read"
            filesystem.update({str(path): "deny" for path in private_workspace_paths(workspace, skill_paths)})
            filesystem.update({str(workspace / name): "deny" for name in _PRIVATE_DIRS if name != ".agents" or not skill_paths})
            for path in skill_paths:
                canonical(path)
                if not path.is_relative_to(workspace / ".agents" / "skills") or path.name != "SKILL.md":
                    raise denied()
                filesystem[str(path)] = "read"
        return {"features.exec_permission_approvals": False, "features.request_permissions_tool": False,
                "default_permissions": PROFILE_ID,
                "permissions": {PROFILE_ID: {"filesystem": minimal_deny_roots(filesystem), "network": {"enabled": False}}}}

    @staticmethod
    def verify_response(result: dict[str, Any], workspace: Path) -> None:
        if (result.get("activePermissionProfile") != {"id": PROFILE_ID, "extends": None}
                or result.get("runtimeWorkspaceRoots") != [str(workspace)] or result.get("cwd") != str(workspace)
                or result.get("approvalPolicy") != "never" or result.get("modelProvider") != "openai"
                or result.get("sandbox") != {"type": "readOnly", "networkAccess": False}):
            raise denied()

    def validate_capabilities(self, execution_id: str, workspace: Path, config: dict[str, Any]) -> tuple[Path, ...]:
        """Reconstruct selectors from durable API evidence, not IPC authority."""
        try:
            raw, _ = private_bytes(self.policy.root / "journals" / (execution_id + ".json"), limit=8 * 1024 * 1024)
            saved = json.loads(raw)
            body = saved["request"]
            agent = body["agent"]
            maximum = body["timeout_sec"]
            if type(maximum) is not int or not 1 <= maximum <= 1800:
                raise denied()
            if not isinstance(agent.get("skills", []), list) or len(agent.get("skills", [])) > 32:
                raise denied()
            skills, expected, _ = approved_capabilities(agent, self.policy.root, workspace, maximum, "observe")
            if len(skills) > 32 or len({skill.name for skill in skills}) != len(skills):
                raise denied()
            selected_paths = {workspace / ".agents" / "skills" / skill.name / "SKILL.md" for skill in skills}
            rules = [{"path": str(path), "enabled": False} for path in sorted(discovery_documents(workspace) - selected_paths)] if skills else []
            for skill in skills:
                path = workspace / ".agents" / "skills" / skill.name / "SKILL.md"
                canonical(path)
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o400 or info.st_size > 32768
                            or hashlib.sha256(os.read(fd, 32769)).hexdigest() != skill.sha256):
                        raise denied()
                finally:
                    os.close(fd)
                rules.append({"path": str(path), "enabled": True})
            expected_skills: dict[str, Any] = {"config": rules, "bundled": {"enabled": False}}
            if skills:
                expected_skills["include_instructions"] = True
            if config["skills"] != expected_skills or config["features.skip_host_skill_discovery"] is not (not bool(skills)):
                raise denied()
            manifests = agent.get("mcp_servers", [])
            if not isinstance(manifests, list) or len(manifests) > 16:
                raise denied()
            if len(expected) != len(manifests) or set(config["mcp_servers"]) != set(expected):
                raise denied()
            for name, original in expected.items():
                launch = config["mcp_servers"][name]
                if set(launch) != {"command", "args", "enabled_tools", "tool_timeout_sec", "startup_timeout_sec", "required", "env_vars"}:
                    raise denied()
                args = launch["args"]
                if (launch["command"] != original["command"] or not isinstance(args, list) or len(args) != 5
                        or args[:4] != [*original["args"], "--config"]):
                    raise denied()
                path = Path(args[4])
                if not path.is_relative_to(self.policy.root / "journals") or path.name != "mcp-" + name + ".json":
                    raise denied()
                stored_raw, _ = private_bytes(path)
                stored = json.loads(stored_raw, object_pairs_hook=_closed_object)
                timeout = launch["tool_timeout_sec"]
                if type(timeout) is not int or not 1 <= timeout <= original["tool_timeout_sec"]:
                    raise denied()
                original.update(tool_timeout_sec=timeout, startup_timeout_sec=min(timeout, 10))
                if stored != original or launch != {"command": original["command"], "args": args,
                                                     **{key: original[key] for key in ("enabled_tools", "tool_timeout_sec", "startup_timeout_sec", "required", "env_vars")}}:
                    raise denied()
            return tuple(sorted(selected_paths))
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            raise denied() from exc
