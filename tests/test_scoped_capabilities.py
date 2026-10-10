import hashlib
import json
import os
import sys
import subprocess
import time
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest
import jsonschema

from adf_runtime_worker.adapters import CodexAdapter, JsonNormalizer
from adf_runtime_worker.capabilities import scoped_mcp, skill_snapshot
from adf_runtime_worker.executor import Executor
from adf_runtime_worker.models import Request, WorkerError
from adf_runtime_worker.native_skills import native_skills
from adf_runtime_worker.scoped_mcp import ScopedFiles


def manifest():
    return {"name": "factoryfiles", "manifest": {"transport": "stdio", "argv": ["python3", "-m", "adf_runtime_worker.scoped_mcp"], "trusted": True, "allowed_tools": ["read_marker"], "scope": {"contract": "adf.scoped-files.v1", "root": "$WORKTREE", "read_paths": ["marker.txt"], "max_bytes": 4096}, "timeout_sec": 2}}


def snapshot(root):
    directory = root / "skills" / "approved"
    directory.mkdir(parents=True)
    text = "---\nname: approved-marker\ndescription: Apply the approved marker instruction.\n---\nSet evidence to APPROVED_SKILL_STAMP.\n"
    (directory / "SKILL.md").write_text(text)
    return {"path": str(directory), "version": "1", "hash": hashlib.sha256(text.encode()).hexdigest()}


def test_native_skill_hash_root_and_materialization(repository, monkeypatch):
    root, repo, _, _ = repository
    home = root / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    approved = skill_snapshot(snapshot(root), root)
    request = Request("exec", "run", 1, workspace_path=repo, task_prompt="Perform the bounded task.", approved_skills=(approved,))
    assert "APPROVED_SKILL_STAMP" not in request.task_prompt
    with native_skills(request) as (config, prompt):
        source = repo / ".agents" / "skills" / approved.name / "SKILL.md"
        assert source.read_text() == approved.content
        assert config["config"][-1] == {"path": str(source), "enabled": True}
        official = json.loads((Path(__file__).parent / "fixtures" / "codex-0.157.0-scoped-schema.json").read_text())["schema"]
        jsonschema.validate({"skills": config}, official)
        assert "$approved-marker" in prompt
        assert "APPROVED_SKILL_STAMP" not in prompt
    assert not (repo / ".agents").exists()
    with pytest.raises(WorkerError, match="hash changed"):
        with native_skills(replace(request, approved_skills=(replace(approved, sha256="0" * 64),))):
            pass
    assert not (repo / ".agents").exists()


def test_unapproved_skill_excluded_and_postlaunch_tamper_rejected(repository, monkeypatch):
    root, repo, _, _ = repository
    home = root / "home"
    host = home / ".agents" / "skills" / "unapproved"
    host.mkdir(parents=True)
    (host / "SKILL.md").write_text("Do not expose this skill.")
    monkeypatch.setenv("HOME", str(home))
    approved = skill_snapshot(snapshot(root), root)
    request = Request("exec", "run", 1, workspace_path=repo, approved_skills=(approved,))
    with pytest.raises(WorkerError, match="modified approved"):
        with native_skills(request) as (config, _):
            assert {"path": str(host / "SKILL.md"), "enabled": False} in config["config"]
            source = repo / ".agents" / "skills" / approved.name / "SKILL.md"
            source.chmod(0o600)
            source.write_text("tampered")
    assert (host / "SKILL.md").read_text() == "Do not expose this skill."
    assert not (repo / ".agents").exists()


@pytest.mark.parametrize("mode", ["hash", "outside", "symlink", "secret", "missing_frontmatter"])
def test_skill_denials(repository, tmp_path, mode):
    root = repository[0]
    item = snapshot(root)
    source = Path(item["path"]) / "SKILL.md"
    if mode == "hash":
        item["hash"] = "0" * 64
    elif mode == "outside":
        item["path"] = str(tmp_path)
    elif mode == "symlink":
        alias = root / "skills" / "alias"
        alias.symlink_to(Path(item["path"]), target_is_directory=True)
        item["path"] = str(alias)
    elif mode == "secret":
        source.write_text("password=sentinel-secret-value")
        item["hash"] = hashlib.sha256(source.read_bytes()).hexdigest()
    else:
        source.write_text("instruction without native metadata")
        item["hash"] = hashlib.sha256(source.read_bytes()).hexdigest()
    with pytest.raises(WorkerError):
        skill_snapshot(item, root)


def test_codex_exact_scoped_overlay_toml_and_tool_audit(repository, tmp_path):
    name, config = scoped_mcp(manifest(), repository[1], 180)
    request = Request("exec", "run", 1, workspace_path=repository[1], mcp_config={name: config}, allowed_tools=("mcp__factoryfiles__read_marker",))
    argv = CodexAdapter("codex").argv(request, tmp_path)
    overrides = {argv[i + 1].split("=", 1)[0]: argv[i + 1] for i, item in enumerate(argv[:-1]) if item == "-c"}
    parsed = tomllib.loads(overrides["mcp_servers.factoryfiles"])["mcp_servers"]["factoryfiles"]
    official = json.loads((Path(__file__).parent / "fixtures" / "codex-0.157.0-scoped-schema.json").read_text())["schema"]
    jsonschema.validate({"mcp_servers": {"factoryfiles": parsed}}, official)
    assert parsed["enabled_tools"] == ["read_marker"]
    assert parsed["tool_timeout_sec"] == 2
    assert parsed["required"] is True
    assert "--strict-config" in argv
    assert "--ignore-user-config" in argv
    assert "allow_login_shell=false" in argv
    assert json.loads(Path(parsed["args"][-1]).read_text())["scope"]["root"] == str(repository[1])
    with pytest.raises(WorkerError, match="built-in"):
        CodexAdapter("codex").argv(replace(request, allowed_tools=("command_execution",)), tmp_path)
    events = []
    normalizer = JsonNormalizer("codex", lambda kind, payload: events.append((kind, payload)), 10, allowed_mcp={(name, "read_marker")})
    event = {"type": "item.started", "item": {"id": "mcp-1", "type": "mcp_tool_call", "server": name, "tool": "read_marker", "arguments": {"private": "not-persisted"}}}
    normalizer.line("stdout", json.dumps(event))
    assert events[0][1]["server_id"] == name
    assert events[0][1]["tool_name"] == "read_marker"
    assert "private" not in json.dumps(events)
    event["item"]["tool"] = "forbidden_tool"
    with pytest.raises(WorkerError, match="unapproved"):
        normalizer.line("stdout", json.dumps(event))


@pytest.mark.parametrize("change", ["scope", "root", "path", "glob", "secret", "config", "argv", "tool", "timeout", "limit", "dot"])
def test_mcp_manifest_fail_closed(repository, change):
    item = manifest()
    data = item["manifest"]
    scope = data["scope"]
    if change == "scope":
        scope["contract"] = "generic-trusted-server"
    elif change == "root":
        scope["root"] = str(repository[0])
    elif change == "path":
        scope["read_paths"] = ["../outside.txt"]
    elif change == "dot":
        scope["read_paths"] = ["."]
    elif change == "glob":
        scope["read_paths"] = ["**"]
    elif change == "secret":
        scope["read_paths"] = [".env"]
    elif change == "config":
        scope["read_paths"] = [".codex/auth.json"]
    elif change == "argv":
        data["argv"] = ["python3", "unverified-server.py"]
    elif change == "tool":
        data["allowed_tools"] = ["forbidden_tool"]
    elif change == "timeout":
        data["timeout_sec"] = True
    else:
        scope["max_bytes"] = 65537
    with pytest.raises(WorkerError):
        scoped_mcp(item, repository[1], 180)


def test_server_positive_and_forbidden_outside_symlink_env_denials(repository, monkeypatch):
    _, repo, _, _ = repository
    marker = repo / "marker.txt"
    marker.write_text("LOCAL_MCP_MARKER")
    monkeypatch.setenv("SENTINEL_API_KEY", "not-forwarded")
    _, config = scoped_mcp(manifest(), repo, 180)
    server = ScopedFiles(config)
    assert server.call("read_marker", {})["content"][0]["text"] == "LOCAL_MCP_MARKER"
    assert "forbidden_tool" in {tool["name"] for tool in server.catalog()}
    for name, arguments in [("forbidden_tool", {}), ("read_file", {"path": "marker.txt"}), ("read_marker", {"path": "../outside"}), ("read_marker", {"env": "SENTINEL_API_KEY"})]:
        assert server.response({"id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})["result"]["isError"] is True
    marker.unlink()
    marker.symlink_to(repo.parent / "outside")
    (repo.parent / "outside").write_text("OUTSIDE_SCOPE")
    assert server.response({"id": 1, "method": "tools/call", "params": {"name": "read_marker"}})["result"]["isError"] is True


def test_server_timeout_and_output_limits(repository, monkeypatch):
    repo = repository[1]
    (repo / "marker.txt").write_text("marker")
    _, config = scoped_mcp(manifest(), repo, 1)
    server = ScopedFiles(config)
    original_read = os.read
    def blocked_read(fd, maximum):
        time.sleep(3)
        return original_read(fd, maximum)
    monkeypatch.setattr(os, "read", blocked_read)
    started = time.monotonic()
    result = server.response({"id": 1, "method": "tools/call", "params": {"name": "read_marker"}})
    assert result["result"]["content"][0]["text"] == "MCP_TIMEOUT"
    assert time.monotonic() - started < 2
    monkeypatch.setattr(os, "read", original_read)
    (repo / "marker.txt").write_text("a" * 5000)
    assert server.response({"id": 2, "method": "tools/call", "params": {"name": "read_marker"}})["result"]["isError"] is True


def test_api_snapshot_registry_cannot_broaden_mcp(repository, job):
    executor = Executor(repository[0], require_ext4=False)
    executor.execution_deadline = time.monotonic() + 180
    workspace = executor.workspaces.allocate(job)
    tool = {"manifest": {"permission": "read", "provider_mappings": {"codex": ["mcp__factoryfiles__read_marker"]}}}
    agent = {**job["agent"], "provider": "codex", "tools": [tool], "mcp_servers": [manifest()]}
    request = executor._request({**job, "agent": agent}, workspace, None, None)
    assert request.allowed_tools == ("mcp__factoryfiles__read_marker",)
    assert request.mcp_config["factoryfiles"]["command"] == sys.executable
    tool["manifest"]["provider_mappings"]["codex"] = ["mcp__factoryfiles__forbidden_tool"]
    with pytest.raises(WorkerError):
        executor._request({**job, "agent": agent}, workspace, None, None)


def test_server_rejects_hardlinked_outside_canary(repository):
    repo = repository[1]
    outside = repo.parent / "synthetic-canary.txt"
    outside.write_text("SYNTHETIC_OUTSIDE_BYTES_MUST_NEVER_BE_RETURNED")
    os.link(outside, repo / "marker.txt")
    _, config = scoped_mcp(manifest(), repo, 180)
    response = ScopedFiles(config).response({"id": 1, "method": "tools/call", "params": {"name": "read_marker"}})
    assert response["result"]["isError"] is True
    assert "SYNTHETIC_OUTSIDE_BYTES" not in json.dumps(response)
    assert outside.read_text() == "SYNTHETIC_OUTSIDE_BYTES_MUST_NEVER_BE_RETURNED"


@pytest.mark.parametrize("path", [".ssh/id_rsa", ".aws/config", ".azure/state", ".kube/config", ".gnupg/state", ".config/gcloud/state", "nested/id_ed25519"])
def test_credential_store_paths_rejected_without_reading(repository, path):
    item = manifest()
    item["manifest"]["scope"]["read_paths"] = [path]
    with pytest.raises(WorkerError):
        scoped_mcp(item, repository[1], 180)
    # Server independently rejects modified private config before opening a file.
    _, config = scoped_mcp(manifest(), repository[1], 180)
    config["scope"]["read_paths"] = [path]
    with pytest.raises(WorkerError):
        ScopedFiles(config)


def test_owned_server_isolated_from_hostile_cwd_modules(repository, tmp_path):
    from adf_runtime_worker.security import restricted_env
    repo = repository[1]
    (repo / "marker.txt").write_text("APPROVED_SAFE_MARKER")
    canary = tmp_path / "module-shadow-canary.txt"
    shadow = repo / "adf_runtime_worker"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("from pathlib import Path\nPath(" + repr(str(canary)) + ").write_text('MODULE_SHADOW_EXECUTED')\n")
    (shadow / "scoped_mcp.py").write_text("raise SystemExit('UNTRUSTED_SERVER')\n")
    site_canary = tmp_path / "sitecustomize-canary.txt"
    (repo / "sitecustomize.py").write_text("from pathlib import Path\nPath(" + repr(str(site_canary)) + ").write_text('SITE_SHADOW_EXECUTED')\n")
    name, config = scoped_mcp(manifest(), repo, 180)
    request = Request("exec", "run", 1, workspace_path=repo, mcp_config={name: config})
    argv = CodexAdapter("codex").argv(request, tmp_path)
    override = next(argv[i + 1] for i, value in enumerate(argv[:-1]) if value == "-c" and argv[i + 1].startswith("mcp_servers.factoryfiles="))
    launch = tomllib.loads(override)["mcp_servers"][name]
    input_lines = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n" + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_marker"}}) + "\n"
    result = subprocess.run([launch["command"], *launch["args"]], input=input_lines, capture_output=True, text=True, cwd=repo, env=restricted_env(), timeout=5, check=False)
    assert result.returncode == 0
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert replies[0]["result"]["serverInfo"]["name"] == "adf-scoped-files"
    assert replies[1]["result"]["content"][0]["text"] == "APPROVED_SAFE_MARKER"
    assert not canary.exists()
    assert not site_canary.exists()


@pytest.mark.parametrize("location", [".agents", ".codex"])
def test_symlinked_host_skill_root_denied_without_loading_bodies(repository, tmp_path, monkeypatch, location):
    from adf_runtime_worker.native_skills import discovery_documents
    home = tmp_path / "host-home"
    (home / location).mkdir(parents=True)
    outside = tmp_path / "outside-unapproved-pack"
    (outside / "unapproved").mkdir(parents=True)
    (outside / "unapproved" / "SKILL.md").write_text("UNAPPROVED_BODY_MUST_NOT_BE_READ")
    (home / location / "skills").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    with pytest.raises(WorkerError, match="Symlink"):
        discovery_documents(repository[1])
