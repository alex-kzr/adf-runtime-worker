"""Non-model native metadata/command probe for synthetic Unix IPC tests only.

The outer namespace mounts one synthetic test root and public system libraries.
It mounts no real HOME, /mnt, /run sockets, profiles or service configuration.
"""
import json
import jsonschema
import os
import queue
import threading
import subprocess
import time
import sys
from pathlib import Path


def toml(value):
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key) + "=" + toml(item) for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(toml(item) for item in value) + "]"
    return json.dumps(value)


def command(params, *, owner_startup=False):
    root = Path(os.environ["ADF_TEST_NATIVE_ROOT"])
    cli = Path(os.environ["ADF_TEST_NATIVE_CODEX"])
    bwrap = cli.parent.parent / "codex-resources" / "bwrap"
    assert root.resolve() == root and cli.is_relative_to(root / "tools")
    profile = root / "native-metadata-profile"
    profile.mkdir(mode=0o700, exist_ok=True)
    home = root / "native-metadata-home"
    home.mkdir(mode=0o700, exist_ok=True)
    outer = [str(bwrap), "--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", "--clearenv", "--cap-drop", "ALL"]
    for system in ("/usr/bin", "/usr/lib", "/usr/lib64"):
        outer += ["--ro-bind", system, system]
    # Public fresh QA venv + public interpreter only, for the owned stdio MCP.
    for public in sorted({Path(sys.executable).parent.parent, Path(sys.base_prefix)}):
        outer += ["--ro-bind", str(public), str(public)]
    for source, target in (("usr/bin", "/bin"), ("usr/lib", "/lib"), ("usr/lib64", "/lib64")):
        outer += ["--symlink", source, target]
    # Private namespace tmpfs only, never a shared host temp directory.
    outer += ["--bind", str(root), str(root), "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chdir", params["cwd"]]  # noqa: S108
    for key, value in {"HOME": str(home), "CODEX_HOME": str(profile), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                       "DISABLE_UPDATES": "1", "PYTHONDONTWRITEBYTECODE": "1"}.items():
        outer += ["--setenv", key, value]
    outer += ["--", str(cli)]
    config = dict(params["config"])
    if owner_startup:
        profile = dict(config["permissions"]["adf_shared_read"])
        profile["filesystem"] = {key: value for key, value in profile["filesystem"].items()
                                 if not key.startswith(params["cwd"])}
        config["permissions"] = {"adf_shared_read": profile}
    for name, value in config.items():
        outer += ["-c", name + "=" + toml(value)]
    return outer


def metadata(params):
    process = subprocess.Popen(command(params, owner_startup=True) + ["app-server", "--strict-config", "--listen", "stdio://"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env={"LANG": "C.UTF-8"}, close_fds=True)
    responses = queue.Queue(maxsize=128)
    def read():
        for line in iter(process.stdout.readline, b""):
            if len(line) > 1024 * 1024:
                return
            responses.put(json.loads(line), timeout=3)
    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    sequence = 0
    def call(method, values):
        nonlocal sequence
        sequence += 1
        process.stdin.write((json.dumps({"id": sequence, "method": method, "params": values}) + "\n").encode())
        process.stdin.flush()
        until = time.monotonic() + 12
        while time.monotonic() < until:
            try:
                response = responses.get(timeout=max(0.01, until - time.monotonic()))
            except queue.Empty:
                break
            if response.get("id") == sequence:
                if "error" in response:
                    raise RuntimeError("Synthetic native metadata request was refused")
                return response["result"]
        raise RuntimeError("Synthetic native metadata request timed out")
    try:
        call("initialize", {"clientInfo": {"name": "adf-native-canary", "version": "0.1.0"}, "capabilities": {"experimentalApi": True}})
        process.stdin.write(b'{"method":"initialized","params":{}}\n')
        process.stdin.flush()
        schemas = json.loads((Path(__file__).parent / "codex-0.157.0-native-read-schema.json").read_text())["schemas"]
        jsonschema.validate(params, schemas["ThreadStartParams"])
        result = call("thread/start", params)
        jsonschema.validate(result, schemas["ThreadStartResponse"])
        summary = {"cwd": params["cwd"], "schema_validated": True, "native_turn_calls": 0,
                   "selected_skill_enabled": False, "unapproved_skill_disabled": False, "mcp_tools": []}
        if params["config"]["skills"]["config"]:
            catalog = call("skills/list", {"cwds": [params["cwd"]], "forceReload": True})
            skills = [item for entry in catalog["data"] for item in entry["skills"]]
            selected = params["cwd"] + "/.agents/skills/scoped/SKILL.md"
            summary["selected_skill_enabled"] = any(item["path"] == selected and item["enabled"] for item in skills)
            summary["unapproved_skill_disabled"] = not any(item["enabled"] and item["path"] != selected for item in skills)
        if params["config"]["mcp_servers"]:
            catalog = call("mcpServerStatus/list", {"threadId": result["thread"]["id"], "detail": "full"})
            summary["mcp_tools"] = sorted(tool["name"] for item in catalog["data"] for tool in item["tools"].values())
        call("thread/unsubscribe", {"threadId": result["thread"]["id"]})
        return result, summary
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        reader.join(timeout=3)
        process.stdin.close()
        process.stdout.close()


def probe(params):
    completed = subprocess.run(command(params) + ["sandbox", "--", "/usr/bin/python3", "-I", "-B", params["cwd"] + "/native-probe.py"],
                               env={"LANG": "C.UTF-8"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False)
    if completed.returncode:
        return {"gate_passed": False, "native_exit_code": completed.returncode}
    for line in reversed(completed.stdout.splitlines()):
        try:
            result = json.loads(line)
            if "canaries" in result:
                return result
        except ValueError:
            continue
    return {"gate_passed": False, "native_result_missing": True}
