"""Non-model native metadata/command probe for synthetic Unix IPC tests only.

The outer namespace mounts one synthetic test root and public system libraries.
It mounts no real HOME, /mnt, /run sockets, profiles or service configuration.
Optional WSL/Nix trees contain only locally generated synthetic canaries.
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


def synthetic_platform(root, *, nix_alias=True):
    """Expose WSL presence and the sole /run minimal root without host data."""
    platform = root / "native-platform"
    for relative in ("run/WSL/canary", "run/other/canary", "nix/store/adf-synthetic-system/canary"):
        path = platform / relative
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_text("ADF synthetic platform canary")
        path.chmod(0o600)
    sw = platform / "run/current-system/sw"
    sw.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if nix_alias:
        sw.symlink_to("/nix/store/adf-synthetic-system")
    else:
        sw.mkdir(mode=0o700)
        (sw / "canary").write_text("ADF synthetic platform canary")
    return [(name, path) for name, path in (
        ("wsl_interop", "/run/WSL/canary"), ("run_other", "/run/other/canary"),
        ("run_minimal", "/run/current-system/sw/canary"),
        ("nix_alias_target", "/nix/store/adf-synthetic-system/canary"),
        ("proc_self_run", "/proc/self/root/run/WSL/canary"))]

def command(params, *, owner_startup=False, profile_path=None, environment=None):
    root = Path(os.environ["ADF_TEST_NATIVE_ROOT"])
    cli = Path(os.environ["ADF_TEST_NATIVE_CODEX"])
    bwrap = cli.parent.parent / "codex-resources" / "bwrap"
    assert root.resolve() == root and cli.is_relative_to(root / "tools")
    profile = profile_path or root / "native-metadata-profile"
    profile.mkdir(mode=0o700, exist_ok=True)
    home = root / "native-metadata-home"
    home.mkdir(mode=0o700, exist_ok=True)
    outer = [str(bwrap), "--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", "--clearenv", "--cap-drop", "ALL"]
    # Mount private tmpfs first: a later /tmp mount would hide CI synthetic
    # workspaces (and public QA runtimes) located beneath /tmp.
    outer += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]  # noqa: S108
    for system in ("/usr/bin", "/usr/lib", "/usr/lib64"):
        outer += ["--ro-bind", system, system]
    # Public fresh QA venv + public interpreter only, for the owned stdio MCP.
    for public in sorted({Path(sys.executable).parent.parent, Path(sys.base_prefix)}):
        outer += ["--ro-bind", str(public), str(public)]
    for source, target in (("usr/bin", "/bin"), ("usr/lib", "/lib"), ("usr/lib64", "/lib64")):
        outer += ["--symlink", source, target]
    # Private namespace tmpfs only, never a shared host temp directory.
    platform = root / "native-platform"
    if platform.is_dir():
        # Public synthetic trees, never the host /run or /nix mounts.
        for name in ("run", "nix"):
            outer += ["--ro-bind", str(platform / name), "/" + name]
    outer += ["--bind", str(root), str(root), "--chdir", params["cwd"]]
    selected_environment = environment if environment is not None else {
        "HOME": str(home), "CODEX_HOME": str(profile), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
        "DISABLE_UPDATES": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    if environment is not None:
        from adf_runtime_worker.security import _SAFE_ENV
        assert set(environment) <= _SAFE_ENV | {"CODEX_HOME", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"}
        assert environment["CODEX_HOME"] == str(profile)
        assert Path(environment["HOME"]) in {root, root.parent, home}
    for key, value in selected_environment.items():
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


def late_run_probe(params):
    """Create host-side synthetic descendants only after native sandbox entry."""
    import selectors
    root = Path(os.environ["ADF_TEST_NATIVE_ROOT"])
    workspace = Path(params["cwd"])
    platform = root / "native-platform"
    assert platform.is_dir() and workspace.is_relative_to(root)
    paths = ["/run/late/deep/canary", "/run/current-system/late/canary", "/run/WSL/late/canary",
             "/run/late-alias/canary", str(workspace / "late-run-alias/canary")]
    program = """import json,pathlib,sys
print('{"ready":true}',flush=True)
assert sys.stdin.readline().strip()=='continue'
results={}
for path in json.loads(sys.argv[1]):
    try:
        pathlib.Path(path).read_bytes()
        results[path]=False
    except OSError:
        results[path]=True
inside=pathlib.Path('inside-canary').read_text()=='ADF synthetic project canary'
print(json.dumps({'late_reads_denied':all(results.values()),'cases':len(results),'inside_read':inside}))
"""
    process = subprocess.Popen(command(params) + ["sandbox", "--", "/usr/bin/python3", "-I", "-B", "-c", program, json.dumps(paths)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"LANG": "C.UTF-8"}, close_fds=True)
    try:
        with selectors.DefaultSelector() as streams:
            streams.register(process.stdout, selectors.EVENT_READ)
            assert streams.select(timeout=6), "Synthetic sandbox readiness timed out"
            assert os.read(process.stdout.fileno(), 512) == b'{"ready":true}\n'
        # These paths did not exist when config/mounts were built. Changing only
        # synthetic backing trees also tests the already-mounted outer RO view.
        for relative in ("run/late/deep/canary", "run/current-system/late/canary", "run/WSL/late/canary"):
            path = platform / relative
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            path.write_text("ADF synthetic late canary")
            path.chmod(0o600)
        (platform / "run/late-alias").symlink_to("/run/late/deep")
        (workspace / "late-run-alias").symlink_to("/run/late/deep")
        output, _ = process.communicate(input=b"continue\n", timeout=6)
        assert process.returncode == 0
        return json.loads(output)
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


# An unproved owner shutdown must keep its skills and allocation locks alive.
# Failed canaries retain this evidence until the test process itself exits.
RETAINED_METADATA_RESOURCES = []


class PersistentMetadataOwner:
    """Actual production argv/cwd, empty profile, one owner; no native turns."""
    def __init__(self, argv, root, profile, *, cleanup_timeout=3, environment=None):
        from adf_runtime_worker.shared_rpc import Rpc
        directory = root / "providers" / "codex"
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        outer = command({"cwd": str(directory), "config": {}}, profile_path=profile, environment=environment)
        if environment is None:
            assert outer[-1] == argv[0]
        else:
            executable = Path(argv[0])
            assert executable.is_relative_to(root / "tools") and executable.resolve().is_relative_to(root / "tools")
        self.methods = []
        self.lock = threading.Lock()
        self.close_lock = threading.Lock()
        self.cleanup_timeout = cleanup_timeout
        self.rpc = None
        self.process = subprocess.Popen(outer[:-1] + argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env={"LANG": "C.UTF-8"}, close_fds=True)
        try:
            self.rpc = Rpc(self.process)
            self.call("initialize", {"clientInfo": {"name": "adf-worker", "version": "0.1.0"},
                                     "capabilities": {"experimentalApi": True}})
            self.rpc.send({"method": "initialized", "params": {}})
        except BaseException:
            self.close()
            raise

    def call(self, method, params):
        # Never accept a model turn, authentication or arbitrary RPC method.
        assert method in {"initialize", "model/list", "thread/start", "thread/unsubscribe", "skills/list", "mcpServerStatus/list"}
        with self.lock:
            self.methods.append(method)
        return self.rpc.call(method, params, timeout=12)

    def metadata(self, params):
        thread_id = ""
        try:
            schemas = json.loads((Path(__file__).parent / "codex-0.157.0-native-read-schema.json").read_text())["schemas"]
            jsonschema.validate(params, schemas["ThreadStartParams"])
            result = self.call("thread/start", params)
            thread_id = result["thread"]["id"]
            events = self.rpc.subscribe(thread_id)
            jsonschema.validate(result, schemas["ThreadStartResponse"])
            catalog = self.call("mcpServerStatus/list", {"threadId": thread_id, "detail": "full"})
            skills = self.call("skills/list", {"cwds": [params["cwd"]], "forceReload": True})
            summary = {"cwd": params["cwd"], "schema_validated": True,
                       "mcp_servers": sorted(item["name"] for item in catalog["data"]),
                       "mcp_tools": sorted(tool["name"] for item in catalog["data"] for tool in item["tools"].values()),
                       "skill_catalog": [{"path": item["path"], "enabled": item["enabled"]}
                                         for entry in skills["data"] for item in entry["skills"]]}
            acknowledgement = self.call("thread/unsubscribe", {"threadId": thread_id})
            if acknowledgement.get("status") != "unsubscribed":
                raise RuntimeError("Synthetic persistent metadata unsubscribe was not acknowledged")
            until = time.monotonic() + self.cleanup_timeout
            while time.monotonic() < until and not self.rpc.failed.is_set():
                try:
                    event = events.get(timeout=min(0.1, max(0.001, until - time.monotonic())))
                except queue.Empty:
                    continue
                if event.get("method") == "thread/closed" and event.get("params", {}).get("threadId") == thread_id:
                    summary["quiescence_proof"] = "thread_closed"
                    return result, summary
            raise RuntimeError("Synthetic persistent metadata thread closure was not proved")
        except jsonschema.ValidationError:
            self.close()
            raise RuntimeError("Synthetic persistent metadata schema validation failed") from None
        except BaseException:
            # An uncertain start/unsubscribe or failed metadata read may leave
            # native threads/MCP alive. Terminate the whole owner before unwind.
            self.close()
            raise
        finally:
            if thread_id and self.rpc is not None:
                self.rpc.forget(thread_id)

    def close(self):
        # Metadata failures may close the shared owner from parallel callers.
        with self.close_lock:
            try:
                if self.process.poll() is None:
                    self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
                if self.rpc is not None:
                    self.rpc.reader.join(timeout=3)
                    if self.rpc.reader.is_alive():
                        raise RuntimeError("Synthetic persistent metadata owner shutdown was not proved")
                for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                    if stream is not None:
                        stream.close()
            except (OSError, ValueError, subprocess.TimeoutExpired):
                raise RuntimeError("Synthetic persistent metadata owner shutdown was not proved") from None
