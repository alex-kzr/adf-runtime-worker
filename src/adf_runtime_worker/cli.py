"""Version probes and safe offline mock; no real factory worker."""
import argparse
import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from uuid import uuid4
from adf_runtime_worker.adapters import MockAdapter, Request

def doctor() -> dict[str, object]:
    probes: dict[str, object] = {}
    for executable in ("git", "codex", "claude"):
        resolved = shutil.which(executable)
        if not resolved:
            probes[executable] = {"installed": False, "auth": "unknown"}
            continue
        try:
            env = {key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "SYSTEMROOT", "TEMP", "TMP"}}
            result = subprocess.run([resolved, "--version"], shell=False, capture_output=True, text=True, timeout=5, env=env)
            probes[executable] = {"installed": True, "version": result.stdout.strip()[:160], "exit_code": result.returncode, "auth": "unknown"}
        except (OSError, subprocess.TimeoutExpired):
            probes[executable] = {"installed": True, "version": "probe failed", "auth": "unknown"}
    linux = platform.system() == "Linux"
    return {"implementation": "scaffold", "linux": linux, "ext4_path_candidate": linux and not str(Path.cwd()).startswith('/mnt/'), "auth_verified": False, "providers": probes, "ready_for_real_execution": False}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    mock = sub.add_parser("mock")
    mock.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "doctor":
        print(json.dumps(doctor()))
        return
    body = json.loads(args.request.read_text(encoding="utf-8"))
    request = Request(body["execution_id"], body["run_id"], body["lease_epoch"])
    sequence = 0
    def sink(kind: str, payload: dict[str, str]) -> None:
        nonlocal sequence
        sequence += 1
        print(json.dumps({"schema_version": "1", "event_id": str(uuid4()), "run_id": request.run_id, "execution_id": request.execution_id, "lease_epoch": request.lease_epoch, "sequence": sequence, "type": kind, "time": datetime.now(timezone.utc).isoformat(), "trace_id": None, "payload": payload}))
    MockAdapter().execute(request, sink, Event())

if __name__ == "__main__":
    main()
