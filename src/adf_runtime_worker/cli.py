"""CLI for diagnostics, offline execution and the WSL host worker."""
from __future__ import annotations
import argparse
import json
import os
import platform
import signal
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from uuid import uuid4
from .adapters import MockAdapter, Request, provider_adapter
from .executor import Executor
from .models import WorkerError
from .service import WorkerService
from .supervisor import supervise_ticket

def doctor(root: Path | None = None, provider_paths: dict[str, str] | None = None,
           provider_profiles: dict[str, str] | None = None) -> dict[str, object]:
    providers = {"mock": provider_adapter("mock").probe()}
    for name in ("codex", "claude"):
        directory = (provider_profiles or {}).get(name)
        if directory is None:
            # Diagnostics must never discover a different auth store implicitly.
            providers[name] = {"provider": name, "installed": None, "auth": "unknown", "health": "blocked",
                               "error_code": "PROFILE_REQUIRED", "probe_performed": False, "profile_directory": None}
            continue
        providers[name] = {**provider_adapter(name, (provider_paths or {}).get(name), Path(directory)).probe(),
                           "probe_performed": True, "profile_directory": directory, "login_per_job": False}
    linux = platform.system() == "Linux"
    root_ok = False
    error = None
    if root:
        from .security import canonical_root
        try:
            canonical_root(root)
            root_ok = True
        except WorkerError as exc:
            error = exc.code
    groups: list[str] = []
    if linux:
        import grp
        groups = sorted(grp.getgrgid(group).gr_name for group in os.getgroups())
    docker_socket = Path("/var/run/docker.sock")
    privilege = {"supplementary_groups": groups, "sudo_group_exposure": "sudo" in groups or "wheel" in groups, "docker_group_exposure": "docker" in groups, "docker_socket_accessible": docker_socket.exists() and os.access(docker_socket, os.R_OK | os.W_OK), "dedicated_account_verified": False}
    capabilities_available = linux and root_ok and any(item.get("health") == "ready" for name, item in providers.items() if name != "mock")
    return {"implementation": "supervised-host-runtime", "linux": linux, "root_validated": root_ok, "root_error": error, "providers": providers, "ready_for_real_execution": False, "execution_capabilities_available": capabilities_available, "privilege_diagnostics": privilege, "readiness_blockers": ["DEDICATED_WORKER_ACCOUNT_UNVERIFIED", "UMBRELLA_ACCEPTANCE_REQUIRED"], "process_unprivileged": linux and os.geteuid() != 0, "dedicated_account_verified": False, "minimal_privilege_verified": False, "mvp_acceptance": "requires umbrella end-to-end gates"}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    probe = sub.add_parser("doctor")
    probe.add_argument("--root", type=Path, default=Path(os.getenv("ADF_WORKER_ROOT", str(Path.home() / "ai-factory"))))
    probe.add_argument("--node", default=os.getenv("ADF_NODE_PATH", str(Path.home() / ".local" / "bin" / "node")))
    probe.add_argument("--codex", default=os.getenv("ADF_CODEX_PATH"))
    probe.add_argument("--claude", default=os.getenv("ADF_CLAUDE_PATH"))
    probe.add_argument("--codex-home", type=Path, help="Existing private Codex profile; omitted profiles are not probed")
    probe.add_argument("--claude-config-dir", type=Path, help="Existing private Claude profile; omitted profiles are not probed")
    mock = sub.add_parser("mock")
    mock.add_argument("--request", type=Path, required=True)
    execute = sub.add_parser("execute")
    execute.add_argument("--request", type=Path, required=True)
    execute.add_argument("--root", type=Path, required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--root", type=Path, default=Path(os.getenv("ADF_WORKER_ROOT", str(Path.home() / "ai-factory"))))
    serve.add_argument("--api-url", default=os.getenv("ADF_API_URL", "http://127.0.0.1:8080"))
    serve.add_argument("--token-file", type=Path, default=os.getenv("ADF_WORKER_TOKEN_FILE"))
    serve.add_argument("--redis-url", default=os.getenv("ADF_REDIS_URL", "redis://adf_worker@127.0.0.1:6380/0"))
    serve.add_argument("--redis-password-file", type=Path, default=os.getenv("ADF_REDIS_PASSWORD_FILE"))
    serve.add_argument("--project-root", type=Path, action="append", default=None)
    serve.add_argument("--max-parallel", type=int, default=3)
    serve.add_argument("--node", default=os.getenv("ADF_NODE_PATH", str(Path.home() / ".local" / "bin" / "node")))
    serve.add_argument("--codex", default=os.getenv("ADF_CODEX_PATH"))
    serve.add_argument("--claude", default=os.getenv("ADF_CLAUDE_PATH"))
    serve.add_argument("--codex-home", type=Path, help="Existing private persistent Codex profile; no login or credential copy")
    serve.add_argument("--claude-config-dir", type=Path, help="Existing private persistent Claude profile; no token generation")
    serve.add_argument("--codex-backend", choices=("subprocess", "shared", "shared-patch"), default="subprocess")
    serve.add_argument("--check-sandbox-manifest", type=Path, help="Separate private operator-pinned bubblewrap/toolchain manifest for shared-patch checks")
    serve.add_argument("--recovery-only", action="store_true", help="Reconcile existing owned executions only; no provider probes, new lease claims or supervisor starts")
    server = sub.add_parser("provider-server", help="Run one persistent pinned Codex app-server; no login")
    server.add_argument("--root", type=Path, required=True)
    server.add_argument("--codex", required=True)
    server.add_argument("--codex-home", type=Path, required=True)
    server.add_argument("--shared-profile-policy", type=Path, required=True, help="Private operator-only exact project trust manifest; no config writes")
    server.add_argument("--shared-native-read-policy", type=Path, required=True, help="Separate private operator-only native read-tool roots; no profile writes")
    server.add_argument("--node", default=os.getenv("ADF_NODE_PATH", str(Path.home() / ".local" / "bin" / "node")))
    supervise = sub.add_parser("supervise", help=argparse.SUPPRESS)
    supervise.add_argument("--ticket", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command in {"doctor", "serve", "provider-server"}:
            node = Path(args.node)
            if not node.is_absolute() or str(node.resolve()).startswith("/mnt/"):
                raise WorkerError("INVALID_PATH", "Node runtime must be an explicit Linux executable")
            os.environ["ADF_NODE_PATH"] = str(node)
        if args.command == "doctor":
            print(json.dumps(doctor(args.root,
                                    {key: value for key, value in {"codex": args.codex, "claude": args.claude}.items() if value},
                                    {key: str(value) for key, value in {"codex": args.codex_home,
                                                                      "claude": args.claude_config_dir}.items() if value})))
        elif args.command == "supervise":
            supervise_ticket(args.ticket)
        elif args.command == "provider-server":
            from .profiles import ProviderProfile
            from .security import canonical_root
            from .shared_server import SharedServer, server_command
            from .profile_policy import SealedProfilePolicy
            from .native_read_policy import NativeReadPolicy
            root = canonical_root(args.root)
            selected = ProviderProfile("codex", args.codex_home)
            selected.environment()
            policy = SealedProfilePolicy(root, args.codex_home, args.shared_profile_policy)
            native_policy = NativeReadPolicy(policy, args.shared_native_read_policy)
            argv, environment, profile = server_command(args.codex, selected, policy, native_policy)
            runtime = SharedServer(root, argv, environment, profile=profile, policy=policy, native_policy=native_policy)
            signal.signal(signal.SIGTERM, lambda *_: runtime.stopping.set())
            signal.signal(signal.SIGINT, lambda *_: runtime.stopping.set())
            runtime.run()
        elif args.command == "serve":
            if not args.token_file or not args.redis_password_file:
                raise WorkerError("AUTH_REQUIRED", "Separate worker token and Redis password files are required")
            checker = None
            if args.check_sandbox_manifest:
                from .profile_policy import private_bytes
                raw, _ = private_bytes(args.check_sandbox_manifest, limit=65536)
                checker = json.loads(raw)
            WorkerService(args.root, args.api_url, args.token_file, args.redis_url, args.redis_password_file, max_parallel=args.max_parallel, provider_paths={key: value for key, value in {"codex": args.codex, "claude": args.claude}.items() if value}, provider_profiles={key: str(value) for key, value in {"codex": args.codex_home, "claude": args.claude_config_dir}.items() if value}, codex_backend=args.codex_backend, project_roots=args.project_root, recovery_only=args.recovery_only, check_sandbox=checker).run()
        else:
            body = json.loads(args.request.read_text(encoding="utf-8"))
            sequence = 0
            def sink(kind: str, payload: dict[str, object]) -> None:
                nonlocal sequence
                sequence += 1
                print(json.dumps({"schema_version": "1", "event_id": str(uuid4()), "run_id": body["run_id"], "execution_id": body["execution_id"], "lease_epoch": body["lease_epoch"], "sequence": sequence, "type": kind, "time": datetime.now(timezone.utc).isoformat(), "trace_id": None, "payload": payload}), flush=True)
            if args.command == "mock":
                result = MockAdapter().execute(Request(body["execution_id"], body["run_id"], body["lease_epoch"]), sink, Event())
                print(json.dumps(asdict(result)))
            else:
                print(json.dumps(Executor(args.root).run(body, sink, Event())))
    except WorkerError as exc:
        print(json.dumps({"code": exc.code, "message": str(exc)}))
        raise SystemExit(1) from exc

if __name__ == "__main__":
    main()
