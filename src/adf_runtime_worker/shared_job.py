"""Per-execution bridge. SIGTERM interrupts only its Codex thread."""
from __future__ import annotations

import argparse
import array
import json
import os
import signal
import socket
import sys
from pathlib import Path
from threading import Event

from .journal import Journal
from .models import WorkerError
from .shared_rpc import FRAME_LIMIT
from .shared_server import recv_frame, send_frame


def bridge(config: dict[str, object], prompt: str, lock_fd: int, journal_path: Path, cancellation: Event) -> int:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(30)
        root = Path(str(config["root"]))
        connection.connect(str(root / "providers" / "codex" / "server.sock"))
        send_frame(connection, {**config, "op": "job", "prompt": prompt})
        accepted = recv_frame(connection)
        if accepted.get("accepted") is not True:
            raise WorkerError("EXECUTION_UNCERTAIN", "Shared job was not accepted")
        Journal(journal_path).update(shared_session={"root": str(root), "execution_id": config["execution_id"], "generation": accepted["generation"]})
        connection.sendmsg([b"B"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [lock_fd]))])
        connection.settimeout(None)
        # Dedicated reader owns framing; main thread can still send cancellation.
        import queue
        import threading
        frames: queue.Queue[dict[str, object]] = queue.Queue(maxsize=128)
        def read() -> None:
            try:
                while True:
                    frame = recv_frame(connection)
                    frames.put(frame, timeout=1)
                    if frame.get("done"):
                        return
            except (OSError, ValueError, WorkerError, queue.Full):
                try:
                    frames.put({"done": True, "status": "uncertain"}, timeout=1)
                except queue.Full:
                    pass
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        sent_cancel = False
        try:
            while True:
                if cancellation.is_set() and not sent_cancel:
                    connection.sendall(b"C")
                    sent_cancel = True
                try:
                    frame = frames.get(timeout=0.1)
                except queue.Empty:
                    if not reader.is_alive():
                        return 1
                    continue
                if "event" in frame:
                    print(json.dumps(frame["event"], separators=(",", ":")), flush=True)
                if frame.get("done"):
                    if frame.get("status") != "succeeded":
                        print(json.dumps({"type": "error", "code": frame.get("code", "EXECUTION_UNCERTAIN")}), flush=True)
                    return 0 if frame.get("status") == "succeeded" and frame.get("quiesced") is True else 1
        finally:
            connection.shutdown(socket.SHUT_RDWR)
            reader.join(timeout=1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--lock-fd", type=int, required=True)
    args = parser.parse_args()
    cancellation = Event()
    signal.signal(signal.SIGTERM, lambda *_: cancellation.set())
    signal.signal(signal.SIGINT, lambda *_: cancellation.set())
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        prompt = sys.stdin.read(FRAME_LIMIT)
        if len(prompt.encode()) >= FRAME_LIMIT or os.name != "posix":
            raise WorkerError("QUOTA_EXCEEDED", "Shared prompt exceeds its quota")
        raise SystemExit(bridge(config, prompt, args.lock_fd, args.journal, cancellation))
    except (WorkerError, OSError, ValueError, KeyError, TypeError):
        print('{"type":"error","code":"EXECUTION_UNCERTAIN"}', flush=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
