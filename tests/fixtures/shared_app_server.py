"""Offline wire double for the pinned 0.157 public protocol; never a model."""
import json
import os
import sys
import threading
from pathlib import Path

lock = threading.Lock()
threads = {}
turns = {}
capture = Path(sys.argv[1])
mode = sys.argv[2]


def send(value):
    with lock:
        print(json.dumps(value), flush=True)


def notify(method, params):
    send({"method": method, "params": params})


def complete(thread_id, turn_id, cancelled):
    if mode == "revoked":
        notify("turn/completed", {"threadId": thread_id, "turn": {"id": turn_id, "status": "failed",
                                 "error": {"codexErrorInfo": "unauthorized", "message": "AUTH_SECRET_MUST_NEVER_ESCAPE"}}})
        return
    if not cancelled.is_set():
        notify("item/completed", {"threadId": thread_id, "turnId": turn_id,
                                 "item": {"type": "reasoning", "text": "private reasoning"}})
        notify("item/completed", {"threadId": thread_id, "turnId": turn_id,
                                 "item": {"type": "agentMessage", "text": threads[thread_id]["cwd"], "id": "answer"}})
    notify("thread/tokenUsage/updated", {"threadId": thread_id, "turnId": turn_id,
                                         "tokenUsage": {"last": {"inputTokens": 4, "outputTokens": 2}}})
    notify("turn/completed", {"threadId": thread_id, "turn": {"id": turn_id, "error": None, "status": "interrupted" if cancelled.is_set() else "completed"}})


for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    params = message.get("params", {})
    with capture.open("a") as stream:
        stream.write(json.dumps({"method": method, "params": params, "pid": os.getpid(),
                                "environment": {name: os.environ.get(name) for name in ("HOME", "PATH", "CODEX_HOME")},
                                "environment_names": sorted(os.environ)}) + "\n")
    if "id" not in message:
        continue
    result = {}
    if method == "account/read":
        if mode == "expired":
            send({"id": message["id"], "error": {"code": -1, "message": "AUTH_SECRET_MUST_NEVER_ESCAPE"}})
            continue
        result = {"account": None if mode == "missing" else {"type": "chatgpt"}, "requiresOpenaiAuth": True}
    elif method == "thread/start":
        thread_id = "thread-" + str(len(threads) + 1)
        threads[thread_id] = params
        result = {"thread": {"id": thread_id}}
    elif method == "turn/start":
        thread_id = params["threadId"]
        turn_id = "turn-" + thread_id
        cancelled = threading.Event()
        turns[thread_id] = cancelled
        result = {"turn": {"id": turn_id, "status": "inProgress"}}
        send({"id": message["id"], "result": result})
        if mode == "crash":
            os._exit(13)
        def run(thread_id=thread_id, turn_id=turn_id, cancelled=cancelled):
            cancelled.wait(3 if mode in {"slow", "slow-no-close"} else 0.6)
            complete(thread_id, turn_id, cancelled)
        threading.Thread(target=run, daemon=True).start()
        continue
    elif method == "turn/interrupt":
        turns[params["threadId"]].set()
    elif method == "thread/unsubscribe":
        send({"id": message["id"], "result": {"status": "unsubscribed"}})
        if mode not in {"no-close", "slow-no-close"}:
            notify("thread/closed", {"threadId": params["threadId"]})
        continue
    send({"id": message["id"], "result": result})
