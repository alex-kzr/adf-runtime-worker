"""RPC outcome distinctions, bounded wakeups and private-payload exclusion."""
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from adf_runtime_worker.shared_rpc import Rpc, RpcError
from adf_runtime_worker.models import WorkerError

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux nonblocking pipes")


@pytest.fixture
def rpc():
    running = []
    def start(reply):
        program = "import json,sys,time\nfor line in sys.stdin:\n request=json.loads(line)\n " + reply
        process = subprocess.Popen([sys.executable, "-I", "-u", "-c", program], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        runtime = Rpc(process)
        running.append((runtime, process))
        return runtime
    yield start
    for runtime, process in running:
        process.terminate()
        process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        runtime.reader.join(timeout=3)


@pytest.mark.parametrize(("reply", "outcome", "numeric"), [
    ('print(json.dumps({"id":request["id"],"error":{"code":-32602,"message":"PRIVATE_SYNTHETIC_SECRET","data":{"token":"PRIVATE_SYNTHETIC_SECRET"}}}),flush=True)', "provider_error", -32602),
    ('print(json.dumps({"id":request["id"],"error":{"code":-1,"message":"PRIVATE_SYNTHETIC_SECRET"}}),flush=True)', "provider_error", None),
    ('print(json.dumps({"id":request["id"],"error":{"code":True,"message":"PRIVATE_SYNTHETIC_SECRET"}}),flush=True)', "malformed_response", None),
    ('print(json.dumps({"id":request["id"],"error":{"code":-32602}}),flush=True)', "malformed_response", None),
    ('print(json.dumps({"id":request["id"],"result":["PRIVATE_SYNTHETIC_SECRET"]}),flush=True)', "malformed_response", None),
    ('print(json.dumps({"id":request["id"],"result":{"thread":{"id":42}}}),flush=True)', "malformed_response", None),
    ('print("PRIVATE_SYNTHETIC_SECRET",flush=True)', "malformed_response", None),
    ('sys.exit(0)', "transport_closed", None),
    ('time.sleep(0.2)', "response_timeout", None),
])
def test_rpc_keeps_safe_outcome_without_error_payload(rpc, reply, outcome, numeric):
    runtime = rpc(reply)
    with pytest.raises(RpcError) as caught:
        runtime.call("thread/start", {}, timeout=0.1 if outcome == "response_timeout" else 2)
    error = caught.value
    receipt = error.receipt()
    assert receipt["method"] == "thread/start" and receipt["outcome"] == outcome
    assert receipt["provider_error_code"] == numeric and 0 <= receipt["elapsed_ms"] <= 86_400_000
    assert "PRIVATE_SYNTHETIC_SECRET" not in str(error) + repr(error) + json.dumps(receipt)
    assert not runtime.pending


def test_rpc_closed_stream_wakes_every_pending_request(rpc):
    runtime = rpc('sys.exit(0)')
    def call():
        try:
            runtime.call("skills/list", {}, timeout=1)
        except RpcError as error:
            return error.receipt()
        pytest.fail("Closed stream was treated as success")
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: call(), range(3)))
    assert all(row["outcome"] in {"transport_closed", "write_uncertain"} for row in results)
    assert all(row["elapsed_ms"] < 1000 for row in results)
    assert not runtime.pending


def test_rpc_unknown_method_and_numeric_code_cannot_exfiltrate():
    receipt = RpcError("PRIVATE_SYNTHETIC_SECRET", "provider_error", 12, 123456789).receipt()
    assert receipt == {"method": "other", "outcome": "provider_error", "elapsed_ms": 12, "provider_error_code": None}


def test_rpc_write_failure_is_unknown_and_never_logs_original_exception(rpc, monkeypatch):
    runtime = rpc('time.sleep(0.1)')
    def fail_write(_):
        raise WorkerError("EXECUTION_UNCERTAIN", "PRIVATE_SYNTHETIC_SECRET")
    monkeypatch.setattr(runtime, "send", fail_write)
    with pytest.raises(RpcError) as caught:
        runtime.call("thread/start", {})
    assert caught.value.code == "EXECUTION_UNCERTAIN"
    assert caught.value.receipt()["outcome"] == "write_uncertain"
    assert "PRIVATE_SYNTHETIC_SECRET" not in str(caught.value) + json.dumps(caught.value.receipt())
    assert caught.value.__suppress_context__ is True and not runtime.pending
