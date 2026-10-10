import json
from adf_runtime_worker.telemetry import attributes

def test_telemetry_attribute_allowlist_never_exports_private_job_fields():
    job = {"run_id": "safe-run", "execution_id": "safe-execution", "task_prompt": "sentinel-private-prompt", "project": {"repo_path": "/private/code"}, "agent": {"id": "safe-agent", "provider": "mock", "prompt": "secret code"}, "authorization": "sentinel-token", "tool_arguments": {"code": "private"}}
    result = attributes(job)
    rendered = json.dumps(result)
    assert "sentinel" not in rendered
    assert "/private" not in rendered
    assert "secret code" not in rendered
    assert result["langfuse.session.id"] == "safe-run"
    assert result["adf.telemetry.eligible"] is True
