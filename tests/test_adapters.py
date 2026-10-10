import json
from dataclasses import replace
from pathlib import Path
import pytest
from adf_runtime_worker.adapters import JsonNormalizer, CodexAdapter, ClaudeAdapter, Request
from adf_runtime_worker.models import WorkerError

@pytest.mark.parametrize("provider,fixture", [("codex", "codex-0.157.0.jsonl"), ("claude", "claude-2.1.296.jsonl")])
def test_pinned_provider_fixture_contract(provider, fixture):
    events = []
    normalizer = JsonNormalizer(provider, lambda kind, data: events.append((kind, data)), 3)
    for line in (Path(__file__).parent / "fixtures" / fixture).read_text().splitlines():
        normalizer.line("stdout", line)
    assert normalizer.terminal
    assert not normalizer.failed
    assert normalizer.usage.source == "provider"
    assert normalizer.usage.cost is None
    assert json.loads(normalizer.final_text)["approved"] is True
    assert "tool_started" in [kind for kind, _ in events]
    assert "tool_finished" in [kind for kind, _ in events]
    assert "private repository content" not in json.dumps(events)
    assert "file_path" not in json.dumps(events)

def test_unknown_terminal_is_never_success_and_tools_are_bounded():
    normalizer = JsonNormalizer("codex", lambda *_: None, 1)
    normalizer.line("stdout", '{"type":"future-success"}')
    assert not normalizer.terminal
    event = '{"type":"item.started","item":{"type":"command_execution"}}'
    normalizer.line("stdout", event)
    with pytest.raises(WorkerError, match="limit"):
        normalizer.line("stdout", event)

def test_malformed_stream_and_error_fail_closed():
    normalizer = JsonNormalizer("codex", lambda *_: None, 3)
    with pytest.raises(WorkerError, match="JSONL"):
        normalizer.line("stdout", "not-json")
    normalizer.line("stdout", '{"type":"turn.failed","error":{"message":"private content"}}')
    assert normalizer.failed
    assert not normalizer.terminal

def test_cli_argv_never_bypasses_permissions_or_enables_api_fallback(tmp_path):
    request = Request("execution", "run", 1, workspace_path=tmp_path, permission_profile="trusted-development", allowed_tools=("Read", "Edit", "Write", "Bash(python -m unittest*)"))
    claude = ClaudeAdapter("/local/claude").argv(request, tmp_path)
    assert "--restricted" in claude
    assert "--safe-mode" in claude
    assert "--bare" not in claude
    assert "--strict-mcp-config" in claude
    assert "--permission-prompts" in claude
    assert "none" in claude
    assert all("dangerously" not in arg for arg in claude)
    assert "--max-budget-usd" not in claude
    codex = CodexAdapter("/local/codex").argv(replace(request, allowed_tools=()), tmp_path)
    assert "--ignore-user-config" in codex
    assert "--ignore-rules" in codex
    assert "workspace-write" in codex
    assert "never" in codex
    assert all("dangerously" not in arg for arg in codex)

def test_unscoped_claude_shell_is_rejected(tmp_path):
    with pytest.raises(WorkerError, match="Unscoped"):
        ClaudeAdapter("claude").argv(Request("execution", "run", 1, allowed_tools=("Bash",), permission_profile="trusted-development"), tmp_path)
