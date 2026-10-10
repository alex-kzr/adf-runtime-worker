"""Immutable execution snapshots shared by adapters and the host supervisor."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any, Protocol

Json = dict[str, Any]
EventSink = Callable[[str, Json], None]

class WorkerError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)

@dataclass(frozen=True)
class Usage:
    source: str = "unknown"
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost: float | None = None
    provider_estimated_cost_usd: float | None = None

@dataclass(frozen=True)
class SkillSnapshot:
    name: str
    sha256: str
    content: str = field(repr=False)

@dataclass(frozen=True)
class Request:
    execution_id: str
    run_id: str
    lease_epoch: int
    workspace_path: Path | None = None
    task_prompt: str = ""
    timeout_sec: int = 1800
    max_steps: int = 1000
    max_output_bytes: int = 20 * 1024 * 1024
    max_disk_bytes: int = 5 * 1024 * 1024 * 1024
    allowed_tools: tuple[str, ...] = ()
    env_allowlist: tuple[str, ...] = ()
    permission_profile: str = "read_only"
    model: str | None = None
    cli_version: str | None = None
    mcp_config: Json = field(default_factory=dict)
    structured_schema: Json | None = None
    journal_path: Path | None = None
    lease_deadline: Callable[[], float] | None = None
    lock_fd: int | None = None
    correlation: Json = field(default_factory=dict)
    wall_deadline: float | None = None
    redaction_values: tuple[str, ...] = field(default=(), repr=False)
    approved_skills: tuple[SkillSnapshot, ...] = ()
    native_skill_config: Json = field(default_factory=dict)

@dataclass(frozen=True)
class AdapterResult:
    status: str
    exit_code: int | None
    output: str = ""
    error_code: str | None = None
    usage: Usage = field(default_factory=Usage)
    process_stopped: bool = True
    process_identity: Json = field(default_factory=dict)

class Adapter(Protocol):
    def probe(self) -> Json: ...
    def execute(self, request: Request, event_sink: EventSink, cancellation: Event) -> AdapterResult: ...
    def cancel(self) -> None: ...
    def collect_usage(self) -> Usage: ...
