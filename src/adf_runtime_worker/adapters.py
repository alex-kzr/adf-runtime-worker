"""Typed adapter foundation. Only metadata-only mock is implemented."""
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event
from typing import Protocol

@dataclass(frozen=True)
class Request:
    execution_id: str
    run_id: str
    lease_epoch: int

@dataclass(frozen=True)
class Usage:
    source: str = "unknown"
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost: float | None = None

EventSink = Callable[[str, dict[str, str]], None]

class Adapter(Protocol):
    def probe(self) -> dict[str, str]: ...
    def execute(self, request: Request, event_sink: EventSink, cancellation: Event) -> str: ...
    def cancel(self) -> None: ...
    def collect_usage(self) -> Usage: ...

class MockAdapter:
    def probe(self) -> dict[str, str]:
        return {"provider": "mock", "health": "ready", "implementation": "offline metadata only"}
    def execute(self, request: Request, event_sink: EventSink, cancellation: Event) -> str:
        if cancellation.is_set():
            event_sink("cancelled", {"reason": "requested"})
            return "cancelled"
        event_sink("started", {"provider": "mock"})
        event_sink("completed", {"result": "mock only; no code or Git operation"})
        return "completed"
    def cancel(self) -> None:
        # Mock execution is immediate; caller cancellation is supplied via Event.
        pass
    def collect_usage(self) -> Usage:
        return Usage()
