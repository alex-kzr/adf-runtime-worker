"""Read-only shared generation; success is not host patch application."""
from __future__ import annotations

from dataclasses import replace
from threading import Event

from .journal import Journal
from .models import AdapterResult, EventSink, Json, Request, WorkerError
from .patches import PATCH_SCHEMA
from .shared_adapter import SharedCodexAdapter


class SharedPatchAdapter(SharedCodexAdapter):
    def execute(self, request: Request, event_sink: EventSink, cancellation: Event) -> AdapterResult:
        if request.permission_profile != "trusted-development" or request.structured_schema != PATCH_SCHEMA:
            raise WorkerError("PERMISSION_DENIED", "Patch generation needs the original bounded developer request")
        # The writer keeps the original authorization. Only the native stage is
        # observe/read-only; this adapter never writes project files.
        native = replace(request, permission_profile="observe")
        def bounded_event(kind: str, payload: Json) -> None:
            # Preserve the normalizer's full private structured result while
            # fitting the existing 64KiB API event boundary after JSON escaping.
            if kind == "output" and isinstance(payload.get("text"), str):
                payload = {**payload, "text": payload["text"][:4096], "truncated": len(payload["text"]) > 4096}
            event_sink(kind, payload)
        result = super().execute(native, bounded_event, cancellation)
        if result.status == "succeeded":
            if not result.process_stopped or request.journal_path is None:
                raise WorkerError("EXECUTION_UNCERTAIN", "Patch generation has no stopped durable native proof")
            Journal(request.journal_path).update(phase="patch_generated", patch_generation={"complete": True, "native_permission": "observe"})
        return result
