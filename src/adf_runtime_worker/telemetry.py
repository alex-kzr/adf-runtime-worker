"""Opt-in, metadata-only OTel. Export failures never block the control plane."""
from __future__ import annotations
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlparse
from opentelemetry import trace
from opentelemetry.propagate import extract
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.trace import Span, Status, StatusCode
from .models import Json

_ALLOWED_NAMES = {"agent.execution", "cli.session", "tool.call", "git.operation", "test.run"}
_IDS = ("project_id", "task_id", "run_id", "node_run_id", "execution_id", "agent_id", "provider")
_SAFE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_initialized = False

def configure() -> None:
    global _initialized
    if _initialized:
        return
    _initialized = True
    if os.getenv("ADF_TELEMETRY_ENABLED", "false").lower() != "true":
        return
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:4318/v1/traces")
    parsed = urlparse(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.password:
        return
    provider = TracerProvider(resource=Resource.create({"service.name": "adf-runtime-worker", "service.version": "0.1.0"}))
    exporter = OTLPSpanExporter(endpoint=endpoint, timeout=2, headers={})
    provider.add_span_processor(BatchSpanProcessor(exporter, max_queue_size=256, max_export_batch_size=32, schedule_delay_millis=1000, export_timeout_millis=2000))
    trace.set_tracer_provider(provider)

def attributes(job: Json, *, eligible: bool = True) -> dict[str, str | bool]:
    values: dict[str, str | bool] = {"adf.telemetry.eligible": eligible, "langfuse.trace.name": "workflow.run", "langfuse.observation.type": "agent"}
    source = {**job, "provider": job.get("agent", {}).get("provider", job.get("provider")), "agent_id": job.get("agent", {}).get("id", job.get("agent_id"))}
    for key in _IDS:
        item = source.get(key)
        if isinstance(item, str) and _SAFE.fullmatch(item):
            values[key] = item
            values["langfuse.trace.metadata." + key] = item
    if isinstance(values.get("run_id"), str):
        values["langfuse.session.id"] = values["run_id"]
    return values

@contextmanager
def span(name: str, job: Json) -> Iterator[Span]:
    configure()
    if name not in _ALLOWED_NAMES:
        raise ValueError("Unregistered telemetry span name")
    context = extract({"traceparent": str(job["traceparent"])}) if job.get("traceparent") else None
    with trace.get_tracer("adf-runtime-worker").start_as_current_span(name, context=context, attributes=attributes(job), record_exception=False, set_status_on_exception=False) as current:
        try:
            yield current
        except Exception:
            current.set_status(Status(StatusCode.ERROR))
            raise

def trace_id(current: Span) -> str | None:
    context = current.get_span_context()
    return format(context.trace_id, "032x") if context.is_valid else None
