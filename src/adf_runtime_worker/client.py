"""Scoped API facade with bounded retries and immutable mutation identities."""
from __future__ import annotations
import time
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse
import httpx
from .models import Json, WorkerError

class Ledger(Protocol):
    def claim(self, execution_id: str) -> Json: ...
    def heartbeat(self, execution_id: str, epoch: int, process: Json | None = None) -> Json: ...
    def control(self, execution_id: str, epoch: int) -> Json: ...
    def events(self, execution_id: str, epoch: int, events: list[Json]) -> Json: ...
    def result(self, execution_id: str, epoch: int, status: str, result: Json) -> Json: ...
    def reconcile(self, execution_id: str, epoch: int, evidence: Json) -> Json: ...
    def artifact(self, execution_id: str, epoch: int, kind: str, content: bytes, media_type: str = "application/json") -> Json: ...

class ApiClient(AbstractContextManager["ApiClient"]):
    def __init__(self, base_url: str, token_file: Path, worker_id: str, *, transport: httpx.BaseTransport | None = None) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.password:
            raise WorkerError("PERMISSION_DENIED", "Worker API requires configured loopback HTTP")
        token = token_file.read_text(encoding="utf-8").strip()
        if len(token) < 24:
            raise WorkerError("AUTH_REQUIRED", "Worker token file is missing or invalid")
        self.worker_id = worker_id
        self.redaction_values = (token,)
        self.client = httpx.Client(base_url=base_url.rstrip("/"), headers={"Authorization": "Bearer " + token}, timeout=httpx.Timeout(3.0), transport=transport, trust_env=False, follow_redirects=False)

    def __enter__(self) -> ApiClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.client.close()

    def request(self, method: str, path: str, body: Json | None = None) -> Json:
        started = time.monotonic()
        for attempt in range(3):
            try:
                response = self.client.request(method, path, json=body)
                if response.status_code in {429, 502, 503, 504} and attempt < 2 and time.monotonic() - started < 6:
                    time.sleep(0.1 * 2 ** attempt)
                    continue
                if response.is_error:
                    try:
                        code = str(response.json().get("code", "API_ERROR"))
                    except (ValueError, AttributeError):
                        code = "API_ERROR"
                    raise WorkerError(code, "Scoped API rejected worker operation")
                data = response.json()
                if not isinstance(data, dict):
                    raise WorkerError("INVALID_RESPONSE", "Internal API response must be an object")
                return data
            except httpx.TransportError as exc:
                if attempt == 2 or time.monotonic() - started >= 6:
                    raise WorkerError("BACKEND_UNAVAILABLE", "Internal API unavailable") from exc
                time.sleep(0.1 * 2 ** attempt)
        raise WorkerError("BACKEND_UNAVAILABLE", "Internal API unavailable")

    def register(self, root: Path, capabilities: Json, project_ids: list[str], allowed_roots: list[Path] | None = None) -> Json:
        return self.request("POST", "/internal/workers/register", {"worker_id": self.worker_id, "capabilities": capabilities, "allowed_roots": [str(path) for path in (allowed_roots or [root / "projects"])], "project_ids": project_ids})

    def worker_heartbeat(self, execution_ids: list[str]) -> Json:
        return self.request("POST", f"/internal/workers/{self.worker_id}/heartbeat", {"running_executions": execution_ids})

    def claim(self, execution_id: str) -> Json:
        return self.request("POST", f"/internal/executions/{execution_id}/claim", {"worker_id": self.worker_id})

    def heartbeat(self, execution_id: str, epoch: int, process: Json | None = None) -> Json:
        return self.request("POST", f"/internal/executions/{execution_id}/heartbeat", {"worker_id": self.worker_id, "epoch": epoch, "process_identity": process or {}})

    def control(self, execution_id: str, epoch: int) -> Json:
        return self.request("GET", f"/internal/executions/{execution_id}/control?worker_id={self.worker_id}&epoch={epoch}")

    def events(self, execution_id: str, epoch: int, events: list[Json]) -> Json:
        return self.request("POST", f"/internal/executions/{execution_id}/events", {"worker_id": self.worker_id, "epoch": epoch, "events": events})

    def result(self, execution_id: str, epoch: int, status: str, result: Json) -> Json:
        return self.request("POST", f"/internal/executions/{execution_id}/result", {"worker_id": self.worker_id, "epoch": epoch, "status": status, "result": result})

    def reconcile(self, execution_id: str, epoch: int, evidence: Json) -> Json:
        return self.request("POST", f"/internal/executions/{execution_id}/reconcile", {"worker_id": self.worker_id, "epoch": epoch, "process_stopped": True, "evidence": evidence})

    def artifact(self, execution_id: str, epoch: int, kind: str, content: bytes, media_type: str = "application/json") -> Json:
        import base64
        import hashlib
        from uuid import NAMESPACE_URL, uuid5
        if len(content) > 20971520:
            raise WorkerError("QUOTA_EXCEEDED", "Artifact exceeds upload limit")
        return self.request("POST", f"/internal/executions/{execution_id}/artifacts", {"worker_id": self.worker_id, "epoch": epoch, "artifact_id": str(uuid5(NAMESPACE_URL, execution_id + ":" + kind + ":" + hashlib.sha256(content).hexdigest())), "kind": kind, "media_type": media_type, "content_base64": base64.b64encode(content).decode(), "sha256": hashlib.sha256(content).hexdigest()})
