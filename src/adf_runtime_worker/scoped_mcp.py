"""ADF-owned, credential-free newline JSON-RPC stdio read-file MCP server.

Only this implementation binds adf.scoped-files.v1 filesystem scope. A generic
MCP declaration does not enforce another server's access to the host.
"""
from __future__ import annotations

import json
import os
import signal
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

from .capabilities import MCP_CONTRACT, MCP_TOOLS, validate_mcp_path
from .models import Json, WorkerError
from .security import Redactor, within_root

MAX_MESSAGE = 65536


@contextmanager
def tool_deadline(seconds: int) -> Iterator[None]:
    def expired(signum: int, frame: object) -> None:
        raise WorkerError("MCP_TIMEOUT", "Scoped tool deadline exhausted")
    old = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


class ScopedFiles:
    def __init__(self, config: Json) -> None:
        scope = config["scope"]
        self.root = Path(scope["root"])
        if scope.get("contract") != MCP_CONTRACT or self.root.resolve(strict=True) != self.root or self.root.is_symlink():
            raise WorkerError("INVALID_PATH", "Invalid scoped MCP root")
        self.paths = tuple(scope["read_paths"])
        self.tools = tuple(config["enabled_tools"])
        if not self.tools or set(self.tools) - MCP_TOOLS:
            raise WorkerError("PERMISSION_DENIED", "Tool outside owned contract")
        self.limit = int(scope["max_bytes"])
        self.timeout = int(config["tool_timeout_sec"])
        if not 1 <= self.limit <= MAX_MESSAGE or not 1 <= self.timeout <= 1800:
            raise WorkerError("INVALID_REQUEST", "Invalid scoped MCP quota")
        for path in self.paths:
            validate_mcp_path(path)
            within_root(self.root / path, self.root, must_exist=False)

    def catalog(self) -> list[Json]:
        # Expose the rejected tool in the server catalog to verify CLI enabled_tools filtering.
        return [{"name": tool, "description": "Read an approved bounded UTF-8 file in this worktree." if tool in MCP_TOOLS else "Forbidden canary: always rejected without side effects.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "additionalProperties": False, **({"required": ["path"]} if tool == "read_file" else {})}, "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}} for tool in ["read_file", "read_marker", "forbidden_tool"]]

    def call(self, name: str, arguments: object) -> Json:
        if name not in self.tools or not isinstance(arguments, dict) or set(arguments) - {"path"}:
            raise WorkerError("PERMISSION_DENIED", "Tool or input outside approved scope")
        path = arguments.get("path", self.paths[0] if name == "read_marker" and len(self.paths) == 1 else None)
        if not isinstance(path, str) or path not in self.paths:
            raise WorkerError("PERMISSION_DENIED", "File outside approved MCP read paths")
        validate_mcp_path(path)
        candidate = within_root(self.root / path, self.root)
        # Open each path component relative to held directory fds; no symlink race escapes.
        fd = os.open(self.root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in self.root.parts[1:]:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = following
        except BaseException:
            os.close(fd)
            raise
        try:
            for part in Path(path).parts[:-1]:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = following
            content_fd = os.open(candidate.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                metadata = os.fstat(content_fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > self.limit:
                    raise WorkerError("MCP_QUOTA_EXCEEDED", "Only bounded single-link regular files are readable")
                with tool_deadline(self.timeout):
                    data = os.read(content_fd, self.limit + 1)
                if len(data) > self.limit:
                    raise WorkerError("MCP_QUOTA_EXCEEDED", "MCP output exceeded its quota")
            finally:
                os.close(content_fd)
        finally:
            os.close(fd)
        return {"content": [{"type": "text", "text": Redactor().text(data.decode("utf-8"))}], "isError": False}

    def response(self, message: Json) -> Json | None:
        request_id = message.get("id")
        if request_id is None:
            return None
        method = message.get("method")
        try:
            if method == "initialize":
                result: Json = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "adf-scoped-files", "version": "1.0.0"}}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": self.catalog()}
            elif method == "tools/call":
                params = message.get("params", {})
                result = self.call(str(params.get("name")), params.get("arguments", {}))
            else:
                raise WorkerError("PERMISSION_DENIED", "Unsupported MCP method")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except (WorkerError, OSError, ValueError) as exc:
            code = exc.code if isinstance(exc, WorkerError) else "MCP_READ_DENIED"
            return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": code}], "isError": True}}


def serve(server: ScopedFiles, source: BinaryIO) -> None:
    while line := source.readline(MAX_MESSAGE + 1):
        if len(line) > MAX_MESSAGE:
            raise WorkerError("MCP_QUOTA_EXCEEDED", "MCP request exceeds quota")
        message = json.loads(line)
        if not isinstance(message, dict):
            raise WorkerError("INVALID_REQUEST", "MCP request must be an object")
        response = server.response(message)
        if response is not None:
            print(json.dumps(response), flush=True)


def main() -> None:
    if sys.platform != "linux" or len(sys.argv) != 3 or sys.argv[1] != "--config":
        raise SystemExit("Scoped MCP requires Linux and one owned configuration")
    config = Path(sys.argv[2])
    if config.is_symlink() or config.stat().st_size > MAX_MESSAGE:
        raise SystemExit("Invalid scoped configuration")
    serve(ScopedFiles(json.loads(config.read_bytes())), sys.stdin.buffer)


if __name__ == "__main__":
    main()
