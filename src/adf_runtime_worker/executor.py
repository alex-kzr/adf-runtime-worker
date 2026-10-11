"""Registered runtime operations; models never own Git commits or approval."""
from __future__ import annotations

import json
import shutil
import sys
import time
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Any, cast
from .adapters import provider_adapter
from .capabilities import scoped_mcp, skill_snapshot
from .git_workspace import GitWorkspaceManager, Workspace
from .models import EventSink, Json, Request, WorkerError
from .process import ProcessRunner, disk_bytes
from .security import Redactor, validate_relative, within_root

_PLAN_SCHEMA: Json = {"type": "object", "additionalProperties": False, "properties": {"tasks": {"type": "array", "minItems": 1, "maxItems": 12, "items": {"type": "object", "additionalProperties": False, "properties": {"id": {"type": "string"}, "title": {"type": "string"}, "description": {"type": "string"}, "acceptance_criteria": {"type": "array", "items": {"type": "string"}}, "expected_files": {"type": "array", "items": {"type": "string"}}, "dependency_ids": {"type": "array", "items": {"type": "string"}}}, "required": ["id", "title", "description", "acceptance_criteria", "expected_files", "dependency_ids"]}}, "unknowns": {"type": "array", "items": {"type": "string"}}}, "required": ["tasks", "unknowns"]}
_REVIEW_SCHEMA: Json = {"type": "object", "additionalProperties": False, "properties": {"approved": {"type": "boolean"}, "findings": {"type": "array", "items": {"type": "string"}}}, "required": ["approved", "findings"]}

class Executor:
    def __init__(self, root: Path, *, require_ext4: bool = True, provider_paths: dict[str, str] | None = None) -> None:
        self.workspaces = GitWorkspaceManager(root, require_ext4=require_ext4)
        self.provider_paths = provider_paths or {}
        self.execution_deadline = float("inf")
        self.secret_values: tuple[str, ...] = ()

    def _request(self, job: Json, workspace: Workspace, lock_fd: int | None, deadline: Any) -> Request:
        agent = job.get("agent", {})
        operation = job["operation"]
        profile = agent.get("permission_profile", "observe")
        if operation in {"review", "planner"}:
            profile = "observe"
        prompt = str(job.get("task_prompt", ""))
        skills = tuple(skill_snapshot(item, self.workspaces.root, self.secret_values) for item in agent.get("skills", []))
        if len({skill.name for skill in skills}) != len(skills):
            raise WorkerError("INVALID_REQUEST", "Approved skill names must be unique")
        mcp: Json = {}
        for item in agent.get("mcp_servers", []):
            name, config = scoped_mcp(item, workspace.path, max(1, int(self.execution_deadline - time.monotonic())))
            if name in mcp:
                raise WorkerError("INVALID_REQUEST", "MCP server names must be unique")
            mcp[name] = config
        provider = agent.get("provider", "mock")
        mapped_tools: list[str] = []
        for item in agent.get("tools", []):
            manifest = item.get("manifest", item)
            mappings = manifest.get("provider_mappings", {})
            selected = mappings.get(provider)
            if not isinstance(selected, list) or any(not isinstance(tool, str) for tool in selected):
                raise WorkerError("CAPABILITY_UNSUPPORTED", "Tool registry needs verified provider mappings")
            if profile != "trusted-development" and manifest.get("permission") != "read":
                raise WorkerError("PERMISSION_DENIED", "Read-only role cannot inherit write/check tools")
            if provider == "codex" and manifest.get("permission") != "read":
                raise WorkerError("PERMISSION_DENIED", "Codex MCP registry requires read permission")
            mapped_tools.extend(selected)
        if provider in {"codex", "claude"}:
            for name, config in mcp.items():
                names = {"mcp__" + name + "__" + tool for tool in config["enabled_tools"]}
                if agent.get("tools"):
                    selected = names.intersection(mapped_tools)
                    # A typed MCP registry narrows a server's approved catalog; never broadens it.
                    config["enabled_tools"] = [tool for tool in config["enabled_tools"] if "mcp__" + name + "__" + tool in selected]
                    if not config["enabled_tools"]:
                        raise WorkerError("PERMISSION_DENIED", "Assigned MCP has no selected registry tools")
                else:
                    mapped_tools.extend(sorted(names))
            if provider == "codex" and any(tool not in {"mcp__" + name + "__" + tool for name, config in mcp.items() for tool in config["enabled_tools"]} for tool in mapped_tools):
                raise WorkerError("CAPABILITY_UNSUPPORTED", "Codex narrow registry supports only assigned scoped MCP tools")
        provider_tools = mapped_tools if agent.get("tools") or agent.get("mcp_servers") else agent.get("allowed_tools", [])
        schema = _PLAN_SCHEMA if operation == "planner" else _REVIEW_SCHEMA if operation == "review" else None
        if schema:
            prompt += "\nReturn only JSON matching this schema: " + json.dumps(schema)
        trusted = "Work only in this allocated task snapshot. Do not commit, push, merge, alter Git refs, read credentials, or modify execution configuration. The worker performs registered checks and Git operations separately.\n"
        prompt = str(job.get("task_prompt", "")) if agent.get("provider") == "mock" else trusted + str(agent.get("prompt", "")) + "\n" + ("\n".join(skill.content for skill in skills) if agent.get("provider") != "codex" else "") + "\n" + prompt
        return Request(str(job["execution_id"]), str(job["run_id"]), int(job["lease_epoch"]), workspace.path, prompt, max(1, min(1800, int(job.get("timeout_sec", 1800)), int(self.execution_deadline - time.monotonic()))), min(1000, int(job.get("max_steps", 1000))), min(20971520, int(job.get("max_output_bytes", 20971520))), min(5368709120, int(job.get("max_disk_bytes", 5368709120))), tuple(provider_tools), tuple(job.get("env_allowlist", [])), profile, agent.get("model"), agent.get("cli_version"), mcp, schema, self.workspaces.journal_for(str(job["execution_id"])).path, deadline, lock_fd, {key: job[key] for key in ("project_id", "task_id", "run_id", "node_run_id", "execution_id") if key in job}, self.execution_deadline, self.secret_values, skills)

    def run(self, job: Json, sink: EventSink, cancellation: Event, *, lease_deadline: Any = None) -> Json:
        from .telemetry import span, trace_id
        operation = job["operation"]
        self.execution_deadline = time.monotonic() + min(1800, int(job.get("timeout_sec", 1800)))
        if job.get("deadline_at"):
            expires = datetime.fromisoformat(str(job["deadline_at"]).replace("Z", "+00:00"))
            remaining = (expires - datetime.now(timezone.utc)).total_seconds()
            self.execution_deadline = min(self.execution_deadline, time.monotonic() + remaining)
        self.workspaces.execution_journal = self.workspaces.journal_for(str(job["execution_id"]))
        def guard() -> None:
            if time.monotonic() >= self.execution_deadline:
                raise WorkerError("EXECUTION_TIMEOUT", "Authoritative execution deadline exhausted")
            if cancellation.is_set():
                raise WorkerError("CANCEL_REQUESTED", "Cancellation prevents further Git operations")
            if lease_deadline and time.monotonic() >= lease_deadline() - 5:
                raise WorkerError("LEASE_LOST", "Lease prevents further Git operations")
        self.workspaces.control_guard = guard
        name = "test.run" if operation == "test" else "git.operation" if operation in {"repo_inspect", "git_commit", "integrate"} else "agent.execution"
        with span(name, job) as current:
            try:
                result = self._run(job, sink, cancellation, lease_deadline=lease_deadline)
                result["trace_id"] = trace_id(current)
                return result
            finally:
                self.workspaces.worktree_lock_fd = None

    def _run(self, job: Json, sink: EventSink, cancellation: Event, *, lease_deadline: Any = None) -> Json:
        operation = job["operation"]
        if operation == "repo_inspect":
            repo = self.workspaces.validate_repo(job["project"])
            branch = str(job["project"].get("default_branch", "main"))
            if branch.startswith("-") or ".." in branch or any(char.isspace() for char in branch):
                raise WorkerError("INVALID_REQUEST", "Invalid default branch")
            sha = self.workspaces.git(repo, "rev-parse", "refs/heads/" + branch + "^{commit}")
            return {"status": "succeeded", "root_base_sha": sha, "default_branch": branch, "dirty_base": bool(self.workspaces.git(repo, "status", "--porcelain")), "process_stopped": True}
        if operation not in {"planner", "agent_task", "test", "review", "git_commit", "integrate"}:
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Unregistered runtime operation")
        policy = job.get("policy", {})
        if operation != "planner" and (not policy.get("approved") or not policy.get("trusted_repository", job.get("project", {}).get("trusted", False))):
            raise WorkerError("PERMISSION_DENIED", "Execution requires approved trusted-repository policy")
        target_id = str(job.get("target_execution_id") or job["execution_id"])
        self.workspaces.validate_repo(job["project"])
        with self.workspaces.worktree_lock(target_id) as lock:
            self.workspaces.worktree_lock_fd = lock.fd
            workspace = self.workspaces.load(target_id) if job.get("target_execution_id") else self.workspaces.allocate(job)
            saved = workspace.journal.read()
            if saved.get("run_id") != job["run_id"] or saved.get("project_id") != job["project_id"]:
                raise WorkerError("PERMISSION_DENIED", "Target allocation belongs to another run/project")
            request = self._request(job, workspace, lock.fd, lease_deadline)
            allowed_paths = job.get("allowed_write_paths", job.get("expected_files", policy.get("allowed_write_paths", [])))
            if operation == "agent_task" and job.get("repair_source_execution_id"):
                self._repair_snapshot(job, workspace, allowed_paths)
                if job.get("agent", {}).get("provider") != "mock":
                    request = replace(request, task_prompt=request.task_prompt + "\nRepair feedback: " + Redactor().text(str(job.get("repair_feedback", "")))[:8192])
            before_head = self.workspaces.git(workspace.path, "rev-parse", "HEAD")
            evidence: Json = {"branch": workspace.branch, "base_sha": workspace.base_sha, "root_base_sha": workspace.root_base_sha, "worktree_key": target_id, "workspace_path": str(workspace.path), "process_stopped": True}
            if cancellation.is_set():
                return {**evidence, "status": "cancelled", "error_code": "CANCEL_REQUESTED"}
            if operation in {"agent_task", "planner", "review"}:
                if operation == "review":
                    prior = workspace.journal.read()
                    changes = self.workspaces.changes(workspace, allowed_paths)
                    developer = prior.get("developer_id")
                    reviewer = job.get("agent", {}).get("agent_id", job.get("agent", {}).get("id"))
                    if not developer or not reviewer or developer == reviewer:
                        raise WorkerError("REVIEW_REQUIRED", "Reviewer must be independent of developer")
                    checks = prior.get("test_results", [])
                    if not checks or any(check.get("status") != "passed" or check.get("tree_sha") != changes["tree_sha"] for check in checks):
                        raise WorkerError("TEST_REQUIRED", "Review requires passing exact-tree checks")
                    if job.get("agent", {}).get("provider") != "mock":
                        request = replace(request, task_prompt=request.task_prompt + "\nReview staged changes, criteria and tests independently. Tree: " + changes["tree_sha"] + "\nChecks: " + json.dumps(checks))
                elif operation == "agent_task":
                    workspace.journal.update(developer_id=job.get("agent", {}).get("agent_id", job.get("agent", {}).get("id")), developer_config_version_id=job.get("agent", {}).get("config_version_id"), allowed_write_paths=allowed_paths)
                provider = job.get("agent", {}).get("provider", "mock")
                adapter = provider_adapter(provider, self.provider_paths.get(provider))
                outcome = adapter.execute(request, sink, cancellation)
                evidence.update(status=outcome.status, exit_code=outcome.exit_code, error_code=outcome.error_code, process_identity=outcome.process_identity, process_stopped=outcome.process_stopped, usage=asdict(outcome.usage))
                if self.workspaces.git(workspace.path, "rev-parse", "HEAD") != before_head:
                    raise WorkerError("PERMISSION_DENIED", "Agent changed Git HEAD; preserved for inspection")
                if outcome.status != "succeeded":
                    return evidence
                if operation == "agent_task":
                    evidence.update(self.workspaces.changes(workspace, allowed_paths))
                    workspace.journal.update(development_result=evidence)
                else:
                    import jsonschema
                    try:
                        parsed = json.loads(outcome.output)
                        jsonschema.validate(parsed, _PLAN_SCHEMA if operation == "planner" else _REVIEW_SCHEMA)
                    except (ValueError, jsonschema.ValidationError) as exc:
                        raise WorkerError("INVALID_PROVIDER_RESULT", "Provider structured result failed schema") from exc
                    if operation == "planner":
                        self._validate_plan(parsed)
                        if self.workspaces.git(workspace.path, "status", "--porcelain"):
                            raise WorkerError("PERMISSION_DENIED", "Planner modified its read-only snapshot")
                        evidence["plan"] = parsed
                    else:
                        after = self.workspaces.changes(workspace, allowed_paths)
                        if after["tree_sha"] != changes["tree_sha"]:
                            raise WorkerError("PERMISSION_DENIED", "Reviewer modified the reviewed tree")
                        review = {**parsed, "tree_sha": changes["tree_sha"], "reviewer_id": reviewer, "developer_id": developer, "reviewer_config_version_id": job.get("agent", {}).get("config_version_id"), "developer_config_version_id": prior.get("developer_config_version_id")}
                        evidence.update(after, review=review)
                        workspace.journal.update(review=review)
                        if not review["approved"]:
                            evidence.update(status="failed", error_code="REVIEW_REJECTED")
            elif operation == "test":
                changes = self.workspaces.changes(workspace, allowed_paths)
                checks = self._checks(job, workspace, request, cancellation, sink, changes["tree_sha"])
                after = self.workspaces.changes(workspace, allowed_paths)
                if after["tree_sha"] != changes["tree_sha"]:
                    raise WorkerError("TEST_TREE_CHANGED", "Check changed the reviewed tree")
                evidence.update(after, test_results=checks, status="succeeded" if checks and all(check["status"] == "passed" for check in checks) else "failed")
                workspace.journal.update(test_results=checks)
            elif operation == "git_commit":
                # Trusted journal evidence wins over a caller-supplied review/test claim.
                prior = workspace.journal.read()
                trusted_job = {**job, "review": prior.get("review", {}), "test_results": prior.get("test_results", [])}
                if lease_deadline and time.monotonic() >= lease_deadline() - 5:
                    raise WorkerError("LEASE_STALE", "Lease safety margin exhausted before Git commit")
                if cancellation.is_set():
                    return {**evidence, "status": "cancelled"}
                evidence.update(self.workspaces.commit(workspace, trusted_job), status="succeeded")
                if cancellation.is_set():
                    evidence.update(status="cancelled", error_code="CANCEL_DURING_COMMIT")
            elif operation == "integrate":
                evidence.update(self.workspaces.integrate(workspace, job))
                tree = evidence["tree_sha"]
                checks = self._checks(job, workspace, request, cancellation, sink, tree)
                if self.workspaces.git(workspace.path, "rev-parse", "HEAD^{tree}") != tree or self.workspaces.git(workspace.path, "status", "--porcelain"):
                    raise WorkerError("TEST_TREE_CHANGED", "Integration checks changed the accepted tree")
                passed = bool(checks) and all(check["status"] == "passed" for check in checks)
                evidence.update(test_results=checks, status="succeeded" if passed else "failed", integration_status="passed" if passed else "failed")
            if disk_bytes(workspace.path.parent) > request.max_disk_bytes:
                raise WorkerError("DISK_QUOTA_EXCEEDED", "Run worktree disk quota exceeded")
            return cast(Json, Redactor(self.secret_values).data(evidence))

    def _repair_snapshot(self, job: Json, workspace: Workspace, allowed_paths: list[str]) -> None:
        from .journal import owned_sessions_stopped
        source_id = str(job["repair_source_execution_id"])
        if source_id == workspace.execution_id:
            raise WorkerError("IDEMPOTENCY_CONFLICT", "Repair requires a fresh allocation")
        with self.workspaces.worktree_lock(source_id):
            source = self.workspaces.load(source_id)
            saved = source.journal.read()
            if saved.get("project_id") != job["project_id"] or saved.get("run_id") != job["run_id"] or source.root_base_sha != workspace.root_base_sha or not owned_sessions_stopped(saved):
                raise WorkerError("EXECUTION_UNCERTAIN", "Repair source has invalid ownership")
            if self.workspaces.git(source.path, "rev-parse", source.base_sha + "^{tree}") != self.workspaces.git(workspace.path, "rev-parse", workspace.base_sha + "^{tree}"):
                raise WorkerError("VERSION_CONFLICT", "Repair dependency snapshot changed")
            changes = self.workspaces.changes(source, allowed_paths)
            for name in changes["changed_paths"]:
                original = source.path / name
                destination = workspace.path / name
                within_root(destination, self.workspaces.root, must_exist=False)
                if original.exists():
                    within_root(original, self.workspaces.root)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(original.read_bytes())
                elif destination.exists():
                    destination.unlink()
            workspace.journal.update(repair_source_execution_id=source_id, repair_source_tree_sha=changes["tree_sha"])

    def _checks(self, job: Json, workspace: Workspace, request: Request, cancellation: Event, sink: EventSink, tree: str) -> list[Json]:
        project = job["project"]
        registry = project.get("check_registry", project.get("checks", {}))
        if isinstance(registry, list):
            registry = {entry["id"]: entry for entry in registry}
        results: list[Json] = []
        started = time.monotonic()
        for check_id in job.get("check_ids", []):
            if check_id not in registry:
                raise WorkerError("PERMISSION_DENIED", "Unregistered check")
            config = registry[check_id]
            argv = config.get("argv", []) if isinstance(config, dict) else config
            if not argv or any(not isinstance(arg, str) for arg in argv):
                raise WorkerError("INVALID_REQUEST", "Check must be a registered argv array")
            if Path(argv[0]).name in {"bash", "sh", "sudo", "docker", "git", "cmd", "powershell", "pwsh"}:
                raise WorkerError("PERMISSION_DENIED", "Shell/privileged/Git check launchers are forbidden")
            executable = sys.executable if argv[0] in {"python", "python3"} else shutil.which(argv[0])
            if executable is None:
                raise WorkerError("CHECK_UNAVAILABLE", "Registered check executable missing")
            remaining = max(1, request.timeout_sec - int(time.monotonic() - started))
            timeout = config.get("timeout_sec", remaining) if isinstance(config, dict) else project.get("check_timeouts", {}).get(check_id, remaining)
            check_request = replace(request, timeout_sec=min(remaining, int(timeout)))
            def output(stream: str, text: str, check_name: str = check_id) -> None:
                sink("output", {"check_id": check_name, "stream": stream, "text": text[:4096]})
            outcome = ProcessRunner().run([executable, *argv[1:]], check_request, output, cancellation)
            results.append({"check_id": check_id, "status": "passed" if outcome.status == "succeeded" else "cancelled" if outcome.status == "cancelled" else "failed", "exit_code": outcome.exit_code, "tree_sha": tree, "error_code": outcome.error_code})
            if outcome.status != "succeeded":
                break
        return results

    @staticmethod
    def _validate_plan(plan: Json) -> None:
        ids = [task["id"] for task in plan["tasks"]]
        if len(set(ids)) != len(ids):
            raise WorkerError("INVALID_PLAN", "Duplicate planned task IDs")
        predecessors = {task["id"]: set(task["dependency_ids"]) for task in plan["tasks"]}
        for task in plan["tasks"]:
            if not task["acceptance_criteria"] or not task["expected_files"]:
                raise WorkerError("INVALID_PLAN", "Every task requires criteria and expected paths")
            for path in task["expected_files"]:
                validate_relative(path)
            if not predecessors[task["id"]].issubset(ids):
                raise WorkerError("INVALID_PLAN", "Unknown planned dependency")
        done: set[str] = set()
        while len(done) < len(ids):
            ready = {key for key, deps in predecessors.items() if key not in done and deps <= done}
            if not ready:
                raise WorkerError("INVALID_PLAN", "Planned dependencies contain a cycle")
            done |= ready
