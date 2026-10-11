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
from .capabilities import approved_capabilities
from .git_workspace import GitWorkspaceManager, Workspace
from .models import Adapter, EventSink, Json, Request, WorkerError
from .process import ProcessRunner, disk_bytes
from .security import Redactor, digest, validate_relative, within_root

_PLAN_SCHEMA: Json = {"type": "object", "additionalProperties": False, "properties": {"tasks": {"type": "array", "minItems": 1, "maxItems": 12, "items": {"type": "object", "additionalProperties": False, "properties": {"id": {"type": "string"}, "title": {"type": "string"}, "description": {"type": "string"}, "acceptance_criteria": {"type": "array", "items": {"type": "string"}}, "expected_files": {"type": "array", "items": {"type": "string"}}, "dependency_ids": {"type": "array", "items": {"type": "string"}}}, "required": ["id", "title", "description", "acceptance_criteria", "expected_files", "dependency_ids"]}}, "unknowns": {"type": "array", "items": {"type": "string"}}}, "required": ["tasks", "unknowns"]}
_REVIEW_SCHEMA: Json = {"type": "object", "additionalProperties": False, "properties": {"approved": {"type": "boolean"}, "findings": {"type": "array", "items": {"type": "string"}}}, "required": ["approved", "findings"]}

class Executor:
    def __init__(self, root: Path, *, require_ext4: bool = True, provider_paths: dict[str, str] | None = None, provider_profiles: dict[str, str] | None = None, codex_backend: str = "subprocess", check_sandbox: Json | None = None) -> None:
        self.workspaces = GitWorkspaceManager(root, require_ext4=require_ext4)
        self.provider_paths = provider_paths or {}
        self.provider_profiles = provider_profiles or {}
        if codex_backend not in {"subprocess", "shared", "shared-patch"}:
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Unknown Codex backend")
        self.codex_backend = codex_backend
        from .check_sandbox import CheckSandbox
        self.check_sandbox = CheckSandbox(check_sandbox)
        self.execution_deadline = float("inf")
        self.secret_values: tuple[str, ...] = ()

    def _request(self, job: Json, workspace: Workspace, lock_fd: int | None, deadline: Any) -> Request:
        agent = job.get("agent", {})
        operation = job["operation"]
        profile = agent.get("permission_profile", "observe")
        if operation in {"review", "planner"}:
            profile = "observe"
        prompt = str(job.get("task_prompt", ""))
        skills, mcp, provider_tools = approved_capabilities(agent, self.workspaces.root, workspace.path,
                                                           max(1, int(self.execution_deadline - time.monotonic())), profile, self.secret_values)
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
            from .profile_policy import check_receipt
            target = str(job.get("target_execution_id") or job["execution_id"])
            check_receipt(self.workspaces.root, self.workspaces.journal_for(target).read())
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
            if saved.get("patch_intents"):
                from .patches import mutation_resolved
                if not mutation_resolved(workspace.journal, workspace.path):
                    raise WorkerError("EXECUTION_UNCERTAIN", "Unresolved patch intent fences all later operations")
            request = self._request(job, workspace, lock.fd, lease_deadline)
            allowed_paths = job.get("allowed_write_paths", job.get("expected_files", policy.get("allowed_write_paths", [])))
            patch_job = self.codex_backend == "shared-patch" and job.get("agent", {}).get("provider") == "codex" and operation == "agent_task"
            if patch_job:
                if request.permission_profile != "trusted-development" or lease_deadline is None or lock.fd is None:
                    raise WorkerError("PERMISSION_DENIED", "Shared-patch requires the original approved developer lease/lock")
                if not allowed_paths or any(not isinstance(name, str) for name in allowed_paths):
                    raise WorkerError("PERMISSION_DENIED", "Shared-patch requires an immutable original write scope")
                # Validate checker capability before spending any model turn.
                self.check_sandbox.launcher()
                self.check_sandbox.command(Path(sys.executable), ["-I", "-c", "pass"], workspace.path, request)
                registry = job["project"].get("check_registry", job["project"].get("checks", {}))
                if isinstance(registry, list):
                    registry = {entry["id"]: entry for entry in registry}
                # API snapshots use [] for developer check_ids. Such an empty
                # list must still validate the checks used by the later loop.
                for check_id in job.get("check_ids") or list(registry):
                    if check_id not in registry:
                        raise WorkerError("PERMISSION_DENIED", "Patch job references an unregistered check")
                    config = registry[check_id]
                    argv = config.get("argv", []) if isinstance(config, dict) else config
                    if not argv or any(not isinstance(arg, str) for arg in argv):
                        raise WorkerError("INVALID_REQUEST", "Patch checks need registered argv arrays")
                    executable = sys.executable if argv[0] in {"python", "python3"} else shutil.which(argv[0])
                    if executable is None:
                        raise WorkerError("CHECK_UNAVAILABLE", "Patch check executable is unavailable")
                    self.check_sandbox.command(Path(executable), argv[1:], workspace.path, request)
                def preflight_output(*_: str) -> None:
                    pass
                if self.workspaces.control_guard is None:
                    raise WorkerError("PERMISSION_DENIED", "Patch preflight needs a live control guard")
                preflight = self.check_sandbox.run(Path(sys.executable), ["-I", "-c", "pass"], [], request, preflight_output,
                                                  cancellation, self.workspaces.control_guard)
                if preflight.status != "succeeded":
                    raise WorkerError("CAPABILITY_UNSUPPORTED", "Checker namespace/resource preflight failed before generation")
            if operation == "agent_task" and job.get("repair_source_execution_id"):
                self._repair_snapshot(job, workspace, allowed_paths, request=request if patch_job else None)
                if job.get("agent", {}).get("provider") != "mock":
                    request = replace(request, task_prompt=request.task_prompt + "\nRepair feedback: " + Redactor().text(str(job.get("repair_feedback", "")))[:8192])
            before_head = self.workspaces.git(workspace.path, "rev-parse", "HEAD")
            patch_baseline: Json = {}
            if patch_job:
                from .patches import PATCH_SCHEMA, baseline
                names = self.workspaces.git(workspace.path, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\x00")
                patch_baseline = baseline(workspace.path, names, allowed_paths)
                request = replace(request, structured_schema=PATCH_SCHEMA, task_prompt=request.task_prompt +
                                  "\nReturn only a bounded adf.text-patch.v1 JSON result. Do not write files or run project code. "
                                  "Use these worker-supplied preimage hashes; null means absent/create. Existing parents only. "
                                  "Unsupported binary, rename, mode, commands and metadata edits must be omitted.\nBaseline: " + json.dumps(patch_baseline) +
                                  "\nSchema: " + json.dumps(PATCH_SCHEMA))
                workspace.journal.update(patch_generation_intent={"execution_id": request.execution_id, "epoch": request.lease_epoch,
                                                                 "baseline": patch_baseline, "scope_sha256": digest(allowed_paths)})
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
                profile = self.provider_profiles.get(provider)
                adapter: Adapter
                if patch_job:
                    from .shared_patch_adapter import SharedPatchAdapter
                    adapter = SharedPatchAdapter(self.workspaces.root)
                elif provider == "codex" and self.codex_backend in {"shared", "shared-patch"}:
                    from .shared_adapter import SharedCodexAdapter
                    adapter = SharedCodexAdapter(self.workspaces.root)
                else:
                    adapter = provider_adapter(provider, self.provider_paths.get(provider), Path(profile) if profile else None)
                outcome = adapter.execute(request, sink, cancellation)
                evidence.update(status=outcome.status, exit_code=outcome.exit_code, error_code=outcome.error_code, process_identity=outcome.process_identity, process_stopped=outcome.process_stopped, usage=asdict(outcome.usage))
                if self.workspaces.git(workspace.path, "rev-parse", "HEAD") != before_head:
                    raise WorkerError("PERMISSION_DENIED", "Agent changed Git HEAD; preserved for inspection")
                if outcome.status != "succeeded":
                    return evidence
                guard = self.workspaces.control_guard
                if guard:
                    guard()
                if operation == "agent_task":
                    if patch_job:
                        from .journal import owned_sessions_stopped
                        from .patches import parse_patch
                        if not outcome.process_stopped or not owned_sessions_stopped(workspace.journal.read()):
                            raise WorkerError("EXECUTION_UNCERTAIN", "Native generation has not quiesced before writing")
                        patch = parse_patch(outcome.output, allowed_paths, patch_baseline, self.secret_values)
                        workspace.journal.update(phase="patch_generated", patch_generation={"complete": True, "native_permission": "observe"})
                        writer = self._patch_writer(job, workspace, request, patch_baseline, allowed_paths)
                        evidence.update(writer.apply(patch))
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
                passed = bool(checks) and all(check["status"] == "passed" for check in checks)
                evidence.update(after, test_results=checks, status="succeeded" if passed else "failed", error_code=None if passed else "TEST_FAILED")
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

    def _patch_writer(self, job: Json, workspace: Workspace, request: Request, expected: Json, scopes: list[str]) -> Any:
        from .patches import PatchWriter
        if request.lease_deadline is None or request.lock_fd is None or self.workspaces.control_guard is None:
            raise WorkerError("PERMISSION_DENIED", "Patch writer cannot run without live supervisor lease")
        dispatch = self.workspaces.journal_for(request.execution_id).read()
        if dispatch.get("epoch", request.lease_epoch) != request.lease_epoch:
            raise WorkerError("LEASE_STALE", "Patch lease epoch differs from durable dispatch")
        binding = {"execution_id": request.execution_id, "run_id": job["run_id"], "project_id": job["project_id"],
                   "epoch": request.lease_epoch, "approved": job["policy"].get("approved") is True,
                   "role": request.permission_profile, "scopes": list(scopes), "policy_sha256": digest(job["policy"]),
                   "baseline": expected, "lock_path": str(self.workspaces.root / "locks" / ("execution-" + workspace.execution_id + ".lock"))}
        return PatchWriter(workspace.path, workspace.journal, self.workspaces.control_guard, lock_fd=request.lock_fd,
                           binding=binding, secrets=self.secret_values)

    def _repair_snapshot(self, job: Json, workspace: Workspace, allowed_paths: list[str], *, request: Request | None = None) -> None:
        from .journal import owned_sessions_stopped
        source_id = str(job["repair_source_execution_id"])
        if source_id == workspace.execution_id:
            raise WorkerError("IDEMPOTENCY_CONFLICT", "Repair requires a fresh allocation")
        with self.workspaces.worktree_lock(source_id):
            source = self.workspaces.load(source_id)
            from .profile_policy import inherit_receipt
            inherit_receipt(self.workspaces.root, workspace.journal, source_id=source_id)
            saved = source.journal.read()
            if saved.get("project_id") != job["project_id"] or saved.get("run_id") != job["run_id"] or source.root_base_sha != workspace.root_base_sha or not owned_sessions_stopped(saved):
                raise WorkerError("EXECUTION_UNCERTAIN", "Repair source has invalid ownership")
            if self.workspaces.git(source.path, "rev-parse", source.base_sha + "^{tree}") != self.workspaces.git(workspace.path, "rev-parse", workspace.base_sha + "^{tree}"):
                raise WorkerError("VERSION_CONFLICT", "Repair dependency snapshot changed")
            changes = self.workspaces.changes(source, allowed_paths)
            if request is not None:
                from .patches import baseline, image, mutation_resolved, parent_fd
                if not mutation_resolved(source.journal, source.path):
                    raise WorkerError("EXECUTION_UNCERTAIN", "Repair source has unresolved patch mutations")
                expected = baseline(workspace.path, changes["changed_paths"], allowed_paths)
                edits: list[Json] = []
                for name in changes["changed_paths"]:
                    with parent_fd(source.path, name) as (fd, leaf):
                        original, raw = image(fd, leaf)
                    pre = expected.get(name)
                    edits.append({"path": name, "action": "delete" if original is None else "replace" if pre else "create",
                                  "preimage": pre, "content": raw.decode("utf-8") if raw is not None else None})
                self._patch_writer(job, workspace, request, expected, allowed_paths).apply({"version": 1, "edits": edits}, key="repair")
                workspace.journal.update(repair_source_execution_id=source_id, repair_source_tree_sha=changes["tree_sha"])
                return
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
            if self.codex_backend == "shared-patch":
                if self.workspaces.control_guard is None:
                    raise WorkerError("PERMISSION_DENIED", "Isolated checks need original lease/policy guard")
                self.workspaces.control_guard()
                names = self.workspaces.git(workspace.path, "ls-files", "--cached", "-z").split("\x00")
                outcome = self.check_sandbox.run(Path(executable), argv[1:], [name for name in names if name], check_request,
                                                 output, cancellation, self.workspaces.control_guard)
            else:
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
