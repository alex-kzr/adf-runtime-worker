"""Worker-owned task snapshots and serial, journaled Git integration."""
from __future__ import annotations

import re
import os
import signal
import time
from collections.abc import Callable
from fnmatch import fnmatchcase
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from .journal import FileLock, Journal
from .models import Json, WorkerError
from .security import canonical_root, inspect_content, restricted_env, validate_relative, within_root

_ID = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")

@dataclass(frozen=True)
class Workspace:
    path: Path
    branch: str
    base_sha: str
    root_base_sha: str
    execution_id: str
    journal: Journal

class GitWorkspaceManager:
    def __init__(self, root: Path, *, require_ext4: bool = True) -> None:
        self.root = canonical_root(root, require_ext4=require_ext4)
        executable = shutil.which("git")
        if executable is None:
            raise WorkerError("UNSUPPORTED_RUNTIME", "Git is not installed")
        self.executable = executable
        self.control_guard: Callable[[], None] | None = None
        self.execution_journal: Journal | None = None
        self.worktree_lock_fd: int | None = None
        self.secret_values: tuple[str, ...] = ()

    def git(self, path: Path, *args: str, check: bool = True) -> str:
        within_root(path, self.root)
        return self._command([self.executable, "-c", "core.quotePath=false", "-C", str(path), *args], check=check)

    def _command(self, argv: list[str], *, check: bool = True) -> str:
        if self.control_guard:
            self.control_guard()
        if self.execution_journal:
            from .journal import process_identity
            self.execution_journal.update(supervisor=process_identity(os.getpid()), git_phase="spawn_intent")
        from .journal import group_alive, process_identity
        import queue
        import threading
        from typing import BinaryIO
        process = subprocess.Popen(argv, pass_fds=(self.worktree_lock_fd,) if os.name == "posix" and self.worktree_lock_fd is not None else (), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, env=restricted_env(), start_new_session=os.name == "posix")
        identity = process_identity(process.pid)
        if self.execution_journal:
            self.execution_journal.update(process=identity, git_phase="running")
        chunks: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=64)
        finished = threading.Event()
        def reader(name: str, stream: BinaryIO) -> None:
            try:
                while not finished.is_set():
                    data = os.read(stream.fileno(), 8192)
                    if not data:
                        break
                    while not finished.is_set():
                        try:
                            chunks.put((name, data), timeout=0.1)
                            break
                        except queue.Full:
                            continue
            finally:
                while not finished.is_set():
                    try:
                        chunks.put((name, None), timeout=0.1)
                        break
                    except queue.Full:
                        continue
        if process.stdout is None or process.stderr is None:
            process.kill()
            process.wait(timeout=3)
            raise WorkerError("SUPERVISOR_FAILED", "Git pipes unavailable")
        readers = [threading.Thread(target=reader, args=(name, stream), daemon=True) for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))]
        for thread in readers:
            thread.start()
        started = time.monotonic()
        stdout = bytearray()
        output_bytes = 0
        closed = 0
        try:
            while closed < 2:
                if self.control_guard:
                    self.control_guard()
                if time.monotonic() - started >= 30:
                    raise WorkerError("GIT_TIMEOUT", "Git operation exceeded its bounded deadline")
                try:
                    stream_name, data = chunks.get(timeout=0.1)
                except queue.Empty:
                    continue
                if data is None:
                    closed += 1
                    continue
                output_bytes += len(data)
                if output_bytes > 20971520:
                    raise WorkerError("QUOTA_EXCEEDED", "Git output exceeds inspection limit")
                if stream_name == "stdout":
                    stdout.extend(data)
            process.wait(timeout=1)
            if check and process.returncode:
                raise WorkerError("GIT_FAILED", "Git operation failed; inspect preserved worktree")
            return stdout.decode("utf-8", errors="replace").rstrip("\r\n")
        finally:
            finished.set()
            # Stop descendants even if the immediate child has already exited.
            if os.name == "posix" and group_alive(identity):
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 1
                while group_alive(identity) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if group_alive(identity):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            elif process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            for thread in readers:
                thread.join(timeout=1)
            for pipe in (process.stdout, process.stderr):
                pipe.close()
            if self.execution_journal:
                self.execution_journal.update(process_stopped=not group_alive(identity), git_phase="stopped")

    def validate_repo(self, project: Json) -> Path:
        repo = within_root(Path(project["repo_path"]), self.root)
        allowed = canonical_root(Path(project.get("allowed_root", self.root)), require_ext4=False)
        if not repo.is_relative_to(allowed) or not allowed.is_relative_to(self.root):
            raise WorkerError("INVALID_PATH", "Project is outside registered roots")
        top = Path(self.git(repo, "rev-parse", "--show-toplevel")).resolve()
        if top != repo:
            raise WorkerError("INVALID_PATH", "Project path is not the Git root")
        common = Path(self.git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
        within_root(common, self.root)
        unsafe_config = self.git(repo, "config", "--local", "--name-only", "--get-regexp", r"^(include\.|includeif\.|core\.fsmonitor$|extensions\.worktreeConfig$|diff\.external$|diff\..*\.(textconv|command)$|merge\..*\.driver$|credential\.|core\.sshCommand$)", check=False)
        if unsafe_config:
            raise WorkerError("PERMISSION_DENIED", "Git includes, drivers, credential commands and custom execution configuration require explicit reviewed policy")
        if self.git(repo, "config", "--local", "--get", "core.hooksPath", check=False):
            raise WorkerError("PERMISSION_DENIED", "Custom Git hooks require a future explicit reviewed policy")
        for hook in (common / "hooks").glob("*"):
            if hook.is_file() and not hook.name.endswith(".sample"):
                raise WorkerError("PERMISSION_DENIED", "Active Git hook requires explicit reviewed policy")
        config = self.git(repo, "config", "--local", "--name-only", "--get-regexp", r"^filter\.", check=False)
        if config or self.git(repo, "ls-files", ".gitmodules"):
            raise WorkerError("PERMISSION_DENIED", "Git filters and nested target submodules are outside MVP")
        if self.git(repo, "config", "--local", "--get", "commit.gpgsign", check=False) == "true":
            raise WorkerError("CAPABILITY_UNSUPPORTED", "Required signing needs a separately verified local signer")
        return repo

    def journal_for(self, execution_id: str) -> Journal:
        if not _ID.fullmatch(execution_id):
            raise WorkerError("INVALID_REQUEST", "Unsafe execution identifier")
        return Journal(self.root / "journals" / f"{execution_id}.json")

    def project_lock(self, project_id: str) -> FileLock:
        if not _ID.fullmatch(project_id):
            raise WorkerError("INVALID_REQUEST", "Unsafe project identifier")
        return FileLock(self.root / "locks" / f"project-{project_id}.lock", blocking=True, guard=self.control_guard, timeout=30)

    def worktree_lock(self, execution_id: str) -> FileLock:
        if not _ID.fullmatch(execution_id):
            raise WorkerError("INVALID_REQUEST", "Unsafe execution identifier")
        return FileLock(self.root / "locks" / f"execution-{execution_id}.lock")

    def allocate(self, request: Json) -> Workspace:
        repo = self.validate_repo(request["project"])
        for name in ("execution_id", "run_id", "task_id", "project_id"):
            if not _ID.fullmatch(str(request[name])):
                raise WorkerError("INVALID_REQUEST", "Unsafe allocation identifier")
        root_sha = request["root_base_sha"]
        if not _SHA.fullmatch(root_sha) or self.git(repo, "rev-parse", root_sha + "^{commit}") != root_sha:
            raise WorkerError("INVALID_REQUEST", "Base must be an existing exact commit")
        execution_id = request["execution_id"]
        journal = self.journal_for(execution_id)
        saved = journal.read()
        integration = request.get("operation") == "integrate"
        predecessors = [] if integration else request.get("predecessor_commits", [])
        if saved.get("workspace"):
            workspace = self.load(execution_id)
            if workspace.root_base_sha != root_sha or saved.get("predecessor_commits", []) != predecessors:
                raise WorkerError("IDEMPOTENCY_CONFLICT", "Existing allocation has a different root/dependency snapshot")
            if not saved.get("dependency_snapshot_complete"):
                with self.project_lock(request["project_id"]):
                    for index, sha in enumerate(predecessors):
                        self._apply_delta(workspace, sha, f"dependency-{index}")
                    data = dict(saved["workspace"])
                    data["base_sha"] = self.git(workspace.path, "rev-parse", "HEAD")
                    journal.update(workspace=data, dependency_snapshot_complete=True)
                workspace = self.load(execution_id)
            return workspace
        branch = f"factory/integration/{request['run_id']}" if integration else f"factory/task/{request['task_id']}/{execution_id}"
        path = self.root / "worktrees" / request["project_id"] / request["run_id"] / execution_id
        path.parent.mkdir(parents=True, exist_ok=True)
        within_root(path, self.root, must_exist=False)
        with self.project_lock(request["project_id"]):
            journal.update(allocation_intent={"path": str(path), "branch": branch, "root_base_sha": root_sha}, project_id=request["project_id"], run_id=request["run_id"], task_id=request["task_id"], execution_id=execution_id)
            # A prior allocation_intent is reconciled using the exact branch/path, never deleted.
            if path.exists():
                if self.git(path, "symbolic-ref", "--short", "HEAD") != branch or self.git(path, "rev-parse", "HEAD") != root_sha:
                    raise WorkerError("EXECUTION_UNCERTAIN", "Incomplete allocation differs from journal")
            else:
                if self.git(repo, "show-ref", "--verify", "refs/heads/" + branch, check=False):
                    raise WorkerError("EXECUTION_UNCERTAIN", "Factory branch already exists without allocation evidence")
                self.git(repo, "worktree", "add", "-b", branch, str(path), root_sha)
            if self.git(path, "status", "--porcelain"):
                raise WorkerError("EXECUTION_UNCERTAIN", "New worktree is unexpectedly dirty")
            journal.update(workspace={"path": str(path), "branch": branch, "root_base_sha": root_sha, "base_sha": root_sha}, phase="allocated", predecessor_commits=predecessors, dependency_snapshot_complete=False)
            workspace = self.load(execution_id)
            for index, sha in enumerate(predecessors):
                self._apply_delta(workspace, sha, f"dependency-{index}")
            base = self.git(path, "rev-parse", "HEAD")
            journal.update(workspace={"path": str(path), "branch": branch, "root_base_sha": root_sha, "base_sha": base}, dependency_snapshot_complete=True)
        return self.load(execution_id)

    def load(self, execution_id: str) -> Workspace:
        journal = self.journal_for(execution_id)
        saved = journal.read()
        data = saved.get("workspace")
        if not data:
            raise WorkerError("EXECUTION_UNCERTAIN", "Target allocation journal is missing")
        path = within_root(Path(data["path"]), self.root)
        branch = self.git(path, "symbolic-ref", "--short", "HEAD")
        if branch != data["branch"] or not branch.startswith("factory/"):
            raise WorkerError("EXECUTION_UNCERTAIN", "Worktree branch identity changed")
        return Workspace(path, branch, data["base_sha"], data["root_base_sha"], execution_id, journal)

    def changes(self, workspace: Workspace, allowed_paths: list[str]) -> Json:
        files = self.git(workspace.path, "ls-files", "--modified", "--others", "--deleted", "--exclude-standard", "-z").split("\x00")
        files += self.git(workspace.path, "diff", "--cached", "--name-only", "-z").split("\x00")
        paths = sorted({validate_relative(name) for name in files if name})
        approved = [validate_relative(path) for path in allowed_paths]
        for name in paths:
            if not approved or not any(scope == "**" or name == scope or name.startswith(scope.rstrip("/") + "/") or fnmatchcase(name, scope) for scope in approved):
                raise WorkerError("PERMISSION_DENIED", "Change is outside approved task paths")
            inspect_content(workspace.path / name, secret_values=self.secret_values)
        # Refuse modifications to tracked execution customizations and ignore rules.
        if any(name in {".gitignore", ".gitattributes", ".gitmodules", ".claude/settings.json", ".codex/config.toml"} for name in paths):
            raise WorkerError("PERMISSION_DENIED", "Execution configuration changes require explicit future policy")
        # Stage only validated paths, never the whole repository.
        if paths:
            self.git(workspace.path, "add", "--", *paths)
        tree = self.git(workspace.path, "write-tree")
        diff = self.git(workspace.path, "diff", "--cached", "--binary")
        import hashlib
        return {"tree_sha": tree, "changed_paths": paths, "diff_sha256": hashlib.sha256(diff.encode()).hexdigest()}

    def commit(self, workspace: Workspace, request: Json) -> Json:
        policy = request.get("policy", {})
        if not policy.get("approved") or not policy.get("allow_commit"):
            raise WorkerError("PERMISSION_DENIED", "Commit requires an approved bounded grant")
        review = request.get("review", {})
        tests = request.get("test_results", workspace.journal.read().get("test_results", []))
        evidence = self.changes(workspace, request.get("allowed_write_paths", policy.get("allowed_write_paths", [])))
        if not review.get("approved") or review.get("tree_sha") != evidence["tree_sha"] or not review.get("reviewer_id") or review.get("reviewer_id") == review.get("developer_id"):
            raise WorkerError("REVIEW_REQUIRED", "Independent review must bind the exact staged tree")
        if not tests or any(item.get("status") != "passed" or item.get("tree_sha") != evidence["tree_sha"] for item in tests):
            raise WorkerError("TEST_REQUIRED", "Passing checks must bind the exact staged tree")
        with self.project_lock(request["project_id"]):
            saved = workspace.journal.read()
            existing = saved.get("commit_sha")
            if existing:
                if self.git(workspace.path, "rev-parse", "HEAD") != existing:
                    raise WorkerError("EXECUTION_UNCERTAIN", "Journaled commit no longer matches HEAD")
                return {**evidence, "commit_sha": existing}
            intent = saved.get("commit_intent")
            head = self.git(workspace.path, "rev-parse", "HEAD")
            if intent:
                if head != intent["parent_sha"]:
                    self._verify_committed(workspace, intent)
                    workspace.journal.update(commit_sha=head, phase="committed")
                    return {**evidence, "commit_sha": head}
                if intent["tree_sha"] != evidence["tree_sha"]:
                    raise WorkerError("EXECUTION_UNCERTAIN", "Commit intent tree changed")
            else:
                intent = {"parent_sha": head, "tree_sha": evidence["tree_sha"], "execution_id": workspace.execution_id, "message": f"feat(adf): apply approved task {request['task_id']}\n\nADF-Run: {request['run_id']}\nADF-Task: {request['task_id']}\nADF-Execution: {workspace.execution_id}"}
                workspace.journal.update(commit_intent=intent, phase="commit_intent")
            if evidence["tree_sha"] == self.git(workspace.path, "rev-parse", "HEAD^{tree}"):
                raise WorkerError("NO_CHANGES", "Task has no reviewed changes to commit")
            self.git(workspace.path, "-c", "user.name=ADF Worker", "-c", "user.email=adf@localhost", "commit", "-m", intent["message"])
            self._verify_committed(workspace, intent)
            sha = self.git(workspace.path, "rev-parse", "HEAD")
            workspace.journal.update(commit_sha=sha, phase="committed")
            return {**evidence, "commit_sha": sha}

    def _verify_committed(self, workspace: Workspace, intent: Json) -> None:
        parent = self.git(workspace.path, "rev-parse", "HEAD^")
        tree = self.git(workspace.path, "rev-parse", "HEAD^{tree}")
        message = self.git(workspace.path, "log", "-1", "--format=%B")
        if parent != intent["parent_sha"] or tree != intent["tree_sha"] or f"ADF-Execution: {intent['execution_id']}" not in message:
            raise WorkerError("EXECUTION_UNCERTAIN", "Commit outcome does not match fsynced intent")

    def _apply_delta(self, workspace: Workspace, sha: str, key: str) -> str:
        if not _SHA.fullmatch(sha):
            raise WorkerError("INVALID_REQUEST", "Integration requires exact commit IDs")
        saved = workspace.journal.read()
        intents = saved.get("delta_intents", {})
        intent = intents.get(key)
        head = self.git(workspace.path, "rev-parse", "HEAD")
        if intent:
            if intent["source_sha"] != sha:
                raise WorkerError("IDEMPOTENCY_CONFLICT", "Delta intent source changed")
            if intent.get("result_sha"):
                return str(intent["result_sha"])
            if head != intent["parent_sha"]:
                message = self.git(workspace.path, "log", "-1", "--format=%B")
                if f"ADF-Source: {sha}" not in message or self.git(workspace.path, "rev-parse", "HEAD^") != intent["parent_sha"]:
                    raise WorkerError("EXECUTION_UNCERTAIN", "Unexpected Git delta outcome")
                intent["result_sha"] = head
                workspace.journal.update(delta_intents=intents)
                return head
            if intent.get("phase") == "applying":
                # A crash may have staged a partial delta. Preserve it for manual resolution.
                raise WorkerError("EXECUTION_UNCERTAIN", "Incomplete cherry-pick requires operator reconciliation")
        else:
            if self.git(workspace.path, "status", "--porcelain"):
                raise WorkerError("EXECUTION_UNCERTAIN", "Integration worktree must be clean")
            intent = {"source_sha": sha, "parent_sha": head, "phase": "applying"}
            intents[key] = intent
            workspace.journal.update(delta_intents=intents)
            try:
                self.git(workspace.path, "cherry-pick", "--no-commit", sha)
            except WorkerError as exc:
                if exc.code != "GIT_FAILED":
                    raise
                conflicts = self.git(workspace.path, "diff", "--name-only", "--diff-filter=U").splitlines()
                intent.update(phase="needs_resolution", conflicting_paths=conflicts)
                workspace.journal.update(delta_intents=intents)
                raise WorkerError("INTEGRATION_CONFLICT", "Preserved integration branch has conflicts") from exc
            intent.update(phase="prepared", tree_sha=self.git(workspace.path, "write-tree"))
            workspace.journal.update(delta_intents=intents)
        if intent["tree_sha"] != self.git(workspace.path, "write-tree"):
            raise WorkerError("EXECUTION_UNCERTAIN", "Prepared integration tree changed")
        message = f"feat(adf): integrate approved task delta\n\nADF-Execution: {workspace.execution_id}\nADF-Source: {sha}"
        self.git(workspace.path, "-c", "user.name=ADF Worker", "-c", "user.email=adf@localhost", "commit", "-m", message)
        intent.update(result_sha=self.git(workspace.path, "rev-parse", "HEAD"), phase="committed")
        workspace.journal.update(delta_intents=intents)
        return str(intent["result_sha"])

    def reconcile_git_evidence(self, execution_id: str) -> Json:
        previous_guard = self.control_guard
        self.control_guard = None
        try:
            workspace = self.load(execution_id)
            saved = workspace.journal.read()
            head = self.git(workspace.path, "rev-parse", "HEAD")
            evidence: Json = {"branch": workspace.branch, "worktree_key": execution_id, "tree_sha": self.git(workspace.path, "rev-parse", "HEAD^{tree}"), "base_sha": workspace.base_sha, "root_base_sha": workspace.root_base_sha}
            intent = saved.get("commit_intent")
            if intent and head != intent["parent_sha"]:
                self._verify_committed(workspace, intent)
                workspace.journal.update(commit_sha=head, phase="committed")
                evidence["commit_sha"] = head
            intents = saved.get("delta_intents", {})
            for item in intents.values():
                if item.get("phase") == "committed" and item.get("result_sha") == head:
                    evidence["commit_sha"] = head
                    evidence["applied_source_commits"] = [entry["source_sha"] for entry in intents.values() if entry.get("phase") == "committed"]
                if item.get("phase") == "prepared" and head != item["parent_sha"]:
                    message = self.git(workspace.path, "log", "-1", "--format=%B")
                    if f"ADF-Source: {item['source_sha']}" in message and self.git(workspace.path, "rev-parse", "HEAD^") == item["parent_sha"] and evidence["tree_sha"] == item["tree_sha"]:
                        item.update(result_sha=head, phase="committed")
                        workspace.journal.update(delta_intents=intents)
                        evidence["commit_sha"] = head
            return evidence
        finally:
            self.control_guard = previous_guard

    def integrate(self, workspace: Workspace, request: Json) -> Json:
        if not request.get("policy", {}).get("approved") or not request.get("policy", {}).get("allow_commit"):
            raise WorkerError("PERMISSION_DENIED", "Integration requires an approved bounded grant")
        with self.project_lock(request["project_id"]):
            if request.get("manual_resolution"):
                expected = request.get("resolution_tree_sha")
                tree = self.git(workspace.path, "rev-parse", "HEAD^{tree}")
                if not expected or expected != tree or self.git(workspace.path, "status", "--porcelain"):
                    raise WorkerError("REVIEW_REQUIRED", "Manual resolution requires an approved clean exact tree")
                intents = workspace.journal.read().get("delta_intents", {})
                conflicted = [intent for intent in intents.values() if intent.get("phase") == "needs_resolution"]
                if not conflicted:
                    raise WorkerError("EXECUTION_UNCERTAIN", "No journaled conflict to resolve")
                # Human acceptance names the complete resolved tree; no original delta is replayed.
                workspace.journal.update(manual_resolution={"tree_sha": tree, "commit_sha": self.git(workspace.path, "rev-parse", "HEAD"), "approved_source_commits": request.get("integration_commits", [])})
                return {"integration_status": "passed", "commit_sha": self.git(workspace.path, "rev-parse", "HEAD"), "tree_sha": tree, "branch": workspace.branch}
            for index, sha in enumerate(request.get("integration_commits", [])):
                self._apply_delta(workspace, sha, f"integration-{index}")
        return {"integration_status": "passed", "commit_sha": self.git(workspace.path, "rev-parse", "HEAD"), "tree_sha": self.git(workspace.path, "rev-parse", "HEAD^{tree}"), "branch": workspace.branch}
