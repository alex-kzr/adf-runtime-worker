"""Immutable accepted Git deltas are data, never inherited execution grants."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from .journal import FileLock
from .models import Json, WorkerError

if TYPE_CHECKING:
    from .git_workspace import GitWorkspaceManager, Workspace

_SHA = re.compile(r"^[0-9a-f]{40}$")


def denied() -> WorkerError:
    return WorkerError("PERMISSION_DENIED", "Accepted commit lineage validation failed")


def validation(saved: Json, request: Json, tree: str) -> Json:
    """Capture trusted check/review acceptance when the worker commits a delta."""
    review, checks = request.get("review", {}), request.get("test_results", [])
    expected = [item["id"] for item in request.get("project", {}).get("checks", [])]
    if (request.get("policy", {}).get("approved") is not True
            or request.get("policy", {}).get("allow_commit") is not True
            or review.get("approved") is not True or review.get("tree_sha") != tree
            or not review.get("developer_id") or not review.get("reviewer_id")
            or review["developer_id"] == review["reviewer_id"]
            or not expected or any(not isinstance(item, str) or not item for item in expected)
            or len(expected) != len(set(expected)) or not checks or len(checks) != len(expected)
            or {item.get("check_id") for item in checks} != set(expected)
            or any(item.get("status") != "passed" or type(item.get("exit_code")) is not int or item["exit_code"] != 0
                   or item.get("tree_sha") != tree for item in checks)):
        raise denied()
    if any(request.get(key) != saved.get(key) for key in ("project_id", "run_id", "task_id")):
        raise denied()
    return {"version": 1, "project_id": saved["project_id"], "repository_root": saved["repository_root"],
            "run_id": saved["run_id"], "task_id": saved["task_id"], "execution_id": saved["execution_id"],
            "tree_sha": tree, "allowed_write_paths": request.get("allowed_write_paths", []),
            "review": review, "test_results": checks, "check_ids": expected}


def source_validation(saved: Json, tree: str) -> Json:
    """Derive acceptance from original private dispatch and worker evidence."""
    request = saved["request"]
    paths = request.get("allowed_write_paths", request.get("expected_files", request.get("policy", {}).get("allowed_write_paths", [])))
    developer = request.get("agent", {}).get("agent_id", request.get("agent", {}).get("id"))
    if (request.get("operation") != "agent_task" or request.get("execution_id") != saved["execution_id"]
            or request.get("project", {}).get("repo_path") != saved["repository_root"]
            or paths != saved.get("allowed_write_paths") or not developer
            or saved.get("developer_id") != developer or saved.get("review", {}).get("developer_id") != developer):
        raise denied()
    return validation(saved, {**request, "allowed_write_paths": paths,
                              "review": saved.get("review", {}), "test_results": saved.get("test_results", [])}, tree)


def published_commit(paths: list[Path], source: Json, sha: str, tree: str) -> None:
    """A writer's prior terminal result never proves commit API acceptance."""
    from .profile_policy import _closed_object, private_bytes
    matches = 0
    for path in paths:
        with FileLock(path.with_suffix(".write.lock"), blocking=True, timeout=1):
            raw, _ = private_bytes(path, limit=8 * 1024 * 1024)
        saved = json.loads(raw, object_pairs_hook=_closed_object)
        request = saved.get("request", {})
        result = saved.get("terminal_result", {})
        if (request.get("operation") != "git_commit" or request.get("target_execution_id") != source["execution_id"]
                or saved.get("execution_id") == source["execution_id"]
                or saved.get("execution_id") != path.stem or request.get("execution_id") != saved.get("execution_id")
                or saved.get("result_persisted") is not True or saved.get("terminal_persisted") is not True
                or result.get("status") != "succeeded" or result.get("commit_sha") != sha or result.get("tree_sha") != tree
                or request.get("policy", {}).get("approved") is not True or request.get("policy", {}).get("allow_commit") is not True
                or any(request.get(key) != source[key] for key in ("project_id", "run_id", "task_id"))
                or request.get("project", {}).get("repo_path") != source["repository_root"]
                or request.get("review") != source.get("review")):
            continue
        matches += 1
        if matches > 1:
            raise denied()
    if matches != 1:
        raise denied()


def check_import_fence(root: Path, saved: Json) -> None:
    """Additional current-operator validation only; it grants no native capability."""
    if "artifact_import_fence" not in saved:
        return
    fence = saved["artifact_import_fence"]
    required = {"shared_profile_policy", "shared_workspace_seal"}
    if (not isinstance(fence, dict) or not required <= fence.keys()
            or fence.keys() - required - {"shared_native_read_policy"}
            or not isinstance(fence["shared_profile_policy"], dict) or fence["shared_workspace_seal"] is None
            or "shared_native_read_policy" in fence and not isinstance(fence["shared_native_read_policy"], dict)):
        raise denied()
    from .profile_policy import check_receipt
    check_receipt(root, {**{k: v for k, v in saved.items() if k != "artifact_import_fence"}, **fence})


def accepted_delta(manager: GitWorkspaceManager, workspace: Workspace, sha: str) -> bool:
    """Validate current selection and local durable provenance before Git mutation.

    Returns true only when the caller must skip historical live-grant inheritance.
    Existing execution/repair/check/commit generation fences remain mandatory.
    """
    from .profile_policy import SealedProfilePolicy, _closed_object, check_receipt, private_bytes
    try:
        target = workspace.journal.read()
        scope = target.get("delta_authorization", {})
        if (not isinstance(sha, str) or _SHA.fullmatch(sha) is None
                or scope.get("approved") is not True or scope.get("trusted_repository") is not True
                or sha not in scope.get("selected_commits", [])
                or any(scope.get(k) != target.get(k) for k in ("project_id", "run_id", "task_id", "execution_id", "repository_root"))):
            raise denied()
        check_receipt(manager.root, target)
        paths = list((manager.root / "journals").glob("*.json"))
        if len(paths) > 8192:
            raise denied()
        matches = []
        for path in paths:
            with FileLock(path.with_suffix(".write.lock"), blocking=True, timeout=1):
                raw, _ = private_bytes(path, limit=8 * 1024 * 1024)
            saved = json.loads(raw, object_pairs_hook=_closed_object)
            if saved.get("commit_sha") == sha:
                matches.append((path, saved))
                if len(matches) > 1:
                    raise denied()
        if len(matches) != 1:
            raise denied()
        source_path, source = matches[0]
        intent = source["commit_intent"]
        trusted = source_validation(source, intent["tree_sha"])
        proof = source.get("commit_validation", trusted)
        if (type(proof.get("version")) is not int or proof != trusted or source_path.stem != source["execution_id"]
                or proof["project_id"] != scope["project_id"] or proof["repository_root"] != scope["repository_root"]):
            raise denied()
        published_commit(paths, source, sha, proof["tree_sha"])
        if (intent["execution_id"] != source["execution_id"] or intent["tree_sha"] != proof["tree_sha"]
                or manager.git(workspace.path, "rev-parse", sha + "^{commit}") != sha
                or manager.git(workspace.path, "rev-parse", sha + "^{tree}") != proof["tree_sha"]
                or manager.git(workspace.path, "rev-parse", sha + "^") != intent["parent_sha"]):
            raise denied()
        message = manager.git(workspace.path, "show", "-s", "--format=%B", sha).splitlines()
        if any("ADF-" + name + ": " + source[key] not in message
               for name, key in (("Run", "run_id"), ("Task", "task_id"), ("Execution", "execution_id"))):
            raise denied()
        from fnmatch import fnmatchcase
        from .security import validate_relative
        names = manager.git(workspace.path, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", sha).split("\x00")
        allowed = proof["allowed_write_paths"]
        if not allowed or any(not any(scope == "**" or validate_relative(name) == scope or name.startswith(scope.rstrip("/") + "/")
                                       or fnmatchcase(name, scope) for scope in allowed) for name in names if name):
            raise denied()
        receipt = source.get("shared_profile_policy")
        if receipt is None:
            return True
        from .journal import Journal
        state = Journal(manager.root / "providers/codex/server.json").read()
        if state.get("generation") == receipt["generation"]:
            check_receipt(manager.root, source)
            return False
        policy = SealedProfilePolicy(manager.root, Path(receipt["profile"]), Path(receipt["manifest"]), validate_repositories=False)
        if policy.digest != receipt["seal"] or not isinstance(state.get("generation"), str):
            raise denied()
        identity = policy.allocation_identity(workspace.execution_id, target)
        fence = {"shared_profile_policy": {**receipt, "generation": state["generation"]},
                 "shared_workspace_seal": [list(identity[0]), identity[1]]}
        native = source.get("shared_native_read_policy")
        if native is not None:
            fence["shared_native_read_policy"] = {**native, "generation": state["generation"]}
        if target.get("artifact_import_fence") not in (None, fence):
            raise denied()
        check_import_fence(manager.root, {**target, "artifact_import_fence": fence})
        workspace.journal.update(artifact_import_fence=fence)
        return True
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise denied() from exc
