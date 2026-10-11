from pathlib import Path
import subprocess
import json
import pytest
from adf_runtime_worker.git_workspace import GitWorkspaceManager

@pytest.fixture
def repository(tmp_path: Path):
    root = tmp_path / "factory"
    repo = root / "projects" / "example" / "repo"
    repo.mkdir(parents=True)
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    git("init", "-b", "main")
    git("config", "user.name", "ADF Test")
    git("config", "user.email", "test@localhost")
    (repo / "README.md").write_text("test repository\n")
    (repo / ".gitignore").write_text("__pycache__/\n.pytest_cache/\n")
    git("add", "README.md", ".gitignore")
    git("commit", "-m", "test: initialize scratch repository")
    project = {"repo_path": str(repo), "allowed_root": str(root), "default_branch": "main", "trusted": True, "checks": [{"id": "python", "argv": ["python", "-c", "import pathlib; assert pathlib.Path('README.md').exists()"], "timeout_sec": 10}]}
    return root, repo, git("rev-parse", "HEAD"), project

@pytest.fixture
def manager(repository):
    return GitWorkspaceManager(repository[0], require_ext4=False)

@pytest.fixture
def job(repository):
    _, _, sha, project = repository
    return {"execution_id": "execution-1", "run_id": "run-1", "task_id": "task-1", "project_id": "project-1", "lease_epoch": 1, "operation": "agent_task", "root_base_sha": sha, "execution_base_sha": sha, "project": project, "agent": {"id": "developer", "provider": "mock", "permission_profile": "trusted-development"}, "policy": {"approved": True, "allow_commit": True, "trusted_repository": True, "allowed_write_paths": ["feature.py"]}, "allowed_write_paths": ["feature.py"], "check_ids": ["python"], "task_prompt": '{"mock_files":{"feature.py":"value = 42\\n"}}', "timeout_sec": 10, "max_steps": 20, "max_output_bytes": 100000, "max_disk_bytes": 1000000}

@pytest.fixture
def sealed_policy(repository):
    from adf_runtime_worker.profile_policy import SealedProfilePolicy
    root, repo, _, _ = repository
    profile = root / "provider-profiles" / "codex"
    profile.mkdir(parents=True, mode=0o700)
    manifest = root / "tools" / "shared-profile-policy.json"
    manifest.parent.mkdir()
    manifest.write_text(json.dumps({"version": 1, "project_roots": [str(repo)]}))
    manifest.chmod(0o600)
    return SealedProfilePolicy(root, profile, manifest)
