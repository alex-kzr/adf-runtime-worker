import pytest
from adf_runtime_worker.models import WorkerError
from adf_runtime_worker.security import Redactor, restricted_env, within_root, validate_relative, inspect_content
from adf_runtime_worker.journal import FileLock

def test_sensitive_environment_is_never_forwarded(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sentinel-value-for-tests")
    assert "OPENAI_API_KEY" not in restricted_env()
    with pytest.raises(WorkerError):
        restricted_env(("OPENAI_API_KEY",))
    assert Redactor().text("sentinel-value-for-tests") == "[REDACTED]"

@pytest.mark.parametrize("name", ["../escape", "/absolute/escape", ".env", "credentials.json", ".git/config", "module/key.pem", "node_modules/dependency"])
def test_unsafe_or_secret_paths_are_rejected(name):
    with pytest.raises(WorkerError):
        validate_relative(name)

def test_symlink_escape_is_rejected(tmp_path):
    inside = tmp_path / "root"
    outside = tmp_path / "outside"
    inside.mkdir()
    outside.mkdir()
    try:
        (inside / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink unsupported")
    with pytest.raises(WorkerError):
        within_root(inside / "link", inside)

def test_secret_material_cannot_be_staged(tmp_path):
    path = tmp_path / "config.txt"
    path.write_text("password=" + "sentinel-credential-value")
    with pytest.raises(WorkerError, match="credential"):
        inspect_content(path)

def test_worktree_lock_has_one_owner(tmp_path):
    with FileLock(tmp_path / "lock"):
        with pytest.raises(WorkerError, match="lock"):
            with FileLock(tmp_path / "lock"):
                pass
