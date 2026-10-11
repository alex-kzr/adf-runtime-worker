"""Trusted operator profiles persist independently of job cwd and credential contents."""
from pathlib import Path
import os

import pytest

from adf_runtime_worker.models import WorkerError
from adf_runtime_worker.profiles import ProviderProfile
from adf_runtime_worker.security import restricted_env

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Owned Linux profile permissions")


@pytest.fixture
def home(tmp_path, monkeypatch):
    directory = tmp_path / "home"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: directory))
    return directory


@pytest.mark.parametrize("provider,variable", [("codex", "CODEX_HOME"), ("claude", "CLAUDE_CONFIG_DIR")])
def test_three_worktrees_use_one_operator_profile_without_credentials(home, provider, variable):
    directory = home / provider
    directory.mkdir(mode=0o700)
    profile = ProviderProfile(provider, directory)
    for number in range(3):
        worktree = home / "worktrees" / str(number)
        worktree.mkdir(parents=True)
        assert profile.environment(worktree) == {variable: str(directory)}
    assert not list(directory.iterdir())  # No login, token generation, copied file or per-job cache.
    assert profile.metadata()["login_per_job"] is False


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770])
def test_explicit_profile_must_be_private(home, mode):
    profile = home / "profile"
    profile.mkdir(mode=mode)
    profile.chmod(mode)
    with pytest.raises(WorkerError, match="private"):
        ProviderProfile("codex", profile).environment()


def test_profile_refuses_symlink_outside_home_and_job_paths(home, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    link = home / "linked"
    link.symlink_to(outside, target_is_directory=True)
    for value in [link, outside, Path("/mnt/c/example"), Path("relative")]:
        with pytest.raises(WorkerError):
            ProviderProfile("codex", value).environment()
    job = home / "job"
    job.mkdir(mode=0o700)
    nested = job / "profile"
    nested.mkdir(mode=0o700)
    with pytest.raises(WorkerError, match="worktrees"):
        ProviderProfile("claude", nested).environment(job)


def test_missing_profile_is_operator_action_and_secrets_still_denied(home, monkeypatch):
    with pytest.raises(WorkerError) as error:
        ProviderProfile("claude", home / "missing").environment()
    assert error.value.code == "AUTH_REQUIRED"
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "synthetic-private-value")
    monkeypatch.setenv("CODEX_HOME", "/mnt/c/unapproved")
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in restricted_env()
    assert "CODEX_HOME" not in restricted_env()
    with pytest.raises(WorkerError):
        restricted_env(("CLAUDE_CODE_OAUTH_TOKEN",))
    assert ProviderProfile("claude").environment() == {}
