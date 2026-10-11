"""Doctor selects trusted operator profiles without default auth or job env fallback."""
import json
import os
from pathlib import Path
import sys

import pytest

from adf_runtime_worker import cli
from adf_runtime_worker.models import WorkerError
from adf_runtime_worker.security import restricted_env

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Owned Linux profiles and executable fixtures")


@pytest.fixture
def profile_cli(tmp_path, monkeypatch):
    home = tmp_path / "empty-home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", "/mnt/c/unapproved:/usr/bin:/bin")
    profiles = {}
    paths = {}
    for name in ("codex", "claude"):
        profile = home / "profiles" / name
        profile.mkdir(parents=True, mode=0o700)
        profiles[name] = str(profile)
        executable = home / ("fixture-" + name)
        variable = "CODEX_HOME" if name == "codex" else "CLAUDE_CONFIG_DIR"
        version = "0.157.0" if name == "codex" else "2.1.296"
        status = ["login", "status"] if name == "codex" else ["auth", "status"]
        executable.write_text("#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n"
            + "variable=" + repr(variable) + "\nprofile=Path(os.environ.get(variable,str(Path.home()/'.codex')))\n"
            + "profile.mkdir(parents=True,exist_ok=True)\n"
            + "with (profile/'probe-audit.jsonl').open('a') as out:\n"
            + " out.write(json.dumps({'argv':sys.argv[1:],'HOME':os.environ.get('HOME'),'selector':os.environ.get(variable),"
            + "'environment_names':sorted(os.environ)})+'\\n')\n"
            + "if sys.argv[1:]==['--version']:\n print(" + repr(version) + ");sys.exit(0)\n"
            + "if sys.argv[1:]==" + repr(status) + ":\n"
            + (" print(json.dumps({'loggedIn':False}));sys.exit(0)\n" if name == "claude" else " sys.exit(1)\n")
            + "sys.exit(97)\n")
        executable.chmod(0o755)
        paths[name] = str(executable)
    monkeypatch.setenv("CODEX_HOME", str(home / "unapproved-codex"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / "unapproved-claude"))
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ADF_WORKER_TOKEN"):
        monkeypatch.setenv(name, "synthetic-private-value")
    return home, paths, profiles


def assert_profile_probes(home, profiles):
    for name, directory in profiles.items():
        calls = [json.loads(line) for line in (Path(directory) / "probe-audit.jsonl").read_text().splitlines()]
        assert [call["argv"] for call in calls] == [["--version"], ["login", "status"] if name == "codex" else ["auth", "status"]]
        assert all(call["HOME"] == str(home) and call["selector"] == directory for call in calls)
        forbidden = {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ADF_WORKER_TOKEN"}
        assert all(not forbidden.intersection(call["environment_names"]) for call in calls)
        assert all(other not in call["environment_names"] for call in calls
                   for other in ({"CLAUDE_CONFIG_DIR"} if name == "codex" else {"CODEX_HOME"}))
        assert not (Path(directory) / "auth.json").exists()
    for name in (".codex", ".claude", "unapproved-codex", "unapproved-claude"):
        assert not (home / name).exists()


def test_doctor_probes_actual_child_environment_in_empty_home(profile_cli):
    home, paths, profiles = profile_cli
    result = cli.doctor(provider_paths=paths, provider_profiles=profiles)
    assert_profile_probes(home, profiles)
    assert result["ready_for_real_execution"] is False
    for name in ("codex", "claude"):
        health = result["providers"][name]
        assert health["profile_directory"] == profiles[name] and health["probe_performed"] is True
        assert health["pin_matches"] is True and health["auth"] == "required"


def test_doctor_cli_forwards_explicit_profiles(profile_cli, monkeypatch, capsys):
    home, paths, profiles = profile_cli
    monkeypatch.setattr(sys, "argv", ["adf-worker", "doctor", "--node", "/usr/bin/node",
        "--codex", paths["codex"], "--claude", paths["claude"],
        "--codex-home", profiles["codex"], "--claude-config-dir", profiles["claude"]])
    cli.main()
    report = json.loads(capsys.readouterr().out)
    assert_profile_probes(home, profiles)
    assert report["ready_for_real_execution"] is False
    assert "synthetic-private-value" not in json.dumps(report)


def test_omitted_profiles_skip_real_cli_even_when_shell_selectors_exist(profile_cli):
    home, paths, profiles = profile_cli
    result = cli.doctor(provider_paths=paths)
    for name in ("codex", "claude"):
        health = result["providers"][name]
        assert health["error_code"] == "PROFILE_REQUIRED" and health["probe_performed"] is False
        assert health["auth"] == "unknown" and health["installed"] is None
        assert not (Path(profiles[name]) / "probe-audit.jsonl").exists()
    assert not (home / ".codex").exists()


def test_one_explicit_profile_does_not_probe_other_provider(profile_cli):
    home, paths, profiles = profile_cli
    selected = {"codex": profiles["codex"]}
    result = cli.doctor(provider_paths=paths, provider_profiles=selected)
    assert_profile_probes(home, selected)
    assert result["providers"]["claude"]["probe_performed"] is False
    assert not (Path(profiles["claude"]) / "probe-audit.jsonl").exists()


@pytest.mark.parametrize("invalid", ["missing", "public", "relative", "outside", "symlink"])
def test_invalid_operator_profile_never_falls_back(profile_cli, tmp_path, invalid):
    home, paths, profiles = profile_cli
    profile = home / "invalid"
    if invalid == "public":
        profile.mkdir(mode=0o755)
        profile.chmod(0o755)
    elif invalid == "relative":
        profile = Path("relative-profile")
    elif invalid == "outside":
        profile = tmp_path / "outside"
        profile.mkdir(mode=0o700)
    elif invalid == "symlink":
        profile.symlink_to(Path(profiles["codex"]), target_is_directory=True)
    with pytest.raises(WorkerError):
        cli.doctor(provider_paths=paths, provider_profiles={"codex": str(profile)})
    assert not (home / ".codex").exists()
    assert not (Path(profiles["codex"]) / "probe-audit.jsonl").exists()


@pytest.mark.parametrize("selector", ["CODEX_HOME", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_OAUTH_TOKEN"])
def test_doctor_flags_do_not_enable_job_environment_overrides(selector):
    with pytest.raises(WorkerError):
        restricted_env((selector,))
