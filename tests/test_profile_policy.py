import json
import os

import pytest

from adf_runtime_worker.models import WorkerError
from adf_runtime_worker.profile_policy import SealedProfilePolicy, private_bytes
from adf_runtime_worker.shared_server import clean_config, server_command
from adf_runtime_worker.profiles import ProviderProfile

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux no-follow private policy")


def rebuild(policy):
    return SealedProfilePolicy(policy.root, policy.profile, policy.manifest)


def config(policy, text):
    path = policy.profile / "config.toml"
    path.write_text(text)
    path.chmod(0o600)
    return path


def test_absence_and_exact_trust_are_sealed_without_writes(sealed_policy):
    policy = sealed_policy
    policy.check()
    assert not (policy.profile / "config.toml").exists()
    text = '[projects.' + json.dumps(str(policy.repositories[0])) + ']\ntrust_level = "trusted"\n'
    path = config(policy, text)
    with pytest.raises(WorkerError):
        policy.check()
    accepted = rebuild(policy)
    before = path.stat()
    accepted.check()
    assert path.read_text() == text
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    with pytest.raises(WorkerError):
        clean_config(policy.profile)


@pytest.mark.parametrize("text", [
    '', 'model = "POLICY_VALUE_MUST_NOT_ESCAPE"', 'model_provider = "other"', 'notice = {}',
    '[mcp_servers]\nx = {}', '[hooks]\nx = {}', '[features]\napps = true',
    'env = "POLICY_VALUE_MUST_NOT_ESCAPE"', 'include = "other"', 'profile = "other"',
    '[projects."/tmp/unlisted"]\ntrust_level = "trusted"', '[projects."*"]\ntrust_level = "trusted"',
    'projects = {}', '[projects', 'projects = {}\nprojects = {}',
    'x=' + '{a=' * 2000 + '1' + '}' * 2000,
])
def test_config_has_closed_schema_and_fixed_errors(sealed_policy, text):
    config(sealed_policy, text)
    with pytest.raises(WorkerError) as error:
        rebuild(sealed_policy)
    assert str(error.value) == "Shared operator policy validation failed"
    assert "POLICY_VALUE" not in str(error.value)


@pytest.mark.parametrize("extra", ['trust_level = "untrusted"', 'trust_level = true', 'trust_level = "trusted"\nmodel = "other"'])
def test_project_fields_and_values_are_exact(sealed_policy, extra):
    config(sealed_policy, '[projects.' + json.dumps(str(sealed_policy.repositories[0])) + ']\n' + extra)
    with pytest.raises(WorkerError):
        rebuild(sealed_policy)


@pytest.mark.parametrize("kind", ["symlink", "loop", "hardlink", "mode", "large", "directory", "fifo"])
@pytest.mark.parametrize("target", ["manifest", "config"])
def test_policy_files_reject_unsafe_metadata(sealed_policy, kind, target):
    path = sealed_policy.manifest if target == "manifest" else config(sealed_policy, 'projects = {}')
    if kind == "symlink":
        destination = path.with_suffix(".saved")
        path.rename(destination)
        path.symlink_to(destination)
    elif kind == "loop":
        path.unlink()
        path.symlink_to(path.name)
    elif kind == "hardlink":
        os.link(path, path.with_suffix(".alias"))
    elif kind == "mode":
        path.chmod(0o644)
    elif kind == "large":
        path.write_bytes(b" " * 65537)
    elif kind == "directory":
        path.unlink()
        path.mkdir(mode=0o600)
    else:
        path.unlink()
        os.mkfifo(path, 0o600)
    with pytest.raises(WorkerError):
        rebuild(sealed_policy)


@pytest.mark.parametrize("data", [
    {"version": True, "project_roots": []}, {"version": 1, "project_roots": []},
    {"version": 1, "project_roots": ["/unapproved-root"]}, {"version": 1, "project_roots": [42]},
    {"version": 1, "project_roots": [], "config": {}},
])
def test_manifest_is_closed_and_cannot_broaden_roots(sealed_policy, data):
    sealed_policy.manifest.write_text(json.dumps(data))
    with pytest.raises(WorkerError):
        rebuild(sealed_policy)


def test_duplicate_manifest_keys_and_roots_rejected(sealed_policy):
    policy = sealed_policy
    policy.manifest.write_text('{"version":1,"version":1,"project_roots":[]}')
    with pytest.raises(WorkerError):
        rebuild(policy)
    policy.manifest.write_text(json.dumps({"version": 1, "project_roots": [str(policy.repositories[0])] * 2}))
    with pytest.raises(WorkerError):
        rebuild(policy)


@pytest.mark.parametrize("layer", ["rules", "skills", "AGENTS.md", "environments.toml"])
def test_broken_symlink_layers_are_denied(sealed_policy, layer):
    (sealed_policy.profile / layer).symlink_to(sealed_policy.profile / "missing")
    with pytest.raises(WorkerError):
        rebuild(sealed_policy)
    with pytest.raises(WorkerError):
        clean_config(sealed_policy.profile)


def test_main_repository_ancestor_layers_are_denied(sealed_policy):
    (sealed_policy.repositories[0].parent / ".codex").symlink_to("missing")
    with pytest.raises(WorkerError):
        sealed_policy.check()


def test_replacement_during_read_and_identical_bytes_after_seal_are_denied(sealed_policy, monkeypatch):
    path = sealed_policy.manifest
    original = os.read
    replaced = False
    def read(fd, size):
        nonlocal replaced
        raw = original(fd, size)
        if not replaced:
            replaced = True
            replacement = path.with_suffix(".new")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(path)
        return raw
    monkeypatch.setattr(os, "read", read)
    with pytest.raises(WorkerError):
        private_bytes(path)
    monkeypatch.setattr(os, "read", original)
    with pytest.raises(WorkerError):
        sealed_policy.check()


def test_validation_precedes_native_probe_and_override_is_owner_derived(sealed_policy, monkeypatch):
    from adf_runtime_worker.adapters import CodexAdapter
    policy = sealed_policy
    monkeypatch.setenv("HOME", str(policy.root.parent))
    probes = []
    monkeypatch.setattr(CodexAdapter, "probe", lambda *_: probes.append(True) or {"health": "ready"})
    selected = ProviderProfile("codex", policy.profile)
    from adf_runtime_worker.native_read_policy import NativeReadPolicy
    tool = policy.root / "tools" / "public-bin"
    tool.mkdir(mode=0o700)
    manifest = policy.root / "tools" / "native-read.json"
    manifest.write_text(json.dumps({"version": 1, "read_tool_roots": [str(tool)]}))
    manifest.chmod(0o600)
    native = NativeReadPolicy(policy, manifest)
    argv, _, _ = server_command("never-executed-codex", selected, policy, native)
    assert probes == [True]
    assert any(arg.startswith("projects=") for arg in argv)
    assert not (policy.profile / "config.toml").exists()
    config(policy, 'model = "POLICY_VALUE_MUST_NOT_ESCAPE"')
    for candidate in (None, policy):
        with pytest.raises(WorkerError):
            server_command("never-executed-codex", selected, candidate)
    assert probes == [True]


def test_noncanonical_or_job_owned_manifest_location_is_denied(sealed_policy):
    policy = sealed_policy
    alias = policy.root / "alias"
    alias.symlink_to(policy.manifest.parent, target_is_directory=True)
    for path in (alias / policy.manifest.name, policy.repositories[0] / "policy.json"):
        if path.parent == policy.repositories[0]:
            path.write_bytes(policy.manifest.read_bytes())
            path.chmod(0o600)
        with pytest.raises(WorkerError):
            SealedProfilePolicy(policy.root, policy.profile, path)
