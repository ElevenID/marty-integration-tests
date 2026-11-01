"""No-pull local issuer feedback preserves the pinned official runner."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("local_oidf_runner", SCRIPTS / "oidf_runner_compose.py")
assert spec and spec.loader
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_local_issuer_runner_requires_cached_digest_images_and_no_pull(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "docker-compose-prebuilt.yml").write_text("services: {}\n", encoding="utf-8")
    monkeypatch.setenv("MARTY_LOCAL_NATIVE_FUNCTIONAL_BINDING", str(tmp_path / "binding.json"))
    monkeypatch.setattr(runner, "_validate_runner_tls_environment", lambda _env: None)
    monkeypatch.setattr(runner, "docker_endpoint_is_local", lambda _env: True)
    monkeypatch.setattr(runner, "docker_command", lambda args: args)
    image = "example.com/runner@sha256:" + "a" * 64
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        if "config" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps({"services": {"server": {"image": image}}}), "")
        if "inspect" in command:
            return subprocess.CompletedProcess(command, 0, "sha256:" + "b" * 64 + "\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(runner.subprocess, "run", run)
    args = ["--runner", str(tmp_path), "--prebuilt", "--project", "oidf-runner-x",
            "--marty-project", "marty-conformance-x", "--", "up", "--detach", "--wait",
            "--pull", "never", "--no-build"]
    assert runner.main(args) == 0
    assert calls[-1][-5:] == ["--detach", "--wait", "--pull", "never", "--no-build"]

    calls.clear()
    assert runner.main(args[:-6] + ["cache-check"]) == 0
    assert len(calls) == 2 and "config" in calls[0] and "inspect" in calls[1]

    calls.clear()
    with pytest.raises(ValueError, match="disable image builds and pulls"):
        runner.main(args[:-3])
    assert not calls


def test_local_evidence_binds_three_sources_and_refuses_release_shape(tmp_path: Path) -> None:
    evidence_spec = importlib.util.spec_from_file_location("local_oidf_evidence", SCRIPTS / "oidf_conformance.py")
    assert evidence_spec and evidence_spec.loader
    module = importlib.util.module_from_spec(evidence_spec)
    evidence_spec.loader.exec_module(module)
    binding = tmp_path / "binding.json"
    roles = {role: {"sourceRevision": "a" * 40, "binary": {"sha256": "b" * 64}}
             for role in ("auth", "gateway", "signing-keys")}
    binding.write_text(json.dumps({"schema": "elevenid.local-native-functional-binding/v1",
                                   "state": "FUNCTIONAL_ONLY", "roles": roles}), encoding="utf-8")
    result = module.local_native_functional_evidence(binding)
    assert set(result["roles"]) == set(roles)
    roles.pop("gateway")
    binding.write_text(json.dumps({"schema": "elevenid.local-native-functional-binding/v1",
                                   "state": "FUNCTIONAL_ONLY", "roles": roles}), encoding="utf-8")
    with pytest.raises(ValueError, match="not closed"):
        module.local_native_functional_evidence(binding)
