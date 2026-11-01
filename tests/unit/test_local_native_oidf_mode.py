"""No-pull local issuer feedback preserves the pinned official runner."""

from __future__ import annotations

import importlib.util
import ast
import json
import subprocess
import sys
from types import SimpleNamespace
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


def test_partial_local_up_always_downs_exact_project_even_if_diagnostic_fails() -> None:
    source = ast.parse((SCRIPTS / "official_interoperability_lane.py").read_text(encoding="utf-8"))
    selected = [node for node in source.body if isinstance(node, ast.FunctionDef)
                and node.name in {"run_oid4vci_issuer", "down_local_native_issuer"}]
    code = compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                   "official_interoperability_lane.py", "exec")
    calls: list[str] = []

    def run(command, _environment, **_kwargs):
        calls.append(command[0])
        return 1 if command[0] == "up" else 0

    def failed_diagnostic(_run_id):
        raise RuntimeError("diagnostic failed")

    namespace = {"argparse": __import__("argparse"), "subprocess": subprocess, "run": run,
                 "compose_command": lambda _args, action, **_kwargs: [action],
                 "emit_keycloak_initializer_diagnostic": failed_diagnostic}
    exec(code, namespace)
    args = SimpleNamespace(run_id="owned", local_native_functional_binding="private-binding")
    with pytest.raises(RuntimeError, match="diagnostic failed"):
        namespace["run_oid4vci_issuer"](args, {})
    assert calls == ["up", "down"]


def test_local_log_failure_still_cleans_project_and_failed_down_surfaces(tmp_path: Path) -> None:
    source = ast.parse((SCRIPTS / "official_interoperability_lane.py").read_text(encoding="utf-8"))
    selected = [node for node in source.body if isinstance(node, ast.FunctionDef)
                and node.name in {"run_oid4vci_issuer", "down_local_native_issuer"}]
    namespace = {"argparse": __import__("argparse"), "subprocess": subprocess,
                 "compose_command": lambda _args, action, **_kwargs: [action],
                 "wait_for_public_stack": lambda _env: (_ for _ in ()).throw(RuntimeError("readiness failed")),
                 "emit_oid4vci_runtime_diagnostic": lambda _path: None}
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                 "official_interoperability_lane.py", "exec"), namespace)
    args = SimpleNamespace(run_id="owned", local_native_functional_binding="private-binding",
                           output_dir=tmp_path)
    calls: list[str] = []

    def log_failed(command, _environment, **_kwargs):
        calls.append(command[0])
        if command[0] == "logs":
            raise OSError("log capture failed")
        return 0

    namespace["run"] = log_failed
    with pytest.raises(OSError, match="log capture failed"):
        namespace["run_oid4vci_issuer"](args, {})
    assert calls == ["up", "logs", "down"]
    calls.clear()

    def down_failed(command, _environment, **_kwargs):
        calls.append(command[0])
        return 1 if command[0] == "down" else 0

    namespace["run"] = down_failed
    with pytest.raises(RuntimeError, match="cleanup failed"):
        namespace["run_oid4vci_issuer"](args, {})
    assert calls == ["up", "logs", "down"]
    calls.clear()

    def timed_out(command, _environment, **_kwargs):
        calls.append(command[0])
        if command[0] == "up":
            raise OSError("startup transport timed out")
        return 0

    namespace["run"] = timed_out
    with pytest.raises(OSError, match="timed out"):
        namespace["run_oid4vci_issuer"](args, {})
    assert calls == ["up", "down"]


def test_native_binding_drift_rejected_after_official_issuer_test() -> None:
    source = ast.parse((SCRIPTS / "official_interoperability_lane.py").read_text(encoding="utf-8"))
    selected = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                    and node.name == "require_stable_local_native_attestation")
    namespace: dict = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[selected], type_ignores=[])),
                 "official_interoperability_lane.py", "exec"), namespace)
    check = namespace["require_stable_local_native_attestation"]
    before = {"schema": "elevenid.local-native-runtime-attestation/v1", "project": "marty-conformance-owned",
              "roles": {"auth": {"cid": "a" * 64}}, "bindingSha256": "b" * 64,
              "state": "FUNCTIONAL_ONLY", "releaseQualified": False}
    check(before, dict(before))
    with pytest.raises(RuntimeError, match="binding identity changed"):
        check(before, {**before, "bindingSha256": "c" * 64})
    with pytest.raises(RuntimeError, match="binding identity changed"):
        check(before, {**before, "roles": {"auth": {"cid": "d" * 64}}})
