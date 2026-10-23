from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from official_process_environment import GITHUB_AUTH_KEYS, subprocess_environment  # noqa: E402


@pytest.mark.parametrize("module_name", ["official_interoperability_lane", "official_suite_compose"])
@pytest.mark.parametrize("native_attestation", [False, True])
def test_both_subprocess_boundaries_strip_auth_unless_native_startup_opts_in(
    monkeypatch: pytest.MonkeyPatch, module_name: str, native_attestation: bool,
) -> None:
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "scripts" / f"{module_name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("GH_TOKEN", "synthetic-native-attestation-authority")
    incoming = dict.fromkeys(GITHUB_AUTH_KEYS, "synthetic-upstream-must-not-inherit")
    incoming["OFFICIAL_SUITE_RUN_ID"] = "synthetic-1"
    observed = []

    def capture(_command: list[str], **options: Any) -> SimpleNamespace:
        observed.append(options["env"])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module.subprocess, "run", capture)
    assert module.run([sys.executable, "controlled-entrypoint.py"], incoming,
                      native_attestation=native_attestation) == 0
    environment = observed[0]
    assert set(environment) & GITHUB_AUTH_KEYS == ({"GH_TOKEN"} if native_attestation else set())
    if native_attestation:
        assert environment["GH_TOKEN"] == "synthetic-native-attestation-authority"
    assert set(incoming) & GITHUB_AUTH_KEYS == GITHUB_AUTH_KEYS
    assert environment["OFFICIAL_SUITE_RUN_ID"] == "synthetic-1"


def test_real_child_receives_no_github_authority_by_default() -> None:
    incoming = {**os.environ, **dict.fromkeys(GITHUB_AUTH_KEYS, "synthetic-authority")}
    child = subprocess.run(
        [sys.executable, "-c", "import os,json;print(json.dumps(sorted(k for k in os.environ if k in "
         "['GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN'])))"],
        env=subprocess_environment(incoming), capture_output=True, text=True, check=True,
    )
    assert json.loads(child.stdout) == []


def test_certificate_refresh_scopes_attestation_authority_to_native_launcher(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "refresh_lane", ROOT / "scripts" / "official_interoperability_lane.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("GH_TOKEN", "synthetic-trusted-startup-authority")
    monkeypatch.setattr(module, "issue_verifier_certificate", lambda *_a, **_kw: {
        "certificate_sha256": "sha256:" + "0" * 64, "dns_names": "issuer.test",
    })
    certificate = {"VERIFIER_X509_CERT_PEM": "synthetic-public-certificate"}
    monkeypatch.setattr(module, "load_verifier_environment", lambda *_a: certificate)
    monkeypatch.setattr(module, "wait_for_public_stack", lambda *_a: None)
    observed: list[tuple[list[str], dict[str, str]]] = []

    def capture(command: list[str], **options: Any) -> SimpleNamespace:
        observed.append((command, options["env"]))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module.subprocess, "run", capture)
    args = SimpleNamespace(
        marty_ui=tmp_path / "marty-ui", haip_material=tmp_path / "haip",
        run_id="refresh-1", stack_manifest=tmp_path / "stack-manifest.json",
        release_ui_revision="f" * 40,
    )
    incoming = dict.fromkeys(GITHUB_AUTH_KEYS, "synthetic-untrusted-input")
    incoming["OIDF_MARTY_GATEWAY_URL"] = "https://issuer.test"
    assert module.refresh_request_signing_certificate(args, incoming, {}) == certificate
    assert module.run([sys.executable, "official-upstream.py"], incoming) == 0
    command, environment = observed[0]
    assert command[1] == str((args.marty_ui / "scripts" / "conformance_stack.py").resolve())
    assert "--resume" in command and command[-1] == "up"
    assert set(environment) & GITHUB_AUTH_KEYS == {"GH_TOKEN"}
    assert environment["GH_TOKEN"] == "synthetic-trusted-startup-authority"
    assert not set(observed[1][1]) & GITHUB_AUTH_KEYS
