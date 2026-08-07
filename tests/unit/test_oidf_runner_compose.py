"""Regression checks for the isolated official-runner network overlay."""

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_runner_compose", ROOT / "scripts" / "oidf_runner_compose.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load OIDF runner Compose launcher")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def runner_tls_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, mode: str = "generated") -> None:
    values = {
        "OIDF_RUNNER_TLS_CERT_FILE": tmp_path / "oidf-runner-tls.crt",
        "OIDF_RUNNER_TLS_KEY_FILE": tmp_path / "oidf-runner-tls.key",
        "OIDF_RUNNER_TRUSTSTORE_FILE": tmp_path / "truststore.jks",
    }
    for name, path in values.items():
        path.write_text(name, encoding="ascii")
        if name == "OIDF_RUNNER_TLS_KEY_FILE":
            path.chmod(0o600)
        monkeypatch.setenv(name, str(path.resolve()))
    monkeypatch.setenv("OIDF_RUNNER_TRUSTSTORE_PASSWORD", "disposable-password")
    monkeypatch.setenv("OIDF_RUNNER_TLS_MODE", mode)


def test_official_runner_bridge_attaches_only_runner_server() -> None:
    overlay = (ROOT / "conformance" / "oidf-runner-bridge.compose.yml").read_text(encoding="utf-8")
    assert "  server:" in overlay
    assert "      default: {}" in overlay
    assert "      marty_oidf_bridge: {}" in overlay
    assert "external: true" in overlay
    assert "marty-network" not in overlay
    assert "OIDF_RUNNER_TLS_CERT_FILE" in overlay
    assert "OIDF_RUNNER_TLS_KEY_FILE" in overlay
    assert "OIDF_RUNNER_TRUSTSTORE_FILE" in overlay
    assert "javax.net.ssl.trustStore" in overlay
    assert "insecure" not in overlay.lower()


def test_runner_compose_helper_uses_upstream_file_and_versioned_overlay() -> None:
    helper = (ROOT / "scripts" / "oidf_runner_compose.py").read_text(encoding="utf-8")
    assert 'ROOT / "conformance" / "oidf-runner-bridge.compose.yml"' in helper
    assert 'compose_name = "docker-compose-prebuilt.yml" if args.prebuilt else "docker-compose.yml"' in helper
    assert "args.runner.resolve() / compose_name" in helper
    assert 'f"{args.marty_project}_oidf-runner"' in helper
    assert "command = docker_command(" in helper


def test_runner_uses_the_selected_docker_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "docker-compose-prebuilt.yml").write_text("services: {}", encoding="utf-8")
    runner_tls_environment(tmp_path, monkeypatch)
    calls: list[tuple[list[str], dict]] = []

    monkeypatch.setattr(
        launcher,
        "docker_command",
        lambda arguments: ["docker", "--context", "conformance-vm", *arguments],
    )
    monkeypatch.setattr(launcher, "docker_endpoint_is_local", lambda *_args: True)

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(launcher.subprocess, "run", fake_run)
    assert (
        launcher.main(
            [
                "--runner",
                str(tmp_path),
                "--prebuilt",
                "--project",
                "oidf-runner-run1",
                "--marty-project",
                "marty-conformance-run1",
                "--",
                "up",
                "--detach",
            ]
        )
        == 0
    )
    assert calls[0][0][:4] == ["docker", "--context", "conformance-vm", "compose"]


def test_runner_rejects_missing_tls_material_before_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "docker-compose-prebuilt.yml").write_text("services: {}", encoding="utf-8")
    monkeypatch.setattr(launcher, "docker_endpoint_is_local", lambda *_args: True)
    called = False

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(launcher.subprocess, "run", fake_run)
    with pytest.raises(SystemExit, match="missing OIDF runner TLS environment"):
        launcher.main(
            [
                "--runner",
                str(tmp_path),
                "--prebuilt",
                "--marty-project",
                "marty-conformance-run1",
                "--",
                "config",
            ]
        )
    assert called is False


def test_remote_runner_rejects_client_generated_tls_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "docker-compose-prebuilt.yml").write_text("services: {}", encoding="utf-8")
    runner_tls_environment(tmp_path, monkeypatch)
    monkeypatch.setattr(launcher, "docker_endpoint_is_local", lambda *_args: False)

    with pytest.raises(SystemExit, match="cannot be bind-mounted through a remote Docker context"):
        launcher.main(
            [
                "--runner",
                str(tmp_path),
                "--prebuilt",
                "--marty-project",
                "marty-conformance-run1",
                "--",
                "config",
            ]
        )


def test_runner_rejects_nonconformance_project_names(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="isolated marty-conformance"):
        launcher.main(
            [
                "--runner",
                str(tmp_path),
                "--marty-project",
                "production",
                "--",
                "ps",
            ]
        )
    with pytest.raises(SystemExit, match="oidf-runner"):
        launcher.main(
            [
                "--runner",
                str(tmp_path),
                "--marty-project",
                "marty-conformance-run1",
                "--project",
                "shared",
                "--",
                "ps",
            ]
        )


def test_prebuilt_runner_images_are_pinned_by_digest() -> None:
    overlay = (ROOT / "conformance" / "oidf-runner-prebuilt.compose.yml").read_text(encoding="utf-8")
    assert "registry.gitlab.com/openid/conformance-suite@sha256:" in overlay
    assert "registry.gitlab.com/openid/conformance-suite/nginx@sha256:" in overlay
    assert "mongo@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070" in overlay
    assert ":latest" not in overlay


def test_runner_compose_helper_selects_the_pinned_prebuilt_variant() -> None:
    helper = (ROOT / "scripts" / "oidf_runner_compose.py").read_text(encoding="utf-8")
    assert '"docker-compose-prebuilt.yml" if args.prebuilt' in helper
    assert 'ROOT / "conformance" / "oidf-runner-prebuilt.compose.yml"' in helper
