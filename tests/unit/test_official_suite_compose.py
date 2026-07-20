"""Tests for the cross-project official-suite Compose lifecycle."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("official_suite_compose", ROOT / "scripts" / "official_suite_compose.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official suite Compose lifecycle")
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)
haip = importlib.import_module("haip_test_certificates")


def marty_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "marty-ui"
    script = checkout / "scripts" / "conformance_stack.py"
    script.parent.mkdir(parents=True)
    script.write_text("# test fixture\n", encoding="utf-8")
    return checkout


def component(command: list[str]) -> str:
    rendered = " ".join(command)
    if "oidf_runner_compose.py" in rendered:
        return "oidf"
    if "eudi_reference_compose.py" in rendered:
        return "eudi"
    if "conformance_stack.py" in rendered:
        return "marty"
    raise AssertionError(f"unknown command: {rendered}")


def action(command: list[str]) -> str:
    for value in ("up", "down", "ps", "logs"):
        if value in command:
            return value
    raise AssertionError(f"no Compose action in {command}")


def haip_material(tmp_path: Path, name: str) -> Path:
    output = tmp_path / name
    haip.generate_material(output, gateway_url="https://verifier.example:8443")
    return output


def test_projects_are_unique_and_scoped() -> None:
    assert lifecycle.project_names("123-1") == {
        "marty": "marty-conformance-123-1",
        "oidf": "oidf-runner-123-1",
        "eudi": "eudi-reference-123-1",
    }
    with pytest.raises(ValueError, match="run id"):
        lifecycle.project_names("production/stack")


def test_selected_context_is_forwarded_to_marty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setenv(lifecycle.CONTEXT_ENV, "conformance-vm")
    monkeypatch.setattr(
        lifecycle,
        "docker_command",
        lambda arguments: calls.append(arguments) or ["docker", "--context", "conformance-vm", *arguments],
    )
    environment = lifecycle.child_environment()
    assert calls == [["info"]]
    assert environment["DOCKER_CONTEXT"] == "conformance-vm"


def test_generated_haip_material_is_wired_to_marty(tmp_path: Path) -> None:
    material = haip_material(tmp_path, "generated")
    environment: dict[str, str] = {}
    lifecycle.configure_haip_environment(environment, material)
    assert environment["VERIFIER_SIGNING_KEY_PEM"] == (material / haip.KEY_FILE).read_text(encoding="ascii")
    assert environment["VERIFIER_X509_CERT_PEM"] == (material / haip.CERTIFICATE_FILE).read_text(encoding="ascii")


def test_external_haip_pem_pair_takes_precedence(tmp_path: Path) -> None:
    generated = haip_material(tmp_path, "generated")
    external = haip_material(tmp_path, "external")
    signing_key = (external / haip.KEY_FILE).read_text(encoding="ascii")
    certificate = (external / haip.CERTIFICATE_FILE).read_text(encoding="ascii")
    environment = {
        "VERIFIER_SIGNING_KEY_PEM": signing_key,
        "VERIFIER_X509_CERT_PEM": certificate,
    }
    lifecycle.configure_haip_environment(environment, generated)
    assert environment == {
        "VERIFIER_SIGNING_KEY_PEM": signing_key,
        "VERIFIER_X509_CERT_PEM": certificate,
    }


def test_haip_rejects_a_partial_external_pair(tmp_path: Path) -> None:
    material = haip_material(tmp_path, "generated")
    environment = {
        "VERIFIER_SIGNING_KEY_PEM": (material / haip.KEY_FILE).read_text(encoding="ascii"),
    }
    with pytest.raises(ValueError, match="set both"):
        lifecycle.configure_haip_environment(environment, material)


def test_failed_up_unwinds_only_started_projects_in_reverse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(lifecycle, "child_environment", dict)

    def fake_run(command: list[str], _environment: dict[str, str]) -> int:
        call = (component(command), action(command))
        calls.append(call)
        return 17 if call == ("oidf", "up") else 0

    monkeypatch.setattr(lifecycle, "run", fake_run)
    result = lifecycle.main(
        [
            "up",
            "--run-id",
            "run1",
            "--marty-ui",
            str(marty_checkout(tmp_path)),
            "--oidf-runner",
            str(tmp_path / "oidf"),
            "--oidf",
            "--eudi",
        ]
    )
    assert result == 17
    assert calls == [
        ("marty", "up"),
        ("oidf", "up"),
        ("oidf", "down"),
        ("marty", "down"),
    ]


def test_down_always_runs_eudi_oidf_then_marty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(lifecycle, "child_environment", dict)
    monkeypatch.setattr(
        lifecycle,
        "run",
        lambda command, _environment: calls.append((component(command), action(command))) or 0,
    )
    assert (
        lifecycle.main(
            [
                "down",
                "--run-id",
                "run1",
                "--marty-ui",
                str(marty_checkout(tmp_path)),
                "--oidf-runner",
                str(tmp_path / "oidf"),
                "--oidf",
                "--eudi",
            ]
        )
        == 0
    )
    assert calls == [
        ("eudi", "down"),
        ("oidf", "down"),
        ("marty", "down"),
    ]
