"""Regression checks for the isolated official-runner network overlay."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_official_runner_bridge_attaches_only_runner_server() -> None:
    overlay = (ROOT / "conformance" / "oidf-runner-bridge.compose.yml").read_text(encoding="utf-8")
    assert "  server:" in overlay
    assert "      default: {}" in overlay
    assert "      marty_oidf_bridge: {}" in overlay
    assert "external: true" in overlay
    assert "marty-network" not in overlay


def test_runner_compose_helper_uses_upstream_file_and_versioned_overlay() -> None:
    helper = (ROOT / "scripts" / "oidf_runner_compose.py").read_text(encoding="utf-8")
    assert 'ROOT / "conformance" / "oidf-runner-bridge.compose.yml"' in helper
    assert 'compose_name = "docker-compose-prebuilt.yml" if args.prebuilt else "docker-compose.yml"' in helper
    assert "args.runner.resolve() / compose_name" in helper
    assert 'f"{args.marty_project}_oidf-runner"' in helper
    assert '"docker", "compose"' in helper


def test_prebuilt_runner_images_are_pinned_by_digest() -> None:
    overlay = (ROOT / "conformance" / "oidf-runner-prebuilt.compose.yml").read_text(encoding="utf-8")
    assert "registry.gitlab.com/openid/conformance-suite@sha256:" in overlay
    assert "registry.gitlab.com/openid/conformance-suite/nginx@sha256:" in overlay
    assert ":latest" not in overlay


def test_runner_compose_helper_selects_the_pinned_prebuilt_variant() -> None:
    helper = (ROOT / "scripts" / "oidf_runner_compose.py").read_text(encoding="utf-8")
    assert '"docker-compose-prebuilt.yml" if args.prebuilt' in helper
    assert 'ROOT / "conformance" / "oidf-runner-prebuilt.compose.yml"' in helper
