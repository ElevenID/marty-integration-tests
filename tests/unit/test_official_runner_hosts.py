import importlib.util
import sys
from pathlib import Path

import pytest

SOURCE = Path(__file__).parents[2] / "scripts/official_runner_hosts.py"
SPEC = importlib.util.spec_from_file_location("official_runner_hosts", SOURCE)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def report(gateway: str = "https://marty-oidf.test:18443") -> dict:
    return {
        "schema": "elevenid.eudi-test-material-report/v1",
        "urls": {"gateway": gateway, "verifier": "https://marty-oidf.test:28091",
                 "wallet": "http://127.0.0.1:29090", "local": "http://localhost:8080"},
    }


def test_generated_clients_share_deduplicated_names_without_ip_aliases() -> None:
    assert MODULE.material_aliases(report()) == ["localhost.emobix.co.uk", "marty-oidf.test"]


@pytest.mark.parametrize("gateway", ["https://user:secret@marty.test", "https://marty.test\nevil", "file:///etc/hosts"])
def test_invalid_material_cannot_stage_hostnames(gateway: str) -> None:
    with pytest.raises(ValueError, match="generated material URL"):
        MODULE.material_aliases(report(gateway))


@pytest.mark.parametrize(("address", "aliases"), [
    ("not-an-ip", ["openbao"]), ("127.0.0.1", ["good.test\nevil.test"]),
    ("127.0.0.1", ["good.test # comment"]), ("127.0.0.1", []),
])
def test_invalid_host_records_are_rejected_before_writer(
    address: str, aliases: list[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_writer(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("invalid alias reached privileged writer")

    monkeypatch.setattr(MODULE.subprocess, "Popen", forbidden_writer)
    with pytest.raises(ValueError, match="invalid|address"):
        MODULE.append_host_aliases(address, aliases)


def test_existing_correct_alias_is_not_appended_again() -> None:
    existing = "127.0.0.1 localhost marty-oidf.test\n"
    assert MODULE.missing_aliases(existing, ["marty-oidf.test", "localhost.emobix.co.uk"]) == [
        "localhost.emobix.co.uk"
    ]


def test_conflicting_alias_is_preserved_and_rejected() -> None:
    with pytest.raises(ValueError, match="conflicting"):
        MODULE.missing_aliases("192.0.2.1 marty-oidf.test\n", ["marty-oidf.test"])


def test_workflow_uses_the_shared_material_host_setup() -> None:
    workflow = (SOURCE.parents[1] / ".github/workflows/official-interoperability.yml").read_text(encoding="utf-8")
    assert "python scripts/official_runner_hosts.py --material-report work/material/report.json --install" in workflow


@pytest.mark.skipif(sys.platform != "linux", reason="Linux private hosts custody")
def test_owned_namespace_hosts_preserves_existing_records_without_elevation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"127.0.0.1 localhost\n# preserved fixture comment\n")
    hosts.chmod(0o600)
    monkeypatch.setenv("MARTY_OFFICIAL_PRIVATE_HOSTS", "1")
    monkeypatch.setattr(MODULE, "HOSTS_FILE", hosts)
    monkeypatch.setattr(MODULE.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("sudo writer used"))
    MODULE.append_host_aliases("192.0.2.1", ["openbao"])
    assert hosts.read_bytes() == b"127.0.0.1 localhost\n# preserved fixture comment\n\n192.0.2.1 openbao\n"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux private hosts custody")
def test_owned_hosts_refuses_symlinks_and_writable_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"preserve")
    link = tmp_path / "hosts"
    link.symlink_to(target)
    monkeypatch.setenv("MARTY_OFFICIAL_PRIVATE_HOSTS", "1")
    monkeypatch.setattr(MODULE, "HOSTS_FILE", link)
    with pytest.raises(ValueError, match="regular"):
        MODULE.append_host_aliases("127.0.0.1", ["openbao"])
    monkeypatch.setattr(MODULE, "HOSTS_FILE", target)
    target.chmod(0o666)
    with pytest.raises(ValueError, match="custody"):
        MODULE.append_host_aliases("127.0.0.1", ["openbao"])
    assert target.read_bytes() == b"preserve"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux private hosts custody")
def test_private_hosts_wrong_owner_refuses_privileged_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"preserve")
    monkeypatch.setenv("MARTY_OFFICIAL_PRIVATE_HOSTS", "1")
    monkeypatch.setattr(MODULE, "HOSTS_FILE", hosts)
    monkeypatch.setattr(MODULE.os, "getuid", lambda: hosts.stat().st_uid + 1)
    monkeypatch.setattr(MODULE.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("sudo writer used"))
    with pytest.raises(ValueError, match="custody is unavailable"):
        MODULE.append_host_aliases("127.0.0.1", ["openbao"])
    assert hosts.read_bytes() == b"preserve"
