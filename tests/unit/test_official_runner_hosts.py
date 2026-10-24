import importlib.util
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
