"""Controller bounds and custody guards; mocked transport is not live evidence."""

import base64
import json
import ssl
from pathlib import Path
from typing import Any

import pytest

from scripts import didcomm_sender_fixture as fixture

TENANT = "00000000-0000-0000-0000-000000000011"
ISSUER = "did:web:marty.test%3A18443:orgs:owned"
RUN = "owned-run"


def provisioner(tmp_path: Path) -> fixture.SenderProvisioner:
    descriptor = tmp_path / "descriptor.json"
    descriptor.write_text(json.dumps({
        "schema": fixture.SCHEMA, "run_id": RUN, "origin": "https://openbao:8200",
        "public_origin": "https://marty.test:18443", "ca_file": "controller-only-ca",
        "names": ["interop_owned_run_sender", "interop_owned_run_mismatch"],
        "create_token": "synthetic-controller-only-test-value", "expires_at": 2**53,
    }), encoding="utf-8")
    descriptor.chmod(0o600)
    return fixture.SenderProvisioner(descriptor, Path(ssl.get_default_verify_paths().cafile), RUN)


def test_exact_binding_is_cached_but_other_tenant_cannot_reuse_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = provisioner(tmp_path)
    calls = []

    def create(tenant: str, name: str, issuer: str, fragment: str) -> dict[str, str]:
        calls.append((tenant, name, issuer))
        return {"key_reference": f"didcomm/keys/{tenant}/{name}/versions/{'a' * 32}",
                "sender_key_id": f"{issuer}#{fragment}",
                "public_key": base64.urlsafe_b64encode(bytes([len(calls)]) * 32).rstrip(b"=").decode()}

    monkeypatch.setattr(controller, "_create", create)
    first = controller.provision(TENANT, ISSUER)
    assert controller.provision(TENANT, ISSUER) == first
    assert len(calls) == 2
    first["sender"]["public_key"] = "mutated"
    assert controller.provision(TENANT, ISSUER)["sender"]["public_key"] != "mutated"
    with pytest.raises(ValueError, match="exhausted"):
        controller.provision("00000000-0000-0000-0000-000000000012", ISSUER)
    assert len(calls) == 2
    assert controller._token == ""
    assert "synthetic-controller-only" not in repr(controller)


def test_partial_failure_cannot_reset_or_leak_creation_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = provisioner(tmp_path)
    calls = []

    def fail(*args: object) -> dict[str, str]:
        calls.append(args)
        raise ValueError("provider failure")

    monkeypatch.setattr(controller, "_create", fail)
    with pytest.raises(ValueError, match="provider failure"):
        controller.provision(TENANT, ISSUER)
    with pytest.raises(ValueError, match="exhausted"):
        controller.provision(TENANT, ISSUER)
    assert len(calls) == 1
    assert controller._token == ""


@pytest.mark.parametrize(("tenant", "issuer"), [
    ("../escape", ISSUER), (TENANT, "did:web:other.test:orgs:owned"),
    (TENANT, "did:web:marty.test%3A18443:orgs:../escape"),
])
def test_unbound_inputs_fail_before_any_provider_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tenant: str, issuer: str,
) -> None:
    controller = provisioner(tmp_path)
    monkeypatch.setattr(controller, "_create", lambda *_args: pytest.fail("provider called"))
    with pytest.raises(ValueError, match="invalid|outside|UUID"):
        controller.provision(tenant, issuer)
    assert not controller._attempted


def test_stage_issues_only_two_create_operations_without_inheriting_root(tmp_path: Path) -> None:
    class Bao:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, dict[str, Any]]] = []

        def request(self, method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
            self.calls.append((method, path, body))
            if path == "auth/token/create":
                return {"auth": {"client_token": "synthetic-child-capability-value", "accessor": "synthetic-accessor"}}
            if path == "auth/token/lookup-accessor":
                return {"data": {"num_uses": 2, "policies": ["interop-owned-run"], "renewable": False, "ttl": 599}}
            return {}

    bao = Bao()
    path = fixture.stage(bao, "synthetic-root-not-exported", tmp_path, RUN,
                         "https://marty.test:18443", tmp_path / "public-ca.pem")
    policy = bao.calls[0][2]["policy"]
    assert policy.count('capabilities = ["create", "update"]') == 2
    assert 'didcomm/keys/+/interop_owned_run_sender"' in policy
    assert "pack/" not in policy
    assert "transit/" not in policy
    assert "versions/" not in policy
    assert bao.calls[1][2]["num_uses"] == 2
    assert bao.calls[1][2]["no_default_policy"]
    assert "synthetic-root-not-exported" not in path.read_text(encoding="utf-8")
    assert path.stat().st_mode & 0o077 == 0
