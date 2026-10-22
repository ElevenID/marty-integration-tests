import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


SOURCE = Path(__file__).parents[2] / "scripts" / "official_kms_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("official_kms_bootstrap", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_bootstrap_discovers_required_inputs_in_extended_native_service(tmp_path: Path) -> None:
    base = tmp_path / "docker-compose.base.yml"
    native = tmp_path / "docker-compose.native.yml"
    service = tmp_path / "docker-compose.service.issuance-native.yml"
    base.write_text("services:\n  openbao:\n    image: ${MARTY_OPENBAO_DIDCOMM_IMAGE:?pin plugin}\n", encoding="utf-8")
    native.write_text("services:\n  issuance-native:\n    extends:\n      file: docker-compose.service.issuance-native.yml\n      service: issuance-native\n", encoding="utf-8")
    service.write_text("services:\n  issuance-native:\n    environment:\n      TOKEN_HMAC_KEY: ${TOKEN_HMAC_KEY:?required}\n", encoding="utf-8")
    compose = ["docker", "compose", "--file", str(base), "--file", str(native)]
    assert MODULE.compose_sources(compose) == {base, native, service}
    environment = MODULE.placeholder_environment(
        compose, {"MARTY_OPENBAO_DIDCOMM_IMAGE": "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "a" * 64,
                  "MARTY_KEYCLOAK_IMAGE": "ghcr.io/elevenid/marty-ui-oss/keycloak@sha256:" + "b" * 64},
        tmp_path, "marty-conformance-test123", {"OIDF_PUBLIC_BASE_URL": "https://marty.test"},
    )
    assert environment["TOKEN_HMAC_KEY"] == "bootstrap-only"
    assert environment["MARTY_CONFORMANCE_PROJECT"] == "marty-conformance-test123"


def test_bootstrap_rejects_plain_openbao_in_released_conformance_graph(monkeypatch, tmp_path: Path) -> None:
    plugin = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "a" * 64
    services = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64
    graph = {"services": {name: {"image": plugin} for name in ("openbao", "openbao-tls-init", "openbao-init")}}
    graph["services"]["issuance-native"] = {"image": services}
    monkeypatch.setattr(MODULE, "run", lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(graph)))
    images = {"MARTY_OPENBAO_DIDCOMM_IMAGE": plugin, "MARTY_SERVICES_IMAGE": services}
    MODULE.require_kms_only_images(["docker", "compose"], {}, tmp_path, images)
    graph["services"]["openbao"]["image"] = "quay.io/openbao/openbao@sha256:" + "c" * 64
    with pytest.raises(ValueError, match="replaces its attested KMS-only OpenBao plugin"):
        MODULE.require_kms_only_images(["docker", "compose"], {}, tmp_path, images)


def test_runtime_environment_requires_exact_private_kms_inputs(tmp_path: Path) -> None:
    tls, keycloak, extra = (tmp_path / name for name in ("tls", "keycloak", "extra"))
    for directory in (tls, keycloak, extra):
        directory.mkdir()
    for filename in MODULE.KEYCLOAK_FILES.values():
        (keycloak / filename).write_text("scoped", encoding="ascii")
    for prefix, (certificate, token, _) in MODULE.ENV_ROLES.items():
        directory = extra if prefix == "ENVOY_ISSUANCE" else tls
        (directory / certificate).write_text("certificate", encoding="ascii")
        (directory / token).write_text("scoped", encoding="ascii")
    for path in (tls / "workload_identity_ca_cert", tmp_path / "ca.crt",
                 extra / "oidf_edge_tls_kms_token", extra / "oidf-edge.crt"):
        path.write_text("certificate", encoding="ascii")
    origin = "https://marty-oidf.test:18443"
    values = MODULE.runtime_environment(tls, keycloak, extra, tmp_path / "ca.crt",
                                        {"OIDF_PUBLIC_BASE_URL": origin},
                                        ("official-test-oidf-edge", extra / "oidf-edge.crt"))
    MODULE.validate_runtime_environment(values, tmp_path, origin)
    with pytest.raises(ValueError, match="origin is invalid"):
        MODULE.validate_runtime_environment({**values, "OIDF_TLS_KMS_ADDR": "http://openbao:8200"},
                                            tmp_path, origin)
    with pytest.raises(ValueError, match="missing or unsupported"):
        MODULE.validate_runtime_environment({key: value for key, value in values.items()
                                             if key != "OIDF_TLS_KMS_TOKEN_FILE"}, tmp_path, origin)
