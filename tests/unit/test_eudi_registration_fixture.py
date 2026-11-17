"""Mocked Bao protocol tests with real local cryptographic verification.

Private test keys exist only in this simulated unit server, never the producer
or fixture output. These tests do not establish actual OpenBao custody.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "eudi_registration_fixture", ROOT / "scripts/eudi_registration_fixture.py"
)
assert SPEC is not None
assert SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
RUN = "standards490-test-r1"
ORIGIN = "https://verifier.fixture.invalid:28091"


class SimulatedBao:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.now = datetime.now(UTC) - timedelta(seconds=1)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Isolated test root")])
        self.ca = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.now - timedelta(minutes=1))
            .not_valid_after(self.now + timedelta(hours=8))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(self.ca_key, hashes.SHA256())
        )
        self.calls = []
        self.export_root = False

    def request(self, method: str, path: str, data: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((method, path, data, kwargs))
        if path.endswith("/csr"):
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(self.key, hashes.SHA256())
            return {"data": {"csr": csr.public_bytes(serialization.Encoding.PEM).decode()}}
        if path.startswith("sys/mounts/") or "/roles/" in path:
            return {}
        if path.endswith("/root/generate/internal"):
            result = {"certificate": self.ca.public_bytes(serialization.Encoding.PEM).decode()}
            if self.export_root:
                result["private_key"] = "forbidden-private-data"
            return {"data": result}
        if path.endswith("/sign/registration"):
            assert data is not None
            csr = x509.load_pem_x509_csr(data["csr"].encode())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, data["common_name"])])
            leaf = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(self.ca.subject)
                .public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(self.now - timedelta(minutes=1))
                .not_valid_after(self.now + timedelta(hours=7, minutes=50))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
                .sign(self.ca_key, hashes.SHA256())
            )
            return {"data": {"certificate": leaf.public_bytes(serialization.Encoding.PEM).decode()}}
        if path.startswith("transit/sign/"):
            assert kwargs["token"] == "scoped-token"
            assert data is not None
            assert data["key_version"] == 1
            assert data["marshaling_algorithm"] == "jws"
            signature = self.key.sign(base64.b64decode(data["input"]), ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(signature)
            return {
                "data": {
                    "signature": "vault:v1:" + base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()
                }
            }
        raise AssertionError("Unexpected simulated request")

    def public(self, *_args: object) -> str:
        return (
            self.key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )


def provision(bao: SimulatedBao) -> dict[str, Any]:
    return module.provision(
        bao,
        RUN,
        ORIGIN,
        provision_key=bao.public,
        scoped_signer=lambda *_args: "scoped-token",
        authority="private-root-authority",
    )


def load_config(path: Path, digest: str, run_id: str, origin: str) -> str:
    return module.load_bootstrap_configuration(
        path, digest, run_id, origin, client_id_prefix="x509_san_dns", original_client_id="verifier.fixture.invalid"
    )


def test_simulated_producer_emits_only_governed_public_bundle_and_verifiable_jwt() -> None:
    bao = SimulatedBao()
    bundle = provision(bao)
    assert module.validate_bundle(bundle, RUN, ORIGIN) == bundle["registration_jwt"]
    assert set(bundle) == {"registration_record", "registration_jwt", "registrar_root_certificate"}
    assert "PRIVATE KEY" not in str(bundle)
    assert "scoped-token" not in str(bundle)
    assert all("/export" not in call[1] and "/backup" not in call[1] for call in bao.calls)
    assert bundle["registration_record"]["scope"].endswith("NOT_NATIONAL_REGISTRATION")


@pytest.mark.parametrize("field", ["registration_record", "registration_jwt", "registrar_root_certificate"])
def test_rejects_replaced_record_token_or_trust_anchor(field: str) -> None:
    bundle = provision(SimulatedBao())
    if field == "registration_record":
        bundle[field]["subject"] = "another-verifier"
    elif field == "registration_jwt":
        bundle[field] = bundle[field][:-8] + "AAAAAAAA"
    else:
        bundle[field] = SimulatedBao().ca.public_bytes(serialization.Encoding.PEM).decode()
    with pytest.raises((ValueError, InvalidSignature)):
        module.validate_bundle(bundle, RUN, ORIGIN)


def test_rejects_exported_root_and_mismatched_csr() -> None:
    bao = SimulatedBao()
    bao.export_root = True
    with pytest.raises(ValueError, match="root key was exported"):
        provision(bao)
    bao = SimulatedBao()
    other = SimulatedBao()
    with pytest.raises(ValueError, match="CSR does not match"):
        module.provision(
            bao, RUN, ORIGIN, provision_key=other.public, scoped_signer=lambda *_: "scoped-token", authority="root"
        )


def test_registration_is_bound_to_exact_run_origin_and_expiry() -> None:
    bundle = provision(SimulatedBao())
    for run, origin in [("another-run", ORIGIN), (RUN, "https://another.fixture.invalid:28091")]:
        with pytest.raises(ValueError, match="record binding"):
            module.validate_bundle(bundle, run, origin)
    with pytest.raises(ValueError, match="validity"):
        module.validate_bundle(bundle, RUN, ORIGIN, datetime.now(UTC) + timedelta(hours=9))


@pytest.mark.parametrize(
    "origin",
    [
        "http://verifier.fixture.invalid",
        "https://user:pass@verifier.fixture.invalid",
        "https://verifier.fixture.invalid/path",
        "https://verifier.fixture.invalid#fragment",
    ],
)
def test_rejects_invalid_governed_verifier_origin(origin: str) -> None:
    with pytest.raises(ValueError, match="origin"):
        module.record_for(RUN, origin)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX private bootstrap file custody")
def test_bootstrap_loader_requires_pinned_owned_original_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / module.REGISTRATION_FILE
    bundle = provision(SimulatedBao())
    content = module.canonical(bundle)
    path.write_bytes(content)
    path.chmod(0o600)
    digest = hashlib.sha256(content).hexdigest()
    config = json.loads(load_config(path, digest, RUN, ORIGIN))
    assert config["verifier"]["intendedUses"][0]["registrationCertificate"] == bundle["registration_jwt"]
    with pytest.raises(ValueError, match="bootstrap pin"):
        load_config(path, "0" * 64, RUN, ORIGIN)
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match="directory custody"):
        load_config(path, digest, RUN, ORIGIN)
    tmp_path.chmod(0o700)
    original = module.os.read
    monkeypatch.setattr(module.os, "read", lambda fd, _n: original(fd, max(1, len(content) - 1)))
    with pytest.raises(ValueError, match="incomplete"):
        load_config(path, digest, RUN, ORIGIN)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX private bootstrap file custody")
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "mode", "oversize"])
def test_bootstrap_loader_rejects_unsafe_file_custody(tmp_path: Path, kind: str) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / module.REGISTRATION_FILE
    content = module.canonical(provision(SimulatedBao()))
    path.write_bytes(content)
    path.chmod(0o600)
    if kind == "symlink":
        other = tmp_path / "actual.json"
        path.rename(other)
        path.symlink_to(other)
    elif kind == "hardlink":
        os.link(path, tmp_path / "second.json")
    elif kind == "mode":
        path.chmod(0o644)
    else:
        path.write_bytes(b"x" * 262145)
    with pytest.raises((ValueError, OSError)):
        load_config(path, hashlib.sha256(content).hexdigest(), RUN, ORIGIN)


@pytest.mark.parametrize(
    ("prefix", "original"), [("x509_hash", "verifier.fixture.invalid"), ("x509_san_dns", "other.fixture.invalid")]
)
def test_registration_configuration_rejects_different_actual_client_identity(
    tmp_path: Path, prefix: str, original: str
) -> None:
    with pytest.raises(ValueError, match="client identity"):
        module.load_bootstrap_configuration(
            tmp_path / module.REGISTRATION_FILE,
            "0" * 64,
            RUN,
            ORIGIN,
            client_id_prefix=prefix,
            original_client_id=original,
        )


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX private bootstrap file custody")
def test_pinned_loader_rejects_fully_reissued_self_consistent_bundle(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / module.REGISTRATION_FILE
    original = module.canonical(provision(SimulatedBao()))
    replacement = provision(SimulatedBao())
    assert module.validate_bundle(replacement, RUN, ORIGIN)
    path.write_bytes(module.canonical(replacement))
    path.chmod(0o600)
    with pytest.raises(ValueError, match="bootstrap pin"):
        load_config(path, hashlib.sha256(original).hexdigest(), RUN, ORIGIN)


def test_registration_rejects_over_asking_record() -> None:
    bundle = provision(SimulatedBao())
    bundle["registration_record"]["credentials"][0]["claim"].append(
        {"path": ["eu.europa.ec.eudi.pid.1", "unapproved_attribute"]}
    )
    with pytest.raises(ValueError, match="record binding"):
        module.validate_bundle(bundle, RUN, ORIGIN)
