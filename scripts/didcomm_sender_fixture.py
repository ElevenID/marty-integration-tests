"""Run-scoped non-exportable sender provisioning for owned Gateway evidence.

The bootstrap authority stays in the controller. Its two-use, create-only
capability is mounted only into the existing fixture controller; peer tests
receive public binding metadata, never an OpenBao token or sender secret.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import ssl
import stat
import threading
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_BYTES = 16 * 1024
SCHEMA = "elevenid.didcomm-sender-bootstrap/v1"


def stage(bao: Any, authority: str, directory: Path, run_id: str,
          public_origin: str, ca_file: Path) -> Path:
    """Create only two named sender keys in this fresh disposable Bao."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}[a-z0-9]", run_id):
        raise ValueError("invalid DIDComm fixture run")
    names = [f"interop_{run_id.replace('-', '_')}_{kind}" for kind in ("sender", "mismatch")]
    policy_name = f"interop-{run_id}"
    policy = "\n".join(
        f'path "didcomm/keys/+/{name}" {{ capabilities = ["create", "update"] }}'
        for name in names
    )
    bao.request("PUT", f"sys/policies/acl/{policy_name}", {"policy": policy})
    auth = bao.request("POST", "auth/token/create", {
        "policies": [policy_name], "no_default_policy": True,
        "ttl": "10m", "explicit_max_ttl": "10m", "renewable": False,
        "num_uses": 2,
    })["auth"]
    token = auth.get("client_token")
    accessor = auth.get("accessor")
    if not isinstance(token, str) or len(token) < 20 or token == authority or not accessor:
        raise ValueError("invalid DIDComm create-only capability")
    # Operator lookup does not consume either use of the child capability.
    metadata = bao.request("POST", "auth/token/lookup-accessor", {"accessor": accessor})["data"]
    if (metadata.get("num_uses") != 2 or metadata.get("policies") != [policy_name]
            or metadata.get("renewable") is not False
            or not 0 < metadata.get("ttl", 0) <= 600):
        raise ValueError("DIDComm create-only capability exceeds its scope")
    path = directory / "didcomm-sender-bootstrap.json"
    descriptor = {
        "schema": SCHEMA, "run_id": run_id, "origin": "https://openbao:8200",
        "public_origin": public_origin, "ca_file": str(ca_file),
        "names": names, "create_token": token, "expires_at": int(time.time()) + 600,
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(descriptor, output, separators=(",", ":"))
        output.write("\n")
    return path


class SenderProvisioner:
    """One tenant/issuer pair, at most two create calls, public output only."""

    def __init__(self, descriptor: Path, ca_file: Path, run_id: str) -> None:
        info = descriptor.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_uid != os.getuid() or info.st_size > MAX_BYTES):
            raise ValueError("unsafe DIDComm fixture descriptor")
        data = json.loads(descriptor.read_text(encoding="utf-8"))
        required = {"schema", "run_id", "origin", "public_origin", "ca_file",
                    "names", "create_token", "expires_at"}
        if set(data) != required or data["schema"] != SCHEMA or data["run_id"] != run_id:
            raise ValueError("DIDComm fixture source mismatch")
        if data["origin"] != "https://openbao:8200":
            raise ValueError("DIDComm fixture origin mismatch")
        expected_names = [f"interop_{run_id.replace('-', '_')}_{kind}" for kind in ("sender", "mismatch")]
        if data["names"] != expected_names or not isinstance(data["create_token"], str):
            raise ValueError("DIDComm fixture capability mismatch")
        origin = urlsplit(data["public_origin"])
        if (origin.scheme != "https" or not origin.hostname or origin.username
                or origin.password or origin.path or origin.query or origin.fragment):
            raise ValueError("invalid DIDComm public origin")
        authority = origin.hostname
        if origin.port and origin.port != 443:
            authority += f"%3A{origin.port}"
        self._issuer_prefix = f"did:web:{authority}:orgs:"
        self._token = data["create_token"]
        self._expires = data["expires_at"]
        self._names = expected_names
        self._tls = ssl.create_default_context(cafile=str(ca_file))
        self._lock = threading.Lock()
        self._attempted = False
        self._binding: tuple[str, str] | None = None
        self._public: dict[str, Any] | None = None

    def __repr__(self) -> str:
        return "SenderProvisioner(<private capability>)"

    def _create(self, tenant: str, name: str, issuer: str, fragment: str) -> dict[str, str]:
        connection = http.client.HTTPSConnection("openbao", 8200, timeout=10, context=self._tls)
        try:
            connection.request("POST", f"/v1/didcomm/keys/{tenant}/{name}",
                               body=json.dumps({"sender_did": issuer, "sender_key_id": f"{issuer}#{fragment}"}),
                               headers={"X-Vault-Token": self._token, "Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read(MAX_BYTES + 1)
            if response.status != 200 or len(body) > MAX_BYTES:
                raise ValueError("DIDComm sender creation failed")
            value = json.loads(body)["data"]
        finally:
            connection.close()
        fields = {"tenant", "name", "version", "sender_did", "sender_key_id", "public_key"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("unexpected DIDComm sender metadata")
        version = value["version"]
        public = value["public_key"]
        if (value["tenant"] != tenant or value["name"] != name
                or value["sender_did"] != issuer or value["sender_key_id"] != f"{issuer}#{fragment}"
                or not isinstance(version, str) or not re.fullmatch(r"[0-9a-f]{32}", version)
                or not isinstance(public, str)):
            raise ValueError("DIDComm sender binding mismatch")
        decoded = base64.urlsafe_b64decode(public + "=" * (-len(public) % 4))
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != public:
            raise ValueError("invalid DIDComm sender public key")
        return {"key_reference": f"didcomm/keys/{tenant}/{name}/versions/{version}",
                "sender_key_id": value["sender_key_id"], "public_key": public}

    def provision(self, organization_id: str, issuer_did: str) -> dict[str, Any]:
        if str(uuid.UUID(organization_id)) != organization_id:
            raise ValueError("invalid DIDComm fixture organization")
        slug = issuer_did.removeprefix(self._issuer_prefix)
        if not issuer_did.startswith(self._issuer_prefix) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", slug):
            raise ValueError("DIDComm issuer outside owned public origin")
        with self._lock:
            if self._public is not None and self._binding == (organization_id, issuer_did):
                return deepcopy(self._public)
            if self._attempted or not isinstance(self._expires, int) or time.time() >= self._expires:
                raise ValueError("DIDComm fixture capability exhausted")
            self._attempted = True  # Failure cannot reset a partially consumed capability.
            self._binding = (organization_id, issuer_did)
            try:
                sender = self._create(organization_id, self._names[0], issuer_did, "didcomm-authcrypt-x25519")
                mismatch = self._create(organization_id, self._names[1], issuer_did, "didcomm-authcrypt-mismatch")
                if sender["public_key"] == mismatch["public_key"]:
                    raise ValueError("DIDComm fixture did not create distinct senders")
                self._public = {"organization_id": organization_id, "issuer_did": issuer_did,
                                "sender": sender, "mismatch": mismatch}
                return deepcopy(self._public)
            finally:
                self._token = ""  # The server also expires it after its second use.
