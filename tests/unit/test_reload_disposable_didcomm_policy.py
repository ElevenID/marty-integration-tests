"""Mocked lifecycle guards, not a real Docker reload qualification."""

import hashlib
import json
from pathlib import Path

import pytest

from scripts import reload_disposable_didcomm_policy as reload

IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64
CID = "a" * 64


@pytest.mark.parametrize("mutation", ["none", "engine", "image", "mount", "after-restart"])
def test_reload_requires_exact_engine_artifact_readonly_mount_and_final_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    policy = tmp_path / "didcomm-encryption-policy.json"
    policy.write_text('{"version":1,"issuers":{}}', encoding="utf-8")
    digest = hashlib.sha256(policy.read_bytes()).hexdigest()
    owner = tmp_path / "owned-project.json"
    project = "marty-conformance-owned-run"
    owner.write_text(json.dumps({
        "schema": "elevenid.disposable-project-ownership/v1", "run_id": "owned-run",
        "projects": [project, project + "-trust-registry"], "engine_id": "owned-engine",
        "cleanup_environment": {"MARTY_SERVICES_IMAGE": IMAGE},
    }), encoding="utf-8")
    owner.chmod(0o600)
    calls: list[tuple[str, ...]] = []

    def docker(*args: str, timeout: int = 20) -> str:
        assert timeout <= 45
        calls.append(args)
        if args[0] == "info":
            return json.dumps("other-engine" if mutation == "engine" else "owned-engine")
        if args[0] == "ps":
            return CID
        if args[0] == "inspect":
            return "\n".join([
                json.dumps(IMAGE + "wrong" if mutation == "image" else IMAGE),
                json.dumps({"com.docker.compose.project": project, "com.docker.compose.service": "issuance-native"}),
                json.dumps([{"Destination": reload.TARGET, "Source": str(policy),
                             "Type": "bind", "RW": mutation == "mount"}]),
                json.dumps("10001:10001"), "true", "healthy",
            ])
        if args[0] == "restart":
            assert args[-1] == CID
            if mutation == "after-restart":
                policy.write_text("changed-during-await", encoding="utf-8")
            return CID
        assert args == ("exec", CID, "sha256sum", reload.TARGET)
        return digest + "  " + reload.TARGET

    monkeypatch.setattr(reload, "docker", docker)
    if mutation == "none":
        reload.refresh(owner, policy, digest)
        assert sum(command[0] == "restart" for command in calls) == 1
    else:
        with pytest.raises(reload.PolicyReloadError, match="differs|binding|atomic policy"):
            reload.refresh(owner, policy, digest)
        if mutation != "after-restart":
            assert not any(command[0] == "restart" for command in calls)
