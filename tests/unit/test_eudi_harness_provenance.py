from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "eudi_harness_provenance", ROOT / "scripts" / "eudi_harness_provenance.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load EUDI harness provenance helper")
provenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provenance)


def test_report_records_only_content_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    digest = "sha256:" + "a" * 64
    monkeypatch.setattr(
        provenance.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, digest + "\n", ""),
    )
    report = provenance.build_report("eudi-reference-eudi-123-1")
    assert report["image_digest"] == digest
    assert report["component"] == "eudi-wallet-harness"
    assert set(report["recipe"]) == {
        "services/eudi-wallet-harness/Dockerfile",
        "services/eudi-wallet-harness/gradle.lockfile",
        "services/eudi-wallet-harness/gradle/verification-metadata.xml",
    }
    assert all(provenance.DIGEST.fullmatch(value) for value in report["recipe"].values())


def test_image_inspection_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        provenance.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", "missing"),
    )
    with pytest.raises(ValueError, match="could not inspect"):
        provenance.inspect_digest("eudi-reference-eudi-123-1")
