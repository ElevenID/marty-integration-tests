from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_release_checksum_does_not_include_its_incomplete_output() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "find . -type f ! -name SHA256SUMS" in workflow
    assert "> ../SHA256SUMS" in workflow
    assert "mv ../SHA256SUMS SHA256SUMS" in workflow
    assert "--bundle SHA256SUMS.sigstore.json SHA256SUMS" in workflow
    assert "xargs -0 sha256sum > SHA256SUMS" not in workflow


def test_release_is_completed_as_an_immutable_draft() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "Reject any existing release" in workflow
    assert "python scripts/check_release_absent.py" in workflow
    assert "draft: true" in workflow
    assert "overwrite_files: false" in workflow
    assert "gh release edit" in workflow
    assert "--draft=false --latest" in workflow
