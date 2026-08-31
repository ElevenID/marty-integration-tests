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


def test_release_lineage_is_checked_before_install_and_rechecked_immediately_before_publish() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    command = (
        'python scripts/check_release_lineage.py --repository "$GITHUB_REPOSITORY" '
        '--tag "$GITHUB_REF_NAME" --expected-commit "$GITHUB_SHA"'
    )

    assert workflow.count(command) == 2
    first_gate = workflow.index("- name: Bind release tag to protected main")
    dependency_install = workflow.index("- name: Install uv without a tag-scoped dependency cache")
    draft_upload = workflow.index("- uses: softprops/action-gh-release@")
    final_gate = workflow.index("- name: Revalidate release tag lineage before publication")
    publication = workflow.index("- name: Publish complete immutable release")

    assert first_gate < dependency_install
    assert draft_upload < final_gate < publication
    assert workflow[final_gate:publication].rstrip().endswith(command)
