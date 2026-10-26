from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_release_checksum_does_not_include_its_incomplete_output() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "find . -type f ! -name SHA256SUMS" in workflow
    assert "> ../SHA256SUMS" in workflow
    assert "mv ../SHA256SUMS SHA256SUMS" in workflow
    assert "--bundle SHA256SUMS.sigstore.json SHA256SUMS" in workflow
    assert "xargs -0 sha256sum > SHA256SUMS" not in workflow


def test_release_is_created_once_without_upsert_or_draft_adoption() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "Reject any existing release" in workflow
    assert "python scripts/check_release_absent.py" in workflow
    assert "--actions-write-token" in workflow
    assert "softprops/action-gh-release" not in workflow
    assert "gh release edit" not in workflow
    assert 'gh release create "$GITHUB_REF_NAME" --verify-tag --target "$GITHUB_SHA"' in workflow
    assert "--generate-notes --latest release-assets/*" in workflow


def test_release_lineage_is_checked_before_install_and_rechecked_immediately_before_publish() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    command = (
        'python scripts/check_release_lineage.py --repository "$GITHUB_REPOSITORY" '
        '--tag "$GITHUB_REF_NAME" --expected-commit "$GITHUB_SHA"'
    )

    assert workflow.count(command) == 3
    first_gate = workflow.index("- name: Bind release tag to protected main")
    dependency_install = workflow.index("- name: Install uv without a tag-scoped dependency cache")
    attestation = workflow.index("- uses: actions/attest-build-provenance@")
    final_gate = workflow.index("- name: Revalidate release tag lineage before publication")
    publication = workflow.index("- name: Publish complete immutable release")

    assert first_gate < dependency_install
    assert attestation < final_gate < publication
    assert workflow[final_gate:publication].rstrip().endswith(command)
    assert workflow[publication:].index("python scripts/check_release_absent.py") < workflow[publication:].index(
        "gh release create"
    )


def test_all_official_lanes_and_release_environment_remain_required() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    jobs = workflow["jobs"]
    assert jobs["verify-source"]["permissions"] == {"contents": "write"}
    assert jobs["verify-source"]["environment"] == "release"
    assert jobs["official-interoperability"]["needs"] == "verify-source"
    assert jobs["official-interoperability"]["with"]["lane"] == "all"
    assert jobs["official-interoperability"]["uses"] == "./.github/workflows/official-interoperability.yml"
    assert jobs["release"]["needs"] == ["verify-source", "official-interoperability"]
    assert jobs["release"]["environment"] == "release"
    assert workflow["concurrency"]["cancel-in-progress"] is False
    for name in ("verify-source", "release"):
        checkout = next(s for s in jobs[name]["steps"] if s.get("uses", "").startswith("actions/checkout@"))
        assert checkout["with"]["persist-credentials"] is False


def test_owned_fixture_workflow_is_main_only_and_uses_release_environment() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/release-preflight.yml").read_text())
    job = workflow["jobs"]["release-lookup-probe"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["environment"] == "release"
    assert job["permissions"] == {"contents": "write"}
    assert job["timeout-minutes"] == 10
    script = next(s["run"] for s in job["steps"] if "probe_release_lookup.py" in s.get("run", ""))
    assert '--fixture-tag "$FIXTURE_TAG"' in script
    assert not any("gh release create" in s.get("run", "") for s in job["steps"])
