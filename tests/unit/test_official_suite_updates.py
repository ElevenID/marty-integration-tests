from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("official_suite_updates", ROOT / "scripts" / "official_suite_updates.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official-suite update helper")
updates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updates)


def test_drift_requires_a_real_pinned_to_latest_difference() -> None:
    no_drift = {
        "upstreams": {
            "oidf": {"pinned_release": "release-v1", "latest_release": "release-v1"},
            "w3c": {"pinned_commit": "a" * 40, "latest_commit": "a" * 40},
        }
    }
    assert updates.has_drift(no_drift) is False
    no_drift["upstreams"]["w3c"]["latest_commit"] = "b" * 40
    assert updates.has_drift(no_drift) is True


def test_observation_tracks_every_eudi_wallet_library(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates, "latest_oidf_release", lambda: "release-v5.2.0")
    monkeypatch.setattr(updates, "git_head", lambda *_args: "f" * 40)
    monkeypatch.setattr(updates, "git_tag_commit", lambda *_args: "e" * 40)
    observation = updates.observe()
    assert set(observation["upstreams"]) == {
        "oidf",
        "w3c_vc_data_model_v2",
        "eudi_wallet_tester",
        "eudi_verifier_endpoint",
        "eudi_wallet_kit_oid4vp",
        "eudi_wallet_kit_oid4vci",
        "eudi_wallet_kit_sd_jwt",
    }
    assert observation["upstreams"]["oidf"] == {
        "pinned_release": "release-v5.2.0",
        "latest_release": "release-v5.2.0",
        "pinned_commit": updates.load_json("conformance/oidf-runner.json")["official_runner"]["commit"],
        "latest_commit": "e" * 40,
    }


def test_tag_resolution_prefers_the_peeled_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    tag_object = "a" * 40
    commit = "b" * 40
    monkeypatch.setattr(
        updates.subprocess,
        "check_output",
        lambda *_args, **_kwargs: f"{tag_object}\trefs/tags/release-v1\n{commit}\trefs/tags/release-v1^{{}}\n",
    )

    assert updates.git_tag_commit("https://example.test/repository.git", "release-v1") == commit


def test_one_monthly_draft_pr_updater_is_the_only_upstream_update_mechanism() -> None:
    workflows = ROOT / ".github" / "workflows"
    mechanisms = []
    for path in workflows.glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        if "official_suite_updates.py" in text or "oidf_conformance.py check-update" in text:
            mechanisms.append(path.name)

    assert mechanisms == ["official-suite-updates.yml"]
    assert not (workflows / "oidf-runner-update.yml").exists()
    workflow = (workflows / "official-suite-updates.yml").read_text(encoding="utf-8")
    assert workflow.count("cron:") == 1
    assert 'branch="automation/official-suite-updates"' in workflow
    assert "automation/official-suite-updates-" not in workflow
    assert "gh pr list --state open" in workflow
    assert "gh pr edit" in workflow
    assert "gh pr create --draft" in workflow
    assert "gh pr merge" not in workflow
    assert "--auto-merge" not in workflow
    assert "check-update" not in (ROOT / "scripts" / "oidf_conformance.py").read_text(encoding="utf-8")
