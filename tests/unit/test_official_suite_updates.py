from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

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
    monkeypatch.setattr(updates, "latest_oidf_release", lambda: "release-v5.2.2")
    monkeypatch.setattr(updates, "latest_github_release", lambda _repository: "latest-eudi")
    monkeypatch.setattr(updates, "git_head", lambda *_args: "f" * 40)
    monkeypatch.setattr(updates, "git_tag_commit", lambda *_args: "e" * 40)
    observation = updates.observe()
    assert set(observation["upstreams"]) == {
        "oidf",
        "w3c_vc_data_model_v2",
        "didcomm_independent_implementation",
        "eudi_verifier_endpoint",
        "eudi_wallet_kit_oid4vp",
        "eudi_wallet_kit_oid4vci",
        "eudi_wallet_kit_sd_jwt",
        "eudi_wallet_kit_mdoc",
    }
    assert observation["upstreams"]["oidf"] == {
        "pinned_release": "release-v5.2.2",
        "latest_release": "release-v5.2.2",
        "pinned_commit": updates.load_json("conformance/oidf-runner.json")["official_runner"]["commit"],
        "latest_commit": "e" * 40,
    }
    w3c_manifest = updates.load_json("conformance/w3c-vc-data-model-v2.json")
    assert observation["upstreams"]["w3c_vc_data_model_v2"] == {
        "pinned_commit": w3c_manifest["official_suite"]["commit"],
        "latest_commit": "f" * 40,
    }
    didcomm_manifest = updates.load_json("conformance/didcomm-interoperability.json")
    didcomm = didcomm_manifest["independent_implementation"]
    assert observation["upstreams"]["didcomm_independent_implementation"] == {
        "pinned_release": didcomm["release"],
        "latest_release": "latest-eudi",
        "pinned_commit": didcomm["commit"],
        "latest_commit": "e" * 40,
    }
    eudi_manifest = updates.load_json("conformance/eudi-reference-interop.json")
    verifier = eudi_manifest["components"]["verifier_endpoint"]
    assert observation["upstreams"]["eudi_verifier_endpoint"] == {
        "pinned_release": verifier["release"],
        "latest_release": "latest-eudi",
        "pinned_commit": verifier["commit"],
        "latest_commit": "e" * 40,
    }


def test_latest_github_release_uses_only_a_valid_github_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"tag_name":"v1.2.3"}'

    captured: dict[str, object] = {}

    def urlopen(request: Any, timeout: int) -> Response:
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(updates.urllib.request, "urlopen", urlopen)

    assert updates.latest_github_release("https://github.com/example/project.git") == "v1.2.3"
    assert captured == {
        "url": "https://api.github.com/repos/example/project/releases/latest",
        "timeout": 20,
    }
    with pytest.raises(RuntimeError, match="not on GitHub"):
        updates.latest_github_release("https://example.test/project.git")


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
