import importlib.util
import json
from pathlib import Path


MODULE_PATH = Path(__file__).parents[2] / "scripts" / "render_stack_env.py"
SPEC = importlib.util.spec_from_file_location("render_stack_env", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def manifest():
    artifacts = [
        "ghcr.io/elevenid/marty-ui-oss/ui",
        "ghcr.io/elevenid/marty-ui-oss/services",
        "ghcr.io/elevenid/marty-ui-oss/migrations",
        "ghcr.io/elevenid/marty-credentials-issuance",
    ]
    return {
        "schema": "marty.stack/v1",
        "release": "marty-ui@1.0.0",
        "components": [
            {
                "name": "images",
                "artifacts": [
                    {"type": "oci", "uri": uri, "digest": "sha256:" + "a" * 64}
                    for uri in artifacts
                ],
            },
            {
                "name": "marty-core-python",
                "artifacts": [{
                    "type": "python",
                    "uri": "https://github.com/ElevenID/marty-core/releases/download/v0.1.0/marty_rs.whl",
                    "digest": "sha256:" + "b" * 64,
                }],
            },
            {
                "name": "marty-common",
                "artifacts": [{
                    "type": "python",
                    "uri": "https://github.com/ElevenID/Marty/releases/download/v0.1.0/marty_common.whl",
                    "digest": "sha256:" + "c" * 64,
                }],
            },
        ],
    }


def test_maps_required_images_by_immutable_uri():
    images = MODULE.image_map(manifest())
    assert images["MARTY_UI_IMAGE"].endswith("@sha256:" + "a" * 64)
    assert len(images) == 4


def test_maps_required_python_artifacts_by_component_and_digest():
    artifacts = MODULE.python_artifact_map(manifest())
    assert artifacts["MARTY_RS_URI"].endswith("/marty_rs.whl")
    assert artifacts["MARTY_RS_DIGEST"] == "sha256:" + "b" * 64
    assert artifacts["MARTY_COMMON_URI"].endswith("/marty_common.whl")
    assert artifacts["MARTY_COMMON_DIGEST"] == "sha256:" + "c" * 64


def test_rejects_ambiguous_repository_names():
    value = manifest()
    value["components"][0]["artifacts"].append(
        {
            "type": "oci",
            "uri": "ghcr.io/another-owner/ui",
            "digest": "sha256:" + "b" * 64,
        }
    )
    try:
        MODULE.image_map(value)
    except ValueError as error:
        assert "repository name ui" in str(error)
        assert "found 2" in str(error)
    else:
        raise AssertionError("ambiguous image role was accepted")


def test_rejects_commerce_markers(tmp_path):
    value = manifest()
    value["components"][0]["name"] = "billing"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    try:
        MODULE.load_manifest(path)
    except ValueError as error:
        assert "commerce" in str(error)
    else:
        raise AssertionError("commerce marker was accepted")
