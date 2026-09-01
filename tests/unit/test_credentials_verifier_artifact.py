from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import tarfile
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "credentials_verifier_artifact",
    ROOT / "scripts" / "credentials_verifier_artifact.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load credentials verifier artifact helper")
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


def valid_pin() -> dict[str, object]:
    return {
        "schema": artifact.PIN_SCHEMA,
        "state": "ready",
        "repository": artifact.EXPECTED_REPOSITORY,
        "release_tag": "v1.2.3",
        "version": "1.2.3",
        "commit": "a" * 40,
        "source_ref": "refs/heads/main",
        "image": {
            "uri": artifact.EXPECTED_IMAGE_URI,
            "digest": "sha256:" + "b" * 64,
        },
        "sbom": {
            "asset": "marty-credentials-verification.spdx.json",
            "digest": "sha256:" + "c" * 64,
        },
    }


def valid_rust_pin() -> dict[str, object]:
    return {
        "schema": artifact.RUST_PIN_SCHEMA,
        "state": "ready",
        "repository": artifact.RUST_REPOSITORY,
        "release_tag": "v1.2.3",
        "version": "1.2.3",
        "commit": "a" * 40,
        "source_ref": "refs/tags/v1.2.3",
        "image": {
            "uri": artifact.RUST_IMAGE_URI,
            "digest": "sha256:" + "b" * 64,
        },
        "sbom": {
            "asset": "marty-ui-services-sbom.cdx.json",
            "digest": "sha256:" + "c" * 64,
        },
    }


def valid_candidate_pin() -> dict[str, object]:
    commit = "a" * 40
    return {
        "schema": artifact.CANDIDATE_PIN_SCHEMA,
        "state": "candidate",
        "repository": artifact.RUST_REPOSITORY,
        "version": f"0.0.0-candidate.{commit[:12]}",
        "commit": commit,
        "source_ref": "refs/heads/main",
        "run": {
            "repository": artifact.RUST_REPOSITORY,
            "workflow": artifact.CANDIDATE_BUILD_WORKFLOW,
            "id": "123456789",
            "attempt": 1,
        },
        "archive": {
            "asset": "marty-ui-services.oci.tar",
            "digest": "sha256:" + "d" * 64,
        },
        "image": {
            "uri": artifact.RUST_IMAGE_URI,
            "digest": "sha256:" + "b" * 64,
            "config_digest": "sha256:" + "e" * 64,
            "archive_tag": "candidate-" + commit,
        },
        "sbom": {
            "asset": "marty-ui-services-sbom.cdx.json",
            "digest": "sha256:" + "c" * 64,
        },
        "metadata": {
            "asset": "marty-ui-services-build-metadata.json",
            "digest": "sha256:" + "1" * 64,
        },
        "provenance": {
            "asset": "marty-ui-services-provenance.json",
            "digest": "sha256:" + "f" * 64,
        },
    }


def known_ineligible_failure() -> dict[str, object]:
    return {
        "id": artifact.KNOWN_INELIGIBLE_FAILURE_ID,
        "message": artifact.KNOWN_INELIGIBLE_FAILURE_MESSAGE,
    }


def write_pin(path: Path, value: dict[str, object] | None = None) -> Path:
    path.write_text(json.dumps(value or valid_pin()), encoding="utf-8")
    return path


def valid_sbom() -> dict[str, object]:
    return {
        "spdxVersion": "SPDX-2.3",
        "name": artifact.EXPECTED_IMAGE_URI,
        "packages": [
            {
                "name": artifact.EXPECTED_IMAGE_URI,
                "versionInfo": "sha256:" + "b" * 64,
            },
            {"name": "marty-rs", "versionInfo": "0.1.46"},
            {"name": "marty-verification-py", "versionInfo": "0.1.46"},
        ],
    }


def valid_rust_sbom(pin: dict[str, object] | None = None) -> dict[str, object]:
    pin = pin or valid_rust_pin()
    root_ref = "urn:elevenid:services-image"
    component_ref = "pkg:cargo/marty-verification@1"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "syft", "version": "1.0"}]},
            "component": {
                "type": "container",
                "name": artifact.RUST_IMAGE_URI,
                "version": pin["image"]["digest"],  # type: ignore[index]
                "bom-ref": root_ref,
            },
            "properties": [
                {
                    "name": "syft:image:labels:org.opencontainers.image.source",
                    "value": "https://github.com/ElevenID/marty-ui",
                },
                {
                    "name": "syft:image:labels:org.opencontainers.image.revision",
                    "value": pin["commit"],
                },
                {
                    "name": "syft:image:labels:org.opencontainers.image.version",
                    "value": pin["version"],
                },
            ],
        },
        "components": [{"type": "library", "name": "marty-verification", "bom-ref": component_ref}],
        "dependencies": [{"ref": root_ref, "dependsOn": [component_ref]}],
    }


def test_repository_pin_is_ready_exact_and_immutable(tmp_path: Path) -> None:
    pin = artifact.load_pin(write_pin(tmp_path / "pin.json"))

    assert artifact.image_reference(pin) == (artifact.EXPECTED_IMAGE_URI + "@sha256:" + "b" * 64)
    assert pin["release_tag"] == "v1.2.3"
    assert pin["commit"] == "a" * 40


def test_default_pin_preserves_oracle_and_stale_rust_candidate_is_ineligible() -> None:
    oracle = artifact.load_pin()

    assert artifact.DEFAULT_PIN.name == "credentials-verifier-oracle.json"
    assert oracle["release_tag"] == "v0.1.71"
    assert oracle["commit"] == "94f19ad369e7e41883f2aa3d77656ce561bb6534"
    assert oracle["image"]["digest"] == ("sha256:fcec33e259c2d7856606f434e5c9830e392e820a548ab7a6ff4bd4afb3395b3b")

    with pytest.raises(ValueError, match="artifact pin must be ready"):
        artifact.load_pin(ROOT / "config" / "credentials-verifier-under-test.json")

    rejected = artifact.load_pin(
        ROOT / "config" / "credentials-verifier-under-test.json",
        expected_state="ineligible",
    )
    assert rejected["release_tag"] == "v1.1.208"
    assert rejected["commit"] == "7c8fa31500acd8f2ec589781232c444fe81dd22e"
    assert rejected["expected_failure"] == known_ineligible_failure()


def test_ineligible_pin_still_validates_every_immutable_coordinate(tmp_path: Path) -> None:
    pin = valid_rust_pin()
    pin["state"] = "ineligible"
    pin["expected_failure"] = known_ineligible_failure()
    pin["image"]["digest"] = "mutable"  # type: ignore[index]

    with pytest.raises(ValueError, match="image digest"):
        artifact.load_pin(
            write_pin(tmp_path / "rejected.json", pin),
            expected_state="ineligible",
        )


def test_workflow_runs_oracle_and_exact_known_negative_control() -> None:
    workflow = (ROOT / ".github" / "workflows" / "credentials-verifier-artifact.yml").read_text(encoding="utf-8")

    assert "pin: config/credentials-verifier-oracle.json" in workflow
    assert "pin: config/credentials-verifier-under-test.json" in workflow
    assert "state: ineligible" in workflow
    assert "mode: expected-failure" in workflow
    assert 'validate-pin --pin "$PIN_FILE" --state "$PIN_STATE"' in workflow
    assert "run-expected-failure" in workflow
    assert "compare-evidence" in workflow
    assert workflow.count('--pin "$PIN_FILE"') == 4


def test_sbom_is_bound_to_pinned_image_and_native_packages(tmp_path: Path) -> None:
    path = tmp_path / "verification.spdx.json"
    path.write_text(json.dumps(valid_sbom()), encoding="utf-8")

    value = artifact.validate_sbom(path, valid_pin())

    assert value["name"] == artifact.EXPECTED_IMAGE_URI


def test_rust_pin_and_cyclonedx_sbom_are_bound_to_canonical_services_image(tmp_path: Path) -> None:
    pin_path = write_pin(tmp_path / "rust-pin.json", valid_rust_pin())
    pin = artifact.load_pin(pin_path)
    sbom_path = tmp_path / "services.cdx.json"
    sbom_path.write_text(json.dumps(valid_rust_sbom()), encoding="utf-8")

    value = artifact.validate_sbom(sbom_path, pin)

    assert artifact.artifact_target(pin) is artifact.RUST_TARGET
    assert artifact.image_reference(pin) == artifact.RUST_IMAGE_URI + "@sha256:" + "b" * 64
    assert value["metadata"]["component"]["version"] == pin["image"]["digest"]


def test_candidate_pin_is_non_release_and_runs_by_commit_bound_local_reference(tmp_path: Path) -> None:
    candidate = valid_candidate_pin()
    pin = artifact.load_pin(
        write_pin(tmp_path / "candidate.json", candidate),
        expected_state="candidate",
    )

    assert "release_tag" not in pin
    assert artifact.artifact_target(pin) is artifact.RUST_TARGET
    assert artifact.image_reference(pin) == (artifact.CANDIDATE_LOCAL_IMAGE_REPOSITORY + ":verified-" + "a" * 40)
    assert artifact.evidence_subject(pin) == {
        "repository": artifact.RUST_REPOSITORY,
        "commit": "a" * 40,
        "source_ref": "refs/heads/main",
        "version": "0.0.0-candidate." + "a" * 12,
        "run": candidate["run"],
        "archive": candidate["archive"],
        "image": candidate["image"],
        "sbom": candidate["sbom"],
        "metadata": candidate["metadata"],
        "provenance": candidate["provenance"],
        "provenance_verified": True,
    }


def _descriptor(value: bytes, media_type: str, **extra: object) -> dict[str, object]:
    return {
        "mediaType": media_type,
        "digest": f"sha256:{hashlib.sha256(value).hexdigest()}",
        "size": len(value),
        **extra,
    }


def rewrite_tar_end(raw: bytes, *, eoa_blocks: int = 2, trailer: bytes = b"") -> bytes:
    zero_pair = bytes(artifact.TAR_BLOCK_BYTES * 2)
    offset = next(
        position
        for position in range(0, len(raw), artifact.TAR_BLOCK_BYTES)
        if raw[position : position + len(zero_pair)] == zero_pair
    )
    return raw[:offset] + bytes(artifact.TAR_BLOCK_BYTES * eoa_blocks) + trailer


def write_oci_archive(
    path: Path,
    pin: dict[str, object],
    *,
    revision: str | None = None,
    platform: dict[str, str] | None = None,
    corrupt_layer_digest: bool = False,
    config_media_type: str = "application/vnd.oci.image.config.v1+json",
    config_platform_qualifiers: dict[str, object] | None = None,
    manifest_payload_media_type: str | None = artifact.OCI_MANIFEST,
    omit_platform: bool = False,
    nested_index: bool = False,
    nested_index_schema_version: int = 2,
    nested_index_payload_media_type: str | None = artifact.OCI_INDEX,
    top_index_platform: dict[str, str] | None = None,
    index_payload_media_type: str | None = None,
    compressed_outer: bool = False,
    uncompressed_layer_override: bytes | None = None,
    outer_eoa_blocks: int = 2,
    outer_trailer: bytes = b"",
    layer_eoa_blocks: int = 2,
    layer_trailer: bytes = b"",
    directories: tuple[str, ...] = (),
    unreferenced_regular: bool = False,
) -> None:
    labels = {
        "org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
        "org.opencontainers.image.revision": revision or str(pin["commit"]),
        "org.opencontainers.image.version": str(pin["version"]),
    }
    layer_tar = io.BytesIO()
    with tarfile.open(fileobj=layer_tar, mode="w") as layer_archive:
        layer_member = tarfile.TarInfo("candidate.txt")
        layer_content = b"candidate layer"
        layer_member.size = len(layer_content)
        layer_archive.addfile(layer_member, io.BytesIO(layer_content))
    uncompressed_layer = uncompressed_layer_override or rewrite_tar_end(
        layer_tar.getvalue(),
        eoa_blocks=layer_eoa_blocks,
        trailer=layer_trailer,
    )
    layer = gzip.compress(uncompressed_layer, mtime=0)
    config_value: dict[str, object] = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Env": [
                "SERVICE_NAME=verification",
                f"MARTY_RELEASE_VERSION={pin['version']}",
                f"MARTY_UI_SHA={pin['commit']}",
            ],
            "Labels": labels,
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": [f"sha256:{hashlib.sha256(uncompressed_layer).hexdigest()}"],
        },
    }
    config_value.update(config_platform_qualifiers or {})
    config = artifact.canonical_json(config_value)
    config_descriptor = _descriptor(config, config_media_type)
    layer_descriptor = _descriptor(layer, artifact.OCI_GZIP_LAYER)
    if corrupt_layer_digest:
        layer_descriptor["digest"] = "sha256:" + "9" * 64
    manifest_value: dict[str, object] = {
        "schemaVersion": 2,
        "config": config_descriptor,
        "layers": [layer_descriptor],
    }
    if manifest_payload_media_type is not None:
        manifest_value["mediaType"] = manifest_payload_media_type
    manifest = artifact.canonical_json(manifest_value)
    manifest_fields: dict[str, object] = {
        "annotations": {
            "org.opencontainers.image.ref.name": pin["image"]["archive_tag"]  # type: ignore[index]
        }
    }
    if not omit_platform:
        manifest_fields["platform"] = platform or {"architecture": "amd64", "os": "linux"}
    manifest_descriptor = _descriptor(manifest, artifact.OCI_MANIFEST, **manifest_fields)
    index_descriptor = manifest_descriptor
    nested_member: tuple[str, bytes] | None = None
    if nested_index:
        nested_value: dict[str, object] = {
            "schemaVersion": nested_index_schema_version,
            "manifests": [manifest_descriptor],
        }
        if nested_index_payload_media_type is not None:
            nested_value["mediaType"] = nested_index_payload_media_type
        nested = artifact.canonical_json(nested_value)
        nested_fields: dict[str, object] = {
            "annotations": {
                "org.opencontainers.image.ref.name": pin["image"]["archive_tag"]  # type: ignore[index]
            }
        }
        if top_index_platform is not None:
            nested_fields["platform"] = top_index_platform
        index_descriptor = _descriptor(nested, artifact.OCI_INDEX, **nested_fields)
        nested_member = (
            f"blobs/sha256/{index_descriptor['digest'].split(':', 1)[1]}",
            nested,
        )
    index_value: dict[str, object] = {"schemaVersion": 2, "manifests": [index_descriptor]}
    if index_payload_media_type is not None:
        index_value["mediaType"] = index_payload_media_type
    index = artifact.canonical_json(index_value)
    layout = artifact.canonical_json({"imageLayoutVersion": "1.0.0"})
    members = {
        "oci-layout": layout,
        "index.json": index,
        f"blobs/sha256/{config_descriptor['digest'].split(':', 1)[1]}": config,
        f"blobs/sha256/{manifest_descriptor['digest'].split(':', 1)[1]}": manifest,
        f"blobs/sha256/{hashlib.sha256(layer).hexdigest()}": layer,
    }
    if nested_member is not None:
        members[nested_member[0]] = nested_member[1]
    if unreferenced_regular:
        members["unreferenced.txt"] = b"not reachable"
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        for name in directories:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
        for name, content in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    raw_archive = rewrite_tar_end(
        archive_buffer.getvalue(),
        eoa_blocks=outer_eoa_blocks,
        trailer=outer_trailer,
    )
    path.write_bytes(gzip.compress(raw_archive, mtime=0) if compressed_outer else raw_archive)
    pin["image"]["digest"] = manifest_descriptor["digest"]  # type: ignore[index]
    pin["image"]["config_digest"] = config_descriptor["digest"]  # type: ignore[index]


def write_candidate_bundle(tmp_path: Path) -> tuple[dict[str, object], dict[str, Path]]:
    pin = valid_candidate_pin()
    paths = {
        "archive": tmp_path / "marty-ui-services.oci.tar",
        "sbom": tmp_path / "marty-ui-services-sbom.cdx.json",
        "metadata": tmp_path / "marty-ui-services-build-metadata.json",
        "provenance": tmp_path / "marty-ui-services-provenance.json",
    }
    write_oci_archive(paths["archive"], pin)
    pin["archive"]["digest"] = artifact.file_digest(paths["archive"])  # type: ignore[index]
    sbom = valid_rust_sbom(pin)
    paths["sbom"].write_text(json.dumps(sbom), encoding="utf-8")
    pin["sbom"]["digest"] = artifact.file_digest(paths["sbom"])  # type: ignore[index]
    metadata = {
        "schema": artifact.CANDIDATE_METADATA_SCHEMA,
        "source": {
            "repository": pin["repository"],
            "commit": pin["commit"],
            "ref": pin["source_ref"],
        },
        "builder": pin["run"],
        "build": {
            "context": ".",
            "dockerfile": "services/Dockerfile",
            "dockerfile_digest": "sha256:" + "9" * 64,
            "platform": "linux/amd64",
            "version": pin["version"],
            "arguments": {
                "SERVICE_NAME": "verification",
                "MARTY_RELEASE_VERSION": pin["version"],
                "MARTY_UI_SHA": pin["commit"],
            },
        },
        "image": pin["image"],
    }
    paths["metadata"].write_text(json.dumps(metadata), encoding="utf-8")
    pin["metadata"]["digest"] = artifact.file_digest(paths["metadata"])  # type: ignore[index]
    provenance = {
        "schema": artifact.CANDIDATE_PROVENANCE_SCHEMA,
        "source": metadata["source"],
        "builder": pin["run"],
        "subjects": {
            "archive": pin["archive"],
            "image": pin["image"],
            "sbom": pin["sbom"],
            "metadata": pin["metadata"],
        },
    }
    paths["provenance"].write_text(json.dumps(provenance), encoding="utf-8")
    pin["provenance"]["digest"] = artifact.file_digest(paths["provenance"])  # type: ignore[index]
    return pin, paths


def valid_candidate_attestation(pin: dict[str, object]) -> list[dict[str, object]]:
    run = pin["run"]
    return [
        {
            "verificationResult": {
                "statement": {
                    "predicate": {
                        "buildDefinition": {
                            "externalParameters": {
                                "workflow": {
                                    "ref": pin["source_ref"],
                                    "repository": f"https://github.com/{artifact.RUST_REPOSITORY}",
                                    "path": artifact.CANDIDATE_BUILD_WORKFLOW,
                                }
                            },
                            "resolvedDependencies": [
                                {
                                    "uri": (f"git+https://github.com/{artifact.RUST_REPOSITORY}@{pin['source_ref']}"),
                                    "digest": {"gitCommit": pin["commit"]},
                                }
                            ],
                        },
                        "runDetails": {
                            "builder": {
                                "id": (
                                    f"https://github.com/{artifact.RUST_REPOSITORY}/"
                                    f"{artifact.CANDIDATE_BUILD_WORKFLOW}@{pin['source_ref']}"
                                )
                            },
                            "metadata": {
                                "invocationId": (
                                    f"https://github.com/{artifact.RUST_REPOSITORY}/actions/runs/"
                                    f"{run['id']}/attempts/{run['attempt']}"  # type: ignore[index]
                                )
                            },
                        },
                    }
                }
            }
        }
    ]


def valid_candidate_run_record(pin: dict[str, object]) -> dict[str, object]:
    return {
        "status": "completed",
        "conclusion": "success",
        "head_sha": pin["commit"],
        "head_branch": "main",
        "event": "workflow_dispatch",
        "run_attempt": pin["run"]["attempt"],  # type: ignore[index]
        "path": artifact.CANDIDATE_BUILD_WORKFLOW,
    }


def valid_candidate_inspection(pin: dict[str, object]) -> dict[str, object]:
    return {
        "Id": pin["image"]["config_digest"],  # type: ignore[index]
        "Descriptor": {"digest": pin["image"]["digest"]},  # type: ignore[index]
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "Env": [
                "SERVICE_NAME=verification",
                f"MARTY_RELEASE_VERSION={pin['version']}",
                f"MARTY_UI_SHA={pin['commit']}",
            ],
            "Labels": {
                "org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
                "org.opencontainers.image.revision": pin["commit"],
                "org.opencontainers.image.version": pin["version"],
            },
        },
    }


def leaf_paths(value: object, path: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    if isinstance(value, dict):
        return [nested for key, item in value.items() for nested in leaf_paths(item, (*path, key))]
    if isinstance(value, list):
        return [nested for index, item in enumerate(value) for nested in leaf_paths(item, (*path, index))]
    return [path]


def replace_path(value: object, path: tuple[object, ...], replacement: object) -> None:
    cursor = value
    for key in path[:-1]:
        cursor = cursor[key]  # type: ignore[index]
    cursor[path[-1]] = replacement  # type: ignore[index]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(release_tag="v1.2.3"), "must not reserve"),
        (lambda value: value.update(version="0.0.0-candidate.bbbbbbbbbbbb"), "must agree"),
        (lambda value: value.update(source_ref="refs/pull/1/head"), "protected main"),
        (lambda value: value["run"].update(workflow=".github/workflows/release.yml"), "workflow changed"),
        (lambda value: value["run"].update(id="0"), "run ID"),
        (lambda value: value["run"].update(attempt=0), "run attempt"),
        (lambda value: value["image"].update(config_digest="sha256:" + "E" * 64), "config digest"),
        (lambda value: value["archive"].update(asset="services.tar"), "archive asset"),
    ],
)
def test_candidate_pin_rejects_release_or_mutable_coordinates(
    tmp_path: Path,
    mutate: object,
    message: str,
) -> None:
    pin = valid_candidate_pin()
    mutate(pin)  # type: ignore[operator]

    with pytest.raises(ValueError, match=message):
        artifact.load_pin(
            write_pin(tmp_path / "candidate.json", pin),
            expected_state="candidate",
        )


def test_candidate_inputs_bind_archive_sbom_and_provenance(tmp_path: Path) -> None:
    pin, paths = write_candidate_bundle(tmp_path)
    loaded = artifact.load_pin(
        write_pin(tmp_path / "candidate.json", pin),
        expected_state="candidate",
    )

    assert (
        artifact.validate_candidate_inputs(
            loaded,
            archive_path=paths["archive"],
            sbom_path=paths["sbom"],
            metadata_path=paths["metadata"],
            provenance_path=paths["provenance"],
        )["subjects"]
        == json.loads(paths["provenance"].read_text(encoding="utf-8"))["subjects"]
    )

    paths["archive"].write_bytes(b"changed")
    with pytest.raises(ValueError, match="archive digest changed"):
        artifact.validate_candidate_inputs(
            loaded,
            archive_path=paths["archive"],
            sbom_path=paths["sbom"],
            metadata_path=paths["metadata"],
            provenance_path=paths["provenance"],
        )


@pytest.mark.parametrize(
    ("archive_options", "message"),
    [
        ({"revision": "b" * 40}, "source labels changed"),
        ({"platform": {"architecture": "arm64", "os": "linux"}}, "platform changed"),
        ({"corrupt_layer_digest": True}, "archive member is missing"),
        ({"config_media_type": "application/json"}, "config media type changed"),
        ({"omit_platform": True}, "platform changed"),
        ({"index_payload_media_type": "application/json"}, "index media type changed"),
        ({"manifest_payload_media_type": "application/json"}, "manifest media type changed"),
        ({"nested_index": True, "nested_index_schema_version": 1}, "image index schema changed"),
        (
            {"nested_index": True, "nested_index_payload_media_type": "application/json"},
            "image index media type changed",
        ),
        (
            {"nested_index": True, "top_index_platform": {"architecture": "amd64", "os": "linux"}},
            "index descriptor platform changed",
        ),
        ({"nested_index": True, "omit_platform": True}, "platform changed"),
        ({"compressed_outer": True}, "not a readable OCI archive"),
    ],
)
def test_oci_archive_rejects_rebound_or_incomplete_images(
    tmp_path: Path,
    archive_options: dict[str, object],
    message: str,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    write_oci_archive(archive_path, pin, **archive_options)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=message):
        artifact.inspect_oci_archive(archive_path, pin)


@pytest.mark.parametrize("nested_index", [False, True], ids=["direct", "nested-index"])
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("variant", "v1"),
        ("variant", None),
        ("os.version", "6.8"),
        ("os.version", ""),
        ("os.features", ["sse4"]),
        ("os.features", []),
    ],
)
def test_oci_archive_rejects_every_config_platform_qualifier(
    tmp_path: Path,
    nested_index: bool,
    key: str,
    value: object,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    write_oci_archive(
        archive_path,
        pin,
        nested_index=nested_index,
        config_platform_qualifiers={key: value},
    )

    with pytest.raises(ValueError, match="config platform changed"):
        artifact.inspect_oci_archive(archive_path, pin)


@pytest.mark.parametrize("nested_index", [False, True], ids=["direct", "nested-index"])
def test_oci_archive_accepts_canonical_payload_and_unqualified_platform(
    tmp_path: Path,
    nested_index: bool,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    write_oci_archive(archive_path, pin, nested_index=nested_index)
    artifact.inspect_oci_archive(archive_path, pin)


@pytest.mark.parametrize(
    ("archive_options", "message"),
    [
        ({"outer_eoa_blocks": 0}, "missing the canonical tar end-of-archive"),
        ({"outer_eoa_blocks": 1}, "missing the canonical tar end-of-archive"),
        ({"outer_trailer": b"x" + bytes(511)}, "non-zero data after its end-of-archive"),
        ({"layer_eoa_blocks": 0}, "missing the canonical tar end-of-archive"),
        ({"layer_eoa_blocks": 1}, "missing the canonical tar end-of-archive"),
        ({"layer_trailer": b"x" + bytes(511)}, "non-zero data after its end-of-archive"),
        ({"unreferenced_regular": True}, "unreferenced regular member"),
        ({"directories": ("unreferenced",)}, "unreferenced directory member"),
    ],
)
def test_oci_archive_rejects_noncanonical_ends_and_unreachable_members(
    tmp_path: Path,
    archive_options: dict[str, object],
    message: str,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    write_oci_archive(archive_path, pin, **archive_options)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=message):
        artifact.inspect_oci_archive(archive_path, pin)


def test_oci_archive_accepts_only_reachable_buildx_directories(tmp_path: Path) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    write_oci_archive(archive_path, pin, directories=("blobs", "blobs/sha256"))

    artifact.inspect_oci_archive(archive_path, pin)


@pytest.mark.parametrize(
    ("limit", "message"),
    [
        ("MAX_ARCHIVE_MEMBERS", "too many members"),
        ("MAX_ARCHIVE_REGULAR_MEMBERS", "too many regular members"),
        ("MAX_LAYERS", "too many layers"),
        ("MAX_COMPRESSED_LAYER_BYTES", "compressed layer is too large"),
        ("MAX_TOTAL_COMPRESSED_LAYER_BYTES", "aggregate compressed layers are too large"),
        ("MAX_EXPANDED_LAYER_BYTES", "expanded layer is too large"),
        ("MAX_TOTAL_EXPANDED_LAYER_BYTES", "aggregate expanded layers are too large"),
        ("MAX_LAYER_MEMBERS", "layer contains too many members"),
        ("MAX_TOTAL_LAYER_MEMBERS", "aggregate layer members are too large"),
    ],
)
def test_candidate_archive_resource_limits_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
    message: str,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    write_oci_archive(archive_path, pin)
    monkeypatch.setattr(artifact, limit, 0 if limit.endswith(("MEMBERS", "LAYERS")) else 1)

    with pytest.raises(ValueError, match=message):
        artifact.inspect_oci_archive(archive_path, pin)


def test_candidate_archive_size_fails_before_archive_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "candidate.oci.tar"
    archive_path.write_bytes(b"oversized")
    monkeypatch.setattr(artifact, "MAX_ARCHIVE_BYTES", 1)
    monkeypatch.setattr(
        artifact.tarfile,
        "open",
        lambda *_args, **_kwargs: pytest.fail("oversized archive was read"),
    )

    with pytest.raises(ValueError, match="archive is too large"):
        artifact.inspect_oci_archive(archive_path, valid_candidate_pin())


def test_candidate_archive_never_collects_tar_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    write_oci_archive(archive_path, pin)
    monkeypatch.setattr(
        tarfile.TarFile,
        "getmembers",
        lambda *_args, **_kwargs: pytest.fail("tar members were collected"),
    )

    artifact.inspect_oci_archive(archive_path, pin)


def special_tar_header(typeflag: bytes, size: int, payload: bytes = b"") -> bytes:
    member = tarfile.TarInfo("special-header")
    member.type = typeflag
    member.size = size
    header = member.tobuf(format=tarfile.GNU_FORMAT)
    padding = bytes((-len(payload)) % artifact.TAR_BLOCK_BYTES)
    return header + payload + padding + bytes(artifact.TAR_BLOCK_BYTES * 2)


@pytest.mark.parametrize(
    "typeflag",
    [
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
    ],
)
def test_tar_scan_rejects_oversized_special_headers_before_payload_read(typeflag: bytes) -> None:
    content = special_tar_header(typeflag, artifact.MAX_TAR_SPECIAL_HEADER_BYTES + 1)

    with pytest.raises(ValueError, match="special tar header is too large"):
        artifact._scan_tar_headers(
            io.BytesIO(content),
            stream_bytes=len(content),
            maximum_members=artifact.MAX_ARCHIVE_MEMBERS,
            label="test archive",
        )


def test_outer_archive_rejects_oversized_special_header_before_tarfile_iteration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "candidate.oci.tar"
    archive_path.write_bytes(special_tar_header(tarfile.XHDTYPE, artifact.MAX_TAR_SPECIAL_HEADER_BYTES + 1))
    monkeypatch.setattr(
        artifact.tarfile,
        "open",
        lambda *_args, **_kwargs: pytest.fail("outer tarfile iteration began before the raw scan"),
    )

    with pytest.raises(ValueError, match="special tar header is too large"):
        artifact.inspect_oci_archive(archive_path, valid_candidate_pin())


def test_inner_layer_rejects_oversized_special_header_before_tarfile_iteration(tmp_path: Path) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    write_oci_archive(
        archive_path,
        pin,
        uncompressed_layer_override=special_tar_header(
            tarfile.GNUTYPE_LONGNAME,
            artifact.MAX_TAR_SPECIAL_HEADER_BYTES + 1,
        ),
    )

    with pytest.raises(ValueError, match="OCI layer special tar header is too large"):
        artifact.inspect_oci_archive(archive_path, pin)


@pytest.mark.parametrize("document_name", ["metadata", "provenance"])
def test_candidate_inputs_reject_every_metadata_and_provenance_leaf_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    document_name: str,
) -> None:
    original_pin, paths = write_candidate_bundle(tmp_path)
    original_document = json.loads(paths[document_name].read_text(encoding="utf-8"))
    monkeypatch.setattr(artifact, "inspect_oci_archive", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(artifact, "validate_sbom", lambda *_args, **_kwargs: {})

    for path in leaf_paths(original_document):
        pin = copy.deepcopy(original_pin)
        document = copy.deepcopy(original_document)
        replace_path(document, path, None)
        paths[document_name].write_text(json.dumps(document), encoding="utf-8")
        pin[document_name]["digest"] = artifact.file_digest(paths[document_name])  # type: ignore[index]
        with pytest.raises(ValueError, match=r".+"):
            artifact.validate_candidate_inputs(
                pin,
                archive_path=paths["archive"],
                sbom_path=paths["sbom"],
                metadata_path=paths["metadata"],
                provenance_path=paths["provenance"],
            )
        paths[document_name].write_text(json.dumps(original_document), encoding="utf-8")


def test_tar_scan_rejects_malformed_pax_metadata() -> None:
    payload = b"12 path=bad"
    content = special_tar_header(tarfile.XHDTYPE, len(payload), payload)

    with pytest.raises(ValueError, match="malformed PAX metadata"):
        artifact._scan_tar_headers(
            io.BytesIO(content),
            stream_bytes=len(content),
            maximum_members=artifact.MAX_ARCHIVE_MEMBERS,
            label="test archive",
        )


def test_tar_scan_accepts_bounded_real_pax_long_paths() -> None:
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("nested/" + "a" * 150)
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))

    artifact._scan_tar_headers(
        content,
        stream_bytes=len(content.getvalue()),
        maximum_members=artifact.MAX_LAYER_MEMBERS,
        label="test layer",
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(components=[]), "components are missing"),
        (lambda value: value["components"][0].update(type="unknown"), "component type changed"),
        (lambda value: value["components"][0].update(name=" "), "component name is missing"),
        (
            lambda value: value["components"].append(copy.deepcopy(value["components"][0])),
            "component reference is duplicated",
        ),
        (lambda value: value["metadata"].update(tools={"components": []}), "not generated by Syft"),
        (lambda value: value["metadata"]["component"].update(type="library"), "root is not a container"),
        (
            lambda value: value["metadata"]["component"].__setitem__("bom-ref", value["components"][0]["bom-ref"]),
            "root reference is duplicated",
        ),
        (lambda value: value.update(dependencies=[{"ref": "unknown", "dependsOn": []}]), "dependency reference"),
        (
            lambda value: value.update(
                dependencies=[
                    value["dependencies"][0],
                    copy.deepcopy(value["dependencies"][0]),
                ]
            ),
            "dependency reference",
        ),
        (
            lambda value: value.update(
                dependencies=[{"ref": value["dependencies"][0]["ref"], "dependsOn": ["unknown"]}]
            ),
            "dependency edge",
        ),
        (lambda value: value["metadata"]["component"].update(purl="pkg:generic/rebound"), "identity is contradictory"),
        (lambda value: value["metadata"].update(properties=[]), "image labels changed"),
        (
            lambda value: value["metadata"]["properties"].append(copy.deepcopy(value["metadata"]["properties"][0])),
            "property is duplicated",
        ),
        (lambda value: value["metadata"]["properties"][0].update(value="rebound"), "image labels changed"),
    ],
)
def test_candidate_sbom_rejects_semantic_mutations(
    tmp_path: Path,
    mutate: Callable[[dict[str, object]], object],
    message: str,
) -> None:
    pin = valid_candidate_pin()
    sbom = valid_rust_sbom(pin)
    mutate(sbom)
    path = tmp_path / "candidate.cdx.json"
    path.write_text(json.dumps(sbom), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        artifact.validate_sbom(path, pin)


@pytest.mark.parametrize(
    ("limit", "message"),
    [
        ("MAX_SBOM_TOP_LEVEL_KEYS", "top-level fields"),
        ("MAX_SBOM_COMPONENTS", "components are missing"),
        ("MAX_SBOM_DEPENDENCIES", "dependencies changed"),
        ("MAX_SBOM_PROPERTIES", "image labels are missing"),
        ("MAX_SBOM_SCANNER_COMPONENTS", "not generated by Syft"),
    ],
)
def test_candidate_sbom_collection_limits_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
    message: str,
) -> None:
    pin = valid_candidate_pin()
    path = tmp_path / "candidate.cdx.json"
    path.write_text(json.dumps(valid_rust_sbom(pin)), encoding="utf-8")
    monkeypatch.setattr(artifact, limit, 0)

    with pytest.raises(ValueError, match=message):
        artifact.validate_sbom(path, pin)


def test_candidate_sbom_dependency_edges_accept_exact_and_reject_exact_plus_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    sbom = valid_rust_sbom(pin)
    path = tmp_path / "candidate.cdx.json"
    monkeypatch.setattr(artifact, "MAX_SBOM_DEPENDENCY_EDGES_PER_ENTRY", 1)
    path.write_text(json.dumps(sbom), encoding="utf-8")
    artifact.validate_sbom(path, pin)
    sbom["dependencies"][0]["dependsOn"].append(sbom["metadata"]["component"]["bom-ref"])  # type: ignore[index]
    path.write_text(json.dumps(sbom), encoding="utf-8")
    with pytest.raises(ValueError, match="fan-out is too large"):
        artifact.validate_sbom(path, pin)


def test_candidate_sbom_aggregate_edges_accept_exact_and_reject_exact_plus_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    sbom = valid_rust_sbom(pin)
    root = sbom["metadata"]["component"]["bom-ref"]  # type: ignore[index]
    component = sbom["components"][0]["bom-ref"]  # type: ignore[index]
    sbom["dependencies"] = [
        {"ref": root, "dependsOn": [component]},
        {"ref": component, "dependsOn": [root]},
    ]
    path = tmp_path / "candidate.cdx.json"
    path.write_text(json.dumps(sbom), encoding="utf-8")
    monkeypatch.setattr(artifact, "MAX_TOTAL_SBOM_DEPENDENCY_EDGES", 2)
    artifact.validate_sbom(path, pin)
    monkeypatch.setattr(artifact, "MAX_TOTAL_SBOM_DEPENDENCY_EDGES", 1)
    with pytest.raises(ValueError, match="aggregate dependency edges"):
        artifact.validate_sbom(path, pin)


def test_candidate_sbom_rejects_duplicate_dependency_edges(tmp_path: Path) -> None:
    pin = valid_candidate_pin()
    sbom = valid_rust_sbom(pin)
    sbom["dependencies"][0]["dependsOn"] *= 2  # type: ignore[index]
    path = tmp_path / "candidate.cdx.json"
    path.write_text(json.dumps(sbom), encoding="utf-8")
    with pytest.raises(ValueError, match="dependency edge is duplicated"):
        artifact.validate_sbom(path, pin)


@pytest.mark.parametrize(
    ("input_name", "limit_name", "message"),
    [
        ("archive", "MAX_ARCHIVE_BYTES", "OCI archive is too large"),
        ("sbom", "MAX_SBOM_BYTES", "candidate SBOM is too large"),
        ("metadata", "MAX_CANDIDATE_METADATA_BYTES", "candidate metadata is too large"),
        ("provenance", "MAX_CANDIDATE_PROVENANCE_BYTES", "candidate provenance is too large"),
    ],
)
def test_candidate_inputs_preflight_every_file_before_any_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_name: str,
    limit_name: str,
    message: str,
) -> None:
    pin, paths = write_candidate_bundle(tmp_path)
    assert paths[input_name].stat().st_size > 1
    monkeypatch.setattr(artifact, limit_name, 1)
    monkeypatch.setattr(
        artifact,
        "file_digest",
        lambda *_args, **_kwargs: pytest.fail("candidate input was hashed before all preflights"),
    )

    with pytest.raises(ValueError, match=message):
        artifact.validate_candidate_inputs(
            pin,
            archive_path=paths["archive"],
            sbom_path=paths["sbom"],
            metadata_path=paths["metadata"],
            provenance_path=paths["provenance"],
        )


@pytest.mark.parametrize("input_name", ["archive", "sbom", "metadata", "provenance"])
def test_candidate_inputs_reject_non_regular_files_before_any_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_name: str,
) -> None:
    pin, paths = write_candidate_bundle(tmp_path)
    replacement = tmp_path / f"{input_name}-directory"
    replacement.mkdir()
    paths[input_name] = replacement
    monkeypatch.setattr(
        artifact,
        "file_digest",
        lambda *_args, **_kwargs: pytest.fail("non-regular candidate input was hashed"),
    )

    with pytest.raises(ValueError, match="must be a regular file"):
        artifact.validate_candidate_inputs(
            pin,
            archive_path=paths["archive"],
            sbom_path=paths["sbom"],
            metadata_path=paths["metadata"],
            provenance_path=paths["provenance"],
        )


def test_candidate_entrypoint_rejects_oversized_archive_before_any_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    archive_path.write_bytes(b"oversized")
    untouched = tmp_path / "untouched"
    untouched.write_bytes(b"")
    monkeypatch.setattr(artifact, "MAX_ARCHIVE_BYTES", 1)
    monkeypatch.setattr(
        artifact,
        "file_digest",
        lambda *_args, **_kwargs: pytest.fail("candidate input was hashed"),
    )
    monkeypatch.setattr(
        artifact,
        "inspect_oci_archive",
        lambda *_args, **_kwargs: pytest.fail("candidate archive was inspected"),
    )

    with pytest.raises(ValueError, match="archive is too large"):
        artifact.validate_candidate_inputs(
            pin,
            archive_path=archive_path,
            sbom_path=untouched,
            metadata_path=untouched,
            provenance_path=untouched,
        )


def test_candidate_attestation_binds_exact_successful_producer_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    calls: list[list[str]] = []
    attestation = valid_candidate_attestation(pin)
    run_record = valid_candidate_run_record(pin)

    def run(command: list[str], **_kwargs: object) -> str:
        calls.append(command)
        return json.dumps(attestation if command[1:3] == ["attestation", "verify"] else run_record)

    monkeypatch.setattr(artifact, "_run", run)

    assert artifact.verify_candidate_attestations(pin, tmp_path / "candidate.json", archive_path) == {
        "pin": attestation[0],
        "archive": attestation[0],
    }
    assert calls[0][:3] == ["gh", "attestation", "verify"]
    assert ["--signer-digest", pin["commit"]] == calls[0][calls[0].index("--signer-digest") :][:2]
    assert "--deny-self-hosted-runners" in calls[0]
    assert calls[1][:3] == ["gh", "attestation", "verify"]
    assert calls[2] == [
        "gh",
        "api",
        (
            f"repos/{artifact.RUST_REPOSITORY}/actions/runs/{pin['run']['id']}"  # type: ignore[index]
            f"/attempts/{pin['run']['attempt']}"  # type: ignore[index]
        ),
    ]


def test_candidate_attestation_rejects_missing_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    monkeypatch.setattr(artifact, "_run", lambda *_args, **_kwargs: "[]")

    with pytest.raises(ValueError, match="returned no result"):
        artifact.verify_candidate_attestations(
            pin,
            tmp_path / "candidate.json",
            tmp_path / "candidate.oci.tar",
        )


def test_candidate_attestation_rejects_a_failed_producer_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    attestation = valid_candidate_attestation(pin)
    run_record = {**valid_candidate_run_record(pin), "conclusion": "failure"}

    def run(command: list[str], **_kwargs: object) -> str:
        return json.dumps(attestation if command[1:3] == ["attestation", "verify"] else run_record)

    monkeypatch.setattr(artifact, "_run", run)

    with pytest.raises(ValueError, match="completed successfully"):
        artifact.verify_candidate_attestations(
            pin,
            tmp_path / "candidate.json",
            tmp_path / "candidate.oci.tar",
        )


def test_candidate_attestation_rejects_an_in_progress_same_run_consumer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    attestation = valid_candidate_attestation(pin)
    run_record = {**valid_candidate_run_record(pin), "status": "in_progress", "conclusion": None}

    def run(command: list[str], **_kwargs: object) -> str:
        return json.dumps(attestation if command[1:3] == ["attestation", "verify"] else run_record)

    monkeypatch.setattr(artifact, "_run", run)
    with pytest.raises(ValueError, match="completed successfully"):
        artifact.verify_candidate_attestations(
            pin,
            tmp_path / "candidate.json",
            tmp_path / "candidate.oci.tar",
        )


@pytest.mark.parametrize(
    "field",
    [
        "workflow.ref",
        "workflow.repository",
        "workflow.path",
        "dependency.uri",
        "dependency.digest",
        "builder.id",
        "metadata.invocationId",
        "duplicate",
        "run.status",
        "run.conclusion",
        "run.head_sha",
        "run.head_branch",
        "run.event",
        "run.run_attempt",
        "run.path",
    ],
)
def test_candidate_attestation_rejects_every_producer_binding_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    pin = valid_candidate_pin()
    attestation = copy.deepcopy(valid_candidate_attestation(pin))
    run_record = valid_candidate_run_record(pin)
    if field == "duplicate":
        attestation.append(copy.deepcopy(attestation[0]))
    elif field.startswith("run."):
        run_record[field.removeprefix("run.")] = "mutated"
    else:
        predicate = attestation[0]["verificationResult"]["statement"]["predicate"]
        locations = {
            "workflow.ref": predicate["buildDefinition"]["externalParameters"]["workflow"],
            "workflow.repository": predicate["buildDefinition"]["externalParameters"]["workflow"],
            "workflow.path": predicate["buildDefinition"]["externalParameters"]["workflow"],
            "dependency.uri": predicate["buildDefinition"]["resolvedDependencies"][0],
            "dependency.digest": predicate["buildDefinition"]["resolvedDependencies"][0]["digest"],
            "builder.id": predicate["runDetails"]["builder"],
            "metadata.invocationId": predicate["runDetails"]["metadata"],
        }
        locations[field][field.rsplit(".", 1)[1]] = "mutated"

    def run(command: list[str], **_kwargs: object) -> str:
        return json.dumps(attestation if command[1:3] == ["attestation", "verify"] else run_record)

    monkeypatch.setattr(artifact, "_run", run)
    with pytest.raises(ValueError, match="exact producer run|identity or conclusion changed|completed successfully"):
        artifact.verify_candidate_attestations(
            pin,
            tmp_path / "candidate.json",
            tmp_path / "candidate.oci.tar",
        )


def test_run_candidate_is_one_fail_closed_validation_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    pin_path = write_pin(tmp_path / "candidate.json", pin)
    paths = {name: tmp_path / f"{name}.json" for name in ("archive", "sbom", "metadata", "provenance")}
    evidence = tmp_path / "evidence.json"
    calls: list[str] = []
    monkeypatch.setattr(
        artifact,
        "validate_candidate_inputs",
        lambda *_args, **_kwargs: calls.append("validate") or {},
    )
    monkeypatch.setattr(
        artifact,
        "verify_candidate_attestations",
        lambda *_args, **_kwargs: calls.append("attest") or {},
    )
    monkeypatch.setattr(
        artifact,
        "load_candidate_archive",
        lambda *_args, **_kwargs: calls.append("load") or artifact.image_reference(pin),
    )
    monkeypatch.setattr(
        artifact,
        "_remove_candidate_image",
        lambda reference: calls.append(f"remove:{reference}"),
    )

    @contextmanager
    def staged(*_args: object, **_kwargs: object) -> object:
        calls.append("stage")
        yield paths["archive"]

    monkeypatch.setattr(artifact, "stage_candidate_archive", staged)
    monkeypatch.setattr(
        artifact,
        "run_artifact_test",
        lambda *_args, **kwargs: calls.append(f"run:{kwargs['provenance_verified']}") or {"status": "passed"},
    )

    assert (
        artifact.main(
            [
                "run-candidate",
                "--pin",
                str(pin_path),
                "--archive",
                str(paths["archive"]),
                "--sbom",
                str(paths["sbom"]),
                "--metadata",
                str(paths["metadata"]),
                "--provenance",
                str(paths["provenance"]),
                "--evidence",
                str(evidence),
            ]
        )
        == 0
    )
    assert calls == [
        "validate",
        "attest",
        "stage",
        "load",
        "run:True",
        f"remove:{pin['image']['archive_tag']}:latest",  # type: ignore[index]
        f"remove:{artifact.image_reference(pin)}",
    ]
    candidate_options = {
        option
        for action in artifact.parser()._subparsers._group_actions[0].choices["run-candidate"]._actions
        for option in action.option_strings
    }
    assert "--provenance-verified" not in candidate_options


@pytest.mark.parametrize("failing_stage", ["validate", "attest", "stage", "load"])
def test_run_candidate_removes_stale_evidence_before_early_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failing_stage: str,
) -> None:
    pin_path = write_pin(tmp_path / "candidate.json", valid_candidate_pin())
    paths = {name: tmp_path / f"{name}.json" for name in ("archive", "sbom", "metadata", "provenance")}
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"status":"stale"}\n', encoding="utf-8")

    def stage(name: str) -> Callable[..., object]:
        def run(*_args: object, **_kwargs: object) -> object:
            if name == failing_stage:
                raise ValueError(f"{name} failed")
            return {}

        return run

    monkeypatch.setattr(artifact, "validate_candidate_inputs", stage("validate"))
    monkeypatch.setattr(artifact, "verify_candidate_attestations", stage("attest"))
    monkeypatch.setattr(artifact, "load_candidate_archive", stage("load"))

    @contextmanager
    def staged(*_args: object, **_kwargs: object) -> object:
        if failing_stage == "stage":
            raise ValueError("stage failed")
        yield paths["archive"]

    monkeypatch.setattr(artifact, "stage_candidate_archive", staged)
    monkeypatch.setattr(artifact, "run_artifact_test", lambda *_args, **_kwargs: {"status": "passed"})

    with pytest.raises(ValueError, match=f"{failing_stage} failed"):
        artifact.main(
            [
                "run-candidate",
                "--pin",
                str(pin_path),
                "--archive",
                str(paths["archive"]),
                "--sbom",
                str(paths["sbom"]),
                "--metadata",
                str(paths["metadata"]),
                "--provenance",
                str(paths["provenance"]),
                "--evidence",
                str(evidence),
            ]
        )
    assert not evidence.exists()


def test_run_candidate_cleans_created_tags_when_runtime_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    pin_path = write_pin(tmp_path / "candidate.json", pin)
    paths = {name: tmp_path / f"{name}.json" for name in ("archive", "sbom", "metadata", "provenance")}
    removed: list[str] = []
    monkeypatch.setattr(artifact, "validate_candidate_inputs", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(artifact, "verify_candidate_attestations", lambda *_args, **_kwargs: {})

    @contextmanager
    def staged(*_args: object, **_kwargs: object) -> object:
        yield paths["archive"]

    monkeypatch.setattr(artifact, "stage_candidate_archive", staged)
    monkeypatch.setattr(artifact, "load_candidate_archive", lambda *_args: artifact.image_reference(pin))
    monkeypatch.setattr(
        artifact,
        "run_artifact_test",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("runtime failed")),
    )
    monkeypatch.setattr(artifact, "_remove_candidate_image", removed.append)

    with pytest.raises(ValueError, match="runtime failed"):
        artifact.main(
            [
                "run-candidate",
                "--pin",
                str(pin_path),
                "--archive",
                str(paths["archive"]),
                "--sbom",
                str(paths["sbom"]),
                "--metadata",
                str(paths["metadata"]),
                "--provenance",
                str(paths["provenance"]),
                "--evidence",
                str(tmp_path / "evidence.json"),
            ]
        )
    assert removed == [
        f"{pin['image']['archive_tag']}:latest",  # type: ignore[index]
        artifact.image_reference(pin),
    ]


def test_candidate_comparison_removes_stale_evidence_before_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "comparison.json"
    evidence.write_text('{"status":"stale"}\n', encoding="utf-8")
    monkeypatch.setattr(
        artifact,
        "load_pin",
        lambda *_args, expected_state="ready": (
            valid_candidate_pin() if expected_state == "candidate" else artifact.FROZEN_LEGACY_SAFE_SESSION_PIN
        ),
    )
    monkeypatch.setattr(
        artifact,
        "compare_oracle_candidate_evidence",
        lambda *_args: (_ for _ in ()).throw(ValueError("comparison failed")),
    )

    with pytest.raises(ValueError, match="comparison failed"):
        artifact.main(
            [
                "compare-candidate-evidence",
                "--oracle",
                str(tmp_path / "oracle.json"),
                "--candidate",
                str(tmp_path / "candidate.json"),
                "--oracle-pin",
                str(tmp_path / "oracle-pin.json"),
                "--candidate-pin",
                str(tmp_path / "candidate-pin.json"),
                "--evidence",
                str(evidence),
            ]
        )
    assert not evidence.exists()


def test_candidate_archive_is_privately_staged_rehashed_and_reverified(tmp_path: Path) -> None:
    pin, paths = write_candidate_bundle(tmp_path)
    staged_path: Path | None = None

    with artifact.stage_candidate_archive(pin, paths["archive"]) as staged:
        staged_path = staged
        assert staged != paths["archive"]
        assert staged.is_file()
        assert artifact.file_digest(staged) == pin["archive"]["digest"]  # type: ignore[index]
        assert staged.read_bytes() == paths["archive"].read_bytes()

    assert staged_path is not None
    assert not staged_path.exists()


def test_candidate_archive_private_staging_rejects_wrong_digest(tmp_path: Path) -> None:
    pin, paths = write_candidate_bundle(tmp_path)
    pin["archive"]["digest"] = "sha256:" + "0" * 64  # type: ignore[index]

    with (
        pytest.raises(ValueError, match="digest changed during private staging"),
        artifact.stage_candidate_archive(pin, paths["archive"]),
    ):
        pytest.fail("wrong-digest archive was staged")


def test_candidate_archive_private_staging_rejects_lstat_open_toctou(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin, paths = write_candidate_bundle(tmp_path)
    original_fstat = artifact.os.fstat

    def changed_fstat(descriptor: int) -> object:
        opened = original_fstat(descriptor)
        fields = list(opened)
        fields[1] += 1
        return artifact.os.stat_result(fields)

    monkeypatch.setattr(artifact.os, "fstat", changed_fstat)
    with (
        pytest.raises(ValueError, match="changed before private staging"),
        artifact.stage_candidate_archive(pin, paths["archive"]),
    ):
        pytest.fail("TOCTOU-mutated archive was staged")


def test_candidate_runtime_rejects_an_unloaded_or_rebound_config_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    inspection = {
        "Id": "sha256:" + "f" * 64,
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "Env": [
                "SERVICE_NAME=verification",
                f"MARTY_RELEASE_VERSION={pin['version']}",
                f"MARTY_UI_SHA={pin['commit']}",
            ],
            "Labels": {
                "org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
                "org.opencontainers.image.revision": pin["commit"],
                "org.opencontainers.image.version": pin["version"],
            },
        },
    }
    monkeypatch.setattr(artifact, "_run", lambda *_args, **_kwargs: json.dumps(inspection))

    with pytest.raises(ValueError, match="loaded candidate image identity changed"):
        artifact.run_artifact_test(pin, tmp_path / "evidence.json", provenance_verified=True)


def test_candidate_archive_load_rechecks_exact_config_platform_and_labels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "candidate.oci.tar"
    calls: list[list[str]] = []
    inspection = {
        "Id": pin["image"]["config_digest"],  # type: ignore[index]
        "Descriptor": {"digest": pin["image"]["digest"]},  # type: ignore[index]
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "Env": [
                "SERVICE_NAME=verification",
                f"MARTY_RELEASE_VERSION={pin['version']}",
                f"MARTY_UI_SHA={pin['commit']}",
            ],
            "Labels": {
                "org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
                "org.opencontainers.image.revision": pin["commit"],
                "org.opencontainers.image.version": pin["version"],
            },
        },
    }

    def run(command: list[str], **_kwargs: object) -> str:
        calls.append(command)
        return f"Loaded image: {pin['image']['archive_tag']}:latest" if command[1] == "load" else ""

    monkeypatch.setattr(artifact, "_run", run)
    inspections = iter([None, None, None, inspection, inspection])
    monkeypatch.setattr(artifact, "_inspect_optional_docker_image", lambda *_args: next(inspections))
    monkeypatch.setattr(artifact, "_verify_staged_candidate_archive", lambda *_args: None)
    monkeypatch.setattr(artifact, "_remove_candidate_image", lambda *_args: None)

    artifact.load_candidate_archive(pin, archive_path)

    assert calls == [
        ["docker", "load", "--input", str(archive_path)],
        [
            "docker",
            "image",
            "tag",
            f"{pin['image']['archive_tag']}@{pin['image']['digest']}",  # type: ignore[index]
            artifact.image_reference(pin),
        ],
    ]


@pytest.mark.parametrize("returncode", [0, 1])
def test_candidate_image_removal_accepts_only_verified_absence(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
) -> None:
    reference = "ghcr.io/elevenid/marty-ui-verification-candidate:cleanup"
    commands: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> object:
        commands.append(command)
        return artifact.subprocess.CompletedProcess(command, returncode, stdout="", stderr="private")

    monkeypatch.setattr(artifact.subprocess, "run", run)
    monkeypatch.setattr(artifact, "_inspect_optional_docker_image", lambda *_args: None)

    artifact._remove_candidate_image(reference)

    assert commands == [["docker", "image", "rm", "-f", reference]]


def test_candidate_image_removal_rejects_a_still_present_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "ghcr.io/elevenid/marty-ui-verification-candidate:cleanup"
    monkeypatch.setattr(
        artifact.subprocess,
        "run",
        lambda command, **_kwargs: artifact.subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(artifact, "_inspect_optional_docker_image", lambda *_args: {"Id": "private"})

    with pytest.raises(
        artifact.ArtifactRuntimeError,
        match="remove candidate image did not remove its scoped reference",
    ):
        artifact._remove_candidate_image(reference)


def test_candidate_image_removal_sanitizes_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "ghcr.io/elevenid/marty-ui-verification-candidate:cleanup"

    def timeout(command: list[str], **_kwargs: object) -> object:
        raise artifact.subprocess.TimeoutExpired(command, 30, output="private cleanup output")

    monkeypatch.setattr(artifact.subprocess, "run", timeout)

    with pytest.raises(
        artifact.ArtifactRuntimeError,
        match="^remove candidate image could not complete$",
    ) as raised:
        artifact._remove_candidate_image(reference)
    assert "private cleanup output" not in str(raised.value)


def test_candidate_image_inspection_sanitizes_invalid_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "ghcr.io/elevenid/marty-ui-verification-candidate:cleanup"
    monkeypatch.setattr(
        artifact.subprocess,
        "run",
        lambda command, **_kwargs: artifact.subprocess.CompletedProcess(
            command,
            0,
            stdout="private invalid output",
            stderr="",
        ),
    )

    with pytest.raises(
        artifact.ArtifactRuntimeError,
        match="^inspect candidate image returned invalid output$",
    ) as raised:
        artifact._inspect_optional_docker_image(reference)
    assert "private invalid output" not in str(raised.value)


def test_candidate_image_cleanup_attempts_every_unique_scoped_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def remove(reference: str) -> None:
        calls.append(reference)
        if reference == "failed":
            raise artifact.ArtifactRuntimeError("private failure")

    monkeypatch.setattr(artifact, "_remove_candidate_image", remove)

    with pytest.raises(
        artifact.ArtifactRuntimeError,
        match="^candidate image cleanup did not remove every scoped reference$",
    ) as raised:
        artifact._remove_candidate_images("failed", "removed", "failed")
    assert calls == ["failed", "removed"]
    assert "private failure" not in str(raised.value)


@pytest.mark.parametrize("preexisting", ["archive", "digest", "verified"])
def test_candidate_archive_load_rejects_preexisting_local_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    preexisting: str,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "private.oci.tar"
    inspection = valid_candidate_inspection(pin)
    results = {
        "archive": [inspection],
        "digest": [None, inspection],
        "verified": [None, None, inspection],
    }[preexisting]
    monkeypatch.setattr(artifact, "_verify_staged_candidate_archive", lambda *_args: None)
    monkeypatch.setattr(artifact, "_inspect_optional_docker_image", lambda *_args: results.pop(0))
    monkeypatch.setattr(
        artifact,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("pre-existing image was accepted for candidate load"),
    )

    with pytest.raises(ValueError, match="already exists locally"):
        artifact.load_candidate_archive(pin, archive_path)


@pytest.mark.parametrize("identity", ["manifest", "config"])
def test_candidate_archive_load_requires_both_manifest_and_config_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    identity: str,
) -> None:
    pin = valid_candidate_pin()
    archive_path = tmp_path / "private.oci.tar"
    inspection = valid_candidate_inspection(pin)
    if identity == "manifest":
        inspection["Descriptor"] = {"digest": "sha256:" + "0" * 64}
    else:
        inspection["Id"] = "sha256:" + "0" * 64
    inspections = iter([None, None, None, inspection])
    monkeypatch.setattr(artifact, "_verify_staged_candidate_archive", lambda *_args: None)
    monkeypatch.setattr(artifact, "_inspect_optional_docker_image", lambda *_args: next(inspections))
    monkeypatch.setattr(artifact, "_remove_candidate_image", lambda *_args: None)
    monkeypatch.setattr(
        artifact,
        "_run",
        lambda command, **_kwargs: (
            f"Loaded image: {pin['image']['archive_tag']}:latest" if command[1] == "load" else ""
        ),
    )

    with pytest.raises(ValueError, match="loaded candidate image identity changed"):
        artifact.load_candidate_archive(pin, archive_path)


def test_candidate_archive_load_requires_useful_exact_tag_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_candidate_pin()
    inspections = iter([None, None, None])
    monkeypatch.setattr(artifact, "_verify_staged_candidate_archive", lambda *_args: None)
    monkeypatch.setattr(artifact, "_inspect_optional_docker_image", lambda *_args: next(inspections))
    monkeypatch.setattr(artifact, "_remove_candidate_image", lambda *_args: None)
    monkeypatch.setattr(artifact, "_run", lambda *_args, **_kwargs: "Loaded image ID: sha256:rebound")

    with pytest.raises(ValueError, match="did not report the expected image tag"):
        artifact.load_candidate_archive(pin, tmp_path / "private.oci.tar")


@pytest.mark.skipif(
    os.getenv("RUN_CANDIDATE_DOCKER_TESTS") != "true",
    reason="set RUN_CANDIDATE_DOCKER_TESTS=true for the disposable containerd load contract",
)
def test_candidate_archive_real_containerd_rejects_preexisting_wrong_literal_tag(
    tmp_path: Path,
) -> None:
    pin, paths = write_candidate_bundle(tmp_path)
    literal_reference = f"{pin['image']['archive_tag']}:latest"  # type: ignore[index]
    verified_reference = artifact.image_reference(pin)
    unrelated = tmp_path / "unrelated.tar"
    with tarfile.open(unrelated, mode="w") as archive:
        payload = b"unrelated local image"
        member = tarfile.TarInfo("unrelated.txt")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    artifact._remove_candidate_image(literal_reference)
    artifact._remove_candidate_image(verified_reference)
    try:
        artifact._run(
            ["docker", "image", "import", "--platform", "linux/amd64", str(unrelated), literal_reference],
            label="create unrelated pre-existing candidate tag",
        )
        before = artifact._inspect_optional_docker_image(literal_reference)
        assert before is not None
        with (
            artifact.stage_candidate_archive(pin, paths["archive"]) as staged,
            pytest.raises(ValueError, match="archive tag already exists locally"),
        ):
            artifact.load_candidate_archive(pin, staged)
        after = artifact._inspect_optional_docker_image(literal_reference)
        assert after is not None
        assert after["Id"] == before["Id"]
        assert artifact._inspect_optional_docker_image(verified_reference) is None
    finally:
        artifact._remove_candidate_image(literal_reference)
        artifact._remove_candidate_image(verified_reference)


@pytest.mark.skipif(
    os.getenv("RUN_CANDIDATE_DOCKER_TESTS") != "true",
    reason="set RUN_CANDIDATE_DOCKER_TESTS=true for the disposable containerd load contract",
)
def test_candidate_archive_disposable_containerd_load_contract(tmp_path: Path) -> None:
    pin, paths = write_candidate_bundle(tmp_path)
    expected_reference = f"{pin['image']['archive_tag']}:latest"  # type: ignore[index]
    exact_archive_reference = f"{pin['image']['archive_tag']}@{pin['image']['digest']}"  # type: ignore[index]
    verified_reference = artifact.image_reference(pin)
    artifact._remove_candidate_image(expected_reference)
    artifact._remove_candidate_image(exact_archive_reference)
    artifact._remove_candidate_image(verified_reference)
    try:
        with artifact.stage_candidate_archive(pin, paths["archive"]) as staged:
            assert artifact.load_candidate_archive(pin, staged) == verified_reference
        inspected = json.loads(
            artifact._run(
                ["docker", "image", "inspect", verified_reference, "--format", "{{json .}}"],
                label="inspect disposable candidate",
            )
        )
        exported_config_digest = artifact._exported_candidate_config_digest(verified_reference, pin, inspected)
        artifact._assert_loaded_candidate_inspection(
            inspected,
            pin,
            exported_config_digest=exported_config_digest,
        )
    finally:
        artifact._remove_candidate_image(expected_reference)
        artifact._remove_candidate_image(exact_archive_reference)
        artifact._remove_candidate_image(verified_reference)


def test_oracle_candidate_evidence_comparison_allows_only_documented_runtime_difference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = {
        "repository": artifact.INTEGRATION_REPOSITORY,
        "commit": "f" * 40,
        "hardened_floor": artifact.HARDENED_HARNESS_FLOOR,
    }
    monkeypatch.setattr(artifact, "harness_subject", lambda: harness)
    oracle_pin = artifact.FROZEN_LEGACY_SAFE_SESSION_PIN
    candidate_pin = valid_candidate_pin()
    common = {
        "classification": "ElevenID-owned artifact integration",
        "official_suite_invoked": False,
        "official_suite_source_modified": False,
        "status": "passed",
        "release_clearance": artifact.RELEASE_CLEARANCE_BLOCKED,
        "blockers": [artifact.OID4VP_POSITIVE_RUNTIME_BLOCKER],
        "resolver_request_count": 2,
        "harness": harness,
        "started_at": "2026-08-31T00:00:00Z",
        "completed_at": "2026-08-31T00:01:00Z",
    }
    oracle = {
        **common,
        "schema": artifact.EVIDENCE_SCHEMA,
        "subject": artifact.evidence_subject(oracle_pin),
        "checks": sorted(artifact.EXPECTED_LANGUAGE_NEUTRAL_CHECKS),
        "safe_session_selection": {
            "reason": "frozen_python_v0.1.71_invalid_leading_identifier",
            "resampled_unsafe_ids": 1,
        },
        "documented_differences": [],
    }
    candidate = {
        **common,
        "schema": artifact.CANDIDATE_EVIDENCE_SCHEMA,
        "subject": artifact.evidence_subject(candidate_pin),
        "checks": sorted(artifact.EXPECTED_LANGUAGE_NEUTRAL_CHECKS | artifact.RUST_ONLY_CHECKS),
        "safe_session_selection": {
            "reason": "not_allowlisted_no_resampling",
            "resampled_unsafe_ids": 0,
        },
        "documented_differences": sorted(artifact.DOCUMENTED_TARGET_DIFFERENCES),
    }
    oracle_path = tmp_path / "oracle.json"
    candidate_path = tmp_path / "candidate.json"
    oracle_path.write_text(json.dumps(oracle), encoding="utf-8")
    candidate_path.write_text(json.dumps(candidate), encoding="utf-8")

    comparison = artifact.compare_oracle_candidate_evidence(
        oracle_path,
        candidate_path,
        oracle_pin,
        candidate_pin,
    )

    assert comparison == {
        "schema": "elevenid.credentials-verifier-candidate-comparison/v1",
        "status": "matched_with_runtime_blocker",
        "release_clearance": artifact.RELEASE_CLEARANCE_BLOCKED,
        "blockers": [artifact.OID4VP_POSITIVE_RUNTIME_BLOCKER],
        "language_neutral_checks": sorted(artifact.EXPECTED_LANGUAGE_NEUTRAL_CHECKS),
        "candidate_only_checks": sorted(artifact.RUST_ONLY_CHECKS),
        "documented_differences": sorted(artifact.DOCUMENTED_TARGET_DIFFERENCES),
    }

    for label, original in (("oracle", oracle), ("candidate", candidate)):
        for field in original:
            changed_oracle = copy.deepcopy(oracle)
            changed_candidate = copy.deepcopy(candidate)
            target = changed_oracle if label == "oracle" else changed_candidate
            target[field] = None
            oracle_path.write_text(json.dumps(changed_oracle), encoding="utf-8")
            candidate_path.write_text(json.dumps(changed_candidate), encoding="utf-8")
            with pytest.raises(ValueError, match=r".+"):
                artifact.compare_oracle_candidate_evidence(
                    oracle_path,
                    candidate_path,
                    oracle_pin,
                    candidate_pin,
                )


def test_default_disabled_start_requires_native_health_without_compatibility_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    absent_probes: list[str] = []
    monkeypatch.setattr(
        artifact,
        "_run",
        lambda command, **_kwargs: commands.append(command) or "",
    )
    monkeypatch.setattr(artifact, "_service_port", lambda *_args: 43123)
    monkeypatch.setattr(
        artifact,
        "_wait_for_health",
        lambda *_args: {"status": "healthy", "service": "verification", "components": {}},
    )
    monkeypatch.setattr(
        artifact,
        "_assert_compatibility_routes_absent",
        lambda url: absent_probes.append(url),
    )

    base_url = artifact._start_service(
        ["docker", "run", "candidate"],
        "disabled-service",
        artifact.RUST_TARGET,
        label="start disabled",
        compatibility_enabled=False,
    )

    assert commands == [["docker", "run", "candidate"]]
    assert base_url == "http://127.0.0.1:43123"
    assert absent_probes == [base_url]


def test_verification_database_snapshot_is_stable_and_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    def run(command: list[str], **_kwargs: object) -> str:
        captured.extend(command)
        return "header\n\\restrict token-one\nCREATE TABLE verification_service.a ();\n\\unrestrict token-one"

    monkeypatch.setattr(artifact, "_run", run)

    assert artifact._verification_database_snapshot("postgres-test") == (
        "header\nCREATE TABLE verification_service.a ();"
    )
    assert "postgres-test" in captured
    assert "--no-owner" in captured
    assert not any(value.startswith("--schema") for value in captured)
    assert "--schema-only" not in captured


def test_verification_migration_heads_are_exact_and_ordered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    def run(command: list[str], **_kwargs: object) -> str:
        captured.extend(command)
        return f"{artifact.EXPECTED_MIGRATION_HEAD}\n"

    monkeypatch.setattr(artifact, "_run", run)

    assert artifact._verification_migration_heads("postgres-test") == [artifact.EXPECTED_MIGRATION_HEAD]
    assert "verification_service.alembic_version" in captured[-1]
    assert "ORDER BY version_num" in captured[-1]


def test_harness_subject_binds_current_commit_and_hardened_ancestry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "f" * 40
    calls: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> str:
        calls.append(command)
        return commit if "rev-parse" in command else ""

    monkeypatch.setattr(artifact, "_run", run)

    assert artifact.harness_subject() == {
        "repository": artifact.INTEGRATION_REPOSITORY,
        "commit": commit,
        "hardened_floor": artifact.HARDENED_HARNESS_FLOOR,
        "script": {
            "path": "scripts/credentials_verifier_artifact.py",
            "digest": artifact.file_digest(Path(artifact.__file__).resolve()),
        },
    }
    assert calls[0][-3:] == ["--quiet", "--ignore-submodules", "--"]
    assert calls[1][-4:] == ["--cached", "--quiet", "--ignore-submodules", "--"]
    assert calls[2][:3] == ["git", "-C", str(artifact.ROOT)]
    assert calls[3][-3:] == ["--is-ancestor", artifact.HARDENED_HARNESS_FLOOR, commit]


@pytest.mark.parametrize("dirty_mode", ["worktree", "index"])
def test_harness_subject_rejects_tracked_modifications(
    monkeypatch: pytest.MonkeyPatch,
    dirty_mode: str,
) -> None:
    call = 0

    def run(_command: list[str], **_kwargs: object) -> str:
        nonlocal call
        call += 1
        if (dirty_mode == "worktree" and call == 1) or (dirty_mode == "index" and call == 2):
            raise artifact.ArtifactRuntimeError("tracked harness changes")
        return ""

    monkeypatch.setattr(artifact, "_run", run)

    with pytest.raises(artifact.ArtifactRuntimeError, match="tracked harness changes"):
        artifact.harness_subject()


def test_migration_commands_preserve_each_images_runtime_contract() -> None:
    rust = artifact._migration_command(
        "rust-image@sha256:digest",
        artifact.RUST_TARGET,
        "verification-network",
        "postgresql://database",
    )
    legacy = artifact._migration_command(
        "python-image@sha256:digest",
        artifact.LEGACY_TARGET,
        "verification-network",
        "postgresql://database",
    )

    assert rust[-4:] == [
        "--entrypoint",
        "/app/services/entrypoint.sh",
        "rust-image@sha256:digest",
        "migrate",
    ]
    assert "SERVICE_NAME=verification" in rust
    assert legacy[-4:] == [
        "python-image@sha256:digest",
        "python",
        "manage_migrations.py",
        "upgrade",
    ]
    assert "--entrypoint" not in legacy


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(name="attacker/image"), "unexpected image"),
        (
            lambda value: value["packages"][0].update(versionInfo="sha256:" + "d" * 64),
            "not bound",
        ),
        (
            lambda value: value.update(packages=value["packages"][:2]),
            "missing required native",
        ),
    ],
)
def test_sbom_rejects_wrong_subject_or_missing_native_package(
    tmp_path: Path,
    mutate: object,
    message: str,
) -> None:
    value = valid_sbom()
    mutate(value)  # type: ignore[operator]
    path = tmp_path / "verification.spdx.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        artifact.validate_sbom(path, valid_pin())


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("state",), "awaiting_release", "must be ready"),
        (("repository",), "attacker/example", "does not match its schema"),
        (("release_tag",), "v1.2.3-rc.1", "stable SemVer"),
        (("source_ref",), "refs/tags/v1.2.3", "attested release source"),
        (("image", "uri"), artifact.EXPECTED_IMAGE_URI + ":latest", "unexpected verification image URI"),
        (("image", "digest"), "sha256:" + "B" * 64, "image digest"),
        (("sbom", "digest"), "sha256:" + "d" * 63, "SBOM digest"),
    ],
)
def test_pin_rejects_mutable_or_unreviewed_inputs(
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    pin = valid_pin()
    target = pin
    for part in path[:-1]:
        target = target[part]  # type: ignore[assignment,index]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(ValueError, match=message):
        artifact.load_pin(write_pin(tmp_path / "pin.json", pin))


def test_governance_binds_key_to_exact_org_profiles_and_artifact() -> None:
    pin = valid_pin()
    governance = artifact.build_governance(
        pin,
        "ephemeral-api-key",
        "123e4567-e89b-42d3-a456-426614174000",
        "did:web:issuer.integration.invalid",
        vds_only_api_key="vds-only-api-key",
        oid4vp_only_api_key="oid4vp-only-api-key",
    )

    assert governance["component"] == {
        "component_id": "marty-credentials",
        "version": "1.2.3",
        "artifact_digest": "sha256:" + "b" * 64,
        "adapter_id": "verification-service",
        "adapter_version": "1.0.0",
    }
    assert governance["policies"][0]["content"]["required_checks"] == [
        "credential.proof",
        "issuer.trust",
    ]
    assert governance["policies"][1]["content"] == {
        "verifier_id": "did:web:verifier.integration.invalid",
        "presentation_definition_digest": artifact.canonical_digest(artifact.presentation_definition()),
        "required_checks": artifact.OID4VP_REQUIRED_CHECKS,
    }
    assert governance["trust_profiles"][0]["content"] == {
        "trusted_issuers": ["did:web:issuer.integration.invalid"],
        "allow_public_did_fallback": False,
    }
    assert set(governance["clients"][0]["purposes"]) == {
        artifact.SESSION_PURPOSE,
        artifact.DIRECT_PURPOSE,
        artifact.VDS_PURPOSE,
    }
    assert set(governance["clients"][1]["purposes"]) == {artifact.VDS_PURPOSE}
    assert set(governance["clients"][2]["purposes"]) == {
        artifact.SESSION_PURPOSE,
        artifact.DIRECT_PURPOSE,
    }
    assert "ephemeral-api-key" not in json.dumps(governance)
    assert "vds-only-api-key" not in json.dumps(governance)
    assert "oid4vp-only-api-key" not in json.dumps(governance)


def test_missing_required_check_fixture_is_self_consistent() -> None:
    governance = artifact.build_governance(
        valid_pin(),
        "ephemeral-api-key",
        "123e4567-e89b-42d3-a456-426614174000",
        "did:web:issuer.integration.invalid",
    )
    invalid = artifact.invalid_governance_missing_required_check(governance)
    policy = invalid["policies"][0]

    assert policy["content"]["required_checks"] == ["credential.proof"]
    assert policy["content_digest"] == artifact.canonical_digest(policy["content"])


def test_vds_fixture_uses_public_jwk_and_separate_private_key() -> None:
    issuer = "did:web:issuer.integration.invalid"
    private_key, jwk, method_id = artifact.make_vds_key_material(issuer)

    assert set(jwk) == {"kty", "crv", "alg", "x", "y", "kid"}
    assert "d" not in jwk
    assert method_id == f"{issuer}#vdsnc-key"
    assert private_key.public_key().public_numbers().x.to_bytes(32, "big") == __import__("base64").urlsafe_b64decode(
        jwk["x"] + "=="
    )


def test_oid4vp_fixture_is_nonce_audience_bound_and_contains_no_private_jwk() -> None:
    token = artifact.make_oid4vp_jwt("n" * 43, "did:web:verifier.integration.invalid")
    header_segment, payload_segment, signature_segment = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(header_segment + "=="))
    payload = json.loads(base64.urlsafe_b64decode(payload_segment + "=="))

    assert header["alg"] == "EdDSA"
    assert set(header["jwk"]) == {"kty", "crv", "x"}
    assert payload["nonce"] == "n" * 43
    assert payload["aud"] == "did:web:verifier.integration.invalid"
    assert payload["exp"] > payload["iat"]
    assert len(base64.urlsafe_b64decode(signature_segment + "==")) == 64

    nonce_less = artifact.make_oid4vp_jwt(None, "did:web:verifier.integration.invalid")
    nonce_less_payload_segment = nonce_less.split(".")[1]
    nonce_less_payload = json.loads(base64.urlsafe_b64decode(nonce_less_payload_segment + "=="))
    assert "nonce" not in nonce_less_payload


def test_trusted_oid4vp_pass_fixture_projects_all_claim_constraints() -> None:
    value = artifact.trusted_oid4vp_pass_fixture()

    assert value["processing_status"] == "COMPLETED"
    assert value["decision_code"] == "ALL_REQUIRED_CHECKS_PASSED"

    canonical = artifact._assert_canonical(
        value,
        decision="PASS",
        expected_checks=set(artifact.OID4VP_REQUIRED_CHECKS),
        expected_check_projection=artifact.OID4VP_PASS_CHECK_PROJECTION,
        expected_input_digest="sha256:" + "a" * 64,
        expected_verification_method="jwt_vp",
    )

    assert canonical["checks"][-1] == {
        "check_id": "claim.constraints",
        "outcome": "PASSED",
        "code": "CLAIM_CONSTRAINTS_SATISFIED",
    }
    assert value["verified_claims"] is None
    assert value["claim_results"] == []


def test_canonical_projection_requires_exact_vds_check_floor() -> None:
    value = {
        "decision": "PASS",
        "overall_result": "PASS",
        "valid": True,
        "canonical_result": {
            "verification_id": "verification:fixture",
            "decision": "PASS",
            "valid": True,
            "processing_status": "COMPLETED",
            "context": {"transaction_id": "transaction:fixture"},
            "checks": [
                {"check_id": "credential.proof", "outcome": "PASSED"},
                {"check_id": "issuer.trust", "outcome": "PASSED"},
            ],
        },
    }
    value["verification_method"] = "w3c_vc"
    value["canonical_result"]["input_digest"] = "sha256:" + "a" * 64
    assert (
        artifact._assert_canonical(
            value,
            decision="PASS",
            expected_input_digest="sha256:" + "a" * 64,
            expected_verification_method="w3c_vc",
        )
        == value["canonical_result"]
    )

    value["verification_method"] = "jwt_vp"
    with pytest.raises(ValueError, match="verification method projection changed"):
        artifact._assert_canonical(value, decision="PASS", expected_verification_method="w3c_vc")
    value["verification_method"] = "w3c_vc"

    value["canonical_result"]["input_digest"] = "sha256:" + "b" * 64
    with pytest.raises(ValueError, match="canonical input digest changed"):
        artifact._assert_canonical(value, decision="PASS", expected_input_digest="sha256:" + "a" * 64)
    value["canonical_result"]["input_digest"] = "sha256:" + "a" * 64

    value["canonical_result"]["checks"].pop()
    with pytest.raises(ValueError, match="canonical check count changed"):
        artifact._assert_canonical(value, decision="PASS")

    value["decision"] = "FAIL"
    value["overall_result"] = "FAIL"
    value["valid"] = False
    value["canonical_result"] = {
        "verification_id": "verification:fixture",
        "decision": "FAIL",
        "valid": False,
        "processing_status": "COMPLETED",
        "context": {"transaction_id": "transaction:fixture"},
        "checks": [
            {"check_id": "credential.proof", "outcome": "PASSED"},
            {"check_id": "issuer.trust", "outcome": "PASSED"},
        ],
    }
    with pytest.raises(ValueError, match="no failing check"):
        artifact._assert_canonical(value, decision="FAIL")

    value["canonical_result"]["checks"][0]["outcome"] = "FAILED"
    assert artifact._assert_canonical(value, decision="FAIL") == value["canonical_result"]

    value["decision"] = "INDETERMINATE"
    value["overall_result"] = "INDETERMINATE"
    value["canonical_result"]["decision"] = "INDETERMINATE"
    value["canonical_result"]["checks"][0]["outcome"] = "PASSED"
    assert (
        artifact._assert_canonical(
            value,
            decision="INDETERMINATE",
            expected_passed_checks={"credential.proof", "issuer.trust"},
        )
        == value["canonical_result"]
    )


@pytest.mark.parametrize(
    ("decision", "projection"),
    [
        ("PASS", artifact.VDS_PASS_CHECK_PROJECTION),
        ("FAIL", artifact.VDS_FAIL_CHECK_PROJECTION),
    ],
)
def test_vds_projection_requires_exact_outcomes_and_codes(
    decision: str,
    projection: dict[str, tuple[str, str]],
) -> None:
    value = {
        "decision": decision,
        "overall_result": decision,
        "valid": decision == "PASS",
        "canonical_result": {
            "verification_id": "verification:fixture",
            "decision": decision,
            "valid": decision == "PASS",
            "processing_status": "COMPLETED",
            "context": {"transaction_id": "transaction:fixture"},
            "checks": [
                {"check_id": check_id, "outcome": outcome, "code": code}
                for check_id, (outcome, code) in projection.items()
            ],
        },
    }

    artifact._assert_canonical(value, decision=decision, expected_check_projection=projection)

    value["canonical_result"]["checks"][0]["code"] = "WRONG_FAILURE_CATEGORY"
    with pytest.raises(ValueError, match="canonical check projection changed"):
        artifact._assert_canonical(value, decision=decision, expected_check_projection=projection)


def test_session_projection_requires_exact_shape_binding_and_nonce_lifecycle() -> None:
    value = {
        "id": "session-1",
        "organization_id": "org-1",
        "verifier_did": "did:web:verifier.integration.invalid",
        "status": "pending",
        "request_uri": "oid4vp://request?session_id=session-1",
        "nonce": "n" * 43,
        "expires_at": "2026-08-31T15:00:00+00:00",
        "created_at": "2026-08-31T14:50:00+00:00",
    }

    artifact._assert_session(
        value,
        organization_id="org-1",
        expected_status="pending",
        nonce_present=True,
    )

    value["status"] = "failed"
    value["nonce"] = ""
    artifact._assert_session(
        value,
        organization_id="org-1",
        expected_status="failed",
        nonce_present=False,
    )

    value["unexpected"] = True
    with pytest.raises(ValueError, match="session response shape changed"):
        artifact._assert_session(
            value,
            organization_id="org-1",
            expected_status="failed",
            nonce_present=False,
        )


def _pending_session(session_id: str) -> dict[str, object]:
    return {
        "id": session_id,
        "organization_id": "org-1",
        "verifier_did": "did:web:verifier.integration.invalid",
        "status": "pending",
        "request_uri": f"oid4vp://request?session_id={session_id}",
        "nonce": "n" * 43,
        "expires_at": "2026-08-31T15:00:00+00:00",
        "created_at": "2026-08-31T14:50:00+00:00",
    }


def test_safe_session_allowlist_is_exact_and_future_rust_is_not_resampled() -> None:
    for allowed, expected_reason in (
        (artifact.FROZEN_LEGACY_SAFE_SESSION_PIN, "frozen_python_v0.1.71_invalid_leading_identifier"),
        (artifact.REJECTED_RUST_SAFE_SESSION_PIN, "rejected_rust_v1.1.208_invalid_leading_identifier"),
    ):
        assert artifact._safe_session_resample_reason(allowed) == expected_reason

        def mutations(value: object, path: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
            if isinstance(value, dict):
                return [nested for key, item in value.items() for nested in mutations(item, (*path, key))]
            return [path]

        for path in mutations(allowed):
            candidate = json.loads(json.dumps(allowed))
            cursor = candidate
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = "mutated"
            assert artifact._safe_session_resample_reason(candidate) is None

        with_extra = {**allowed, "unexpected": True}
        assert artifact._safe_session_resample_reason(with_extra) is None

    future_rust = valid_rust_pin()
    assert artifact._safe_session_resample_reason(future_rust) is None


def test_safe_session_creation_discards_only_allowlisted_unsafe_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    sessions = iter([_pending_session("_bad"), _pending_session("-bad"), _pending_session("Aok")])
    calls: list[str] = []

    def create(_method: str, url: str, **_kwargs: object) -> dict[str, object]:
        calls.append(url)
        return next(sessions)

    monkeypatch.setattr(artifact, "_http_json", create)
    selected, resampled, reason = artifact._create_safe_session(
        "https://verifier.invalid",
        {"fixture": True},
        "api-key",
        artifact.FROZEN_LEGACY_SAFE_SESSION_PIN,
        "org-1",
    )

    assert selected["id"] == "Aok"
    assert resampled == 2
    assert reason == "frozen_python_v0.1.71_invalid_leading_identifier"
    assert len(calls) == 3
    assert all(url.endswith("/v1/verification/sessions") and "/submit" not in url for url in calls)


def test_safe_session_creation_does_not_resample_future_rust(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def create(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return _pending_session("_future-rust")

    monkeypatch.setattr(artifact, "_http_json", create)
    selected, resampled, reason = artifact._create_safe_session(
        "https://verifier.invalid",
        {"fixture": True},
        "api-key",
        valid_rust_pin(),
        "org-1",
    )

    assert selected["id"] == "_future-rust"
    assert resampled == 0
    assert reason == "not_allowlisted_no_resampling"
    assert calls == 1


def test_safe_session_creation_allows_digit_leading_identifier(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def create(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return _pending_session("7safe")

    monkeypatch.setattr(artifact, "_http_json", create)
    selected, resampled, _reason = artifact._create_safe_session(
        "https://verifier.invalid",
        {"fixture": True},
        "api-key",
        artifact.FROZEN_LEGACY_SAFE_SESSION_PIN,
        "org-1",
    )

    assert selected["id"] == "7safe"
    assert resampled == 0
    assert calls == 1


def test_safe_session_creation_exhausts_without_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"status":"stale"}\n', encoding="utf-8")
    calls = 0

    def create(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return _pending_session("_bad")

    def exhaust(
        pin: dict[str, object],
        _evidence_path: Path,
        *,
        provenance_verified: bool,
    ) -> dict[str, object]:
        assert provenance_verified is True
        artifact._create_safe_session(
            "https://verifier.invalid",
            {"fixture": True},
            "api-key",
            pin,
            "org-1",
            max_creations=4,
        )
        raise AssertionError("safe session selection unexpectedly returned")

    monkeypatch.setattr(artifact, "_http_json", create)
    monkeypatch.setattr(artifact, "_run_artifact_test", exhaust)

    with pytest.raises(ValueError, match="exhausted"):
        artifact.run_artifact_test(
            artifact.FROZEN_LEGACY_SAFE_SESSION_PIN,
            evidence,
            provenance_verified=True,
        )
    assert calls == 4
    assert not evidence.exists()


def test_safe_session_creation_rejects_malformed_created_response(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def malformed(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {"id": "Asafe"}

    monkeypatch.setattr(artifact, "_http_json", malformed)
    with pytest.raises(ValueError, match="session response shape changed"):
        artifact._create_safe_session(
            "https://verifier.invalid",
            {"fixture": True},
            "api-key",
            artifact.FROZEN_LEGACY_SAFE_SESSION_PIN,
            "org-1",
        )
    assert calls == 1


def test_session_selection_evidence_contains_no_ids_or_nonces() -> None:
    evidence = artifact._session_selection_evidence(
        "frozen_python_v0.1.71_invalid_leading_identifier",
        2,
    )
    serialized = json.dumps({"safe_session_selection": evidence})

    assert evidence["resampled_unsafe_ids"] == 2
    assert "session_id" not in serialized
    assert "nonce" not in serialized
    assert "_bad" not in serialized


def test_session_result_limits_legacy_transaction_id_to_the_frozen_oracle() -> None:
    value = {
        "decision": "FAIL",
        "overall_result": "FAIL",
        "valid": False,
        "canonical_result": {
            "verification_id": "verification:session-1",
            "decision": "FAIL",
            "valid": False,
            "processing_status": "COMPLETED",
            "context": {"transaction_id": "session-1"},
            "checks": [{"check_id": check, "outcome": "FAILED"} for check in artifact.OID4VP_REQUIRED_CHECKS],
        },
    }

    artifact._assert_session_result(value, "session-1", artifact.LEGACY_TARGET)
    with pytest.raises(ValueError, match="approved compatibility correction"):
        artifact._assert_session_result(value, "session-1", artifact.RUST_TARGET)
    assert (
        artifact._assert_session_result(
            value,
            "session-1",
            artifact.RUST_TARGET,
            defer_known_difference=True,
        )
        == artifact.KNOWN_INELIGIBLE_FAILURE_ID
    )

    value["canonical_result"]["context"]["transaction_id"] = "transaction:session-1"
    artifact._assert_session_result(value, "session-1", artifact.RUST_TARGET)

    value["canonical_result"]["context"]["transaction_id"] = "transaction:unrelated"
    with pytest.raises(ValueError, match="canonical transaction ID changed") as error:
        artifact._assert_session_result(value, "session-1", artifact.RUST_TARGET)
    assert str(error.value) != artifact.KNOWN_INELIGIBLE_FAILURE_MESSAGE


def test_expected_failure_runner_accepts_only_the_bound_regression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_rust_pin()
    pin["state"] = "ineligible"
    pin["expected_failure"] = known_ineligible_failure()
    evidence_path = tmp_path / "negative-control.json"

    def reject(_pin: object, private_path: Path, **_kwargs: object) -> None:
        selection = {
            "reason": "rejected_rust_v1.1.208_invalid_leading_identifier",
            "resampled_unsafe_ids": 2,
        }
        private_path.write_text(
            json.dumps(
                {
                    "checks": sorted(artifact.EXPECTED_LANGUAGE_NEUTRAL_CHECKS | artifact.RUST_ONLY_CHECKS),
                    "release_clearance": artifact.RELEASE_CLEARANCE_BLOCKED,
                    "blockers": [artifact.OID4VP_POSITIVE_RUNTIME_BLOCKER],
                    "documented_differences": sorted(
                        artifact.DOCUMENTED_TARGET_DIFFERENCES | {artifact.KNOWN_INELIGIBLE_FAILURE_ID}
                    ),
                    "resolver_request_count": 4,
                    "safe_session_selection": selection,
                }
            ),
            encoding="utf-8",
        )
        raise artifact.ArtifactRunError(
            artifact.KNOWN_INELIGIBLE_FAILURE_MESSAGE,
            selection,
        )

    monkeypatch.setattr(artifact, "run_artifact_test", reject)
    monkeypatch.setattr(
        artifact,
        "harness_subject",
        lambda: {
            "repository": artifact.INTEGRATION_REPOSITORY,
            "commit": "f" * 40,
            "hardened_floor": artifact.HARDENED_HARNESS_FLOOR,
            "script": {
                "path": "scripts/credentials_verifier_artifact.py",
                "digest": "sha256:" + "e" * 64,
            },
        },
    )
    evidence = artifact.run_expected_failure(
        pin,
        evidence_path,
        provenance_verified=True,
    )

    assert evidence["status"] == "expected_failure_observed"
    assert evidence["failure_id"] == artifact.KNOWN_INELIGIBLE_FAILURE_ID
    assert evidence["attempts"] == 1
    assert evidence["safe_session_selection"] == {
        "reason": "rejected_rust_v1.1.208_invalid_leading_identifier",
        "resampled_unsafe_ids": 2,
    }
    assert evidence["release_clearance"] == artifact.RELEASE_CLEARANCE_BLOCKED
    assert evidence["blockers"] == [artifact.OID4VP_POSITIVE_RUNTIME_BLOCKER]
    assert set(evidence["checks"]) == artifact.EXPECTED_LANGUAGE_NEUTRAL_CHECKS | artifact.RUST_ONLY_CHECKS
    assert json.loads(evidence_path.read_text(encoding="utf-8")) == evidence

    def wrong_failure(*_args: object, **_kwargs: object) -> None:
        raise ValueError("different failure")

    monkeypatch.setattr(artifact, "run_artifact_test", wrong_failure)
    with pytest.raises(ValueError, match="unexpected reason"):
        artifact.run_expected_failure(pin, evidence_path, provenance_verified=True)

    calls = 0

    def canonical_omission(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise ValueError("verification response omitted canonical_result")

    monkeypatch.setattr(artifact, "run_artifact_test", canonical_omission)
    with pytest.raises(ValueError, match="unexpected reason"):
        artifact.run_expected_failure(pin, evidence_path, provenance_verified=True)
    assert calls == 1
    assert not evidence_path.exists()

    def unexpected_pass(_pin: object, private_path: Path, **_kwargs: object) -> dict[str, str]:
        private_path.write_text('{"status":"passed"}\n', encoding="utf-8")
        return {"status": "passed"}

    monkeypatch.setattr(artifact, "run_artifact_test", unexpected_pass)
    with pytest.raises(ValueError, match="unexpectedly passed"):
        artifact.run_expected_failure(pin, evidence_path, provenance_verified=True)
    assert not evidence_path.exists()


def test_artifact_evidence_comparison_allows_only_documented_target_difference() -> None:
    oracle = {
        "status": "passed",
        "release_clearance": artifact.RELEASE_CLEARANCE_BLOCKED,
        "blockers": [artifact.OID4VP_POSITIVE_RUNTIME_BLOCKER],
        "checks": sorted(artifact.EXPECTED_LANGUAGE_NEUTRAL_CHECKS),
        "documented_differences": [],
        "resolver_request_count": 4,
    }
    candidate = {
        "status": "expected_failure_observed",
        "release_clearance": artifact.RELEASE_CLEARANCE_BLOCKED,
        "blockers": [artifact.OID4VP_POSITIVE_RUNTIME_BLOCKER],
        "failure_id": artifact.KNOWN_INELIGIBLE_FAILURE_ID,
        "checks": sorted(artifact.EXPECTED_LANGUAGE_NEUTRAL_CHECKS | artifact.RUST_ONLY_CHECKS),
        "documented_differences": sorted(
            artifact.DOCUMENTED_TARGET_DIFFERENCES | {artifact.KNOWN_INELIGIBLE_FAILURE_ID}
        ),
        "resolver_request_count": 4,
    }

    result = artifact.compare_artifact_evidence(oracle, candidate)

    assert result["status"] == "matched_with_documented_negative_control"
    assert result["release_clearance"] == artifact.RELEASE_CLEARANCE_BLOCKED
    assert result["blockers"] == [artifact.OID4VP_POSITIVE_RUNTIME_BLOCKER]
    assert set(result["language_neutral_checks"]) == artifact.EXPECTED_LANGUAGE_NEUTRAL_CHECKS
    assert result["candidate_only_checks"] == sorted(artifact.RUST_ONLY_CHECKS)
    assert set(result["documented_difference_details"]) == (
        artifact.DOCUMENTED_TARGET_DIFFERENCES | {artifact.KNOWN_INELIGIBLE_FAILURE_ID}
    )

    candidate["checks"].remove("canonical.vds-positive-pass")
    with pytest.raises(ValueError, match="candidate raw check set diverged"):
        artifact.compare_artifact_evidence(oracle, candidate)

    candidate["checks"].append("canonical.vds-positive-pass")
    candidate["checks"].remove(next(iter(artifact.RUST_ONLY_CHECKS)))
    with pytest.raises(ValueError, match="candidate raw check set diverged"):
        artifact.compare_artifact_evidence(oracle, candidate)

    candidate["checks"].extend(artifact.RUST_ONLY_CHECKS)
    candidate["checks"].append("unexpected.check")
    with pytest.raises(ValueError, match="candidate raw check set diverged"):
        artifact.compare_artifact_evidence(oracle, candidate)

    candidate["checks"].remove("unexpected.check")
    oracle["checks"].append("unexpected.oracle-check")
    with pytest.raises(ValueError, match="oracle raw check set diverged"):
        artifact.compare_artifact_evidence(oracle, candidate)

    oracle["checks"].remove("unexpected.oracle-check")
    oracle["release_clearance"] = "eligible"
    with pytest.raises(ValueError, match="oracle evidence did not block"):
        artifact.compare_artifact_evidence(oracle, candidate)

    oracle["release_clearance"] = artifact.RELEASE_CLEARANCE_BLOCKED
    candidate["blockers"] = []
    with pytest.raises(ValueError, match="candidate evidence omitted"):
        artifact.compare_artifact_evidence(oracle, candidate)

    candidate["blockers"] = [artifact.OID4VP_POSITIVE_RUNTIME_BLOCKER]
    candidate["documented_differences"].append("undocumented")
    with pytest.raises(ValueError, match="undocumented differences"):
        artifact.compare_artifact_evidence(oracle, candidate)


def test_unknown_field_projection_allows_only_the_documented_privacy_minimization() -> None:
    legacy = {
        "detail": [
            {
                "loc": ["body", "organization_id"],
                "type": "extra_forbidden",
            }
        ]
    }
    assert artifact._assert_extra_field_error(legacy, "organization_id") is None
    assert (
        artifact._assert_extra_field_error(
            {"detail": "Request validation failed"},
            "organization_id",
            allow_minimized_detail=True,
        )
        == artifact.VALIDATION_PRIVACY_DIFFERENCE_ID
    )
    with pytest.raises(ValueError, match="disclosed"):
        artifact._assert_extra_field_error(
            {"detail": "Request validation failed", "field": "organization_id"},
            "organization_id",
            allow_minimized_detail=True,
        )


def test_default_disabled_probe_covers_every_compatibility_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, str]] = []

    def absent(method: str, url: str) -> int:
        observed.append((method, url))
        return 404

    monkeypatch.setattr(artifact, "_http_status", absent)
    artifact._assert_compatibility_routes_absent("http://verifier")

    assert observed == [
        ("GET", "http://verifier/v1/verification/health"),
        ("POST", "http://verifier/v1/verification/sessions"),
        ("GET", "http://verifier/v1/verification/sessions/A"),
        ("POST", "http://verifier/v1/verification/sessions/A/submit"),
        ("POST", "http://verifier/v1/verification/verify"),
        ("POST", "http://verifier/v1/verification/verify/vds-nc"),
    ]

    monkeypatch.setattr(
        artifact,
        "_http_status",
        lambda _method, url: 200 if url.endswith("/verify/vds-nc") else 404,
    )
    with pytest.raises(ValueError, match="POST /v1/verification/verify/vds-nc"):
        artifact._assert_compatibility_routes_absent("http://verifier")


def test_health_requires_the_real_native_diagnostic_contract() -> None:
    value = {
        "status": "healthy",
        "native_backend": {
            "available": True,
            "module": "_marty_rs",
            "version": "0.1.46",
            "missing_capabilities": [],
            "error": None,
        },
    }

    artifact._assert_health(value, artifact.LEGACY_TARGET)

    value["native_backend"]["missing_capabilities"] = ["vds_nc_verify"]
    with pytest.raises(ValueError, match="missing required native capabilities"):
        artifact._assert_health(value, artifact.LEGACY_TARGET)


def test_rust_health_requires_canonical_backend_identity() -> None:
    value = {
        "status": "healthy",
        "service": "verification",
        "native_backend": {
            "available": True,
            "module": "marty-verification-service",
            "version": "1.2.3",
            "missing_capabilities": [],
            "error": None,
        },
    }

    artifact._assert_health(value, artifact.RUST_TARGET)

    value["native_backend"]["module"] = "_marty_rs"
    with pytest.raises(ValueError, match="canonical Rust service"):
        artifact._assert_health(value, artifact.RUST_TARGET)


def test_vds_fixture_is_language_neutral_and_uses_standard_signature_base64() -> None:
    issuer = "did:web:issuer.integration.invalid"
    private_key, _jwk, method_id = artifact.make_vds_key_material(issuer)

    barcode = artifact.make_vds_barcode(issuer, method_id, private_key)
    header, payload_json, signature = barcode.split("~")
    payload = json.loads(payload_json)

    assert header == "DC03USA"
    assert payload["_vds"] == {
        "version": "1.0",
        "documentType": "CMC",
        "issuerId": issuer,
        "keyId": method_id,
        "algorithm": "ES256",
    }
    assert artifact.canonical_json(payload).decode("utf-8") == payload_json
    assert len(__import__("base64").b64decode(signature, validate=True)) == 64


def test_vds_private_material_covers_submitted_barcode_and_decoded_claim_sentinels() -> None:
    issuer = "did:web:issuer.integration.invalid"
    private_key, _jwk, method_id = artifact.make_vds_key_material(issuer)
    barcode = artifact.make_vds_barcode(issuer, method_id, private_key)
    tampered = barcode.rsplit("~", 1)[0] + "~" + base64.b64encode(bytes(64)).decode("ascii")

    material = artifact._vds_private_material(tampered)

    assert material[0] == tampered
    assert barcode not in material
    for sentinel in ("dateOfBirth", "documentNumber", "givenNames", "surname", "19900102", "X123456", "ADA", "EXAMPLE"):
        assert sentinel in material
        with pytest.raises(ValueError, match="retained private"):
            artifact._assert_private_material_absent({"decoded": sentinel}, material)
    with pytest.raises(ValueError, match="retained private"):
        artifact._assert_private_material_absent({"submitted": tampered}, material)


def test_expired_terminal_row_requires_complete_minimization(monkeypatch: pytest.MonkeyPatch) -> None:
    row = {
        "status": "expired",
        "presentation_data": None,
        "verified_claims": None,
        "verification_evidence": {"policy": "fixture"},
        "nonce": None,
        "submission_sha256": None,
        "processing_token_sha256": None,
        "processing_started_at": None,
        "processing_expires_at": None,
    }
    monkeypatch.setattr(artifact, "_session_row", lambda _postgres, _session_id: row)

    artifact._assert_expired_row_minimized("postgres", "session", ["sensitive-holder-claim"])

    for field, retained, message in (
        ("presentation_data", "sensitive-holder-claim", "retained raw presentation"),
        ("verified_claims", {"claim": "sensitive-holder-claim"}, "retained raw verified claims"),
        ("nonce", "retained-nonce", "nonce was retained"),
        ("submission_sha256", "unexpected-digest", "rejected submission digest"),
        ("processing_token_sha256", "unexpected-token", "processing_token_sha256 was not cleared"),
        ("processing_started_at", "2026-08-31T00:00:00Z", "processing_started_at was not cleared"),
        ("processing_expires_at", "2026-08-31T00:01:00Z", "processing_expires_at was not cleared"),
        ("verification_evidence", {"raw": "sensitive-holder-claim"}, "retained private"),
    ):
        original = row[field]
        row[field] = retained
        with pytest.raises(ValueError, match=message):
            artifact._assert_expired_row_minimized("postgres", "session", ["sensitive-holder-claim"])
        row[field] = original


def test_malformed_terminal_row_rejects_raw_submission_retention(monkeypatch: pytest.MonkeyPatch) -> None:
    presentation = "header.payload.signature"
    digest = __import__("hashlib").sha256(presentation.encode("utf-8")).hexdigest()
    row = {
        "status": "failed",
        "presentation_data": None,
        "verified_claims": {},
        "verification_evidence": {"submission_sha256": digest},
        "nonce": None,
        "submission_sha256": digest,
        "processing_token_sha256": None,
        "processing_started_at": None,
        "processing_expires_at": None,
    }
    monkeypatch.setattr(artifact, "_session_row", lambda _postgres, _session_id: row)

    artifact._assert_terminal_row_minimized("postgres", "session", presentation, [presentation])

    row["verification_evidence"]["raw_submission"] = presentation
    with pytest.raises(ValueError, match="retained private"):
        artifact._assert_terminal_row_minimized("postgres", "session", presentation, [presentation])


def test_private_material_guard_rejects_retention() -> None:
    artifact._assert_private_material_absent({"decision": "PASS"}, ["secret-value"])
    with pytest.raises(ValueError, match="retained private"):
        artifact._assert_private_material_absent({"evidence": "secret-value"}, ["secret-value"])


def test_health_wait_fails_immediately_when_container_exits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def not_running(arguments: list[str], *, label: str, timeout: int = 60) -> str:
        assert arguments[:3] == ["docker", "inspect", "--format"]
        assert label == "inspect verification service"
        assert timeout == 60
        return "false"

    monkeypatch.setattr(artifact, "_run", not_running)

    with pytest.raises(artifact.ArtifactRuntimeError, match="exited before becoming healthy"):
        artifact._wait_for_health("http://127.0.0.1:8006", "verifier-under-test")
