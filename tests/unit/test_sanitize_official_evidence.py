from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "sanitize_official_evidence", ROOT / "scripts" / "sanitize_official_evidence.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official evidence sanitizer")
sanitizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sanitizer)


def test_sanitizer_emits_only_safe_structured_summary(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    secret = "eyJabcdefghijk.abcdefghijklmnop.signature"
    (raw / "runner.log").write_text("must never be copied " + secret, encoding="utf-8")
    (raw / "evidence.json").write_text(
        json.dumps(
            {
                "authorization": "Bearer secret",
                "endpoint": "https://user:pass@example.test/path?code=secret",
                "configuration": "C:\\private\\marty-verifier.json",
                "jwt": secret,
                "result": {"passed": False},
            }
        ),
        encoding="utf-8",
    )
    (raw / "junit.xml").write_text(
        '<testsuite tests="3" failures="1" errors="0" skipped="1"><testcase name="secret-name"/></testsuite>',
        encoding="utf-8",
    )
    summary = sanitizer.build_summary(raw, lane="haip", harness_commit="a" * 40, exit_code=1)
    serialized = json.dumps(summary)
    assert "Bearer secret" not in serialized
    assert secret not in serialized
    assert "?code=" not in serialized
    assert "secret-name" not in serialized
    assert summary["junit"][0]["tests"] == 3
    assert summary["result"] == {"exit_code": 1, "passed": False}


def test_main_writes_no_raw_files(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "runner.log").write_text("private", encoding="utf-8")
    output = tmp_path / "public"
    assert (
        sanitizer.main(
            [
                "--input",
                str(raw),
                "--output",
                str(output),
                "--lane",
                "eudi",
                "--harness-commit",
                "b" * 40,
                "--exit-code",
                "0",
            ]
        )
        == 0
    )
    assert [path.name for path in output.iterdir()] == ["summary.json"]


def test_summary_records_public_safe_eudi_harness_image_digest(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    report = tmp_path / "harness-image.json"
    report.write_text(
        json.dumps(
            {
                "schema": "elevenid.eudi-harness-build/v1",
                "component": "eudi-wallet-harness",
                "image_digest": "sha256:" + "a" * 64,
                "recipe": {"gradle.lockfile": "sha256:" + "b" * 64},
            }
        ),
        encoding="utf-8",
    )
    summary = sanitizer.build_summary(
        raw,
        lane="eudi",
        harness_commit="c" * 40,
        exit_code=0,
        harness_image_report=report,
    )
    assert summary["eudi_harness_image"]["image_digest"] == "sha256:" + "a" * 64
