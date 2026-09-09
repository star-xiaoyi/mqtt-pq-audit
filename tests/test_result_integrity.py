from __future__ import annotations

import csv
import json
import shutil
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIR = REPO_ROOT / "experiments" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from result_package import (  # noqa: E402
    CONFIG_SCHEMA,
    MANIFEST_NAME,
    PackageError,
    atomic_write_json,
    create_completion_manifest,
    ensure_new_result_target,
    seal_config,
    validate_completion_manifest,
    write_package_metadata,
)


def _completed_package(tmp_path: Path) -> Path:
    package = tmp_path / "run"
    ensure_new_result_target(package)
    package.mkdir(parents=True)
    config = seal_config(
        {
            "schema": CONFIG_SCHEMA,
            "run_id": "stage4-quick-test",
            "timestamp_utc": "2026-07-10T00:00:00Z",
            "mode": "quick",
            "seed": 20260710,
            "description": "synthetic integrity fixture",
        }
    )
    atomic_write_json(package / "protocol_config.json", config)
    snapshot = {
        "git": {
            "commit": "a" * 40,
            "dirty": False,
            "branch": "test",
            "source_tree_hash": "b" * 64,
        },
        "dependencies": {
            "python": "3.12.13",
            "packages": {"paho-mqtt": "2.1.0"},
        },
        "environment": {"platform": "test"},
    }
    write_package_metadata(package, config=config, preflight_snapshot=snapshot)
    atomic_write_json(
        package / "preflight_report.json",
        {
            "overall_status": "PASS",
            "snapshot": {
                **snapshot,
                "run_id": config["run_id"],
                "timestamp_utc": config["timestamp_utc"],
                "mode": config["mode"],
                "seed": config["seed"],
                "config_hash": config["config_hash"],
            },
            "checks": [],
        },
    )
    (package / "preflight_report.md").write_text("PASS\n", encoding="utf-8")
    with (package / "measurements.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["run_id", "status", "value"])
        writer.writeheader()
        writer.writerow({"run_id": config["run_id"], "status": "PASS", "value": 1})
    atomic_write_json(
        package / "quality_report.json",
        {
            "schema": "aapa-independent-quality-report-v2",
            "run_id": config["run_id"],
            "timestamp_utc": config["timestamp_utc"],
            "mode": config["mode"],
            "config_hash": config["config_hash"],
            "overall_status": "PASS",
            "checks": [],
        },
    )
    (package / "quality_report.md").write_text("PASS\n", encoding="utf-8")
    assert not (package / MANIFEST_NAME).exists()
    create_completion_manifest(package)
    assert not validate_completion_manifest(package)
    return package


def _issue_codes(package: Path) -> set[str]:
    return {issue.code for issue in validate_completion_manifest(package)}


def test_completion_manifest_is_written_last_and_valid(tmp_path: Path) -> None:
    package = _completed_package(tmp_path)
    manifest = json.loads((package / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["quality_status"] == "PASS"
    assert manifest["file_count"] == len(manifest["files"])
    assert [entry["path"] for entry in manifest["files"]] == sorted(
        entry["path"] for entry in manifest["files"]
    )


@pytest.mark.parametrize(
    ("mutation", "expected_codes"),
    [
        ("csv_pass", {"FILE_HASH"}),
        ("config", {"CONFIG_HASH", "FILE_HASH"}),
        ("run_id", {"CONFIG_HASH", "FILE_HASH"}),
        ("timestamp", {"CONFIG_HASH", "FILE_HASH"}),
        ("metadata", {"DEPENDENCY_HASH", "FILE_HASH"}),
        ("delete", {"FILE_MISSING"}),
        ("add", {"FILE_UNDECLARED"}),
        ("mixed_run", {"FILE_UNDECLARED"}),
    ],
)
def test_declared_metadata_hash_and_file_mutations_are_rejected(
    tmp_path: Path, mutation: str, expected_codes: set[str]
) -> None:
    original = _completed_package(tmp_path / "original")
    package = tmp_path / mutation
    shutil.copytree(original, package)

    if mutation == "csv_pass":
        path = package / "measurements.csv"
        path.write_text(path.read_text(encoding="utf-8").replace("PASS", "FAIL"), encoding="utf-8")
    elif mutation in {"config", "run_id", "timestamp"}:
        path = package / "protocol_config.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        if mutation == "config":
            value["description"] = "mutated"
        elif mutation == "run_id":
            value["run_id"] = "another-run"
        else:
            value["timestamp_utc"] = "2026-07-10T00:00:01Z"
        atomic_write_json(path, value)
    elif mutation == "metadata":
        path = package / "package_metadata.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["dependencies"]["python"] = "0.0.0"
        atomic_write_json(path, value)
    elif mutation == "delete":
        (package / "measurements.csv").unlink()
    elif mutation == "add":
        (package / "undeclared.json").write_text("{}\n", encoding="utf-8")
    elif mutation == "mixed_run":
        (package / "foreign_run.csv").write_text(
            "run_id,value\nstage4-quick-foreign,9\n", encoding="utf-8"
        )

    codes = _issue_codes(package)
    assert expected_codes <= codes


def test_manifest_tampering_and_duplicate_entries_are_rejected(tmp_path: Path) -> None:
    package = _completed_package(tmp_path)
    path = package / MANIFEST_NAME
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["files"].append(dict(manifest["files"][0]))
    manifest["file_count"] += 1
    atomic_write_json(path, manifest)
    codes = _issue_codes(package)
    assert "MANIFEST_DUPLICATE" in codes
    assert "MANIFEST_ORDER" in codes


def test_existing_even_empty_result_directory_is_never_reused(tmp_path: Path) -> None:
    target = tmp_path / "existing"
    target.mkdir()
    with pytest.raises(PackageError, match="already exists"):
        ensure_new_result_target(target)


def test_completion_refuses_nonpassing_quality_report(tmp_path: Path) -> None:
    package = tmp_path / "run"
    package.mkdir()
    config = seal_config(
        {
            "schema": CONFIG_SCHEMA,
            "run_id": "failed-run",
            "timestamp_utc": "2026-07-10T00:00:00Z",
            "mode": "quick",
            "seed": 1,
        }
    )
    atomic_write_json(package / "protocol_config.json", config)
    write_package_metadata(
        package,
        config=config,
        preflight_snapshot={
            "git": {
                "commit": "a" * 40,
                "dirty": False,
                "branch": "test",
                "source_tree_hash": "b" * 64,
            },
            "dependencies": {},
            "environment": {},
        },
    )
    atomic_write_json(
        package / "quality_report.json",
        {
            "run_id": config["run_id"],
            "timestamp_utc": config["timestamp_utc"],
            "mode": config["mode"],
            "config_hash": config["config_hash"],
            "overall_status": "FAIL",
        },
    )
    with pytest.raises(PackageError, match="QUALITY_NOT_PASS"):
        create_completion_manifest(package)
    assert not (package / MANIFEST_NAME).exists()
