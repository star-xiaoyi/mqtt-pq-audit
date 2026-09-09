from __future__ import annotations

import csv
import os
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
CPP_DIR = REPO / "experiments" / "cpp"
CPP_BUILD = CPP_DIR / "build"
CPP_BIN = CPP_BUILD / "aapa_crypto_bench"


def _build_cpp() -> None:
    subprocess.run(
        ["cmake", "-S", str(CPP_DIR), "-B", str(CPP_BUILD), "-DCMAKE_BUILD_TYPE=Release"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["cmake", "--build", str(CPP_BUILD), "-j"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )


def test_cpp_registry_quorum_and_freshness_fail_closed(tmp_path):
    _build_cpp()
    env = os.environ.copy()
    env.update(
        {
            "AAPA_MODE": "quick",
            "AAPA_RUN_ID": "pytest-cpp-security",
            "AAPA_TIMESTAMP_UTC": "2026-07-10T00:00:00Z",
        }
    )
    subprocess.run(
        [
            str(CPP_BIN),
            "--mode",
            "quick",
            "--exp",
            "audit",
            "--runs",
            "1",
            "--audit-runs",
            "1",
            "--warmup",
            "0",
            "--out-dir",
            str(tmp_path),
        ],
        cwd=REPO,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    with (tmp_path / "a6_failure_grid_cpp.csv").open(newline="", encoding="utf-8") as handle:
        rows = {row["case"]: row for row in csv.DictReader(handle)}

    assert rows["valid_current_quorum2"]["accepted"] == "true"
    for case in (
        "duplicate_witness_receipt_cannot_reach_quorum",
        "untrusted_witness_cannot_reach_quorum",
        "self_signed_publisher_rejected",
        "future_witness_timestamp_rejected",
        "below_quorum",
    ):
        assert rows[case]["accepted"] == "false", case
