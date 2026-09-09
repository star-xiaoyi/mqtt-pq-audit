#!/usr/bin/env python3
"""Run the complete Stage 4 experiment protocol into one coherent result package.

This is the manuscript-grade entry point. It fixes the common failure mode where
figures accidentally combine CSVs from several different run IDs.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parent
CPP_DIR = EXPERIMENT_DIR / "cpp"
CPP_BUILD = CPP_DIR / "build"
CPP_BIN = CPP_BUILD / "aapa_crypto_bench"
LIBOQS_INSTALL = REPO_ROOT / "build" / "liboqs-install"
LIBOQS_CMAKE_DIR = LIBOQS_INSTALL / "lib" / "cmake" / "liboqs"
PYTHON_DIR = EXPERIMENT_DIR / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from result_package import (  # noqa: E402 - local experiment helper
    CONFIG_SCHEMA,
    PackageError,
    atomic_write_json,
    create_completion_manifest,
    ensure_new_result_target,
    seal_config,
    validate_timestamp_utc,
    write_package_metadata,
)
from preflight import collect_git_snapshot  # noqa: E402
from experiment_grids import E7_CORPUS_CONTRACT, axes_for  # noqa: E402
from experiment_profiles import PROFILES  # noqa: E402  canonical quick/full intensity, shared with the validator

DEFAULT_SEED = 20260710


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "run"


def run_step(name: str, cmd: list[str], *, env: dict[str, str], log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{name}.log"
    print(f"\n[{name}] {' '.join(cmd)}")
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            cmd,
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
            log.write(line)
        rc = proc.wait()
    if rc != 0:
        raise SystemExit(f"[{name}] failed with exit code {rc}; see {log_path}")


def protocol_config(mode: str, run_id: str, timestamp: str, seed: int) -> dict:
    return seal_config({
        "schema": CONFIG_SCHEMA,
        "run_id": run_id,
        "timestamp_utc": timestamp,
        "mode": mode,
        "seed": seed,
        **PROFILES[mode],
        "e7_corpus": E7_CORPUS_CONTRACT,
        "coverage": axes_for(mode),
        "notes": [
            "quick is a pipeline smoke profile only",
            "full is the minimum profile intended for manuscript tables/figures",
            "plot generation is disabled by default in this runner",
            "E7 is a deterministic capability matrix (see e7_corpus); its repetitions are not a sample size",
            "coverage seals the exact expected cell axes per experiment for independent validation",
            "quick A6 witness_count/min_receipts=1/1 is a baseline; formal quorum cost is full's 3/2",
        ],
    })


def run_preflight_before_result_dir(
    *,
    python: str,
    mode: str,
    run_id: str,
    timestamp: str,
    config_hash: str,
    seed: int,
    env: dict[str, str],
    allow_nonfirstpaper: bool,
    allow_dirty: bool,
) -> tuple[dict, str, Path]:
    """Run preflight in /tmp; no formal result directory exists yet."""
    temp_root = Path(tempfile.mkdtemp(prefix="aapa-preflight-"))
    command = [
        python,
        "experiments/python/preflight.py",
        "--mode",
        mode,
        "--out-dir",
        str(temp_root),
        "--run-id",
        run_id,
        "--timestamp-utc",
        timestamp,
        "--config-hash",
        config_hash,
        "--seed",
        str(seed),
    ]
    if allow_nonfirstpaper:
        command.append("--allow-nonfirstpaper")
    if allow_dirty:
        command.append("--allow-dirty")
    print(f"\n[00_preflight] {' '.join(command)}")
    process = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    output = process.stdout + process.stderr
    print(output, end="")
    if process.returncode != 0:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise SystemExit(
            "[00_preflight] failed before result directory creation "
            f"with exit code {process.returncode}"
        )
    try:
        report = json.loads((temp_root / "preflight_report.json").read_text(encoding="utf-8"))
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
    return report, output, temp_root


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a coherent Stage 4 result package")
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--timestamp-utc", default=None)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument(
        "--allow-nonfirstpaper",
        action="store_true",
        help="Allow full-mode preflight outside the firstpaper conda environment",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Diagnostic only: allow a dirty full tree; completed full validation will still reject it",
    )
    parser.add_argument("--skip-python", action="store_true")
    parser.add_argument("--skip-cpp", action="store_true")
    parser.add_argument(
        "--with-plots", action="store_true",
        help="Deprecated and rejected: manuscript figures are generated only after sealing by the standalone plotter",
    )
    parser.add_argument("--skip-plots", action="store_true",
                        help="Deprecated compatibility flag; plots are skipped unless --with-plots is set")
    parser.add_argument("--skip-validation", action="store_true")
    args = parser.parse_args()

    timestamp = args.timestamp_utc or utc_timestamp()
    try:
        validate_timestamp_utc(timestamp)
    except PackageError as exc:
        raise SystemExit(str(exc)) from exc
    if args.seed < 0 or args.seed >= 2**64:
        raise SystemExit("--seed must be an unsigned 64-bit integer")
    if args.skip_preflight:
        raise SystemExit("--skip-preflight is disabled: coherent packages require a recorded preflight")
    run_id = args.run_id or f"stage4-{args.mode}-{timestamp}"
    result_dir = Path(args.out_dir).resolve() if args.out_dir else (
        EXPERIMENT_DIR
        / "results"
        / ("stage4_full" if args.mode == "full" else "stage4_nonfull")
        / safe_id(run_id)
    )
    try:
        ensure_new_result_target(result_dir)
    except PackageError as exc:
        raise SystemExit(str(exc)) from exc
    config = protocol_config(args.mode, run_id, timestamp, args.seed)
    profile = PROFILES[args.mode]

    env = os.environ.copy()
    local_lib_dir = str(LIBOQS_INSTALL / "lib")
    inherited_library_path = env.get("LD_LIBRARY_PATH", "")
    env.update(
        {
            "AAPA_MODE": args.mode,
            "AAPA_TIMESTAMP_UTC": timestamp,
            "AAPA_RUN_ID": run_id,
            "AAPA_RESULT_DIR": str(result_dir),
            "AAPA_CONFIG_HASH": config["config_hash"],
            "AAPA_SEED": str(args.seed),
            "PYTHONHASHSEED": str(args.seed % (2**32)),
            "OQS_INSTALL_PATH": str(LIBOQS_INSTALL),
            "LD_LIBRARY_PATH": (
                local_lib_dir
                if not inherited_library_path
                else f"{local_lib_dir}{os.pathsep}{inherited_library_path}"
            ),
        }
    )

    preflight_report, preflight_output, preflight_temp = run_preflight_before_result_dir(
        python=args.python,
        mode=args.mode,
        run_id=run_id,
        timestamp=timestamp,
        config_hash=config["config_hash"],
        seed=args.seed,
        env=env,
        allow_nonfirstpaper=args.allow_nonfirstpaper,
        allow_dirty=args.allow_dirty,
    )
    try:
        ensure_new_result_target(result_dir)
        result_dir.mkdir(parents=True, exist_ok=False)
        raw_dir = result_dir / "raw"
        raw_dir.mkdir(parents=False, exist_ok=False)
        atomic_write_json(result_dir / "protocol_config.json", config)
        shutil.move(str(preflight_temp / "preflight_report.json"), result_dir)
        shutil.move(str(preflight_temp / "preflight_report.md"), result_dir)
        (raw_dir / "00_preflight.log").write_text(preflight_output, encoding="utf-8")
        metadata = write_package_metadata(
            result_dir,
            config=config,
            preflight_snapshot=preflight_report["snapshot"],
        )
    finally:
        shutil.rmtree(preflight_temp, ignore_errors=True)
    env.update(
        {
            "AAPA_GIT_COMMIT": metadata["git_commit"],
            "AAPA_DEPENDENCY_HASH": metadata["dependency_hash"],
            "AAPA_SOURCE_TREE_HASH": metadata["source_tree_hash"],
        }
    )

    print("=" * 78)
    print("Stage 4 coherent experiment protocol")
    print(f"  mode      : {args.mode}")
    print(f"  run_id    : {run_id}")
    print(f"  timestamp : {timestamp}")
    print(f"  seed      : {args.seed}")
    print(f"  config    : {config['config_hash']}")
    print(f"  result dir: {result_dir}")
    print(f"  profile   : {profile['description']}")
    print(f"  plots     : {'enabled' if args.with_plots and not args.skip_plots else 'disabled'}")
    print("=" * 78)

    if not args.skip_build:
        configure_cmd = [
            "cmake",
            "-S",
            str(CPP_DIR),
            "-B",
            str(CPP_BUILD),
            "-DCMAKE_BUILD_TYPE=Release",
        ]
        if LIBOQS_CMAKE_DIR.is_dir():
            configure_cmd.append(f"-Dliboqs_DIR={LIBOQS_CMAKE_DIR}")
        run_step(
            "01_cmake_configure",
            configure_cmd,
            env=env,
            log_dir=raw_dir,
        )
        run_step(
            "02_cmake_build",
            ["cmake", "--build", str(CPP_BUILD), "-j"],
            env=env,
            log_dir=raw_dir,
        )

    run_step(
        "03_integrity_smoke",
        [args.python, "experiments/python/verify_experiment_integrity.py"],
        env=env,
        log_dir=raw_dir,
    )
    run_step(
        "04_python_cpp_crosscheck",
        [args.python, "experiments/crosscheck/crosscheck.py"],
        env=env,
        log_dir=raw_dir,
    )

    if not args.skip_python:
        run_step(
            "10_python_e4_amortized",
            [
                args.python, "experiments/python/run_final.py", "--exp", "E4",
                "--out-dir", str(result_dir),
                "--a6-witness-count", str(profile["python"]["a6_witness_count"]),
            ],
            env=env,
            log_dir=raw_dir,
        )
        py = profile["python"]
        py_cmd = [
            args.python,
            "experiments/python/run_optimized.py",
            "--exp",
            "all",
            "--out-dir",
            str(result_dir),
            "--e3-msgs",
            str(py["e3_msgs"]),
            "--e5-reps",
            str(py["e5_reps"]),
            "--e5-msgs",
            str(py["e5_msgs"]),
            "--e5-qos",
            str(py["e5_qos"]),
            "--e6-reps",
            str(py["e6_reps"]),
            "--e6-burst",
            str(py["e6_burst"]),
            "--e6-drain-timeout",
            str(py["e6_drain_timeout"]),
            "--e6-max-inflight",
            str(py["e6_max_inflight"]),
            "--e6-qos",
            str(py["e6_qos"]),
            "--e8-reps",
            str(py["e8_reps"]),
            "--e8-lifecycle-reps",
            str(py["e8_lifecycle_reps"]),
            "--e9-hours",
            str(py["e9_hours"]),
            "--e9-max-messages",
            str(py["e9_max_messages"]),
            "--a6-witness-count",
            str(py["a6_witness_count"]),
            "--a6-min-receipts",
            str(py["a6_min_receipts"]),
        ]
        if args.mode == "quick":
            py_cmd.insert(2, "--quick")
        run_step("11_python_qos_end_to_end", py_cmd, env=env, log_dir=raw_dir)
        run_step(
            "12_security_offline_artifacts",
            [
                args.python,
                "experiments/python/generate_security_artifacts.py",
                "--out-dir",
                str(result_dir),
                "--seed",
                str(args.seed),
            ],
            env=env,
            log_dir=raw_dir,
        )

    if not args.skip_cpp:
        cpp_cmd = [
            str(CPP_BIN),
            "--mode",
            args.mode,
            "--exp",
            "all",
            "--runs",
            str(profile["cpp"]["runs"]),
            "--audit-runs",
            str(profile["cpp"]["audit_runs"]),
            "--out-dir",
            str(result_dir),
        ]
        run_step("20_cpp_crypto_audit", cpp_cmd, env=env, log_dir=raw_dir)

    if not args.skip_validation:
        run_step(
            "30_quality_gate",
            [
                args.python,
                "experiments/python/validate_result_package.py",
                "--data-dir",
                str(result_dir),
                "--mode",
                args.mode,
                "--pre-finalize",
                "--report-dir",
                str(result_dir),
            ],
            env=env,
            log_dir=raw_dir,
        )

    if args.with_plots and not args.skip_plots:
        raise SystemExit(
            "[40_figures] integrated plotting is disabled: finalize and seal the package first, "
            "then run experiments/plotting/plot_results.py separately with an external output directory"
        )

    if not args.skip_validation:
        current_git = collect_git_snapshot()
        if (
            current_git.get("commit") != metadata["git_commit"]
            or current_git.get("source_tree_hash") != metadata["source_tree_hash"]
            or current_git.get("dirty") != metadata["git_dirty"]
        ):
            raise SystemExit(
                "[31_finalize_package] source tree changed after preflight; "
                "discard this incomplete package and rerun"
            )
        try:
            manifest = create_completion_manifest(result_dir)
        except PackageError as exc:
            raise SystemExit(f"[31_finalize_package] {exc}") from exc
        print(
            f"\n[31_finalize_package] PASS: {manifest['file_count']} files sealed -> "
            f"{result_dir / 'completion_manifest.json'}"
        )
    else:
        print("\nPackage remains incomplete because validation was skipped.")

    print("\nDone.")
    print(f"Result package: {result_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
