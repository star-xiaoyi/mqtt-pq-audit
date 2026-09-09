#!/usr/bin/env python3
"""Preflight checks for manuscript-grade Stage 4 experiment runs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiment_paths import REPO_ROOT, add_liboqs_python_to_path


PINNED_PYTHON_PACKAGES = {
    "paho-mqtt": "2.1.0",
    "cryptography": "48.0.0",
    "pandas": "3.0.3",
    "numpy": "2.4.6",
    "matplotlib": "3.10.9",
    "seaborn": "0.13.2",
}
REQUIRED_PYTHON_PACKAGES = tuple(PINNED_PYTHON_PACKAGES)
PINNED_SOURCE_COMMITS = {
    "liboqs": "5a1a854b0dc9f2141bdc771c555ee60c37950183",
    "liboqs_python": "35eceb69d2b363cb0421085cf1ae1c682dee1acc",
}
PINNED_LIBOQS_VERSION = "0.16.0"
PINNED_PYTHON_VERSION = "3.12.13"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def command_output(cmd: list[str]) -> dict[str, Any]:
    exe = shutil.which(cmd[0])
    if exe is None:
        return {"available": False, "path": None, "returncode": None, "output": ""}
    try:
        proc = subprocess.run(
            [exe, *cmd[1:]],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (proc.stdout + proc.stderr).strip()
        return {
            "available": True,
            "path": exe,
            "returncode": proc.returncode,
            "output": output.splitlines()[:5],
        }
    except Exception as exc:  # pragma: no cover - defensive preflight path
        return {
            "available": True,
            "path": exe,
            "returncode": None,
            "output": [f"error: {exc}"],
        }


def check_broker(host: str, port: int, timeout_s: float = 2.0) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return {"host": host, "port": port, "reachable": True, "error": ""}
    except OSError as exc:
        return {"host": host, "port": port, "reachable": False, "error": str(exc)}


def _git_output(args: list[str], *, binary: bool = False) -> str | bytes:
    return subprocess.check_output(
        ["git", *args],
        cwd=str(REPO_ROOT),
        text=not binary,
    )


def collect_git_snapshot() -> dict[str, Any]:
    """Capture a content hash without embedding a user's uncommitted diff."""
    try:
        commit = str(_git_output(["rev-parse", "HEAD"])).strip()
        branch = str(_git_output(["rev-parse", "--abbrev-ref", "HEAD"])).strip()
        porcelain = str(
            _git_output(["status", "--porcelain=v1", "--untracked-files=all"])
        )
        dirty = bool(porcelain.strip())

        digest = hashlib.sha256()
        digest.update(b"aapa-source-tree-v1\0")
        digest.update(commit.encode("ascii"))
        digest.update(b"\0")
        digest.update(bytes(_git_output(["diff", "--binary", "HEAD", "--"], binary=True)))
        untracked = bytes(
            _git_output(["ls-files", "--others", "--exclude-standard", "-z"], binary=True)
        ).split(b"\0")
        untracked_count = 0
        for encoded in sorted(item for item in untracked if item):
            relative = encoded.decode("utf-8", errors="surrogateescape")
            path = REPO_ROOT / relative
            if not path.is_file() or path.is_symlink():
                continue
            untracked_count += 1
            digest.update(b"untracked\0")
            digest.update(encoded)
            digest.update(b"\0")
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
        return {
            "commit": commit,
            "dirty": dirty,
            "branch": branch,
            "changed_entry_count": len(porcelain.splitlines()),
            "untracked_file_count": untracked_count,
            "source_tree_hash": digest.hexdigest(),
        }
    except Exception as exc:
        return {
            "commit": None,
            "dirty": None,
            "branch": None,
            "changed_entry_count": None,
            "untracked_file_count": None,
            "source_tree_hash": None,
            "error": str(exc),
        }


def collect_pinned_source(path: Path) -> dict[str, Any]:
    if not (path / ".git").exists():
        return {"path": str(path), "available": False}
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=path, text=True
        ).strip()
        describe = subprocess.check_output(
            ["git", "describe", "--tags", "--always"], cwd=path, text=True
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain", "--untracked-files=no"],
                cwd=path,
                text=True,
            ).strip()
        )
        return {
            "path": str(path),
            "available": True,
            "commit": commit,
            "describe": describe,
            "dirty": dirty,
        }
    except Exception as exc:
        return {"path": str(path), "available": False, "error": str(exc)}


def collect_snapshot(
    mode: str,
    broker_host: str,
    broker_port: int,
    *,
    run_id: str = "",
    timestamp_utc: str = "",
    config_hash: str = "",
    seed: int = 0,
) -> dict[str, Any]:
    add_liboqs_python_to_path()
    try:
        import oqs

        oqs_version = oqs.oqs_version()
        oqs_import_ok = True
        oqs_error = ""
    except Exception as exc:  # pragma: no cover - environment-specific
        oqs_version = None
        oqs_import_ok = False
        oqs_error = str(exc)

    packages = {
        package: package_version(package)
        for package in REQUIRED_PYTHON_PACKAGES
    }

    git = collect_git_snapshot()
    commands = {
        "cmake": command_output(["cmake", "--version"]),
        "mosquitto": command_output(["mosquitto", "-h"]),
        "openssl": command_output(["openssl", "version"]),
    }
    python_version = sys.version.split()[0]
    dependencies = {
        "python": python_version,
        "python_implementation": platform.python_implementation(),
        "packages": packages,
        "liboqs": oqs_version,
        "commands": {
            name: value.get("output", [])
            for name, value in commands.items()
        },
        "pinned_sources": {
            "liboqs": collect_pinned_source(REPO_ROOT / "build" / "liboqs"),
            "liboqs_python": collect_pinned_source(REPO_ROOT / "build" / "liboqs-python"),
        },
        "oqs_install_path": os.environ.get("OQS_INSTALL_PATH", ""),
    }

    return {
        "observed_at_utc": _utc_now(),
        "timestamp_utc": timestamp_utc or os.environ.get("AAPA_TIMESTAMP_UTC", ""),
        "run_id": run_id or os.environ.get("AAPA_RUN_ID", ""),
        "mode": mode,
        "config_hash": config_hash or os.environ.get("AAPA_CONFIG_HASH", ""),
        "seed": seed,
        "repo_root": str(REPO_ROOT),
        "git": git,
        "python": {
            "executable": sys.executable,
            "version": python_version,
            "implementation": platform.python_implementation(),
            "prefix": sys.prefix,
            "base_prefix": sys.base_prefix,
            "conda_default_env": os.environ.get("CONDA_DEFAULT_ENV", ""),
            "virtual_env": os.environ.get("VIRTUAL_ENV", ""),
        },
        "packages": packages,
        "oqs": {
            "import_ok": oqs_import_ok,
            "liboqs_version": oqs_version,
            "error": oqs_error,
        },
        "commands": commands,
        "dependencies": dependencies,
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "mqtt_broker": check_broker(broker_host, broker_port),
    }


def evaluate(
    snapshot: dict[str, Any],
    *,
    require_firstpaper: bool,
    require_clean_tree: bool,
    allow_dirty: bool = False,
) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    def add(name: str, ok: bool, detail: str, severity: str = "FAIL") -> None:
        checks.append({
            "name": name,
            "status": "PASS" if ok else severity,
            "detail": detail,
        })

    packages = snapshot["packages"]
    for package in REQUIRED_PYTHON_PACKAGES:
        version = packages.get(package)
        expected = PINNED_PYTHON_PACKAGES[package]
        add(
            f"python_package:{package}",
            version == expected,
            f"version={version} expected={expected}",
        )

    add(
        "oqs_import",
        bool(snapshot["oqs"]["import_ok"])
        and snapshot["oqs"]["liboqs_version"] == PINNED_LIBOQS_VERSION,
        f"liboqs_version={snapshot['oqs']['liboqs_version']} error={snapshot['oqs']['error']}",
    )
    pinned_sources = snapshot["dependencies"].get("pinned_sources", {})
    for name, expected_commit in PINNED_SOURCE_COMMITS.items():
        source = pinned_sources.get(name, {})
        add(
            f"pinned_source:{name}",
            source.get("available") is True
            and source.get("commit") == expected_commit
            and source.get("dirty") is False,
            f"commit={source.get('commit')} expected={expected_commit} dirty={source.get('dirty')}",
        )
    add(
        "cmake_available",
        bool(snapshot["commands"]["cmake"]["available"]),
        f"path={snapshot['commands']['cmake']['path']}",
    )
    add(
        "mosquitto_available",
        bool(snapshot["commands"]["mosquitto"]["available"]),
        f"path={snapshot['commands']['mosquitto']['path']}",
    )
    broker = snapshot["mqtt_broker"]
    add(
        "mqtt_broker_reachable",
        bool(broker["reachable"]),
        f"{broker['host']}:{broker['port']} {broker['error']}",
    )

    git = snapshot["git"]
    add(
        "git_snapshot",
        bool(git.get("commit")) and bool(git.get("source_tree_hash")),
        f"commit={git.get('commit')} source_tree_hash={git.get('source_tree_hash')}",
    )
    clean = git.get("dirty") is False
    if require_clean_tree:
        add(
            "git_clean_full_run",
            clean,
            f"dirty={git.get('dirty')} changed_entries={git.get('changed_entry_count')}",
            severity="WARN" if allow_dirty else "FAIL",
        )
    else:
        add(
            "git_state_recorded",
            isinstance(git.get("dirty"), bool),
            f"dirty={git.get('dirty')} changed_entries={git.get('changed_entry_count')}",
        )

    python_info = snapshot["python"]
    conda_env = python_info["conda_default_env"]
    python_prefix = python_info["prefix"]
    executable = python_info["executable"]
    firstpaper_python = (
        conda_env == "firstpaper"
        or Path(python_prefix).name == "firstpaper"
        or "/envs/firstpaper/" in executable
    )
    add(
        "python_version",
        python_info["version"] == PINNED_PYTHON_VERSION,
        f"version={python_info['version']} expected={PINNED_PYTHON_VERSION}",
    )
    if require_firstpaper:
        add(
            "conda_env_firstpaper",
            firstpaper_python,
            f"CONDA_DEFAULT_ENV={conda_env or '<unset>'}; prefix={python_prefix}; executable={executable}",
        )
    else:
        add(
            "conda_env_recorded",
            True,
            f"CONDA_DEFAULT_ENV={conda_env or '<unset>'}; prefix={python_prefix}; executable={executable}",
        )

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Stage 4 environment preflight checks")
    parser.add_argument("--mode", choices=["quick", "full"], default=os.environ.get("AAPA_MODE", "quick"))
    parser.add_argument("--out-dir", default=os.environ.get("AAPA_RESULT_DIR"))
    parser.add_argument("--broker-host", default="localhost")
    parser.add_argument("--broker-port", type=int, default=1883)
    parser.add_argument("--run-id", default=os.environ.get("AAPA_RUN_ID", ""))
    parser.add_argument("--timestamp-utc", default=os.environ.get("AAPA_TIMESTAMP_UTC", ""))
    parser.add_argument("--config-hash", default=os.environ.get("AAPA_CONFIG_HASH", ""))
    parser.add_argument("--seed", type=int, default=int(os.environ.get("AAPA_SEED", "0")))
    parser.add_argument(
        "--allow-nonfirstpaper",
        action="store_true",
        help="Do not fail full-mode runs when CONDA_DEFAULT_ENV is not firstpaper",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Diagnostic override: record a WARN instead of failing a dirty full run",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir or ".").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    snapshot = collect_snapshot(
        args.mode,
        args.broker_host,
        args.broker_port,
        run_id=args.run_id,
        timestamp_utc=args.timestamp_utc,
        config_hash=args.config_hash,
        seed=args.seed,
    )
    require_firstpaper = args.mode == "full" and not args.allow_nonfirstpaper
    checks = evaluate(
        snapshot,
        require_firstpaper=require_firstpaper,
        require_clean_tree=args.mode == "full",
        allow_dirty=args.allow_dirty,
    )
    failed = [c for c in checks if c["status"] == "FAIL"]
    warned = [c for c in checks if c["status"] == "WARN"]
    overall = "FAIL" if failed else ("WARN" if warned else "PASS")

    report = {
        "overall_status": overall,
        "snapshot": snapshot,
        "checks": checks,
    }
    (out_dir / "preflight_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Stage 4 Preflight Report",
        "",
        f"Overall status: **{overall}**",
        "",
        "| Check | Status | Detail |",
        "|---|---:|---|",
    ]
    for check in checks:
        lines.append(f"| {check['name']} | {check['status']} | {check['detail']} |")
    (out_dir / "preflight_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"preflight report: {overall} -> {out_dir / 'preflight_report.md'}")
    return 1 if overall == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
