#!/usr/bin/env python3
"""Shared Stage 4 provenance and output-directory helpers."""

from __future__ import annotations

import csv
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping

from experiment_paths import EXPERIMENT_DIR as EXPERIMENT_ROOT

EXPERIMENT_DIR = str(EXPERIMENT_ROOT)
DEFAULT_ENV_ID = "wsl2-ubuntu26-r9000p-20260608"
PROVENANCE_FIELDS = [
    "env_id",
    "run_id",
    "timestamp_utc",
    "mode",
    "config_hash",
    "seed",
    "git_commit",
    "dependency_hash",
    "source_tree_hash",
    "source_script",
]


@dataclass(frozen=True)
class Provenance:
    env_id: str
    run_id: str
    timestamp_utc: str
    mode: str
    config_hash: str
    seed: int
    git_commit: str
    dependency_hash: str
    source_tree_hash: str
    source_script: str
    result_dir: str

    def fields(self) -> dict:
        return {
            "env_id": self.env_id,
            "run_id": self.run_id,
            "timestamp_utc": self.timestamp_utc,
            "mode": self.mode,
            "config_hash": self.config_hash,
            "seed": self.seed,
            "git_commit": self.git_commit,
            "dependency_hash": self.dependency_hash,
            "source_tree_hash": self.source_tree_hash,
            "source_script": self.source_script,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "run"


def _load_env_id() -> str:
    env_path = os.path.join(EXPERIMENT_DIR, "env.json")
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return str(data.get("env_id") or DEFAULT_ENV_ID)
    except Exception:
        return DEFAULT_ENV_ID


def init_provenance(
    source_script: str,
    *,
    mode: str | None = None,
    out_dir: str | None = None,
    create_dir: bool = True,
) -> Provenance:
    resolved_mode = mode or os.environ.get("AAPA_MODE") or "full"
    timestamp = os.environ.get("AAPA_TIMESTAMP_UTC") or _utc_now()
    run_id = os.environ.get("AAPA_RUN_ID") or f"stage4-{resolved_mode}-{timestamp}"
    safe_run_id = _safe_id(run_id)

    result_dir = out_dir or os.environ.get("AAPA_RESULT_DIR")
    if not result_dir:
        parent = "stage4_full" if resolved_mode == "full" else "stage4_nonfull"
        result_dir = os.path.join(EXPERIMENT_DIR, "results", parent, safe_run_id)
    result_dir = os.path.abspath(result_dir)
    if create_dir:
        os.makedirs(result_dir, exist_ok=True)

    return Provenance(
        env_id=_load_env_id(),
        run_id=run_id,
        timestamp_utc=timestamp,
        mode=resolved_mode,
        config_hash=os.environ.get("AAPA_CONFIG_HASH", "unregistered"),
        seed=int(os.environ.get("AAPA_SEED", "0")),
        git_commit=os.environ.get("AAPA_GIT_COMMIT", "unregistered"),
        dependency_hash=os.environ.get("AAPA_DEPENDENCY_HASH", "unregistered"),
        source_tree_hash=os.environ.get("AAPA_SOURCE_TREE_HASH", "unregistered"),
        source_script=source_script,
        result_dir=result_dir,
    )


def add_provenance(row: Mapping, provenance: Provenance) -> dict:
    merged = dict(row)
    merged.update(provenance.fields())
    return {**provenance.fields(), **{k: v for k, v in merged.items() if k not in PROVENANCE_FIELDS}}


def add_provenance_to_rows(rows: Iterable[Mapping], provenance: Provenance) -> list[dict]:
    return [add_provenance(row, provenance) for row in rows]


def fieldnames_for(rows: Iterable[Mapping]) -> list[str]:
    names = []
    for row in rows:
        for field in row:
            if field not in names:
                names.append(field)
    ordered = [field for field in PROVENANCE_FIELDS if field in names]
    ordered.extend(field for field in names if field not in PROVENANCE_FIELDS)
    return ordered


def write_csv(path: str, rows: list[Mapping], provenance: Provenance) -> list[dict]:
    out_rows = add_provenance_to_rows(rows, provenance)
    if not out_rows:
        return []
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames_for(out_rows))
        writer.writeheader()
        writer.writerows(out_rows)
    return out_rows
