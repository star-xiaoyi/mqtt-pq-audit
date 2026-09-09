#!/usr/bin/env python3
"""Independently validate a Stage 4 result package.

The validator treats runner summaries as untrusted presentation artifacts.  It
checks immutable package membership and hashes, recomputes QoS auditor verdicts
from auditor-only inputs, and derives quality metrics from the separated trace,
ground-truth, and auditor corpora.  It never consumes PASS, expected,
matches_expected, or runner-authored attribution columns as an oracle.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable, Mapping

import pandas as pd

from result_package import (
    MANIFEST_NAME,
    PackageError,
    atomic_write_json,
    load_json_object,
    object_hash,
    sha256_file,
    validate_completion_manifest,
    validate_config,
    validate_metadata,
)


# Every result package must contain this file set regardless of intensity mode.
# Coverage is DERIVED from the sealed protocol_config plus the raw corpus grid
# (see validate_experiment_coverage / validate_qos_corpus), never from a legacy
# per-file row count.  The set therefore only fixes package membership.
REQUIRED_FILES = (
    "e3_online_overhead.csv",
    "e4_amortized_overhead.csv",
    "e5_latency.csv",
    "e6_throughput.csv",
    "e7_qos_auditability.csv",
    "e8_audit_cost.csv",
    "e4_amortized_overhead_cpp.csv",
    "e8_audit_cost_cpp.csv",
    "e9_storage.csv",
    "e10_architecture_boundary.csv",
    "bench_crypto_cpp.csv",
    "object_sizes_cpp.csv",
    "a6_witness_cost_cpp.csv",
    "a6_failure_grid_cpp.csv",
    "e11_qos_auditor_comparison.csv",
)

# Converged native primitive schema.  The C++ micro-benchmarks must characterise
# exactly the post-quantum arms in scope plus the classical baselines; the
# expected rows are derived from the enabled-algorithm set rather than a hardcoded
# count.  SLH-DSA is an optional coverage point emitted only when liboqs enables
# it, so it is never required.
REQUIRED_PRIMITIVES = {
    ("KEM", "ML-KEM-768"),
    ("KEM", "X25519"),
    ("SIG", "ML-DSA-65"),
    ("SIG", "Ed25519"),
}
OPTIONAL_PRIMITIVES = {("SIG", "SLH_DSA_PURE_SHA2_128F")}

PROVENANCE_COLUMNS = {
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
}
MAIN_ARMS = {"A0", "A1", "A2", "A3", "A4", "A6"}
A6_FAILURE_CASES = {
    "valid_current_quorum2",
    "rollback_old_valid_without_freshness",
    "rollback_old_valid_with_freshness",
    "tail_truncation_old_checkpoint_with_latest_anchor",
    "witness_unavailable",
    "below_quorum",
    "split_view_same_witness_extension_only",
}
ARCHITECTURE_BOUNDARY_PATHS = {
    "CLASSICAL_TLS_MQTT",
    "PQ_HYBRID_TLS_MQTT",
    "PQ_E2E_PAYLOAD_ENCRYPTION",
    "PQ_CONNECT_AUTH",
    "A2_SESSION_MAC_ONLY",
    "A4_MERKLE_CHECKPOINT",
    "A6_WITNESSED_MERKLE_CHECKPOINT",
}

CORPUS_FILES = {
    "trace_corpus.jsonl",
    "ground_truth.jsonl",
    "auditor_inputs.jsonl",
    "evidence_observations.jsonl",
    "auditor_results.jsonl",
    "qos_capability_ablation.csv",
    "transferability_results.csv",
}
FORBIDDEN_AUDITOR_INPUT_KEYS = {
    "attack",
    "scenario",
    "scenario_class",
    "ground_truth",
    "expected",
    "expected_result",
    "matches_expected",
    "semantic_violation",
    "attribution",
    "attribution_label",
    "physical_actor",
    "protocol_responsible_party",
}


@dataclass
class Check:
    name: str
    status: str
    detail: str


def read_csv(path: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path)
    except Exception as exc:  # pragma: no cover - defensive for broken packages
        raise RuntimeError(f"cannot read {path.name}: {exc}") from exc


def add(checks: list[Check], name: str, ok: bool, detail: str, warn: bool = False) -> None:
    status = "PASS" if ok else ("WARN" if warn else "FAIL")
    checks.append(Check(name, status, detail))


def require_file(data_dir: Path, name: str, checks: list[Check]) -> pd.DataFrame | None:
    path = data_dir / name
    if not path.exists():
        add(checks, f"file:{name}", False, "missing")
        return None
    df = read_csv(path)
    missing = PROVENANCE_COLUMNS - set(df.columns)
    add(
        checks,
        f"provenance:{name}",
        not missing,
        "has required provenance columns" if not missing else f"missing {sorted(missing)}",
    )
    return df


def unique_values(frames: Iterable[pd.DataFrame], column: str) -> set[str]:
    values: set[str] = set()
    for df in frames:
        if column in df.columns:
            values.update(str(x) for x in df[column].dropna().unique())
    return values


def bool_column(df: pd.DataFrame, column: str) -> pd.Series:
    if column not in df.columns:
        return pd.Series([False] * len(df), index=df.index)
    return df[column].astype(str).str.lower().isin({"true", "1", "yes"})


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"line {line_number} is not an object")
                rows.append(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"cannot read {path.name}: {exc}") from exc
    return rows


def _forbidden_keys(value: Any, *, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if str(key).lower() in FORBIDDEN_AUDITOR_INPUT_KEYS:
                found.append(child_path)
            found.extend(_forbidden_keys(child, path=child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_forbidden_keys(child, path=f"{path}[{index}]"))
    return found


def _jsonable(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return _jsonable(value.to_dict())
    if hasattr(value, "value") and not isinstance(value, (str, bytes, int, float, bool)):
        return _jsonable(value.value)
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(child) for key, child in value.items()}
    if isinstance(value, (tuple, list, set)):
        return [_jsonable(child) for child in value]
    return value


def _verdict_projection(value: Any, *, case_id: str, auditor_mode: str) -> dict[str, Any]:
    verdict = _jsonable(value)
    if not isinstance(verdict, dict):
        raise TypeError(f"auditor verdict must be object-like, got {type(value).__name__}")
    projected = {
        "case_id": case_id,
        "auditor_mode": auditor_mode,
    }
    aliases = {
        "decision": ("decision", "outcome"),
        "detected": ("detected",),
        "attribution": ("attribution", "attribution_label"),
        "attributable": ("attributable",),
        "inconclusive": ("inconclusive",),
        "reason_codes": ("reason_codes",),
        "observed_facts": ("observed_facts",),
        "transferable_attribution": (
            "transferable_attribution",
            "audit_evidence_transferable",
        ),
    }
    for target, candidates in aliases.items():
        for candidate in candidates:
            if candidate in verdict:
                projected[target] = verdict[candidate]
                break
    if "reason_codes" in projected:
        projected["reason_codes"] = sorted(str(x) for x in projected["reason_codes"])
    return projected


def canonical_projection(value: Any) -> str:
    return object_hash(_jsonable(value))


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no", ""}:
            return False
    raise ValueError(f"not a boolean: {value!r}")


def _wilson_upper(successes: int, n: int, z: float = 1.959963984540054) -> float:
    if n <= 0:
        return 1.0
    p = successes / n
    denominator = 1.0 + z * z / n
    centre = p + z * z / (2.0 * n)
    radius = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * n)) / n)
    return (centre + radius) / denominator


def validate_counts(data_dir: Path, mode: str, checks: list[Check]) -> dict[str, pd.DataFrame]:
    """Require the locked file membership; coverage is derived, not row-counted.

    The legacy per-file minimum row counts are retired.  Membership plus a
    non-empty guard is enforced here; scientific coverage is asserted by
    ``validate_experiment_coverage`` (grids), ``validate_qos_corpus`` (the E7
    scenario x context x arm corpus), and ``validate_protocol_intensity``
    (intensities derived from the sealed protocol config).
    """
    frames: dict[str, pd.DataFrame] = {}
    for name in REQUIRED_FILES:
        df = require_file(data_dir, name, checks)
        if df is None:
            continue
        frames[name] = df
        add(
            checks,
            f"nonempty:{name}",
            len(df) >= 1,
            f"rows={len(df)}",
        )
    return frames


def validate_protocol_config(
    data_dir: Path, mode: str, checks: list[Check]
) -> dict[str, Any] | None:
    path = data_dir / "protocol_config.json"
    if not path.exists():
        add(checks, "protocol_config", False, "missing protocol_config.json")
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        add(checks, "protocol_config", False, f"invalid JSON: {exc}")
        return None
    issues = validate_config(data)
    add(
        checks,
        "protocol_config_schema_hash",
        not issues,
        "schema and config hash valid" if not issues else "; ".join(x.detail for x in issues),
    )
    add(checks, "protocol_config_mode", data.get("mode") == mode, f"mode={data.get('mode')}")
    return data


def validate_package_metadata(
    data_dir: Path,
    config: Mapping[str, Any] | None,
    mode: str,
    checks: list[Check],
) -> dict[str, Any] | None:
    path = data_dir / "package_metadata.json"
    if not path.exists():
        add(checks, "package_metadata", False, "missing package_metadata.json")
        return None
    try:
        metadata = load_json_object(path)
    except PackageError as exc:
        add(checks, "package_metadata", False, str(exc))
        return None
    if config is None:
        add(checks, "package_metadata_context", False, "protocol config unavailable")
        return metadata
    mismatches = [f"{issue.code}:{issue.detail}" for issue in validate_metadata(config, metadata)]
    add(
        checks,
        "package_metadata_context",
        not mismatches,
        "metadata matches config" if not mismatches else "; ".join(mismatches),
    )
    if mode == "full":
        add(
            checks,
            "full_clean_source_tree",
            metadata.get("git_dirty") is False,
            f"git_dirty={metadata.get('git_dirty')!r}",
        )
    return metadata


def validate_preflight_report(
    data_dir: Path,
    mode: str,
    config: Mapping[str, Any] | None,
    metadata: Mapping[str, Any] | None,
    checks: list[Check],
) -> None:
    path = data_dir / "preflight_report.json"
    if not path.exists():
        add(checks, "preflight_report", False, "missing preflight_report.json")
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        add(checks, "preflight_report", False, f"invalid JSON: {exc}")
        return

    status = data.get("overall_status")
    snapshot = data.get("snapshot", {})
    preflight_mode = snapshot.get("mode")
    add(checks, "preflight_report", status == "PASS", f"overall_status={status}")
    add(checks, "preflight_mode", preflight_mode == mode, f"mode={preflight_mode}")
    if config is not None:
        mismatches = []
        for field in ("run_id", "timestamp_utc", "mode", "seed", "config_hash"):
            if snapshot.get(field) != config.get(field):
                mismatches.append(
                    f"{field}: preflight={snapshot.get(field)!r} config={config.get(field)!r}"
                )
        add(
            checks,
            "preflight_config_context",
            not mismatches,
            "preflight context matches config" if not mismatches else "; ".join(mismatches),
        )
    if metadata is not None:
        git = snapshot.get("git", {})
        mismatches = []
        for field in ("commit", "dirty", "source_tree_hash"):
            meta_field = {
                "commit": "git_commit",
                "dirty": "git_dirty",
                "source_tree_hash": "source_tree_hash",
            }[field]
            if git.get(field) != metadata.get(meta_field):
                mismatches.append(
                    f"{field}: preflight={git.get(field)!r} metadata={metadata.get(meta_field)!r}"
                )
        if object_hash(snapshot.get("dependencies", {})) != metadata.get("dependency_hash"):
            mismatches.append("dependency snapshot hash mismatch")
        add(
            checks,
            "preflight_metadata_context",
            not mismatches,
            "preflight snapshot matches metadata" if not mismatches else "; ".join(mismatches),
        )


def _config_intensity(config: Mapping[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the sealed (python, cpp) intensity blocks; empty if unavailable."""
    if not config:
        return {}, {}
    py = config.get("python")
    cpp = config.get("cpp")
    return (dict(py) if isinstance(py, Mapping) else {}, dict(cpp) if isinstance(cpp, Mapping) else {})


def _numeric_min(df: pd.DataFrame, column: str) -> float | None:
    if column not in df.columns:
        return None
    series = pd.to_numeric(df[column], errors="coerce").dropna()
    return None if series.empty else float(series.min())


def validate_protocol_intensity(
    frames: dict[str, pd.DataFrame],
    mode: str,
    checks: list[Check],
    *,
    config: Mapping[str, Any] | None = None,
) -> None:
    """Assert intensities meet the sealed protocol_config, not hardcoded floors.

    Every threshold is read from ``protocol_config.json`` (``python``/``cpp``
    blocks), so the quick and full profiles cannot drift from the validator.
    Columns are guarded: a missing intensity column is a clean FAIL, never a
    KeyError crash.  E7 carries no repetition floor — it is a deterministic
    ``scenario x context x arm`` capability matrix validated as a grid.
    """
    py, cpp = _config_intensity(config)

    def floor(df: pd.DataFrame, column: str, threshold: float, name: str, label: str, *, warn: bool = False) -> None:
        value = _numeric_min(df, column)
        if value is None:
            add(checks, name, False, f"missing or non-numeric column {column!r}")
        else:
            add(checks, name, value >= threshold, f"{label}={value} (min {threshold})", warn=warn)

    e3 = frames.get("e3_online_overhead.csv")
    if e3 is not None and "e3_msgs" in py:
        floor(e3, "n_samples", float(py["e3_msgs"]), "intensity:E3_samples", "min_n_samples")

    e5 = frames.get("e5_latency.csv")
    if e5 is not None:
        if "e5_reps" in py:
            floor(e5, "n_repetitions", float(py["e5_reps"]), "intensity:E5_repetitions", "min_reps")
        if "e5_msgs" in py:
            floor(e5, "messages_per_repetition", float(py["e5_msgs"]), "intensity:E5_messages", "min_messages_per_rep")
        for column, gate in (
            ("publish_completion_ratio", "intensity:E5_publish_completion"),
            ("message_receipt_ratio_mean", "intensity:E5_message_receipt"),
        ):
            value = _numeric_min(e5, column)
            if value is not None:
                add(checks, gate, value >= 0.99, f"min_{column}={value:.4f}")
        if "e5_qos" in py and "qos" in e5.columns:
            expected_qos = {int(x) for x in str(py["e5_qos"]).split(",") if x.strip() != ""}
            observed_qos = {int(x) for x in pd.to_numeric(e5["qos"], errors="coerce").dropna().unique()}
            add(
                checks,
                "intensity:E5_qos_coverage",
                observed_qos == expected_qos,
                f"qos={sorted(observed_qos)} expected={sorted(expected_qos)}",
            )

    e6 = frames.get("e6_throughput.csv")
    if e6 is not None:
        if "e6_reps" in py:
            floor(e6, "n_repetitions", float(py["e6_reps"]), "intensity:E6_repetitions", "min_reps")
        if "e6_burst" in py:
            floor(e6, "burst_duration_s", float(py["e6_burst"]), "intensity:E6_burst_duration", "min_burst_s")
        drain = _numeric_min(e6, "subscriber_drain_success_ratio")
        if drain is not None:
            add(checks, "intensity:E6_subscriber_drain", drain >= 0.95, f"min_drain_success_ratio={drain:.4f}", warn=True)
        sent = _numeric_min(e6, "sent_messages_min")
        if sent is not None:
            add(checks, "intensity:E6_nonempty_bursts", sent > 0, f"min_sent_messages={sent:.0f}")

    e8 = frames.get("e8_audit_cost.csv")
    if e8 is not None and "e8_reps" in py:
        floor(e8, "n_repetitions", float(py["e8_reps"]), "intensity:E8_python_repetitions", "min_reps")

    e8cpp = frames.get("e8_audit_cost_cpp.csv")
    if e8cpp is not None and "audit_runs" in cpp:
        floor(e8cpp, "n_repetitions", float(cpp["audit_runs"]), "intensity:E8_cpp_repetitions", "min_reps")

    bench = frames.get("bench_crypto_cpp.csv")
    if bench is not None and "runs" in cpp:
        floor(bench, "n_runs", float(cpp["runs"]), "intensity:cpp_primitive_runs", "min_runs")


def _cell_tuples(df: pd.DataFrame, key_cols: tuple[str, ...]) -> list[tuple[str, ...]]:
    return [tuple(str(row[col]) for col in key_cols) for _, row in df[list(key_cols)].iterrows()]


def _grid_complete(
    df: pd.DataFrame | None, key_cols: tuple[str, ...], label: str, checks: list[Check]
) -> None:
    """Assert the (key_cols) grid is the full cartesian of observed values, once each."""
    if df is None:
        return
    missing_cols = [col for col in key_cols if col not in df.columns]
    if missing_cols:
        add(checks, f"coverage:{label}_columns", False, f"missing key columns {missing_cols}")
        return
    cells = _cell_tuples(df, key_cols)
    from collections import Counter
    from itertools import product

    counts = Counter(cells)
    observed = set(counts)
    axes = [sorted({cell[i] for cell in observed}) for i in range(len(key_cols))]
    expected = set(product(*axes)) if all(axes) else set()
    missing_cells = expected - observed
    duplicates = sorted(cell for cell, n in counts.items() if n > 1)
    add(
        checks,
        f"coverage:{label}_grid",
        not missing_cells and not duplicates,
        f"cells={len(observed)}/{len(expected)} missing={sorted(missing_cells)[:5]} duplicates={duplicates[:5]}",
    )


def _no_duplicate_cells(
    df: pd.DataFrame | None, key_cols: tuple[str, ...], label: str, checks: list[Check]
) -> None:
    if df is None:
        return
    missing_cols = [col for col in key_cols if col not in df.columns]
    if missing_cols:
        add(checks, f"coverage:{label}_columns", False, f"missing key columns {missing_cols}")
        return
    from collections import Counter

    counts = Counter(_cell_tuples(df, key_cols))
    duplicates = sorted(cell for cell, n in counts.items() if n > 1)
    add(
        checks,
        f"coverage:{label}_unique_cells",
        not duplicates,
        f"cells={len(counts)} duplicates={duplicates[:5]}",
    )


E8_VERIFY_SCOPE_BY_ARM = {
    "A3": "full_chain_plus_checkpoint_signature",
    "A4": "selected_merkle_inclusions_plus_checkpoint_signature",
    "A6": "selected_merkle_checkpoint_signature_and_witness_quorum",
}


def _validate_e8_workcells(df: pd.DataFrame | None, label: str, checks: list[Check]) -> None:
    """Work-cell consistency for an E8 cost table (Python or C++).

    A3 discloses the full chain, so distinct k iterations legitimately collapse to
    identical rows; duplicates are tolerated only when the whole work-cell
    (arm, N, k_disclosed, witness_count, min_receipts) — including verify_scope —
    is consistent.  Required arms and per-arm verify_scope are asserted.
    """
    if df is None:
        return
    required = {"arm", "N", "k_disclosed", "verify_scope"}
    if not required <= set(df.columns):
        add(checks, f"coverage:{label}_columns", False, f"missing {sorted(required - set(df.columns))}")
        return
    arms = {str(x) for x in df["arm"].dropna().unique()}
    add(checks, f"coverage:{label}_arms", {"A3", "A4", "A6"} <= arms, f"arms={sorted(arms)}")

    scope_bad: list[str] = []
    k_gt_n: list[str] = []
    inconsistent: list[str] = []
    grouped: dict[tuple[str, ...], set[str]] = {}
    for _, row in df.iterrows():
        arm = str(row["arm"])
        expected_scope = E8_VERIFY_SCOPE_BY_ARM.get(arm)
        if expected_scope is not None and str(row["verify_scope"]) != expected_scope:
            scope_bad.append(f"{arm}:{row['verify_scope']}")
        try:
            if float(row["k_disclosed"]) > float(row["N"]):
                k_gt_n.append(f"{arm} N={row['N']} k={row['k_disclosed']}")
        except (TypeError, ValueError):
            pass
        key = (arm, str(row["N"]), str(row["k_disclosed"]), str(row.get("witness_count", "")), str(row.get("min_receipts", "")))
        grouped.setdefault(key, set()).add(str(row["verify_scope"]))
    for key, scopes in grouped.items():
        if len(scopes) > 1:
            inconsistent.append("/".join(key))
    add(
        checks,
        f"coverage:{label}_verify_scope",
        not scope_bad and not k_gt_n and not inconsistent,
        f"scope_mismatch={scope_bad[:5]} k_gt_N={k_gt_n[:5]} inconsistent_cells={inconsistent[:5]}",
    )


def _validate_primitive_schema(df: pd.DataFrame | None, label: str, checks: list[Check]) -> None:
    if df is None:
        return
    if not {"category", "primitive"} <= set(df.columns):
        add(checks, f"coverage:{label}_columns", False, "missing category/primitive columns")
        return
    observed = {
        (str(row["category"]), str(row["primitive"]))
        for _, row in df[["category", "primitive"]].iterrows()
    }
    missing = REQUIRED_PRIMITIVES - observed
    unexpected = observed - REQUIRED_PRIMITIVES - OPTIONAL_PRIMITIVES
    add(
        checks,
        f"coverage:{label}_primitives",
        not missing and not unexpected,
        f"observed={sorted(observed)} missing={sorted(missing)} unexpected={sorted(unexpected)}",
    )


def validate_experiment_coverage(
    frames: dict[str, pd.DataFrame], checks: list[Check], *, config: Mapping[str, Any] | None = None
) -> None:
    """Assert each experiment's cells EXACTLY match the sealed coverage axes.

    Expected cells are expanded from ``protocol_config['coverage']`` (which is
    config-hash bound), NOT derived from the observed rows, so a deleted arm, a
    deleted axis value, or a single missing cell fails validation.  Duplicate
    work-cells also fail.
    """
    from collections import Counter

    from experiment_grids import CELL_KEY_COLUMNS, expand_cells, observed_cells

    coverage = config.get("coverage") if isinstance(config, Mapping) else None
    for experiment, key_cols in CELL_KEY_COLUMNS.items():
        df = frames.get(experiment)
        if df is None:
            continue
        axes = coverage.get(experiment) if isinstance(coverage, Mapping) else None
        if not axes:
            add(checks, f"coverage:{experiment}", False, "protocol_config.coverage missing sealed axes")
            continue
        missing_cols = [col for col in key_cols if col not in df.columns]
        if missing_cols:
            add(checks, f"coverage:{experiment}", False, f"missing key columns {missing_cols}")
            continue
        try:
            expected = expand_cells(experiment, axes)
        except Exception as exc:
            add(checks, f"coverage:{experiment}", False, f"cannot expand sealed axes: {exc}")
            continue
        observed_list = observed_cells(experiment, df.to_dict("records"))
        observed = set(observed_list)
        duplicates = sorted(cell for cell, count in Counter(observed_list).items() if count > 1)
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        add(
            checks,
            f"coverage:{experiment}",
            not missing and not extra and not duplicates,
            f"cells={len(observed)}/{len(expected)} missing={missing[:5]} extra={extra[:5]} duplicates={duplicates[:5]}",
        )
    _validate_primitive_schema(frames.get("bench_crypto_cpp.csv"), "bench_crypto", checks)
    _validate_primitive_schema(frames.get("object_sizes_cpp.csv"), "object_sizes", checks)
    _validate_e8_workcells(frames.get("e8_audit_cost_cpp.csv"), "E8_cpp", checks)


def validate_coverage_canonical(
    config: Mapping[str, Any] | None, mode: str, checks: list[Check]
) -> None:
    """The sealed ``protocol_config.coverage`` must EQUAL the canonical ``axes_for(mode)``.

    The validator recomputes the canonical axes here instead of trusting the runner's
    sealed coverage as its own reference (the same de-trust principle applied to the
    E7/E11 capability tables).  Without this, a run that sealed a *reduced* coverage
    together with matching reduced CSVs would still pass ``validate_experiment_coverage``,
    because that check only asserts CSV cells == sealed axes.
    """
    from experiment_grids import axes_for

    sealed = config.get("coverage") if isinstance(config, Mapping) else None
    if not isinstance(sealed, Mapping):
        add(checks, "coverage_sealed_equals_canonical", False, "protocol_config.coverage missing")
        return
    try:
        canonical = axes_for(mode)
    except Exception as exc:  # pragma: no cover - defensive
        add(checks, "coverage_sealed_equals_canonical", False, f"cannot compute canonical axes: {exc}")
        return
    mismatches = [
        exp
        for exp in sorted(set(sealed) | set(canonical))
        if canonical_projection(sealed.get(exp)) != canonical_projection(canonical.get(exp))
    ]
    add(
        checks,
        "coverage_sealed_equals_canonical",
        not mismatches,
        f"mode={mode} mismatched_experiments={mismatches[:8]}",
    )


def validate_profile_canonical(
    config: Mapping[str, Any] | None, mode: str, checks: list[Check]
) -> None:
    """The sealed ``config.python`` / ``config.cpp`` / ``config.e7_corpus`` must
    EQUAL the canonical profile recomputed here — the validator does not trust the
    runner's sealed intensity as its own reference.  This blocks a synchronously
    downgraded package (e.g. full's ``e8_lifecycle_reps`` 20->1 or A6 witness
    3/2->1/1 with a recomputed ``config_hash`` and re-synced provenance)."""
    from experiment_profiles import canonical_profile
    from experiment_grids import E7_CORPUS_CONTRACT

    if not isinstance(config, Mapping):
        add(checks, "profile_sealed_equals_canonical", False, "protocol_config missing")
        return
    try:
        canonical = canonical_profile(mode)
    except Exception as exc:  # pragma: no cover - defensive
        add(checks, "profile_sealed_equals_canonical", False, f"cannot compute canonical profile: {exc}")
        return

    mismatches: list[str] = []
    for section in ("python", "cpp"):
        want = canonical.get(section)
        got = config.get(section)
        if canonical_projection(got) != canonical_projection(want):
            want_keys = set(want) if isinstance(want, Mapping) else set()
            got_keys = set(got) if isinstance(got, Mapping) else set()
            diff = sorted(
                (want_keys ^ got_keys)
                | {k for k in (want_keys & got_keys)
                   if canonical_projection(want.get(k)) != canonical_projection(got.get(k))}
            )
            mismatches.append(f"{section}:{diff[:8]}")
    if canonical_projection(config.get("e7_corpus")) != canonical_projection(E7_CORPUS_CONTRACT):
        mismatches.append("e7_corpus")
    add(checks, "profile_sealed_equals_canonical", not mismatches, f"mode={mode} mismatches={mismatches[:6]}")


def validate_provenance(
    frames: dict[str, pd.DataFrame],
    mode: str,
    config: Mapping[str, Any] | None,
    metadata: Mapping[str, Any] | None,
    checks: list[Check],
) -> None:
    expected = {
        "mode": mode,
        "run_id": config.get("run_id") if config else None,
        "timestamp_utc": config.get("timestamp_utc") if config else None,
        "config_hash": config.get("config_hash") if config else None,
        "seed": str(config.get("seed")) if config else None,
        "git_commit": metadata.get("git_commit") if metadata else None,
        "dependency_hash": metadata.get("dependency_hash") if metadata else None,
        "source_tree_hash": metadata.get("source_tree_hash") if metadata else None,
    }
    for field, expected_value in expected.items():
        observed = unique_values(frames.values(), field)
        target = {str(expected_value)} if expected_value is not None else set()
        add(
            checks,
            f"provenance_context:{field}",
            observed == target,
            f"observed={sorted(observed)} expected={sorted(target)}",
        )

    source_scripts = unique_values(frames.values(), "source_script")
    required_sources = {
        "python/run_optimized.py",
        "python/run_final.py",
        "cpp/aapa_crypto_bench.cpp",
    }
    missing_sources = required_sources - source_scripts
    add(
        checks,
        "source_coverage",
        not missing_sources,
        f"sources={sorted(source_scripts)}; missing={sorted(missing_sources)}",
        warn=bool(missing_sources),
    )


def _load_case_crypto_inputs(crypto_artifact: Mapping[str, Any]):
    """Load (registry, anchors, evidence-list) from an embedded crypto_artifact."""
    from audit_verify import AnchorSet, evidence_from_dict
    from trusted_registry import TrustedRegistry

    bundle = crypto_artifact.get("bundle")
    if not bundle:
        return None, None, None
    registry_dict = crypto_artifact.get("trusted_registry")
    anchors_dict = crypto_artifact.get("trusted_anchors")
    registry = TrustedRegistry.from_dict(registry_dict) if registry_dict else None
    anchors = AnchorSet.from_dict(anchors_dict) if anchors_dict else None
    evidence = [evidence_from_dict(ev) for ev in bundle.get("evidence", [])]
    return registry, anchors, evidence


def validate_corpus_crypto_rederivation(
    observation_by_case: Mapping[str, Mapping[str, Any]],
    input_by_case: Mapping[str, Mapping[str, Any]],
    trace_by_case: Mapping[str, Mapping[str, Any]],
    checks: list[Check],
) -> None:
    """Re-derive each case's crypto AND reconstruct the whole auditor_input (G3).

    For every transferable case the validator: (1) recomputes and checks the
    artifact_id, case_id, and arm binding; (2) re-runs ``audit_stream`` over the
    persisted bundle/registry/anchors and compares the FULL reproducible verdict
    (outcome, reason_codes, stream_id, counts, tail/anchor/limitations); (3) asserts
    the witness receipt_id set equals the recomputed set exactly (missing/extra/
    duplicate fail) and re-derives each receipt's registry-bound validity; and
    (4) rebuilds the crypto_artifact and calls ``construct_auditor_input`` on the raw
    trace, comparing every security/semantic projection to the stored auditor_input.
    A forged publisher_identity, witness fact, reason code, or deleted receipt is
    therefore rejected even with matching stored results.  A2 stays non-transferable.
    """
    import hashlib

    try:
        from aapa_mqtt import canonical_json_bytes, witness_receipt_from_dict
        from audit_verify import audit_stream, verify_signature
        from crypto_evidence_bridge import FIXED_AUDIT_TIME
        from evidence_auditor import construct_auditor_input
    except Exception as exc:  # pragma: no cover - defensive
        add(checks, "corpus_crypto_rederivation", False, f"cannot import crypto stack: {exc}")
        return

    provenance_keys = PROVENANCE_COLUMNS | {
        "experiment_config_hash", "experiment_dependency_hash", "experiment_seed",
    }

    def strip_nonreproducible(auditor_input: Mapping[str, Any]) -> dict[str, Any]:
        projection = json.loads(json.dumps(_jsonable(auditor_input)))
        for key in list(projection):
            if key in provenance_keys:
                projection.pop(key, None)
        crypto = projection.get("crypto_verification")
        if isinstance(crypto, dict):
            crypto.pop("artifact_id", None)
            crypto.pop("verification_time_ms", None)
        return projection

    verdict_mismatches: list[str] = []
    witness_mismatches: list[str] = []
    artifact_mismatches: list[str] = []
    input_mismatches: list[str] = []
    a2_violations: list[str] = []
    errors: list[str] = []
    rederived_transferable = 0

    verdict_fields = (
        "outcome", "reason_codes", "stream_id", "verified_checkpoints", "verified_records",
        "tail_complete", "started_from_trusted_anchor", "ended_at_trusted_latest", "limitations",
    )

    for case_id in sorted(observation_by_case):
        observation = observation_by_case[case_id]
        auditor_input = input_by_case.get(case_id, {})
        trace = trace_by_case.get(case_id)
        crypto_artifact = observation.get("crypto_artifact") or {}
        arm = str(crypto_artifact.get("arm_id", observation.get("arm", "")))

        # artifact_id consistency + case_id/arm binding (never trusted self-report).
        body = {key: value for key, value in crypto_artifact.items() if key != "artifact_id"}
        recomputed_artifact_id = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        if str(crypto_artifact.get("artifact_id")) != recomputed_artifact_id:
            artifact_mismatches.append(f"{case_id}:artifact_id")
        if str(crypto_artifact.get("case_id")) != case_id:
            artifact_mismatches.append(f"{case_id}:case_id")
        if str(observation.get("arm", arm)) != arm:
            artifact_mismatches.append(f"{case_id}:arm")

        if arm == "A2":
            crypto_verification = auditor_input.get("crypto_verification", {}) if auditor_input else {}
            if crypto_artifact.get("bundle"):
                a2_violations.append(f"{case_id}: A2 carries a transferable bundle")
            if auditor_input.get("transferable_evidence") is not False:
                a2_violations.append(f"{case_id}: A2 transferable_evidence not False")
            if str(crypto_verification.get("stream_outcome")) == "accept":
                a2_violations.append(f"{case_id}: A2 claims a crypto accept")
            continue

        try:
            registry, anchors, evidence = _load_case_crypto_inputs(crypto_artifact)
            if evidence is None:
                errors.append(f"{case_id}: {arm} has no embedded bundle to replay")
                continue
            replay = audit_stream(
                evidence, arm, registry, anchors,
                audit_time=FIXED_AUDIT_TIME,
                witness_quorum=2 if arm == "A6" else None,
            ).to_dict()
        except Exception as exc:
            errors.append(f"{case_id}: replay error {exc}")
            continue
        rederived_transferable += 1

        stored_verdict = crypto_artifact.get("stream_verdict", {})
        for field in verdict_fields:
            if canonical_projection(_sorted_if_list(replay.get(field))) != canonical_projection(_sorted_if_list(stored_verdict.get(field))):
                verdict_mismatches.append(f"{case_id}:sv.{field}")

        # Witness receipt_id set strict equality + registry-bound validity.
        recomputed_ids: list[str] = []
        rederived_validity: dict[str, bool] = {}
        for evidence_row in crypto_artifact["bundle"].get("evidence", []):
            for receipt in evidence_row.get("witness_receipts", []) or []:
                try:
                    receipt_obj = witness_receipt_from_dict(receipt)
                except Exception:
                    witness_mismatches.append(f"{case_id}: malformed witness receipt")
                    continue
                receipt_id = receipt_obj.receipt_id()
                recomputed_ids.append(receipt_id)
                if str(receipt.get("receipt_id")) != receipt_id:
                    witness_mismatches.append(f"{case_id}: receipt_id mismatch")
                authorization = registry.witness_for_id(receipt_obj.witness_id) if registry is not None else None
                authorized_key = authorization.public_key if authorization is not None else None
                scheme = authorization.signature_scheme if authorization is not None else "ML-DSA-65"
                rederived_validity[receipt_id] = bool(
                    authorized_key
                    and receipt_obj.public_key == authorized_key
                    and receipt_obj.signature
                    and verify_signature(authorized_key, receipt_obj.serialize(), receipt_obj.signature, scheme)
                )
        fact_ids = [str(fact.get("receipt_id")) for fact in crypto_artifact.get("witness_receipt_signatures", []) or []]
        if sorted(recomputed_ids) != sorted(fact_ids):
            witness_mismatches.append(f"{case_id}: witness receipt_id set differs (bundle={len(recomputed_ids)} facts={len(fact_ids)})")

        # Full reconstruction: rebuild the artifact from the re-derived facts and
        # compare construct_auditor_input(trace, ...) to the stored auditor_input.
        if trace is not None and auditor_input:
            rederived_facts = [
                {"receipt_id": receipt_id, "signature_valid": rederived_validity[receipt_id]}
                for receipt_id in recomputed_ids
            ]
            rederived_artifact = dict(crypto_artifact)
            rederived_artifact["stream_verdict"] = replay
            rederived_artifact["witness_receipt_signatures"] = rederived_facts
            try:
                reconstructed = construct_auditor_input(trace, crypto_artifact=rederived_artifact)
            except Exception as exc:
                errors.append(f"{case_id}: reconstruction error {exc}")
            else:
                if canonical_projection(strip_nonreproducible(reconstructed)) != canonical_projection(strip_nonreproducible(auditor_input)):
                    input_mismatches.append(case_id)

    add(checks, "corpus_crypto_artifact_binding", not artifact_mismatches,
        f"artifact_mismatches={artifact_mismatches[:5]}")
    add(checks, "corpus_crypto_verdict_rederived", not verdict_mismatches and not errors,
        f"rederived={rederived_transferable} verdict_mismatches={verdict_mismatches[:5]} errors={errors[:5]}")
    add(checks, "corpus_crypto_witness_rederived", not witness_mismatches,
        f"witness_mismatches={witness_mismatches[:5]}")
    add(checks, "corpus_auditor_input_reconstructed", not input_mismatches,
        f"reconstructed_mismatches={input_mismatches[:5]}")
    add(checks, "corpus_A2_nontransferable_crypto", not a2_violations,
        "A2 stays non-transferable with no faked crypto replay" if not a2_violations else f"a2_violations={a2_violations[:5]}")


def _sorted_if_list(value: Any) -> Any:
    if isinstance(value, list):
        return sorted(str(item) for item in value)
    return value


def _summary_cell_equal(a: Any, b: Any) -> bool:
    def norm(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, float) and math.isnan(value):
            return ""
        text = str(value).strip()
        return "" if text.lower() in ("", "nan", "none") else text
    return norm(a) == norm(b)


def validate_e7_e11_summary(data_dir: Path, checks: list[Check]) -> None:
    """E7/E11 capability tables must equal the independently replayed derivation.

    The runner-authored ``e7_qos_auditability.csv`` / ``e11_qos_auditor_comparison.csv``
    are NOT trusted as the C1 authority: their tamper-prone columns are recomputed
    from ``ground_truth`` + replayed auditor results (via the same ``_summarise_e7`` /
    ``_summarise_e11`` used by the runner) and compared.  A forged detection_rate,
    attribution, or false-positive rate fails closed.
    """
    import csv as _csv

    try:
        from evidence_auditor import audit_evidence
        from qos_experiments import _summarise_e11, _summarise_e7
    except Exception as exc:  # pragma: no cover - defensive
        add(checks, "e7_e11_summary_derived", False, f"cannot import summariser: {exc}")
        return
    try:
        traces = read_jsonl(data_dir / "trace_corpus.jsonl")
        ground_truth = {row["case_id"]: row for row in read_jsonl(data_dir / "ground_truth.jsonl")}
        inputs = {row["case_id"]: row for row in read_jsonl(data_dir / "auditor_inputs.jsonl")}
    except RuntimeError as exc:
        add(checks, "e7_e11_summary_derived", False, str(exc))
        return
    trace_by_case = {row["case_id"]: row for row in traces}

    joined: list[dict[str, Any]] = []
    errors: list[str] = []
    for case_id, auditor_input in sorted(inputs.items()):
        truth = ground_truth.get(case_id)
        trace = trace_by_case.get(case_id)
        if truth is None or trace is None:
            errors.append(f"{case_id}: missing truth/trace")
            continue
        try:
            aware = audit_evidence(auditor_input, qos_aware=True)
            agnostic = audit_evidence(auditor_input, qos_aware=False)
        except Exception as exc:
            errors.append(f"{case_id}: {exc}")
            continue
        joined.append({
            "arm": auditor_input["arm"],
            "scenario": truth["scenario"],
            "scenario_class": truth["scenario_class"],
            "context_id": trace["qos_context"]["context_id"],
            "context": trace["qos_context"],
            "truth": truth,
            "auditor_input": auditor_input,
            "aware": aware,
            "agnostic": agnostic,
        })

    def compare(filename: str, recomputed_rows: list[dict[str, Any]], columns: tuple[str, ...], label: str) -> None:
        path = data_dir / filename
        if not path.is_file():
            add(checks, f"{label}_summary_derived", False, f"missing {filename}")
            return
        with path.open("r", encoding="utf-8", newline="") as handle:
            stored = {
                (str(row.get("arm")), str(row.get("scenario")), str(row.get("context_id"))): row
                for row in _csv.DictReader(handle)
            }
        recomputed = {(str(r["arm"]), str(r["scenario"]), str(r["context_id"])): r for r in recomputed_rows}
        mismatches: list[str] = []
        if set(stored) != set(recomputed):
            mismatches.append(f"group set differs (stored={len(stored)} recomputed={len(recomputed)})")
        for key, recomputed_row in recomputed.items():
            stored_row = stored.get(key)
            if stored_row is None:
                mismatches.append(f"{key}:missing")
                continue
            for column in columns:
                if not _summary_cell_equal(recomputed_row.get(column), stored_row.get(column)):
                    mismatches.append(f"{'/'.join(key)}:{column}")
                    break
        add(checks, f"{label}_summary_derived", not mismatches, f"groups={len(recomputed)} mismatches={mismatches[:5]}")

    compare(
        "e7_qos_auditability.csv",
        _summarise_e7(joined, metadata={}),
        ("detection_rate", "inconclusive_rate", "majority_attribution", "attribution_rate",
         "attribution_correct_rate", "false_positive_rate", "false_negative_rate",
         "semantic_status", "evidence_integrity_violation"),
        "E7",
    )
    compare(
        "e11_qos_auditor_comparison.csv",
        _summarise_e11(joined, metadata={}),
        ("qos_aware_decision", "qos_agnostic_decision", "qos_aware_attribution", "qos_agnostic_attribution",
         "qos_aware_detection_rate", "qos_agnostic_detection_rate",
         "qos_aware_false_positive_rate", "qos_agnostic_false_positive_rate"),
        "E11",
    )
    add(checks, "e7_e11_summary_replay_errors", not errors, f"errors={errors[:5]}")


def validate_qos_corpus(
    data_dir: Path,
    mode: str,
    checks: list[Check],
    *,
    config: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    """Re-run both auditors from answer-free inputs and derive C1 gates.

    `ground_truth.jsonl` is used only after the independent auditor execution.
    It is never passed to the auditor.  The semantic-oracle replay hook is
    validated separately when the QoS experiment module exposes it.
    """
    missing = sorted(name for name in CORPUS_FILES if not (data_dir / name).is_file())
    add(
        checks,
        "corpus_required_files",
        not missing,
        "all separated corpus files present" if not missing else f"missing={missing}",
    )
    if missing:
        return
    try:
        traces = read_jsonl(data_dir / "trace_corpus.jsonl")
        ground_truth = read_jsonl(data_dir / "ground_truth.jsonl")
        auditor_inputs = read_jsonl(data_dir / "auditor_inputs.jsonl")
        observations = read_jsonl(data_dir / "evidence_observations.jsonl")
        stored_results = read_jsonl(data_dir / "auditor_results.jsonl")
    except RuntimeError as exc:
        add(checks, "corpus_parse", False, str(exc))
        return

    expected_provenance = {
        "run_id": config.get("run_id") if config else None,
        "timestamp_utc": config.get("timestamp_utc") if config else None,
        "mode": config.get("mode") if config else None,
        "config_hash": config.get("config_hash") if config else None,
        "seed": config.get("seed") if config else None,
        "git_commit": metadata.get("git_commit") if metadata else None,
        "dependency_hash": metadata.get("dependency_hash") if metadata else None,
        "source_tree_hash": metadata.get("source_tree_hash") if metadata else None,
    }
    provenance_mismatches: list[str] = []
    for label, rows in (
        ("trace", traces),
        ("ground_truth", ground_truth),
        ("auditor_input", auditor_inputs),
        ("observation", observations),
        ("auditor_result", stored_results),
    ):
        for index, row in enumerate(rows):
            for field, expected in expected_provenance.items():
                if expected is not None and str(row.get(field)) != str(expected):
                    provenance_mismatches.append(f"{label}[{index}].{field}")
                    break
    add(
        checks,
        "corpus_provenance_context",
        not provenance_mismatches,
        "all raw rows match package context"
        if not provenance_mismatches
        else f"mismatches={provenance_mismatches[:20]}",
    )

    def by_case(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
        indexed: dict[str, dict[str, Any]] = {}
        duplicates: list[str] = []
        for row in rows:
            case_id = str(row.get("case_id", ""))
            if not case_id or case_id in indexed:
                duplicates.append(case_id or "<missing>")
            indexed[case_id] = row
        add(
            checks,
            f"corpus_unique_cases:{label}",
            not duplicates,
            f"rows={len(rows)} duplicates={sorted(set(duplicates))}",
        )
        return indexed

    trace_by_case = by_case(traces, "trace")
    truth_by_case = by_case(ground_truth, "ground_truth")
    input_by_case = by_case(auditor_inputs, "auditor_input")
    observation_by_case = by_case(observations, "observation")
    # G3: re-derive every case's crypto verdict from the persisted evidence bundle,
    # registry, and anchors — never trust the embedded stream_verdict/facts.
    validate_corpus_crypto_rederivation(observation_by_case, input_by_case, trace_by_case, checks)
    case_sets = {
        "trace": set(trace_by_case),
        "ground_truth": set(truth_by_case),
        "auditor_input": set(input_by_case),
        "observation": set(observation_by_case),
    }
    equal_case_sets = len({frozenset(value) for value in case_sets.values()}) == 1
    add(
        checks,
        "corpus_case_join",
        equal_case_sets and bool(trace_by_case),
        "; ".join(f"{name}={len(value)}" for name, value in case_sets.items()),
    )

    # Derived scenario x context x arm coverage.  Recompute the authoritative
    # case-id grid from the generation definitions at the sealed seed and assert
    # the corpus spans it exactly, with every trace field cryptographically bound
    # to its case_id.  This replaces the retired 5/50 repetition floor and trusts
    # no runner-authored scenario label or row count.
    try:
        from qos_experiments import (
            FORMAL_CORPUS_ARMS,
            MANIPULATION_COVERAGE_STATUS,
            QOS_EXPERIMENT_SCHEMA_VERSION,
            SCENARIO_CONTEXTS,
            derive_expected_corpus,
        )

        qos_config_path = data_dir / "qos_experiment_config.json"
        corpus_reps = 1
        corpus_config: dict[str, Any] = {}
        if qos_config_path.is_file():
            corpus_config = json.loads(qos_config_path.read_text(encoding="utf-8"))
            corpus_reps = int(corpus_config.get("repetitions", 1))
        add(
            checks,
            "corpus_canonical_design_config",
            corpus_config.get("schema_version") == QOS_EXPERIMENT_SCHEMA_VERSION
            and corpus_config.get("scenario_contexts")
            == {key: list(value) for key, value in SCENARIO_CONTEXTS.items()}
            and corpus_config.get("manipulation_coverage_status")
            == MANIPULATION_COVERAGE_STATUS,
            "schema, scenario-context grid, and 44 instantiated/12 scope-excluded "
            "classification match canonical source",
        )
        # E7 contract: the sealed protocol_config e7_corpus must equal what the
        # corpus actually recorded (repetitions/n_records/checkpoint_interval).
        if config is not None and isinstance(config.get("e7_corpus"), Mapping):
            contract_fields = ("repetitions", "n_records", "checkpoint_interval")
            sealed_contract = {field: config["e7_corpus"].get(field) for field in contract_fields}
            actual_contract = {field: corpus_config.get(field) for field in contract_fields}
            add(
                checks,
                "corpus_e7_contract",
                sealed_contract == actual_contract,
                f"protocol_config.e7_corpus={sealed_contract} qos_experiment_config={actual_contract}",
            )
        seed_source = corpus_config.get("seed")
        if seed_source is None and config is not None:
            seed_source = config.get("seed")
        if seed_source is None:
            add(checks, "corpus_grid_coverage", False, "no sealed seed to derive expected corpus")
        else:
            if config is not None and config.get("seed") is not None:
                add(
                    checks,
                    "corpus_seed_binding",
                    int(corpus_config.get("seed", config.get("seed"))) == int(config.get("seed")),
                    f"corpus_seed={corpus_config.get('seed')} protocol_seed={config.get('seed')}",
                )
            expected = derive_expected_corpus(seed=int(seed_source), repetitions=corpus_reps)
            observed_ids = set(trace_by_case)
            missing_cells = sorted(set(expected) - observed_ids)
            extra_cells = sorted(observed_ids - set(expected))
            add(
                checks,
                "corpus_grid_coverage",
                not missing_cells and not extra_cells and len(observed_ids) == len(expected),
                f"cells={len(observed_ids)}/{len(expected)} missing={missing_cells[:5]} extra={extra_cells[:5]}",
            )
            observed_arms = {str(trace.get("arm")) for trace in trace_by_case.values()}
            add(
                checks,
                "corpus_arm_coverage",
                observed_arms == set(FORMAL_CORPUS_ARMS),
                f"arms={sorted(observed_arms)} required={sorted(FORMAL_CORPUS_ARMS)}",
            )
            field_mismatches: list[str] = []
            for case_id, trace in trace_by_case.items():
                cell = expected.get(case_id)
                if cell is None:
                    continue
                if str(trace.get("arm")) != cell["arm"]:
                    field_mismatches.append(f"{case_id}:arm")
                if str(trace.get("qos_context", {}).get("context_id")) != cell["context_id"]:
                    field_mismatches.append(f"{case_id}:context")
                scenario = str(truth_by_case.get(case_id, {}).get("scenario"))
                if scenario != cell["scenario"]:
                    field_mismatches.append(f"{case_id}:scenario")
            add(
                checks,
                "corpus_case_id_integrity",
                not field_mismatches,
                "every case_id binds its own scenario/context/arm"
                if not field_mismatches
                else f"mismatches={field_mismatches[:10]}",
            )
    except Exception as exc:  # pragma: no cover - defensive
        add(checks, "corpus_grid_coverage", False, f"cannot derive expected corpus: {exc}")

    leakage = []
    for case_id, auditor_input in input_by_case.items():
        leakage.extend(f"{case_id}:{path}" for path in _forbidden_keys(auditor_input))
    add(
        checks,
        "auditor_input_no_answer_leakage",
        not leakage,
        "no forbidden ground-truth/expected fields" if not leakage else f"leaks={leakage[:10]}",
    )

    # The trace corpus must likewise remain observational and not smuggle its
    # generator label into the auditor path.
    trace_leakage = []
    for case_id, trace in trace_by_case.items():
        trace_leakage.extend(f"{case_id}:{path}" for path in _forbidden_keys(trace))
    add(
        checks,
        "trace_no_ground_truth_leakage",
        not trace_leakage,
        "trace corpus contains observations only" if not trace_leakage else f"leaks={trace_leakage[:10]}",
    )

    try:
        from qos_semantics import semantic_oracle
    except Exception as exc:
        add(checks, "semantic_oracle_import", False, f"cannot import qos_semantics: {exc}")
        return
    oracle_fields = (
        "case_id",
        "semantic_status",
        "semantic_violation",
        "evidence_integrity_violation",
        "physical_actor",
        "protocol_responsible_party",
        "witness_status",
        "reason_codes",
    )
    oracle_mismatches: list[str] = []
    oracle_errors: list[str] = []
    for case_id in sorted(set(trace_by_case) & set(truth_by_case)):
        try:
            replayed = semantic_oracle(trace_by_case[case_id])
            recorded = truth_by_case[case_id]
            left = {field: replayed.get(field) for field in oracle_fields}
            right = {field: recorded.get(field) for field in oracle_fields}
            for side in (left, right):
                if isinstance(side.get("reason_codes"), list):
                    side["reason_codes"] = sorted(str(x) for x in side["reason_codes"])
            if canonical_projection(left) != canonical_projection(right):
                oracle_mismatches.append(case_id)
        except Exception as exc:
            oracle_errors.append(f"{case_id}: {exc}")
    add(
        checks,
        "semantic_oracle_replay",
        not oracle_errors and not oracle_mismatches,
        f"cases={len(trace_by_case)} errors={oracle_errors[:5]} mismatches={oracle_mismatches[:10]}",
    )

    try:
        from evidence_auditor import audit_evidence as independent_audit
    except Exception as exc:
        add(checks, "independent_auditor_import", False, f"cannot import evidence_auditor: {exc}")
        return

    recomputed: dict[tuple[str, str], dict[str, Any]] = {}
    audit_errors: list[str] = []
    for case_id, auditor_input in sorted(input_by_case.items()):
        for aware, auditor_mode in ((True, "qos_aware"), (False, "qos_agnostic")):
            try:
                verdict = independent_audit(auditor_input, qos_aware=aware)
                recomputed[(case_id, auditor_mode)] = _verdict_projection(
                    verdict, case_id=case_id, auditor_mode=auditor_mode
                )
            except Exception as exc:
                audit_errors.append(f"{case_id}/{auditor_mode}: {exc}")
    add(
        checks,
        "independent_auditor_replay",
        not audit_errors and len(recomputed) == 2 * len(input_by_case),
        f"recomputed={len(recomputed)} errors={audit_errors[:5]}",
    )
    if audit_errors:
        return

    stored: dict[tuple[str, str], dict[str, Any]] = {}
    duplicate_results: list[str] = []
    for row in stored_results:
        key = (str(row.get("case_id", "")), str(row.get("auditor_mode", "")))
        if key in stored:
            duplicate_results.append("/".join(key))
        stored[key] = _verdict_projection(row, case_id=key[0], auditor_mode=key[1])
    mismatched_results = []
    for key in sorted(set(recomputed) | set(stored)):
        if canonical_projection(recomputed.get(key)) != canonical_projection(stored.get(key)):
            mismatched_results.append("/".join(key))
    add(
        checks,
        "auditor_results_reproducible",
        not duplicate_results and not mismatched_results,
        f"duplicates={duplicate_results[:5]} mismatches={mismatched_results[:10]}",
    )

    # Derive clean-control false positives from ground truth joined only after
    # replay.  No runner-authored false_positive or PASS column is read.
    clean_by_arm: dict[str, list[tuple[dict[str, Any], dict[str, Any], str]]] = {}
    aware_false_positives = 0
    agnostic_false_positives = 0
    eligible_nonviolations = 0
    for case_id in sorted(set(input_by_case) & set(truth_by_case)):
        truth = truth_by_case[case_id]
        auditor_input = input_by_case[case_id]
        raw_semantic_violation = truth.get("semantic_violation")
        if raw_semantic_violation is None:
            semantic_violation: bool | None = None
        else:
            try:
                semantic_violation = parse_bool(raw_semantic_violation)
            except ValueError:
                semantic_violation = None
                audit_errors.append(f"{case_id}: invalid semantic_violation")
        arm = str(auditor_input.get("arm", truth.get("arm", "")))
        aware = recomputed.get((case_id, "qos_aware"), {})
        agnostic = recomputed.get((case_id, "qos_agnostic"), {})
        if semantic_violation is False:
            eligible_nonviolations += 1
            try:
                aware_false_positives += int(parse_bool(aware.get("detected", False)))
                agnostic_false_positives += int(parse_bool(agnostic.get("detected", False)))
            except ValueError:
                audit_errors.append(f"{case_id}: invalid detected flag")
        if str(truth.get("scenario", "")) == "clean" and arm != "A2":
            context_id = str(
                trace_by_case.get(case_id, {}).get("qos_context", {}).get("context_id", "")
            )
            clean_by_arm.setdefault(arm, []).append((aware, auditor_input, context_id))
        if arm == "A2":
            transferable = aware.get("transferable_attribution", False)
            attributable = aware.get("attributable", False)
            if (
                parse_bool(transferable)
                or parse_bool(attributable)
                or aware.get("attribution") not in {None, "", "none"}
            ):
                audit_errors.append(f"{case_id}: A2 transferable attribution")
    add(
        checks,
        "A2_nontransferable_replay",
        not audit_errors,
        "A2 never yields transferable attribution" if not audit_errors else "; ".join(audit_errors[:5]),
    )
    add(
        checks,
        "qos_aware_nonviolation_fp_not_worse",
        eligible_nonviolations > 0 and aware_false_positives <= agnostic_false_positives,
        f"n={eligible_nonviolations} aware_fp={aware_false_positives} agnostic_fp={agnostic_false_positives}",
    )
    required_clean_contexts = {
        "q0_connected_clean",
        "q1_connected_persistent",
        "q2_connected_persistent",
        "q1_to_q0_subscription",
        "q2_to_q0_subscription",
        "q1_persistent_reconnected",
    }
    for arm, cases in sorted(clean_by_arm.items()):
        false_positives = sum(
            parse_bool(verdict.get("detected", False)) for verdict, _input, _context in cases
        )
        n = len(cases)
        upper = _wilson_upper(false_positives, n)
        contexts = {context for _verdict, _input, context in cases}
        crypto_replayed = all(
            parse_bool(auditor_input.get("real_crypto_evidence", False))
            and parse_bool(
                verdict.get("observed_facts", {}).get(
                    "real_crypto_verification_performed", False
                )
            )
            for verdict, auditor_input, _context in cases
        )
        add(
            checks,
            f"clean_control:{arm}",
            false_positives == 0
            and required_clean_contexts <= contexts
            and crypto_replayed,
            f"canonical_cases={n} contexts={sorted(contexts)} false_positives={false_positives} "
            f"real_crypto_replayed={crypto_replayed} Wilson95_descriptive_upper={upper:.6f}",
        )


def validate_c4_audit_cost(frames: dict[str, pd.DataFrame], checks: list[Check]) -> None:
    e4 = frames.get("e4_amortized_overhead.csv")
    e8cpp = frames.get("e8_audit_cost_cpp.csv")
    witness = frames.get("a6_witness_cost_cpp.csv")
    if e4 is not None:
        arms = set(e4.get("arm", []))
        add(checks, "C4_checkpoint_cost_arms", MAIN_ARMS <= arms, f"arms={sorted(arms)}")
    if e8cpp is not None:
        arms = set(e8cpp.get("arm", []))
        add(checks, "C4_cpp_verify_cost_arms", {"A3", "A4", "A6"} <= arms, f"arms={sorted(arms)}")
        add(
            checks,
            "C4_cpp_verify_repetitions",
            e8cpp.get("n_repetitions", pd.Series(dtype=int)).min() >= 30,
            f"min_reps={e8cpp.get('n_repetitions', pd.Series([0])).min()}",
            warn=True,
        )
    if witness is not None:
        ops = set(witness.get("operation", []))
        expected_ops = {"one_witness_receipt_sign", "all_witness_receipts_sign", "verify_witness_quorum"}
        add(checks, "C4_witness_operation_costs", expected_ops <= ops, f"ops={sorted(ops)}")


def _norm_int(value: Any) -> str:
    """Canonicalise an integer-valued cell: blanks/NaN/None -> '' , numbers -> int str."""
    try:
        if value is None:
            return ""
        if isinstance(value, float) and math.isnan(value):
            return ""
        text = str(value).strip()
        if text == "" or text.lower() == "nan":
            return ""
        return str(int(float(text)))
    except (ValueError, TypeError):
        return str(value)


def _e8_workitem_index(df: pd.DataFrame) -> dict[tuple[str, ...], dict[str, str]]:
    index: dict[tuple[str, ...], dict[str, str]] = {}
    for _, row in df.iterrows():
        key = (
            str(row["arm"]),
            _norm_int(row["N"]),
            _norm_int(row["k_disclosed"]),
            _norm_int(row.get("witness_count")),
            _norm_int(row.get("min_receipts")),
        )
        # A3 collapses distinct k iterations to identical rows; keep the first,
        # duplicates are asserted consistent by validate_experiment_coverage.
        index.setdefault(
            key,
            {
                "verify_scope": str(row.get("verify_scope")),
                "verify_signature_count": _norm_int(row.get("verify_signature_count")),
                "chain_records_replayed": _norm_int(row.get("chain_records_replayed")),
                "merkle_proofs_verified": _norm_int(row.get("merkle_proofs_verified")),
            },
        )
    return index


def validate_e8_scope_alignment(frames: dict[str, pd.DataFrame], checks: list[Check]) -> None:
    """Compare Python and C++ E8 only on cells of identical measured workload.

    The join key is ``(arm, N, k_disclosed, witness_count, min_receipts)`` so
    non-comparable cells (the C++ witness-count sweep, C++-only N) never pair with
    Python.  For the shared cells the verify scope and work-item counts that define
    the workload must match; timing and ``witness_quorum_verified`` (a differently
    defined quantity) are deliberately not compared.
    """
    py = frames.get("e8_audit_cost.csv")
    cpp = frames.get("e8_audit_cost_cpp.csv")
    if py is None or cpp is None:
        return
    required = {"arm", "N", "k_disclosed", "verify_scope"}
    if not (required <= set(py.columns) and required <= set(cpp.columns)):
        add(checks, "E8_scope_alignment", False, "missing E8 work-item columns")
        return
    py_index = _e8_workitem_index(py)
    cpp_index = _e8_workitem_index(cpp)
    shared = set(py_index) & set(cpp_index)
    compare_fields = (
        "verify_scope",
        "verify_signature_count",
        "chain_records_replayed",
        "merkle_proofs_verified",
    )
    mismatches: list[str] = []
    for key in sorted(shared):
        for field in compare_fields:
            if py_index[key][field] != cpp_index[key][field]:
                mismatches.append(f"{key}:{field}(py={py_index[key][field]},cpp={cpp_index[key][field]})")
    add(
        checks,
        "E8_scope_alignment",
        bool(shared) and not mismatches,
        f"comparable_cells={len(shared)} mismatches={mismatches[:5]}",
    )


def validate_a6_witness_consistency(
    frames: dict[str, pd.DataFrame], checks: list[Check], *, config: Mapping[str, Any] | None = None
) -> None:
    """A6 witness_count/min_receipts must be identical across E4 and E8 and equal the
    sealed protocol_config, so evidence packaging (E4) can never quietly use a
    different quorum than verification (E8)."""
    python_config = config.get("python") if isinstance(config, Mapping) else None
    if not isinstance(python_config, Mapping):
        return
    expected_wc = python_config.get("a6_witness_count")
    expected_mr = python_config.get("a6_min_receipts")
    if expected_wc is None:
        return

    def _distinct_ints(df: pd.DataFrame, column: str, arm: str) -> set[int]:
        if "arm" not in df.columns or column not in df.columns:
            return set()
        subset = df[df["arm"].astype(str) == arm]
        return {int(x) for x in pd.to_numeric(subset[column], errors="coerce").dropna().unique()}

    e4 = frames.get("e4_amortized_overhead.csv")
    if e4 is not None:
        observed = _distinct_ints(e4, "witness_count", "A6")
        add(
            checks,
            "A6_witness_E4_binds_config",
            observed == {int(expected_wc)},
            f"E4 A6 witness_count={sorted(observed)} expected={expected_wc}",
        )

    e8 = frames.get("e8_audit_cost.csv")
    if e8 is not None:
        wc = _distinct_ints(e8, "witness_count", "A6")
        mr = _distinct_ints(e8, "min_receipts", "A6")
        ok = wc == {int(expected_wc)} and (expected_mr is None or mr == {int(expected_mr)})
        add(
            checks,
            "A6_witness_E8_binds_config",
            ok,
            f"E8 A6 witness_count={sorted(wc)} min_receipts={sorted(mr)} expected wc={expected_wc} mr={expected_mr}",
        )


def validate_e8_samples(
    data_dir: Path,
    frames: dict[str, pd.DataFrame],
    checks: list[Check],
    *,
    config: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    """e8_audit_cost_samples.jsonl is REQUIRED and must be consistent with the CSV,
    the sealed config, and the package provenance.

    Verify samples: one row per E8 (arm,N,k) cell, ``len == n_samples ==
    n_repetitions``, recomputed mean/median/std/p95 matching the CSV.  Lifecycle
    samples: the exact key set must equal the canonical ``(arm,N) x {generation,
    serialization}`` (missing / extra / duplicate / unknown-operation fail), with
    ``len == n_samples == config.python.e8_lifecycle_reps``.  Every value must be
    finite and non-negative, and every row's provenance
    (run_id/timestamp_utc/mode/config_hash/seed/git_commit/dependency_hash/
    source_tree_hash/source_script) must match the sealed package context — so a
    shrunk sample count, a duplicated row, an injected Infinity, or a swapped
    provenance field all fail closed.
    """
    import math as _math
    import statistics as _stats

    path = data_dir / "e8_audit_cost_samples.jsonl"
    if not path.is_file():
        add(checks, "e8_samples_present", False, "e8_audit_cost_samples.jsonl is missing")
        return
    try:
        rows = read_jsonl(path)
    except RuntimeError as exc:
        add(checks, "e8_samples_present", False, str(exc))
        return
    add(checks, "e8_samples_present", bool(rows), f"sample rows={len(rows)}")

    e8 = frames.get("e8_audit_cost.csv")

    lifecycle_reps = None
    if isinstance(config, Mapping) and isinstance(config.get("python"), Mapping):
        lifecycle_reps = config["python"].get("e8_lifecycle_reps")

    # Expected provenance: sample rows are runner output and must carry the same
    # sealed run identity as the rest of the package (not trusted from the rows).
    expected_ctx: dict[str, str] = {}
    if isinstance(config, Mapping):
        for field in ("run_id", "timestamp_utc", "mode", "config_hash", "seed"):
            if config.get(field) is not None:
                expected_ctx[field] = str(config.get(field))
    if isinstance(metadata, Mapping):
        for field in ("git_commit", "dependency_hash", "source_tree_hash"):
            if metadata.get(field) is not None:
                expected_ctx[field] = str(metadata.get(field))
    from experiment_profiles import E8_PRODUCER_SOURCE_SCRIPT

    expected_ctx["source_script"] = E8_PRODUCER_SOURCE_SCRIPT  # fixed producer, not read back from the CSV
    if e8 is not None and "source_script" in e8.columns:
        csv_scripts = {str(v) for v in e8["source_script"].tolist()}
        add(
            checks,
            "e8_producer_bound",
            csv_scripts == {E8_PRODUCER_SOURCE_SCRIPT},
            f"e8_audit_cost source_script={sorted(csv_scripts)} expected={E8_PRODUCER_SOURCE_SCRIPT}",
        )

    known_ops = {"verify", "generation", "serialization"}
    sample_by_cell: dict[tuple[str, str, str], list[float]] = {}
    verify_dupes: list[str] = []
    lifecycle_seen: set[tuple[str, str, str]] = set()
    lifecycle_dupes: list[str] = []
    bad: list[str] = []
    prov_bad: list[str] = []
    for row in rows:
        operation = str(row.get("operation"))
        values = row.get("samples_ms") or []
        label = f"{row.get('arm')}/{row.get('N')}/{operation}"
        if operation not in known_ops:
            bad.append(f"{label}:unknown_operation")
        if row.get("n_samples") != len(values):
            bad.append(f"{label}:len!=n_samples")
        if any(
            isinstance(v, bool) or not isinstance(v, (int, float)) or not _math.isfinite(v) or v < 0
            for v in values
        ):
            bad.append(f"{label}:nonfinite_or_negative")
        for field, want in expected_ctx.items():
            if str(row.get(field)) != want:
                prov_bad.append(f"{label}:{field}")
        if operation == "verify":
            key = (str(row.get("arm")), _norm_int(row.get("N")), _norm_int(row.get("k_disclosed")))
            if key in sample_by_cell:
                verify_dupes.append("/".join(key))
            sample_by_cell[key] = [float(v) for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
        elif operation in ("generation", "serialization"):
            lkey = (str(row.get("arm")), _norm_int(row.get("N")), operation)
            if lkey in lifecycle_seen:
                lifecycle_dupes.append("/".join(lkey))
            lifecycle_seen.add(lkey)
            if lifecycle_reps is not None and len(values) != int(lifecycle_reps):
                bad.append(f"{'/'.join(lkey)}:len!=e8_lifecycle_reps({lifecycle_reps})")

    # ---- verify-sample cell map + stats vs CSV ----
    stat_bad: list[str] = []
    csv_cells: set[tuple[str, str, str]] = set()
    if e8 is not None:
        for _, r in e8.iterrows():
            key = (str(r["arm"]), _norm_int(r["N"]), _norm_int(r["k_disclosed"]))
            csv_cells.add(key)
            values = sample_by_cell.get(key)
            if values is None:
                continue
            if str(len(values)) != _norm_int(r.get("n_repetitions")):
                bad.append(f"{'/'.join(key)}:len!=n_repetitions")
            if len(values) >= 2:
                p95_index = min(len(values) - 1, max(0, _math.ceil(0.95 * len(values)) - 1))
                recomputed = {
                    "verify_ms_mean": _stats.mean(values),
                    "verify_ms_median": _stats.median(values),
                    "verify_ms_std": _stats.stdev(values),
                    "verify_ms_p95": sorted(values)[p95_index],
                }
                for column, recompute in recomputed.items():
                    try:
                        csv_value = float(r.get(column))
                    except (TypeError, ValueError):
                        csv_value = None
                    if csv_value is None or abs(csv_value - recompute) > max(1e-3, 0.01 * abs(csv_value)):
                        stat_bad.append(f"{'/'.join(key)}:{column}(csv={csv_value},recompute={round(recompute, 6)})")

    # ---- lifecycle exact key set == canonical (arm,N) x {generation, serialization} ----
    expected_arm_ns: set[tuple[str, str]] = set()
    coverage = config.get("coverage") if isinstance(config, Mapping) else None
    e8_axes = coverage.get("e8_audit_cost.csv") if isinstance(coverage, Mapping) else None
    if isinstance(e8_axes, Mapping) and e8_axes.get("arms") and e8_axes.get("N"):
        expected_arm_ns = {(str(a), _norm_int(n)) for a in e8_axes["arms"] for n in e8_axes["N"]}
    elif e8 is not None:
        expected_arm_ns = {(str(r["arm"]), _norm_int(r["N"])) for _, r in e8.iterrows()}
    expected_lifecycle = {(a, n, op) for (a, n) in expected_arm_ns for op in ("generation", "serialization")}
    missing_l = sorted(expected_lifecycle - lifecycle_seen)
    extra_l = sorted(lifecycle_seen - expected_lifecycle)

    add(
        checks,
        "e8_samples_cell_map",
        set(sample_by_cell) == csv_cells and not verify_dupes,
        f"verify_samples={len(sample_by_cell)} csv={len(csv_cells)} duplicates={verify_dupes[:3]} "
        f"missing={sorted(csv_cells - set(sample_by_cell))[:3]} extra={sorted(set(sample_by_cell) - csv_cells)[:3]}",
    )
    add(checks, "e8_samples_valid", not bad, f"bad={bad[:5]}")
    add(checks, "e8_samples_stats_match_csv", not stat_bad, f"stat_mismatches={stat_bad[:5]}")
    add(checks, "e8_samples_provenance", not prov_bad, f"mismatches={prov_bad[:5]}")
    add(
        checks,
        "e8_lifecycle_samples",
        not missing_l and not extra_l and not lifecycle_dupes,
        f"lifecycle={len(lifecycle_seen)}/{len(expected_lifecycle)} missing={missing_l[:3]} "
        f"extra={extra_l[:3]} duplicates={lifecycle_dupes[:3]} reps={lifecycle_reps}",
    )


def validate_derived_qos_coverage(data_dir: Path, checks: list[Check]) -> None:
    """Exact coverage for the ablation and transferability tables (deletion fails)."""
    try:
        from qos_experiments import FORMAL_CORPUS_ARMS, _ABLATION_DEFINITIONS
    except Exception as exc:  # pragma: no cover - defensive
        add(checks, "ablation_transferability_coverage", False, f"cannot import: {exc}")
        return

    ablation_path = data_dir / "qos_capability_ablation.csv"
    if ablation_path.is_file():
        df = read_csv(ablation_path)
        if {"ablation_dimension", "ablation_level"} <= set(df.columns):
            expected = {(str(item[0]), str(item[5])) for item in _ABLATION_DEFINITIONS}
            observed = {(str(r["ablation_dimension"]), str(r["ablation_level"])) for _, r in df.iterrows()}
            add(
                checks,
                "ablation_coverage",
                observed == expected,
                f"observed={len(observed)} expected={len(expected)} missing={sorted(expected - observed)[:3]} extra={sorted(observed - expected)[:3]}",
            )

    transfer_path = data_dir / "transferability_results.csv"
    if transfer_path.is_file():
        df = read_csv(transfer_path)
        if "arm" in df.columns:
            observed_arms = {str(r["arm"]) for _, r in df.iterrows()}
            add(
                checks,
                "transferability_arm_coverage",
                observed_arms == set(FORMAL_CORPUS_ARMS),
                f"arms={sorted(observed_arms)} required={sorted(FORMAL_CORPUS_ARMS)}",
            )
            if "transferable_attribution" in df.columns:
                a2 = df[df["arm"].astype(str) == "A2"]
                a2_ok = bool(len(a2)) and all(not parse_bool(v) for v in a2["transferable_attribution"])
                add(checks, "transferability_A2_nontransferable", a2_ok, "A2 transferable_attribution all False")


def validate_offline_security_artifacts(
    data_dir: Path,
    checks: list[Check],
    *,
    config: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    """Replay standalone evidence bundles using only registry and anchors."""
    security_dir = data_dir / "security"
    registry_path = security_dir / "trusted_registry.json"
    anchors_path = security_dir / "trusted_anchors.json"
    bundle_dir = security_dir / "bundles"
    verdict_dir = security_dir / "verdicts"
    export_path = security_dir / "security_export.json"
    a2_path = security_dir / "a2_session_mac_only.json"
    required = [registry_path, anchors_path, bundle_dir, verdict_dir, export_path, a2_path]
    missing = [str(path.relative_to(data_dir)) for path in required if not path.exists()]
    add(
        checks,
        "offline_security_artifacts",
        not missing,
        "registry, anchors, bundles, and verdicts present" if not missing else f"missing={missing}",
    )
    if missing:
        return
    try:
        export = load_json_object(export_path)
        a2_boundary = load_json_object(a2_path)
    except PackageError as exc:
        add(checks, "offline_security_metadata", False, str(exc))
        return
    provenance = export.get("provenance", {})
    expected = {
        "run_id": config.get("run_id") if config else None,
        "timestamp_utc": config.get("timestamp_utc") if config else None,
        "mode": config.get("mode") if config else None,
        "config_hash": config.get("config_hash") if config else None,
        "seed": config.get("seed") if config else None,
        "git_commit": metadata.get("git_commit") if metadata else None,
        "dependency_hash": metadata.get("dependency_hash") if metadata else None,
        "source_tree_hash": metadata.get("source_tree_hash") if metadata else None,
    }
    context_mismatches = [
        field
        for field, value in expected.items()
        if value is not None and str(provenance.get(field)) != str(value)
    ]
    add(
        checks,
        "offline_security_provenance",
        not context_mismatches,
        "security export matches package context"
        if not context_mismatches
        else f"mismatches={context_mismatches}",
    )
    a2_ok = (
        a2_boundary.get("arm_id") == "A2"
        and a2_boundary.get("audit_evidence_transferable") is False
        and a2_boundary.get("offline_verifiable_without_session_key") is False
        and a2_boundary.get("session_key_exported") is False
        and a2_boundary.get("checkpoint_count") == 0
        and a2_boundary.get("outcome") == "inconclusive"
    )
    add(
        checks,
        "offline_A2_boundary",
        a2_ok,
        "A2 exports no session key/checkpoint/transferable claim",
    )
    try:
        from aapa_mqtt import receipt_id_from_dict
        from audit_verify import AnchorSet, audit_stream, load_evidence_bundle_v2
        from trusted_registry import TrustedRegistry

        registry = TrustedRegistry.load(registry_path)
        anchors = AnchorSet.load(anchors_path)
    except Exception as exc:
        add(checks, "offline_security_trust_inputs", False, f"cannot load trust inputs: {exc}")
        return

    bundle_paths = sorted(bundle_dir.glob("*.json"))
    add(checks, "offline_security_bundle_count", bool(bundle_paths), f"bundles={len(bundle_paths)}")
    mismatches: list[str] = []
    failures: list[str] = []
    receipt_id_failures: list[str] = []
    accepted_arms: set[str] = set()
    arm_outcomes: dict[str, str] = {}
    for bundle_path in bundle_paths:
        verdict_path = verdict_dir / bundle_path.name
        if not verdict_path.is_file():
            failures.append(f"{bundle_path.name}: missing stored verdict")
            continue
        try:
            arm_id, evidence, _ = load_evidence_bundle_v2(bundle_path)
            replay = audit_stream(evidence, arm_id, registry, anchors).to_dict()
            stored = load_json_object(verdict_path)
            # Independently recompute every witness receipt_id from the canonical
            # signed body + signature + public key.  The packaged value is compared,
            # never trusted: a tampered, missing, or mismatched id fails closed.
            raw_bundle = load_json_object(bundle_path)
            for ev_index, ev_row in enumerate(raw_bundle.get("evidence", []) or []):
                for wr_index, wr in enumerate(ev_row.get("witness_receipts", []) or []):
                    stored_id = wr.get("receipt_id")
                    try:
                        recomputed_id = receipt_id_from_dict(wr)
                    except Exception as exc:
                        receipt_id_failures.append(f"{bundle_path.name}[{ev_index}][{wr_index}]: malformed ({exc})")
                        continue
                    if stored_id is None:
                        receipt_id_failures.append(f"{bundle_path.name}[{ev_index}][{wr_index}]: missing receipt_id")
                    elif str(stored_id) != recomputed_id:
                        receipt_id_failures.append(f"{bundle_path.name}[{ev_index}][{wr_index}]: receipt_id mismatch")
            projection_fields = (
                "outcome",
                "accepted",
                "reason_codes",
                "stream_id",
                "verified_checkpoints",
                "verified_records",
                "tail_complete",
                "started_from_trusted_anchor",
                "ended_at_trusted_latest",
                "limitations",
            )
            replay_projection = {field: replay.get(field) for field in projection_fields}
            stored_projection = {field: stored.get(field) for field in projection_fields}
            for projection in (replay_projection, stored_projection):
                for field in ("reason_codes", "limitations"):
                    if isinstance(projection.get(field), list):
                        projection[field] = sorted(str(item) for item in projection[field])
            if canonical_projection(replay_projection) != canonical_projection(stored_projection):
                mismatches.append(bundle_path.name)
            arm_outcomes[arm_id] = str(replay.get("outcome"))
            if replay.get("outcome") == "accept":
                accepted_arms.add(arm_id)
        except Exception as exc:
            failures.append(f"{bundle_path.name}: {exc}")
    unexpected_verdicts = sorted(
        path.name
        for path in verdict_dir.glob("*.json")
        if not (bundle_dir / path.name).is_file()
    )
    add(
        checks,
        "offline_security_replay",
        not failures and not mismatches and not unexpected_verdicts,
        f"replayed={len(bundle_paths)} failures={failures[:5]} "
        f"mismatches={mismatches[:5]} unexpected_verdicts={unexpected_verdicts[:5]}",
    )
    add(
        checks,
        "offline_receipt_id_integrity",
        not receipt_id_failures,
        "every witness receipt_id recomputes from its signed body"
        if not receipt_id_failures
        else f"failures={receipt_id_failures[:5]}",
    )
    # Per-arm authoritative verdicts re-derived from the bundles (never read from
    # the stored verdicts): clean transferable arms accept only on an exact accept;
    # A1 per-message evidence caps at inconclusive (no unique history binding).
    add(
        checks,
        "offline_transferable_clean_arms",
        {"A4", "A6"} <= accepted_arms,
        f"accepted_arms={sorted(accepted_arms)}",
    )
    present_clean_arms = {"A0", "A3", "A4", "A6"} & set(arm_outcomes)
    non_accept = sorted(arm for arm in present_clean_arms if arm_outcomes.get(arm) != "accept")
    clean_map = {arm: arm_outcomes[arm] for arm in sorted(present_clean_arms)}
    add(
        checks,
        "offline_clean_arms_accept",
        not non_accept,
        f"arm_outcomes={clean_map} non_accept={non_accept}",
    )
    if "A1" in arm_outcomes:
        add(
            checks,
            "offline_A1_inconclusive",
            arm_outcomes.get("A1") == "inconclusive",
            f"A1_outcome={arm_outcomes.get('A1')}",
        )


def validate_a6_failure_grid(frames: dict[str, pd.DataFrame], checks: list[Check]) -> None:
    df = frames.get("a6_failure_grid_cpp.csv")
    if df is None:
        return
    cases = set(df.get("case", []))
    add(checks, "A6_failure_cases", A6_FAILURE_CASES <= cases, f"cases={sorted(cases)}")


def validate_architecture_boundary(frames: dict[str, pd.DataFrame], checks: list[Check]) -> None:
    df = frames.get("e10_architecture_boundary.csv")
    if df is None:
        return

    required_columns = {
        "path_id",
        "path_name",
        "layer",
        "quantum_resistance_scope",
        "payload_hidden_from_broker",
        "transferable_offline_evidence",
        "broker_mutation_detection",
        "broker_mutation_attribution",
        "qos_bounded_attribution",
        "audit_verifier_online_dependency",
        "measured_in_this_work",
        "paper_role",
        "claim_boundary",
    }
    missing = required_columns - set(df.columns)
    add(
        checks,
        "E10_required_columns",
        not missing,
        "has architecture-boundary fields" if not missing else f"missing={sorted(missing)}",
    )
    if missing:
        return

    path_ids = set(df["path_id"].astype(str))
    add(
        checks,
        "E10_path_coverage",
        ARCHITECTURE_BOUNDARY_PATHS == path_ids,
        f"path_ids={sorted(path_ids)}",
    )

    evidence = bool_column(df, "transferable_offline_evidence")
    qos = bool_column(df, "qos_bounded_attribution")
    measured = bool_column(df, "measured_in_this_work")
    hidden = bool_column(df, "payload_hidden_from_broker")

    audit_ids = {"A4_MERKLE_CHECKPOINT", "A6_WITNESSED_MERKLE_CHECKPOINT"}
    audit_mask = df["path_id"].isin(audit_ids)
    non_audit_mask = ~audit_mask
    add(
        checks,
        "E10_transferable_evidence_scope",
        evidence[audit_mask].all() and not evidence[non_audit_mask].any(),
        "only A4/A6 are marked as transferable offline evidence",
    )
    add(
        checks,
        "E10_qos_bounded_scope",
        qos[audit_mask].all() and not qos[non_audit_mask].any(),
        "only audit-evidence paths are marked QoS-bounded",
    )
    e2e_hidden = hidden[df["path_id"].eq("PQ_E2E_PAYLOAD_ENCRYPTION")]
    e2e_hidden_ok = bool(e2e_hidden.iloc[0]) if not e2e_hidden.empty else False
    add(
        checks,
        "E10_payload_confidentiality_separated",
        e2e_hidden_ok and not hidden[audit_mask].any(),
        "payload E2E is separated from audit evidence rows",
    )
    measured_ids = set(df.loc[measured, "path_id"].astype(str))
    add(
        checks,
        "E10_measured_path_scope",
        {"A2_SESSION_MAC_ONLY", "A4_MERKLE_CHECKPOINT", "A6_WITNESSED_MERKLE_CHECKPOINT"} <= measured_ids,
        f"measured_path_ids={sorted(measured_ids)}",
    )
    role_ok = df["paper_role"].astype(str).str.len().min() > 0
    boundary_ok = df["claim_boundary"].astype(str).str.len().min() > 0
    add(checks, "E10_claim_map_text", role_ok and boundary_ok, "paper_role and claim_boundary populated")


def validate_throughput_interpretation(frames: dict[str, pd.DataFrame], checks: list[Check]) -> None:
    df = frames.get("e6_throughput.csv")
    if df is None or "delivery_ratio_mean" not in df.columns:
        return
    min_ratio = float(df["delivery_ratio_mean"].min())
    if min_ratio < 0.95:
        add(
            checks,
            "E6_delivery_ratio_guardrail",
            False,
            f"min_delivery_ratio={min_ratio:.4f}; report publisher and subscriber rates separately",
            warn=True,
        )
    else:
        add(checks, "E6_delivery_ratio_guardrail", True, f"min_delivery_ratio={min_ratio:.4f}")


def write_reports(
    report_dir: Path,
    checks: list[Check],
    *,
    mode: str,
    config: Mapping[str, Any] | None,
) -> str:
    failed = [c for c in checks if c.status == "FAIL"]
    warned = [c for c in checks if c.status == "WARN"]
    overall = "FAIL" if failed else ("WARN" if warned else "PASS")

    report = {
        "schema": "aapa-independent-quality-report-v2",
        "mode": mode,
        "run_id": config.get("run_id") if config else None,
        "timestamp_utc": config.get("timestamp_utc") if config else None,
        "config_hash": config.get("config_hash") if config else None,
        "validator_sha256": sha256_file(Path(__file__).resolve()),
        "overall_status": overall,
        "checks": [asdict(c) for c in checks],
    }
    report_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_json(report_dir / "quality_report.json", report)

    lines = [
        "# Stage 4 Result Package Quality Report",
        "",
        f"Overall status: **{overall}**",
        "",
        "| Check | Status | Detail |",
        "|---|---:|---|",
    ]
    for c in checks:
        lines.append(f"| {c.name} | {c.status} | {c.detail} |")
    (report_dir / "quality_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return overall


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--mode", choices=["quick", "full"], default="full")
    parser.add_argument(
        "--pre-finalize",
        action="store_true",
        help="Validate an in-progress package before its completion manifest is written",
    )
    parser.add_argument(
        "--report-dir",
        default=None,
        help="Optional report destination; completed packages are read-only",
    )
    args = parser.parse_args()

    data_dir = Path(args.data_dir).resolve()
    if not data_dir.exists():
        raise SystemExit(f"data directory does not exist: {data_dir}")

    report_dir = Path(args.report_dir).resolve() if args.report_dir else None
    manifest_path = data_dir / MANIFEST_NAME
    if args.pre_finalize:
        if manifest_path.exists() or manifest_path.is_symlink():
            raise SystemExit("--pre-finalize cannot validate an already completed package")
        if report_dir is None:
            raise SystemExit("--pre-finalize requires --report-dir")
    elif report_dir is not None:
        try:
            report_dir.relative_to(data_dir)
        except ValueError:
            pass
        else:
            raise SystemExit("completed result packages are immutable; write replay reports outside --data-dir")

    checks: list[Check] = []
    if args.pre_finalize:
        add(checks, "completion_state", True, "pre-finalize validation; completion manifest absent")
    else:
        integrity_issues = validate_completion_manifest(data_dir)
        add(
            checks,
            "completion_manifest_integrity",
            not integrity_issues,
            "strict file set, sizes, and hashes valid"
            if not integrity_issues
            else "; ".join(f"{x.code}:{x.detail}" for x in integrity_issues[:20]),
        )
    config = validate_protocol_config(data_dir, args.mode, checks)
    metadata = validate_package_metadata(data_dir, config, args.mode, checks)
    validate_preflight_report(data_dir, args.mode, config, metadata, checks)
    frames = validate_counts(data_dir, args.mode, checks)
    validate_provenance(frames, args.mode, config, metadata, checks)
    validate_protocol_intensity(frames, args.mode, checks, config=config)
    validate_experiment_coverage(frames, checks, config=config)
    validate_coverage_canonical(config, args.mode, checks)
    validate_profile_canonical(config, args.mode, checks)
    validate_e8_samples(data_dir, frames, checks, config=config, metadata=metadata)
    validate_derived_qos_coverage(data_dir, checks)
    validate_qos_corpus(data_dir, args.mode, checks, config=config, metadata=metadata)
    validate_e7_e11_summary(data_dir, checks)
    validate_offline_security_artifacts(data_dir, checks, config=config, metadata=metadata)
    validate_c4_audit_cost(frames, checks)
    validate_e8_scope_alignment(frames, checks)
    validate_a6_witness_consistency(frames, checks, config=config)
    validate_a6_failure_grid(frames, checks)
    validate_architecture_boundary(frames, checks)
    validate_throughput_interpretation(frames, checks)
    if report_dir is not None:
        overall = write_reports(report_dir, checks, mode=args.mode, config=config)
        print(f"quality report: {overall} -> {report_dir / 'quality_report.md'}")
    else:
        failed = sum(check.status == "FAIL" for check in checks)
        warned = sum(check.status == "WARN" for check in checks)
        overall = "FAIL" if failed else ("WARN" if warned else "PASS")
        print(
            f"independent validation: {overall}; checks={len(checks)} "
            f"failed={failed} warned={warned} (read-only)"
        )
        for check in checks:
            if check.status != "PASS":
                print(f"  {check.status} {check.name}: {check.detail}")
    return 1 if overall == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
