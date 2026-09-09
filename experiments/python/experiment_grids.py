#!/usr/bin/env python3
"""Authoritative experiment coverage grids and the deterministic E7 corpus contract.

Single source of truth for which cells each cost/throughput experiment must
produce.  The Stage 4 runner seals ``axes_for(mode)`` and ``E7_CORPUS_CONTRACT``
into ``protocol_config.json`` (so they are config-hash bound), and the independent
validator expands the SEALED axes into the exact expected cell set and compares it
to the observed CSV cells.  Because the expected set is derived from the sealed
axes — not from the observed rows — deleting an entire arm, an axis value, or a
single cell fails validation.

The known structural collapses are encoded here so the sealed expectation matches
the runner byte-for-byte:
  * E5 latency: A1/A2 keep a single checkpoint, so every N collapses to eff_N=1.
  * E8 audit cost: A3 discloses the full chain, so k_disclosed == N for A3.
"""

from __future__ import annotations

import math
from typing import Any, Mapping


# The QoS failure/ambiguity corpus (E7/E11) is a DETERMINISTIC capability matrix:
# one case per scenario x context x arm.  These are the real, mode-independent
# generation parameters; the retired protocol_config values (50 repetitions /
# 300 records / N=50) were never executed by run_optimized._run_qos_suite_once.
E7_CORPUS_CONTRACT = {
    "repetitions": 1,
    "n_records": 8,
    "checkpoint_interval": 4,
    "note": "deterministic capability matrix; one case per scenario x context x arm",
}


GRID_AXES: dict[str, dict[str, dict[str, list[Any]]]] = {
    "quick": {
        "e3_online_overhead.csv": {"arms": ["A0", "A4", "A6"], "qos": [0], "payload_bytes": [32, 128, 512]},
        "e5_latency.csv": {"arms": ["A0", "A4", "A6"], "N": [10], "payload_bytes": [128], "qos": [0]},
        "e6_throughput.csv": {"arms": ["A0", "A4", "A6"], "payload_bytes": [128], "qos": [0]},
        "e8_audit_cost.csv": {"arms": ["A3", "A4", "A6"], "N": [10, 100], "k": [1, 10]},
        "e9_storage.csv": {"arms": ["A0", "A1", "A4", "A6"], "N": [10, 100], "freq": [10]},
        "e4_amortized_overhead.csv": {"arms": ["A0", "A1", "A2", "A3", "A4", "A6"], "N": [1, 10, 50, 100, 500, 1000]},
        "e8_audit_cost_cpp.csv": {"arms": ["A3", "A4", "A6"], "N": [10, 100], "k": [1, 10], "witness_counts": [1, 3]},
        "e4_amortized_overhead_cpp.csv": {"arms": ["A1", "A2", "A3", "A4", "A6"], "N": [10, 100], "witness_counts": [1, 3]},
        "a6_witness_cost_cpp.csv": {"N": [100], "witness_counts": [1, 3]},
    },
    "full": {
        "e3_online_overhead.csv": {"arms": ["A0", "A1", "A2", "A3", "A4", "A6"], "qos": [0, 1, 2], "payload_bytes": [32, 64, 128, 512, 1024]},
        "e5_latency.csv": {"arms": ["A0", "A2", "A3", "A4", "A6"], "N": [10, 100], "payload_bytes": [32, 128, 512], "qos": [0, 1, 2]},
        "e6_throughput.csv": {"arms": ["A0", "A2", "A3", "A4", "A6"], "payload_bytes": [32, 128, 512], "qos": [0]},
        "e8_audit_cost.csv": {"arms": ["A3", "A4", "A6"], "N": [10, 50, 100, 500, 1000], "k": [1, 5, 10, 50, 100]},
        "e9_storage.csv": {"arms": ["A0", "A1", "A2", "A3", "A4", "A6"], "N": [10, 50, 100, 500, 1000], "freq": [1, 10, 100]},
        "e4_amortized_overhead.csv": {"arms": ["A0", "A1", "A2", "A3", "A4", "A6"], "N": [1, 10, 50, 100, 500, 1000]},
        "e8_audit_cost_cpp.csv": {"arms": ["A3", "A4", "A6"], "N": [1, 10, 50, 100, 500, 1000], "k": [1, 5, 10, 50, 100], "witness_counts": [1, 3, 5, 7]},
        "e4_amortized_overhead_cpp.csv": {"arms": ["A1", "A2", "A3", "A4", "A6"], "N": [1, 10, 50, 100, 500, 1000], "witness_counts": [1, 3, 5, 7]},
        "a6_witness_cost_cpp.csv": {"N": [500], "witness_counts": [1, 3, 5, 7]},
    },
}

_WITNESS_OPERATIONS = ("one_witness_receipt_sign", "all_witness_receipts_sign", "verify_witness_quorum")

# Column names that identify one cell in each experiment's CSV.
CELL_KEY_COLUMNS = {
    "e3_online_overhead.csv": ["arm", "qos", "payload_bytes"],
    "e5_latency.csv": ["arm", "N", "payload_bytes", "qos"],
    "e6_throughput.csv": ["arm", "payload_bytes", "qos"],
    "e8_audit_cost.csv": ["arm", "N", "k_disclosed"],
    "e9_storage.csv": ["arm", "N", "freq"],
    "e4_amortized_overhead.csv": ["arm", "N"],
    "e8_audit_cost_cpp.csv": ["arm", "N", "k_disclosed", "witness_count", "min_receipts"],
    "e4_amortized_overhead_cpp.csv": ["arm", "N", "witness_count", "effective_N"],
    "a6_witness_cost_cpp.csv": ["operation", "N", "witness_count", "min_receipts"],
}


def _majority(witness_count: int) -> int:
    return witness_count // 2 + 1


def axes_for(mode: str) -> dict[str, dict[str, list[Any]]]:
    if mode not in GRID_AXES:
        raise ValueError(f"unknown mode: {mode}")
    return GRID_AXES[mode]


def _norm(value: Any) -> str:
    """Canonicalise a cell coordinate to a stable string (ints without .0; NaN/None/'' -> '')."""
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    try:
        return str(int(value))
    except (TypeError, ValueError):
        text = str(value).strip()
        return "" if text.lower() in ("", "nan", "none") else text


def expand_cells(experiment: str, axes: Mapping[str, Any]) -> set[tuple[str, ...]]:
    """Expand sealed axes into the exact expected cell-key set (string-normalised)."""
    if experiment == "e3_online_overhead.csv":
        return {
            (_norm(a), _norm(q), _norm(p))
            for a in axes["arms"] for q in axes["qos"] for p in axes["payload_bytes"]
        }
    if experiment == "e6_throughput.csv":
        return {
            (_norm(a), _norm(p), _norm(q))
            for a in axes["arms"] for p in axes["payload_bytes"] for q in axes["qos"]
        }
    if experiment == "e5_latency.csv":
        cells: set[tuple[str, ...]] = set()
        for arm in axes["arms"]:
            for n in axes["N"]:
                eff = 1 if arm in ("A1", "A2") else n
                for p in axes["payload_bytes"]:
                    for q in axes["qos"]:
                        cells.add((_norm(arm), _norm(eff), _norm(p), _norm(q)))
        return cells
    if experiment == "e8_audit_cost.csv":
        cells = set()
        for arm in axes["arms"]:
            for n in axes["N"]:
                for k in axes["k"]:
                    if k > n:
                        continue
                    k_disclosed = n if arm == "A3" else k
                    cells.add((_norm(arm), _norm(n), _norm(k_disclosed)))
        return cells
    if experiment == "e9_storage.csv":
        return {
            (_norm(a), _norm(n), _norm(f))
            for a in axes["arms"] for n in axes["N"] for f in axes["freq"]
        }
    if experiment == "e4_amortized_overhead.csv":
        cells = set()
        for arm in axes["arms"]:
            arm_ns = [1] if arm in ("A1", "A2") else axes["N"]
            for n in arm_ns:
                cells.add((_norm(arm), _norm(n)))
        return cells
    if experiment == "e4_amortized_overhead_cpp.csv":
        # C++ E4: A1/A2/A3/A4 have witness_count=0; A6 fans out over witness_counts.
        # A1/A2 collapse to a single checkpoint (effective_N=1); others use effective_N=N.
        cells = set()
        for arm in axes["arms"]:
            eff_one = arm in ("A1", "A2")
            witnesses = axes["witness_counts"] if arm == "A6" else [0]
            for n in axes["N"]:
                eff = 1 if eff_one else n
                for wc in witnesses:
                    cells.add((_norm(arm), _norm(n), _norm(wc), _norm(eff)))
        return cells
    if experiment == "e8_audit_cost_cpp.csv":
        cells = set()
        for n in axes["N"]:
            # A3 discloses the full chain: one unique work-cell per N.
            cells.add(("A3", _norm(n), _norm(n), "", ""))
            for k in axes["k"]:
                if k > n:
                    continue
                cells.add(("A4", _norm(n), _norm(k), "", ""))
                for wc in axes["witness_counts"]:
                    cells.add(("A6", _norm(n), _norm(k), _norm(wc), _norm(_majority(wc))))
        return cells
    if experiment == "a6_witness_cost_cpp.csv":
        cells = set()
        for n in axes["N"]:
            for wc in axes["witness_counts"]:
                for operation in _WITNESS_OPERATIONS:
                    if operation == "all_witness_receipts_sign":
                        mr = wc
                    elif operation == "verify_witness_quorum":
                        mr = _majority(wc)
                    else:  # one_witness_receipt_sign
                        mr = 1
                    cells.add((operation, _norm(n), _norm(wc), _norm(mr)))
        return cells
    raise ValueError(f"unknown experiment grid: {experiment}")


def observed_cells(experiment: str, rows: list[Mapping[str, Any]]) -> list[tuple[str, ...]]:
    """Read observed cell keys from CSV rows using the experiment's key columns."""
    key_cols = CELL_KEY_COLUMNS[experiment]
    return [tuple(_norm(row.get(col)) for col in key_cols) for row in rows]
