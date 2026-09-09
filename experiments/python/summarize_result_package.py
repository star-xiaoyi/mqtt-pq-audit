#!/usr/bin/env python3
"""Auto-generate the six experiment summaries and a statistical-QA report.

Every summary value is derived from the raw rows/cases in a result package — no
hand-filled expected values.  Deterministic capability matrices (the corpus runs
one case per ``scenario x context x arm``) are reported as matrices without
fabricated confidence intervals, and the QoS false-positive rate is exact
oracle-compliant-negative counts (no Wilson interval).  E8 timing persists raw
per-repetition samples (verify + generation + serialization), so p99 and a
fixed-seed bootstrap 95% CI are derived from them rather than invented.  A
statistical methodology checklist (data-verified items plus documented
methodology statements — not an automated fallacy scanner) is recorded.

Output is written OUTSIDE the sealed package (default ``<data-dir>-summary``) so
the completion manifest stays valid.

Usage:
    python summarize_result_package.py --data-dir <quick-or-full-package> \
        [--out-dir <dir>]
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping


SUMMARY_SCHEMA_VERSION = "aapa-result-summary-v1"

PROVENANCE_KEYS = {
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
    "experiment_config_hash",
    "experiment_dependency_hash",
    "experiment_seed",
}


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}


def to_float(value: Any) -> float | None:
    try:
        text = str(value).strip()
        if text == "" or text.lower() == "nan":
            return None
        return float(text)
    except (TypeError, ValueError):
        return None


def wilson_interval(successes: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Two-sided Wilson score interval for a binomial proportion."""
    if n <= 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1.0 + z * z / n
    centre = p + z * z / (2.0 * n)
    radius = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * n)) / n)
    low = (centre - radius) / denom
    high = (centre + radius) / denom
    return (round(max(0.0, low), 6), round(min(1.0, high), 6))


def _strip_provenance(row: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in PROVENANCE_KEYS}


# ── Summary 1: capability boundary (deterministic C1 matrix, derived from replay) ──
def summarize_capability_boundary(data_dir: Path) -> dict[str, Any]:
    # Derived from ground_truth + INDEPENDENTLY replayed auditor results, NOT the
    # runner-authored e7 CSV.  The validator separately asserts the CSV equals this
    # derivation, so a tampered detection_rate/attribution cannot pass and this table
    # never depends on the untrusted CSV.
    from evidence_auditor import audit_evidence
    from qos_experiments import _summarise_e7

    ground_truth = {row["case_id"]: row for row in read_jsonl(data_dir / "ground_truth.jsonl")}
    inputs = {row["case_id"]: row for row in read_jsonl(data_dir / "auditor_inputs.jsonl")}
    trace_by_case = {row["case_id"]: row for row in read_jsonl(data_dir / "trace_corpus.jsonl")}

    joined: list[dict[str, Any]] = []
    for case_id, auditor_input in sorted(inputs.items()):
        truth = ground_truth.get(case_id)
        trace = trace_by_case.get(case_id)
        if truth is None or trace is None:
            continue
        joined.append({
            "arm": auditor_input["arm"],
            "scenario": truth["scenario"],
            "scenario_class": truth["scenario_class"],
            "context_id": trace["qos_context"]["context_id"],
            "context": trace["qos_context"],
            "truth": truth,
            "auditor_input": auditor_input,
            "aware": audit_evidence(auditor_input, qos_aware=True),
            "agnostic": audit_evidence(auditor_input, qos_aware=False),
        })
    derived_rows = _summarise_e7(joined, metadata={})
    fields = (
        "arm", "scenario", "scenario_class", "context_id", "publisher_qos",
        "subscription_requested_qos", "effective_qos", "semantic_status",
        "evidence_integrity_violation", "detection_rate", "inconclusive_rate",
        "majority_attribution", "attribution_rate", "attribution_correct_rate",
        "false_positive_rate", "false_negative_rate", "n_repetitions",
    )
    matrix = [{f: row.get(f) for f in fields} for row in derived_rows]
    deterministic = all(int(row.get("n_repetitions", 1)) == 1 for row in derived_rows)
    return {
        "source_file": "ground_truth.jsonl + replayed auditor results (NOT e7_qos_auditability.csv)",
        "traceable_by": ["arm", "scenario", "context_id"],
        "cell_count": len(matrix),
        "statistical_treatment": (
            "deterministic capability matrix (n_repetitions=1) derived from an independent "
            "auditor replay; reported as a matrix with no confidence interval"
            if deterministic
            else "n_repetitions>1; per-cell rates over repetitions"
        ),
        "deterministic": deterministic,
        "rows": matrix,
    }


# ── Summary 2: capability ablation (deterministic) ───────────────────────────
def summarize_ablation(data_dir: Path) -> dict[str, Any]:
    rows = read_csv_rows(data_dir / "qos_capability_ablation.csv")
    fields = (
        "ablation_dimension", "ablation_level", "arm", "context_id",
        "decision", "detected", "attribution", "inconclusive",
        "selective_proof_supported", "auditor_mode", "case_id",
    )
    return {
        "source_file": "qos_capability_ablation.csv",
        "traceable_by": ["ablation_dimension", "ablation_level", "arm", "case_id"],
        "cell_count": len(rows),
        "statistical_treatment": "deterministic ablation matrix; no confidence interval",
        "rows": [{f: row.get(f) for f in fields} for row in rows],
    }


# ── Summary 3: offline transferability (deterministic) ───────────────────────
def summarize_transferability(data_dir: Path) -> dict[str, Any]:
    rows = read_csv_rows(data_dir / "transferability_results.csv")
    fields = (
        "arm", "mechanism", "offline_verifiable", "transferable_attribution",
        "decision", "attribution", "capability_statement", "case_id",
    )
    a2 = [row for row in rows if row.get("arm") == "A2"]
    a2_nontransferable = all(not parse_bool(row.get("transferable_attribution")) for row in a2)
    return {
        "source_file": "transferability_results.csv",
        "traceable_by": ["arm", "case_id"],
        "cell_count": len(rows),
        "a2_present": bool(a2),
        "a2_nontransferable": a2_nontransferable,
        "statistical_treatment": "deterministic per-arm capability; no confidence interval",
        "rows": [{f: row.get(f) for f in fields} for row in rows],
    }


# ── Summary 4: attack/benign controls (oracle-defined FP, exact counts) ──────
def summarize_attack_benign(data_dir: Path) -> dict[str, Any]:
    ground_truth = {row["case_id"]: row for row in read_jsonl(data_dir / "ground_truth.jsonl")}
    arm_by_case = {row["case_id"]: str(row.get("arm")) for row in read_jsonl(data_dir / "auditor_inputs.jsonl")}
    results = read_jsonl(data_dir / "auditor_results.jsonl")

    def is_oracle_compliant_negative(case_id: str) -> bool:
        truth = ground_truth.get(case_id, {})
        # A true negative is a case the ORACLE judged compliant with no
        # evidence-integrity violation — NOT merely a benign-class generator label
        # (benign scenarios can still contain oracle-detected violations/ambiguity).
        return (
            str(truth.get("semantic_status")) == "compliant"
            and not parse_bool(truth.get("evidence_integrity_violation"))
        )

    denominators = {
        # Primary: oracle-compliant negatives, A2 excluded (structurally
        # non-transferable, so it can never yield a transferable false positive).
        "oracle_compliant_negatives_excl_A2":
            lambda cid: is_oracle_compliant_negative(cid) and arm_by_case.get(cid) != "A2",
        "oracle_compliant_negatives_all_arms":
            lambda cid: is_oracle_compliant_negative(cid),
        "oracle_compliant_negatives_benign_class":
            lambda cid: is_oracle_compliant_negative(cid)
            and str(ground_truth.get(cid, {}).get("scenario_class")) == "benign_control",
        "oracle_compliant_negatives_benign_class_excl_A2":
            lambda cid: is_oracle_compliant_negative(cid)
            and str(ground_truth.get(cid, {}).get("scenario_class")) == "benign_control"
            and arm_by_case.get(cid) != "A2",
    }

    rows: list[dict[str, Any]] = []
    for label, keep in denominators.items():
        eligible = {cid for cid in ground_truth if keep(cid)}
        mode_fp: dict[str, int] = {}
        for mode in ("qos_aware", "qos_agnostic"):
            n = len(eligible)
            fp = sum(
                1 for row in results
                if row.get("auditor_mode") == mode
                and row.get("case_id") in eligible
                and parse_bool(row.get("detected"))
            )
            mode_fp[mode] = fp
            rows.append({
                "denominator": label,
                "auditor_mode": mode,
                "n_cases": n,
                "false_positive_cases": fp,
                "false_positive_fraction": f"{fp}/{n}",
            })
        # Paired difference over the SAME eligible cases (deterministic; exact).
        rows.append({
            "denominator": label,
            "auditor_mode": "paired_agnostic_minus_aware",
            "n_cases": len(eligible),
            "false_positive_cases": mode_fp["qos_agnostic"] - mode_fp["qos_aware"],
            "false_positive_fraction": f"agnostic-aware={mode_fp['qos_agnostic'] - mode_fp['qos_aware']}",
        })
    return {
        "source_file": "ground_truth.jsonl + auditor_results.jsonl + auditor_inputs.jsonl",
        "traceable_by": ["case_id", "auditor_mode"],
        "primary_denominator": "oracle_compliant_negatives_excl_A2",
        "false_positive_predicate": (
            "auditor detected on a case the ORACLE judged semantic_status=compliant with "
            "no evidence-integrity violation (not the generator's benign-class label)"
        ),
        "statistical_treatment": (
            "deterministic design units: exact false-positive counts and paired "
            "(agnostic-aware) differences over identical cases; NO confidence intervals"
        ),
        "rows": rows,
    }


# ── Summary 5: role-scoped attribution accounting ──────────────────────────
def summarize_attribution_scope(data_dir: Path) -> dict[str, Any]:
    """Cross-check presenter-scoped labels against delivery responsibility.

    The sealed auditor schema stores only the principal string ``broker``.  In
    the evaluated verifier, every nonempty label is produced by the HistMan
    branch and is therefore presenter-scoped.  The independently authenticated
    NoLinkFail premise required by Lambda_B+ is not instantiated, so the
    verifier emits no delivery-scoped actor claim.  Equality with the oracle's
    protocol_responsible_party is reported only as a post-hoc evaluation
    cross-check, never as a verifier output.
    """

    ground_truth = {
        row["case_id"]: row for row in read_jsonl(data_dir / "ground_truth.jsonl")
    }
    aware_results = [
        row for row in read_jsonl(data_dir / "auditor_results.jsonl")
        if row.get("auditor_mode") == "qos_aware"
    ]
    results_by_case = {row["case_id"]: row for row in aware_results}

    rows: list[dict[str, Any]] = []
    partitions = sorted({
        (
            str(truth.get("semantic_status")),
            parse_bool(truth.get("evidence_integrity_violation")),
        )
        for truth in ground_truth.values()
    })
    for semantic_status, evidence_violation in partitions:
        case_ids = {
            case_id for case_id, truth in ground_truth.items()
            if str(truth.get("semantic_status")) == semantic_status
            and parse_bool(truth.get("evidence_integrity_violation")) == evidence_violation
        }
        broker_labels = [
            results_by_case[case_id]
            for case_id in sorted(case_ids)
            if case_id in results_by_case
            and results_by_case[case_id].get("attribution") == "broker"
        ]
        delivery_matches = sum(
            1 for result in broker_labels
            if ground_truth[result["case_id"]].get("protocol_responsible_party") == "broker"
        )
        rows.append({
            "semantic_status": semantic_status,
            "evidence_integrity_violation": evidence_violation,
            "n_cases": len(case_ids),
            "presenter_scope_labels": len(broker_labels),
            "verifier_delivery_scope_labels": 0,
            "delivery_responsibility_matches": delivery_matches,
            "delivery_responsibility_nonmatches": len(broker_labels) - delivery_matches,
        })

    total_labels = sum(int(row["presenter_scope_labels"]) for row in rows)
    total_matches = sum(int(row["delivery_responsibility_matches"]) for row in rows)
    rows.append({
        "semantic_status": "TOTAL",
        "evidence_integrity_violation": "",
        "n_cases": len(ground_truth),
        "presenter_scope_labels": total_labels,
        "verifier_delivery_scope_labels": 0,
        "delivery_responsibility_matches": total_matches,
        "delivery_responsibility_nonmatches": total_labels - total_matches,
    })
    return {
        "source_file": "ground_truth.jsonl + auditor_results.jsonl (qos_aware)",
        "traceable_by": ["case_id", "semantic_status", "evidence_integrity_violation"],
        "scope_contract": (
            "all nonempty labels are (broker,presenter); Lambda_B+ is not instantiated, "
            "so the verifier emits zero delivery-scoped actor claims"
        ),
        "evaluation_crosscheck": (
            "delivery_responsibility_matches compares presenter-scoped labels with the "
            "oracle protocol_responsible_party after the fact; it is not verifier output"
        ),
        "rows": rows,
    }


# ── Summary 6: full-lifecycle cost (C3: online, verify, witness, storage) ────
def _percentile(sorted_values: list[float], pct: float) -> float | None:
    if not sorted_values:
        return None
    index = min(len(sorted_values) - 1, max(0, math.ceil(pct / 100.0 * len(sorted_values)) - 1))
    return round(sorted_values[index], 6)


def _bootstrap_ci(samples: list[float], *, seed: int = 20260710, iterations: int = 2000) -> tuple[float | None, float | None]:
    """Fixed-seed bootstrap 95% CI of the mean (skew-robust); reproducible."""
    import random

    if len(samples) < 2:
        return (None, None)
    rng = random.Random(seed)
    n = len(samples)
    means: list[float] = []
    for _ in range(iterations):
        resample = [samples[rng.randrange(n)] for _ in range(n)]
        means.append(sum(resample) / n)
    means.sort()
    low = means[int(0.025 * iterations)]
    high = means[min(iterations - 1, int(0.975 * iterations))]
    return (round(low, 6), round(high, 6))


def _select(rows: list[dict[str, str]], columns: tuple[str, ...]) -> list[dict[str, Any]]:
    return [{col: row.get(col) for col in columns} for row in rows]


def summarize_lifecycle_cost(data_dir: Path) -> dict[str, Any]:
    stages: dict[str, Any] = {}
    notes: list[str] = []

    # Verification cost (E8) — with raw per-repetition samples for p99 + bootstrap.
    verify_samples: dict[tuple[str, str, str], list[float]] = {}
    lifecycle_samples: dict[tuple[str, str, str], list[float]] = {}
    samples_path = data_dir / "e8_audit_cost_samples.jsonl"
    if samples_path.is_file():
        for row in read_jsonl(samples_path):
            operation = str(row.get("operation"))
            values = [v for v in (to_float(x) for x in row.get("samples_ms", [])) if v is not None]
            if operation == "verify":
                verify_samples[(str(row.get("arm")), str(row.get("N")), str(row.get("k_disclosed")))] = values
            else:
                lifecycle_samples[(str(row.get("arm")), str(row.get("N")), operation)] = values
        notes.append("raw per-repetition samples persisted (verify + generation + serialization) -> p99 and fixed-seed bootstrap CI derived")
    else:
        notes.append("e8_audit_cost_samples.jsonl absent -> p99/bootstrap marked not-derivable")

    verify_rows: list[dict[str, Any]] = []
    for row in read_csv_rows(data_dir / "e8_audit_cost.csv"):
        key = (str(row.get("arm")), str(row.get("N")), str(row.get("k_disclosed")))
        samples = sorted(verify_samples.get(key, []))
        n = to_float(row.get("n_repetitions"))
        boot_low, boot_high = _bootstrap_ci(samples) if samples else (None, None)
        verify_rows.append({
            "arm": row.get("arm"), "N": row.get("N"), "k_disclosed": row.get("k_disclosed"),
            "verify_scope": row.get("verify_scope"),
            "witness_count": row.get("witness_count"), "min_receipts": row.get("min_receipts"),
            "n": n, "success": n, "failure": 0.0 if n is not None else None,
            "raw_samples": len(samples),
            "verify_ms_mean": to_float(row.get("verify_ms_mean")),
            "verify_ms_median": to_float(row.get("verify_ms_median")),
            "verify_ms_std": to_float(row.get("verify_ms_std")),
            "verify_ms_p95": to_float(row.get("verify_ms_p95")),
            "verify_ms_p99": _percentile(samples, 99),
            "parametric_ci95_low": to_float(row.get("ci95_low")),
            "parametric_ci95_high": to_float(row.get("ci95_high")),
            "bootstrap_ci95_low": boot_low,
            "bootstrap_ci95_high": boot_high,
            "lifecycle_generation_ms": to_float(row.get("lifecycle_generation_ms")),
            "full_evidence_bytes": to_float(row.get("full_evidence_bytes")),
            "proof_bytes": to_float(row.get("proof_bytes")),
        })
    stages["offline_verification"] = {
        "source_file": "e8_audit_cost.csv + e8_audit_cost_samples.jsonl",
        "traceable_by": ["arm", "N", "k_disclosed", "witness_count", "min_receipts"],
        "note": "verification timing excludes generation/signing/proof construction (kept as lifecycle_generation_ms)",
        "rows": verify_rows,
    }

    # Generation (create + sign) and evidence-serialization lifecycle timing, raw-sampled.
    lifecycle_rows: list[dict[str, Any]] = []
    for (arm, n_value, operation), samples in sorted(lifecycle_samples.items()):
        ordered = sorted(samples)
        boot_low, boot_high = _bootstrap_ci(ordered) if ordered else (None, None)
        lifecycle_rows.append({
            "arm": arm, "N": n_value, "operation": operation, "n": len(ordered),
            "mean_ms": round(sum(ordered) / len(ordered), 6) if ordered else None,
            "median_ms": _percentile(ordered, 50), "p95_ms": _percentile(ordered, 95),
            "p99_ms": _percentile(ordered, 99),
            "bootstrap_ci95_low": boot_low, "bootstrap_ci95_high": boot_high,
        })
    if lifecycle_rows:
        stages["generation_and_serialization"] = {
            "source_file": "e8_audit_cost_samples.jsonl (operation=generation/serialization)",
            "traceable_by": ["arm", "N", "operation"],
            "note": "raw-sampled generation (create+sign) and evidence serialization; p99/bootstrap derived from samples",
            "rows": lifecycle_rows,
        }

    def _stage(filename: str, columns: tuple[str, ...], traceable: list[str], note: str) -> None:
        path = data_dir / filename
        if not path.is_file():
            return
        stages[filename.replace(".csv", "")] = {
            "source_file": filename,
            "traceable_by": traceable,
            "note": note,
            "rows": _select(read_csv_rows(path), columns),
        }

    _stage(
        "e3_online_overhead.csv",
        ("arm", "qos", "payload_bytes", "mqtt_pub_bytes_mean", "record_overhead_bytes",
         "overhead_bytes", "deferred_evidence_package_bytes", "n_checkpoints"),
        ["arm", "qos", "payload_bytes"],
        "online publish path: wire bytes and deferred evidence package size",
    )
    _stage(
        "e4_amortized_overhead.csv",
        ("arm", "N", "evidence_package_bytes", "evidence_bytes_per_msg",
         "amortized_bytes_per_msg", "total_wire_bytes"),
        ["arm", "N"],
        "checkpoint amortization: evidence packaging cost per message",
    )
    _stage(
        "a6_witness_cost_cpp.csv",
        ("operation", "N", "witness_count", "min_receipts", "cost_mean_ms",
         "cost_median_ms", "cost_p95_ms", "bytes"),
        ["operation", "N", "witness_count"],
        "witness lifecycle: receipt signing and quorum verification cost",
    )
    _stage(
        "e9_storage.csv",
        ("arm", "N", "freq", "bytes_per_day", "full_evidence_bytes", "ckpt_files_count", "simulated_hours"),
        ["arm", "N", "freq"],
        "storage growth: evidence bytes accumulated per day",
    )
    _stage(
        "e5_latency.csv",
        ("arm", "N", "payload_bytes", "qos", "lat_ms_mean", "lat_ms_median", "lat_ms_p95",
         "subscriber_verify_ms_mean", "n_repetitions"),
        ["arm", "N", "payload_bytes", "qos"],
        "end-to-end publish -> verified-receipt latency",
    )
    _stage(
        "e6_throughput.csv",
        ("arm", "payload_bytes", "qos", "sustained_msg_per_s_mean", "verified_unique_messages_mean",
         "delivery_ratio_mean", "n_repetitions"),
        ["arm", "payload_bytes", "qos"],
        "sustained throughput and verified-unique delivery",
    )

    return {
        "source_file": "e8/e8-samples + e3 + e4 + a6_witness_cost_cpp + e9",
        "coverage": sorted(stages.keys()),
        "statistical_treatment": (
            "verification timing reports n/success/failure/mean/median/std/p95/p99, a parametric "
            "95% CI and a fixed-seed bootstrap 95% CI when raw samples are present; online/witness/"
            "storage stages report per-cell byte and cost aggregates with source traceability"
        ),
        "notes": notes,
        "stages": stages,
    }


# ── Summary 7: reproducibility manifest ──────────────────────────────────────
def summarize_reproducibility(data_dir: Path) -> dict[str, Any]:
    config = load_json(data_dir / "protocol_config.json")
    metadata = load_json(data_dir / "package_metadata.json")
    manifest_path = data_dir / "completion_manifest.json"
    quality_path = data_dir / "quality_report.json"
    manifest = load_json(manifest_path) if manifest_path.is_file() else {}
    quality = load_json(quality_path) if quality_path.is_file() else {}
    return {
        "source_file": "protocol_config.json + package_metadata.json + completion_manifest.json + quality_report.json",
        "run_id": config.get("run_id"),
        "mode": config.get("mode"),
        "seed": config.get("seed"),
        "config_hash": config.get("config_hash"),
        "git_commit": metadata.get("git_commit"),
        "git_dirty": metadata.get("git_dirty"),
        "dependency_hash": metadata.get("dependency_hash"),
        "source_tree_hash": metadata.get("source_tree_hash"),
        "sealed": bool(manifest),
        "file_count": manifest.get("file_count"),
        "quality_overall_status": quality.get("overall_status"),
        "validator_sha256": quality.get("validator_sha256"),
        "engineering_only": "quick" == config.get("mode"),
    }


# ── Statistical methodology checklist (data-verified items + documented ones) ──
def statistical_methodology_checklist(summaries: Mapping[str, Any]) -> list[dict[str, str]]:
    """Methodology checklist — NOT an automated fallacy scanner; the list length is
    not a coverage score.  Items with kind='data_verified' are computed from this
    package's actual data; kind='documented' items are methodology statements about
    how the summaries were constructed."""
    cap = summaries.get("capability_boundary", {})
    deterministic = cap.get("deterministic", True)
    repro = summaries.get("reproducibility_manifest", {})
    mode = str(repro.get("mode", "unknown"))
    engineering_only = mode == "quick"
    lifecycle = summaries.get("lifecycle_cost", {})
    has_samples = any("raw per-repetition" in str(n) for n in lifecycle.get("notes", []))
    fp = summaries.get("attack_benign_controls", {})
    fp_oracle_based = "oracle" in str(fp.get("false_positive_predicate", "")).lower()
    _data_verified = {
        "01_deterministic_fake_ci", "04_skew_reported_by_mean_only",
        "06_base_rate_neglect", "07_small_sample_overinterpretation",
    }
    items = [
        {"id": "01_deterministic_fake_ci", "status": "AVOIDED" if deterministic else "REVIEW",
         "reason": f"capability/ablation/transferability and the FP counts are deterministic (n_repetitions=1) and reported as exact matrices/counts with no confidence intervals (capability_deterministic={deterministic})."},
        {"id": "02_pseudoreplication", "status": "AVOIDED",
         "reason": "proportion/FP summaries aggregate distinct case_ids only; deterministic repetitions are never pooled as independent samples."},
        {"id": "03_multiple_comparisons", "status": "FLAGGED_NA",
         "reason": "capability cells are a descriptive matrix, not simultaneous hypothesis tests; no p-values are computed, so no correction is claimed."},
        {"id": "04_skew_reported_by_mean_only", "status": "MITIGATED" if has_samples else "PARTIAL",
         "reason": ("timing reports median and p95, and from persisted raw samples also p99 and a fixed-seed bootstrap 95% CI"
                    if has_samples else "raw samples absent; median/p95 reported but p99/bootstrap are marked not-derivable, not invented")},
        {"id": "05_cross_workload_comparison", "status": "AVOIDED",
         "reason": "E8 costs are keyed by (arm,N,k,witness_count,min_receipts); cross-implementation comparison is restricted to identical-workload cells."},
        {"id": "06_base_rate_neglect", "status": "MITIGATED" if fp_oracle_based else "REVIEW",
         "reason": f"false positives use the ORACLE compliant-negative predicate (not the generator's benign label) with explicit denominators (oracle_based_predicate={fp_oracle_based})."},
        {"id": "07_small_sample_overinterpretation", "status": "FLAGGED" if engineering_only else "OK",
         "reason": (f"mode={mode}: quick is a reduced-repetition smoke profile, engineering-only, and must not enter paper Results"
                    if engineering_only else f"mode={mode}: manuscript profile; still bounded by the fixed deterministic corpus design")},
        {"id": "08_simpsons_paradox", "status": "MITIGATED",
         "reason": "rates/counts are reported per denominator and per cell, not only pooled."},
        {"id": "09_selective_reporting", "status": "AVOIDED",
         "reason": "every raw cell/case is auto-summarized; none are dropped or cherry-picked."},
        {"id": "10_correlation_vs_causation", "status": "NOT_APPLICABLE",
         "reason": "no causal inference is drawn from timing or size measurements."},
        {"id": "11_survivorship_bias", "status": "AVOIDED",
         "reason": "benign controls and failure-grid cases are included, not only successful or attack cases."},
    ]
    for item in items:
        item["kind"] = "data_verified" if item["id"] in _data_verified else "documented"
    return items


def _write_summary_csv(out_dir: Path, name: str, rows: Iterable[Mapping[str, Any]]) -> None:
    rows = list(rows)
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with (out_dir / name).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_summary(data_dir: Path) -> dict[str, Any]:
    summaries = {
        "capability_boundary": summarize_capability_boundary(data_dir),
        "ablation": summarize_ablation(data_dir),
        "offline_transferability": summarize_transferability(data_dir),
        "attack_benign_controls": summarize_attack_benign(data_dir),
        "attribution_scope": summarize_attribution_scope(data_dir),
        "lifecycle_cost": summarize_lifecycle_cost(data_dir),
        "reproducibility_manifest": summarize_reproducibility(data_dir),
    }
    checklist = statistical_methodology_checklist(summaries)
    verified = sum(1 for item in checklist if item.get("kind") == "data_verified")
    return {
        "schema": SUMMARY_SCHEMA_VERSION,
        "data_dir": str(data_dir),
        "summaries": summaries,
        "statistical_methodology_checklist": checklist,
        "methodology_checklist_summary": (
            f"{verified} data-verified + {len(checklist) - verified} documented methodology items "
            "(this is a checklist, not an automated fallacy scan; the count is not a score)"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Summary destination (outside the sealed package); default <data-dir>-summary",
    )
    args = parser.parse_args()
    data_dir = Path(args.data_dir).resolve()
    if not data_dir.is_dir():
        raise SystemExit(f"data directory does not exist: {data_dir}")
    out_dir = Path(args.out_dir).resolve() if args.out_dir else data_dir.parent / f"{data_dir.name}-summary"
    try:
        out_dir.relative_to(data_dir)
    except ValueError:
        pass
    else:
        raise SystemExit("summary output must live outside --data-dir (sealed packages are immutable)")

    report = build_summary(data_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summaries = report["summaries"]
    _write_summary_csv(out_dir, "summary_capability_boundary.csv", summaries["capability_boundary"]["rows"])
    _write_summary_csv(out_dir, "summary_ablation.csv", summaries["ablation"]["rows"])
    _write_summary_csv(out_dir, "summary_transferability.csv", summaries["offline_transferability"]["rows"])
    _write_summary_csv(out_dir, "summary_attack_benign.csv", summaries["attack_benign_controls"]["rows"])
    _write_summary_csv(
        out_dir,
        "derived_attribution_metrics.csv",
        summaries["attribution_scope"]["rows"],
    )
    for stage_name, stage in summaries["lifecycle_cost"].get("stages", {}).items():
        _write_summary_csv(out_dir, f"summary_lifecycle_{stage_name}.csv", stage.get("rows", []))

    print(f"summary written -> {out_dir}")
    print(f"  methodology checklist: {report['methodology_checklist_summary']}")
    for name, block in summaries.items():
        if name == "lifecycle_cost":
            stages = block.get("stages", {})
            print(f"  {name}: {len(stages)} stages ({', '.join(sorted(stages))})")
            continue
        count = block.get("cell_count", len(block.get("rows", []) or []))
        print(f"  {name}: {count} rows <- {block.get('source_file', '?')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
