"""Regression tests for the T4.8/T6.1 closure.

Each of these MUST fail-closed: a deleted arm, a missing/duplicate cell, a forged
corpus crypto verdict, or a scenario-class (rather than oracle) FP denominator.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import pytest


PYTHON_DIR = Path(__file__).resolve().parents[1] / "experiments" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

import validate_result_package as V  # noqa: E402
import summarize_result_package as S  # noqa: E402
from experiment_grids import CELL_KEY_COLUMNS, E7_CORPUS_CONTRACT, axes_for, expand_cells  # noqa: E402
from experiment_profiles import canonical_profile  # noqa: E402
from qos_experiments import run_qos_experiment_suite  # noqa: E402


def _frame_from_axes(experiment: str, axes: dict) -> pd.DataFrame:
    key_cols = CELL_KEY_COLUMNS[experiment]
    rows = [dict(zip(key_cols, cell)) for cell in sorted(expand_cells(experiment, axes[experiment]))]
    return pd.DataFrame(rows)


def _coverage_status(experiment: str, df: pd.DataFrame, axes: dict) -> str | None:
    checks: list = []
    V.validate_experiment_coverage({experiment: df}, checks, config={"coverage": axes})
    return {c.name: c.status for c in checks}.get(f"coverage:{experiment}")


def test_sealed_grids_pass_when_complete():
    axes = axes_for("quick")
    for experiment in CELL_KEY_COLUMNS:
        df = _frame_from_axes(experiment, axes)
        assert _coverage_status(experiment, df, axes) == "PASS", experiment


@pytest.mark.parametrize("experiment", list(CELL_KEY_COLUMNS))
def test_coverage_fails_on_missing_cell(experiment):
    axes = axes_for("quick")
    df = _frame_from_axes(experiment, axes).iloc[1:]  # drop one cell
    assert _coverage_status(experiment, df, axes) == "FAIL"


def test_coverage_fails_on_deleted_e3_arm():
    axes = axes_for("quick")
    df = _frame_from_axes("e3_online_overhead.csv", axes)
    df = df[df["arm"] != "A6"]  # delete an entire arm
    assert _coverage_status("e3_online_overhead.csv", df, axes) == "FAIL"


def test_coverage_fails_on_duplicate_cell():
    axes = axes_for("quick")
    df = _frame_from_axes("e8_audit_cost.csv", axes)
    df = pd.concat([df, df.iloc[[0]]], ignore_index=True)  # duplicate work-cell
    assert _coverage_status("e8_audit_cost.csv", df, axes) == "FAIL"


def test_sealed_coverage_must_equal_canonical():
    # The validator must recompute axes_for(mode) and reject a sealed coverage that
    # does not equal it, so a run cannot seal a reduced coverage + matching reduced CSVs.
    import copy

    axes = axes_for("quick")
    checks: list = []
    V.validate_coverage_canonical({"coverage": axes}, "quick", checks)
    assert {c.name: c.status for c in checks}.get("coverage_sealed_equals_canonical") == "PASS"

    reduced = copy.deepcopy(axes)
    exp = "e3_online_overhead.csv"
    for key, vals in reduced[exp].items():
        if isinstance(vals, list) and len(vals) > 1:
            reduced[exp][key] = vals[1:]  # seal a strictly reduced axis
            break
    checks = []
    V.validate_coverage_canonical({"coverage": reduced}, "quick", checks)
    assert {c.name: c.status for c in checks}.get("coverage_sealed_equals_canonical") == "FAIL"


def test_g3_forged_corpus_crypto_fails(tmp_path):
    import copy

    run_qos_experiment_suite(
        result_dir=str(tmp_path), provenance=None, write_csv_func=None,
        repetitions=1, seed=20260710, n_records=8, checkpoint_interval=4,
    )
    trace = {r["case_id"]: r for r in (json.loads(l) for l in open(tmp_path / "trace_corpus.jsonl"))}
    obs = {r["case_id"]: r for r in (json.loads(l) for l in open(tmp_path / "evidence_observations.jsonl"))}
    ai = {r["case_id"]: r for r in (json.loads(l) for l in open(tmp_path / "auditor_inputs.jsonl"))}

    def statuses(observations, inputs):
        checks: list = []
        V.validate_corpus_crypto_rederivation(observations, inputs, trace, checks)
        return {c.name: c.status for c in checks}

    # Clean must reconstruct exactly (no false positive).
    clean = statuses(obs, ai)
    assert "FAIL" not in clean.values(), [k for k, v in clean.items() if v == "FAIL"]

    # (1) forged auditor_input crypto_verification is caught by full reconstruction.
    forged_outcome = copy.deepcopy(ai)
    target = next(
        cid for cid, o in obs.items()
        if o.get("arm") in ("A3", "A4", "A6")
        and str(o["crypto_artifact"]["stream_verdict"]["outcome"]) != "accept"
    )
    forged_outcome[target]["crypto_verification"]["stream_outcome"] = "accept"
    assert statuses(obs, forged_outcome).get("corpus_auditor_input_reconstructed") == "FAIL"

    # (1b) forged stored observation stream_verdict is caught by the verdict replay.
    forged_verdict = copy.deepcopy(obs)
    forged_verdict[target]["crypto_artifact"]["stream_verdict"]["outcome"] = "accept"
    assert statuses(forged_verdict, ai).get("corpus_crypto_verdict_rederived") == "FAIL"

    # (2) forged publisher_identity.registry_key_match is caught by reconstruction.
    forged_identity = copy.deepcopy(ai)
    a4 = next(cid for cid, o in obs.items() if o.get("arm") == "A4")
    forged_identity[a4]["publisher_identity"]["registry_key_match"] = False
    assert statuses(obs, forged_identity).get("corpus_auditor_input_reconstructed") == "FAIL"

    # (3) deleted witness facts are caught by the receipt_id set equality.
    deleted_witness = copy.deepcopy(obs)
    a6 = next(cid for cid, o in obs.items() if o.get("arm") == "A6")
    deleted_witness[a6]["crypto_artifact"]["witness_receipt_signatures"] = []
    assert statuses(deleted_witness, ai).get("corpus_crypto_witness_rederived") == "FAIL"


def test_fp_denominator_is_oracle_based(tmp_path):
    # c2 is generated benign_control but the ORACLE judged it a violation, so it must
    # NOT be an FP-eligible negative even though its generator class is benign.
    (tmp_path / "ground_truth.jsonl").write_text(
        json.dumps({"case_id": "c1", "scenario_class": "benign_control", "semantic_status": "compliant", "evidence_integrity_violation": False}) + "\n"
        + json.dumps({"case_id": "c2", "scenario_class": "benign_control", "semantic_status": "violation", "evidence_integrity_violation": False}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "auditor_inputs.jsonl").write_text(
        json.dumps({"case_id": "c1", "arm": "A4"}) + "\n" + json.dumps({"case_id": "c2", "arm": "A4"}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "auditor_results.jsonl").write_text(
        "\n".join(
            json.dumps(r) for r in (
                {"case_id": "c1", "auditor_mode": "qos_aware", "detected": False},
                {"case_id": "c2", "auditor_mode": "qos_aware", "detected": True},
                {"case_id": "c1", "auditor_mode": "qos_agnostic", "detected": False},
                {"case_id": "c2", "auditor_mode": "qos_agnostic", "detected": True},
            )
        ) + "\n",
        encoding="utf-8",
    )
    summary = S.summarize_attack_benign(tmp_path)
    for row in summary["rows"]:
        if row["denominator"] == "oracle_compliant_negatives_all_arms" and row["auditor_mode"] == "qos_aware":
            assert row["n_cases"] == 1  # only c1; c2 excluded as an oracle violation
            assert row["false_positive_cases"] == 0


def test_e4_e8_witness_mismatch_fails():
    config = {"python": {"a6_witness_count": 3, "a6_min_receipts": 2}}
    bad = pd.DataFrame([{"arm": "A6", "N": 10, "witness_count": 1}])
    checks: list = []
    V.validate_a6_witness_consistency({"e4_amortized_overhead.csv": bad}, checks, config=config)
    assert {c.name: c.status for c in checks}.get("A6_witness_E4_binds_config") == "FAIL"
    good = pd.DataFrame([{"arm": "A6", "N": 10, "witness_count": 3}])
    checks = []
    V.validate_a6_witness_consistency({"e4_amortized_overhead.csv": good}, checks, config=config)
    assert {c.name: c.status for c in checks}.get("A6_witness_E4_binds_config") == "PASS"


def test_e8_samples_deletion_and_inconsistency_fail(tmp_path):
    e8 = pd.DataFrame([{
        "arm": "A4", "N": 10, "k_disclosed": 1, "n_repetitions": 3,
        "verify_ms_mean": 2.0, "verify_ms_median": 2.0, "verify_ms_std": 0.0, "verify_ms_p95": 2.0,
    }])
    checks: list = []
    V.validate_e8_samples(tmp_path, {"e8_audit_cost.csv": e8}, checks)
    assert {c.name: c.status for c in checks}.get("e8_samples_present") == "FAIL"  # file missing

    (tmp_path / "e8_audit_cost_samples.jsonl").write_text(
        json.dumps({"arm": "A4", "N": 10, "k_disclosed": 1, "operation": "verify", "n_samples": 3, "samples_ms": [2.0, 2.0, 2.0]}) + "\n",
        encoding="utf-8",
    )
    checks = []
    V.validate_e8_samples(tmp_path, {"e8_audit_cost.csv": e8}, checks)
    status = {c.name: c.status for c in checks}
    assert status.get("e8_samples_present") == "PASS"
    assert status.get("e8_samples_stats_match_csv") == "PASS"

    tampered = e8.copy()
    tampered.loc[0, "verify_ms_mean"] = 99.0
    checks = []
    V.validate_e8_samples(tmp_path, {"e8_audit_cost.csv": tampered}, checks)
    assert {c.name: c.status for c in checks}.get("e8_samples_stats_match_csv") == "FAIL"


# --- Hardened lifecycle-sample + e4_cpp coverage regressions (T6.3/T4.10) -----------

_E8_PROV = {
    "run_id": "r1", "timestamp_utc": "2026-07-12T00:00:00Z", "mode": "quick",
    "config_hash": "c" * 64, "seed": 1, "git_commit": "g" * 40,
    "dependency_hash": "d" * 64, "source_tree_hash": "s" * 64,
    "source_script": "python/run_optimized.py",
}

_CLEAN_E8_SAMPLES = [
    {"arm": "A4", "N": 10, "k_disclosed": 1, "operation": "verify", "n_samples": 3, "samples_ms": [2.0, 2.0, 2.0]},
    {"arm": "A4", "N": 10, "operation": "generation", "n_samples": 5, "samples_ms": [1.0, 1.0, 1.0, 1.0, 1.0]},
    {"arm": "A4", "N": 10, "operation": "serialization", "n_samples": 5, "samples_ms": [1.0, 1.0, 1.0, 1.0, 1.0]},
]


def _e8_status(tmp_path, sample_rows):
    e8 = pd.DataFrame([{
        "arm": "A4", "N": 10, "k_disclosed": 1, "n_repetitions": 3,
        "verify_ms_mean": 2.0, "verify_ms_median": 2.0, "verify_ms_std": 0.0, "verify_ms_p95": 2.0,
        "source_script": _E8_PROV["source_script"],
    }])
    with (tmp_path / "e8_audit_cost_samples.jsonl").open("w", encoding="utf-8") as fh:
        for row in sample_rows:
            fh.write(json.dumps({**_E8_PROV, **row}) + "\n")
    config = {
        "python": {"e8_lifecycle_reps": 5},
        "coverage": {"e8_audit_cost.csv": {"arms": ["A4"], "N": [10], "k": [1]}},
        "run_id": _E8_PROV["run_id"], "timestamp_utc": _E8_PROV["timestamp_utc"],
        "mode": _E8_PROV["mode"], "config_hash": _E8_PROV["config_hash"], "seed": _E8_PROV["seed"],
    }
    metadata = {k: _E8_PROV[k] for k in ("git_commit", "dependency_hash", "source_tree_hash")}
    checks: list = []
    V.validate_e8_samples(tmp_path, {"e8_audit_cost.csv": e8}, checks, config=config, metadata=metadata)
    return {c.name: c.status for c in checks}


def test_e8_lifecycle_hardening_clean_passes(tmp_path):
    st = _e8_status(tmp_path, [dict(r) for r in _CLEAN_E8_SAMPLES])
    for name in ("e8_samples_valid", "e8_samples_provenance", "e8_lifecycle_samples",
                 "e8_samples_cell_map", "e8_samples_stats_match_csv"):
        assert st.get(name) == "PASS", (name, st)


def test_e8_lifecycle_sample_shrink_fails(tmp_path):
    rows = [dict(r) for r in _CLEAN_E8_SAMPLES]
    rows[1]["samples_ms"] = [1.0]
    rows[1]["n_samples"] = 1  # self-consistent 5 -> 1, but != e8_lifecycle_reps
    assert _e8_status(tmp_path, rows).get("e8_samples_valid") == "FAIL"


def test_e8_lifecycle_duplicate_row_fails(tmp_path):
    rows = [dict(r) for r in _CLEAN_E8_SAMPLES]
    rows.append(dict(_CLEAN_E8_SAMPLES[1]))  # duplicate a generation row
    assert _e8_status(tmp_path, rows).get("e8_lifecycle_samples") == "FAIL"


def test_e8_sample_infinity_fails(tmp_path):
    rows = [dict(r) for r in _CLEAN_E8_SAMPLES]
    rows[1]["samples_ms"] = [1.0, 1.0, 1.0, 1.0, float("inf")]
    assert _e8_status(tmp_path, rows).get("e8_samples_valid") == "FAIL"


def test_e8_sample_provenance_swap_fails(tmp_path):
    rows = [dict(r) for r in _CLEAN_E8_SAMPLES]
    rows[0] = {**rows[0], "run_id": "attacker-run"}  # swap one sample's run_id
    assert _e8_status(tmp_path, rows).get("e8_samples_provenance") == "FAIL"


def test_e4_cpp_coverage_fails_on_deleted_rows():
    axes = axes_for("quick")
    df = _frame_from_axes("e4_amortized_overhead_cpp.csv", axes)
    assert len(df) == 12
    assert _coverage_status("e4_amortized_overhead_cpp.csv", df, axes) == "PASS"
    assert _coverage_status("e4_amortized_overhead_cpp.csv", df.iloc[:1], axes) == "FAIL"


def test_ablation_deletion_fails(tmp_path):
    import csv as _csv

    from qos_experiments import _ABLATION_DEFINITIONS

    rows = [{"ablation_dimension": item[0], "ablation_level": item[5]} for item in _ABLATION_DEFINITIONS]
    path = tmp_path / "qos_capability_ablation.csv"

    def write(subset):
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = _csv.DictWriter(handle, fieldnames=["ablation_dimension", "ablation_level"])
            writer.writeheader()
            writer.writerows(subset)

    write(rows)
    checks: list = []
    V.validate_derived_qos_coverage(tmp_path, checks)
    assert {c.name: c.status for c in checks}.get("ablation_coverage") == "PASS"

    write(rows[1:])  # delete one ablation cell
    checks = []
    V.validate_derived_qos_coverage(tmp_path, checks)
    assert {c.name: c.status for c in checks}.get("ablation_coverage") == "FAIL"


# --- Canonical profile contract + fixed E8 producer regressions (T4.11) --------------

def _canonical_config(mode):
    import copy
    prof = canonical_profile(mode)
    return {
        "mode": mode,
        "python": copy.deepcopy(prof["python"]),
        "cpp": copy.deepcopy(prof["cpp"]),
        "e7_corpus": dict(E7_CORPUS_CONTRACT),
    }


def _profile_status(config, mode):
    checks: list = []
    V.validate_profile_canonical(config, mode, checks)
    return {c.name: c.status for c in checks}.get("profile_sealed_equals_canonical")


def test_profile_canonical_clean_passes():
    assert _profile_status(_canonical_config("quick"), "quick") == "PASS"
    assert _profile_status(_canonical_config("full"), "full") == "PASS"


def test_profile_downgrade_lifecycle_reps_fails():
    c = _canonical_config("full")
    c["python"]["e8_lifecycle_reps"] = 1  # synchronised 20 -> 1 downgrade
    assert _profile_status(c, "full") == "FAIL"


def test_profile_missing_field_fails():
    c = _canonical_config("quick")
    del c["python"]["e8_lifecycle_reps"]
    assert _profile_status(c, "quick") == "FAIL"


def test_profile_full_a6_downgrade_fails():
    c = _canonical_config("full")
    c["python"]["a6_witness_count"] = 1
    c["python"]["a6_min_receipts"] = 1  # full A6 1/1 instead of canonical 3/2
    assert _profile_status(c, "full") == "FAIL"


def test_profile_e7_corpus_tamper_fails():
    c = _canonical_config("quick")
    c["e7_corpus"] = {**c["e7_corpus"], "repetitions": 50}
    assert _profile_status(c, "quick") == "FAIL"


def test_profile_cpp_downgrade_fails():
    c = _canonical_config("full")
    c["cpp"] = {**c["cpp"], "audit_runs": 30}  # full cpp audit_runs 200 -> 30
    assert _profile_status(c, "full") == "FAIL"


def test_e8_source_script_producer_bound_clean(tmp_path):
    st = _e8_status(tmp_path, [dict(r) for r in _CLEAN_E8_SAMPLES])
    assert st.get("e8_producer_bound") == "PASS"


def test_e8_source_script_swap_both_fails(tmp_path):
    # Swap BOTH the E8 CSV producer AND the samples' source_script.  Because the
    # validator anchors to the fixed producer constant (not to the CSV), both the
    # CSV-producer bind and the sample provenance still fail closed.
    e8 = pd.DataFrame([{
        "arm": "A4", "N": 10, "k_disclosed": 1, "n_repetitions": 3,
        "verify_ms_mean": 2.0, "verify_ms_median": 2.0, "verify_ms_std": 0.0, "verify_ms_p95": 2.0,
        "source_script": "attacker/script.py",
    }])
    prov = {**_E8_PROV, "source_script": "attacker/script.py"}
    with (tmp_path / "e8_audit_cost_samples.jsonl").open("w", encoding="utf-8") as fh:
        for row in _CLEAN_E8_SAMPLES:
            fh.write(json.dumps({**prov, **row}) + "\n")
    config = {
        "python": {"e8_lifecycle_reps": 5},
        "coverage": {"e8_audit_cost.csv": {"arms": ["A4"], "N": [10], "k": [1]}},
        "run_id": _E8_PROV["run_id"], "timestamp_utc": _E8_PROV["timestamp_utc"],
        "mode": _E8_PROV["mode"], "config_hash": _E8_PROV["config_hash"], "seed": _E8_PROV["seed"],
    }
    metadata = {k: _E8_PROV[k] for k in ("git_commit", "dependency_hash", "source_tree_hash")}
    checks: list = []
    V.validate_e8_samples(tmp_path, {"e8_audit_cost.csv": e8}, checks, config=config, metadata=metadata)
    st = {c.name: c.status for c in checks}
    assert st.get("e8_producer_bound") == "FAIL"
    assert st.get("e8_samples_provenance") == "FAIL"
