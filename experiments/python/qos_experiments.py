#!/usr/bin/env python3
"""Run the separated trace -> oracle -> evidence -> auditor experiments.

This is the implementation shared by E7 (failure/ambiguity grid) and E11
(same-evidence QoS-aware versus QoS-agnostic comparison).  Raw per-case files
are authoritative; CSV files are derived summaries only.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from evidence_auditor import (
    ARM_CAPABILITIES,
    TrustProfile,
    assert_auditor_input_is_blind,
    audit_evidence,
    construct_auditor_input,
)
from crypto_evidence_bridge import (
    bind_trace_to_crypto,
    build_crypto_template,
    verify_real_crypto_case,
)
from qos_semantics import QoSContext, contexts_by_id, representative_contexts, semantic_oracle
from trace_corpus import (
    ALL_SCENARIOS,
    BENIGN_SCENARIOS,
    DEFAULT_CORPUS_SEED,
    FAILURE_GRID_SCENARIOS,
    MALICIOUS_SCENARIOS,
    _scenario_class,
    assert_trace_has_no_expected_labels,
    canonical_json_bytes,
    case_id_for,
    generate_trace,
)


QOS_EXPERIMENT_SCHEMA_VERSION = "qos-experiment-suite-v2"
CORE_CORPUS_FILES = (
    "trace_corpus.jsonl",
    "ground_truth.jsonl",
    "evidence_observations.jsonl",
    "auditor_inputs.jsonl",
    "auditor_results.jsonl",
    "qos_capability_ablation.csv",
    "transferability_results.csv",
)


CONNECTED_MANIPULATION_CONTEXTS = (
    "q0_connected_clean",
    "q1_connected_persistent",
    "q2_connected_persistent",
    "q1_to_q0_subscription",
    "q2_to_q0_subscription",
    "q1_persistent_reconnected",
)
OFFLINE_MANIPULATION_CONTEXTS = (
    "q1_persistent_offline",
    "q1_clean_offline",
)

SCENARIO_CONTEXTS: dict[str, tuple[str, ...]] = {
    "clean": (
        "q0_connected_clean", "q1_connected_persistent", "q2_connected_persistent",
        "q1_to_q0_subscription", "q2_to_q0_subscription", "q1_persistent_reconnected",
    ),
    "tamper": CONNECTED_MANIPULATION_CONTEXTS,
    "delete": CONNECTED_MANIPULATION_CONTEXTS + OFFLINE_MANIPULATION_CONTEXTS,
    "inject": CONNECTED_MANIPULATION_CONTEXTS,
    "duplicate": CONNECTED_MANIPULATION_CONTEXTS,
    "replay": CONNECTED_MANIPULATION_CONTEXTS,
    "reorder": CONNECTED_MANIPULATION_CONTEXTS,
    "cross_epoch_replay": CONNECTED_MANIPULATION_CONTEXTS,
    "checkpoint_splice": ("q2_connected_persistent",),
    "rollback": ("q2_connected_persistent",),
    "middle_truncation": ("q2_connected_persistent",),
    "tail_truncation": ("q2_connected_persistent",),
    "split_view": ("q2_connected_persistent",),
    "witness_unavailable": ("q2_connected_persistent",),
    "below_quorum": ("q2_connected_persistent",),
    "stale_anchor": ("q2_connected_persistent",),
    "qos0_loss": (
        "q0_connected_clean", "q1_to_q0_subscription", "q2_to_q0_subscription",
        "q1_connected_persistent",
    ),
    "qos1_duplicate": ("q1_connected_persistent", "q2_connected_persistent"),
    "qos1_to_qos0_duplicate": ("q1_to_q0_subscription",),
    "qos1_reconnect_late_duplicate": ("q1_persistent_reconnected",),
    "subscriber_disconnect": ("q1_persistent_offline", "q1_clean_offline"),
    "delayed_delivery": ("q1_connected_persistent",),
}


# Pre-run, config-hash-bound coverage classification.  Every connected context
# is instantiated for every manipulation.  Only non-delete manipulations in a
# pre-reconnect offline phase are excluded: the current corpus models queue/
# absence ambiguity there, not arbitrary hidden content/order transformations.
MANIPULATION_COVERAGE_STATUS: dict[str, dict[str, str]] = {
    scenario: {
        context_id: (
            "Instantiated"
            if context_id in SCENARIO_CONTEXTS[scenario]
            else "Scope-excluded"
        )
        for context_id in CONNECTED_MANIPULATION_CONTEXTS + OFFLINE_MANIPULATION_CONTEXTS
    }
    for scenario in MALICIOUS_SCENARIOS
}


def _scenario_arms(scenario: str, arms: Iterable[str]) -> tuple[str, ...]:
    selected = tuple(arm for arm in arms if arm in ARM_CAPABILITIES)
    if scenario in ("witness_unavailable", "below_quorum"):
        return tuple(arm for arm in selected if arm == "A6")
    if scenario in ("checkpoint_splice", "rollback", "middle_truncation", "tail_truncation"):
        return tuple(arm for arm in selected if arm in ("A0", "A3", "A4", "A6"))
    return selected


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        return "unknown"


def _dependency_fingerprint() -> tuple[str, dict[str, str]]:
    versions = {"python": platform.python_version()}
    for distribution in ("paho-mqtt", "cryptography", "liboqs-python"):
        try:
            versions[distribution] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            versions[distribution] = "not-installed"
    return hashlib.sha256(canonical_json_bytes(versions)).hexdigest(), versions


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(canonical_json_bytes(dict(row)).decode("utf-8"))
            handle.write("\n")


def _provenance_fields(provenance: Any | None) -> dict[str, Any]:
    if provenance is None:
        return {}
    fields = getattr(provenance, "fields", None)
    return dict(fields()) if callable(fields) else {}


def _metadata(
    *,
    provenance: Any | None,
    seed: int,
    config_hash: str,
    git_commit: str,
    dependency_hash: str,
) -> dict[str, Any]:
    shared = _provenance_fields(provenance)
    if shared:
        return {
            **shared,
            "experiment_config_hash": config_hash,
            "experiment_dependency_hash": dependency_hash,
            "experiment_seed": seed,
        }
    return {
        "config_hash": config_hash,
        "seed": seed,
        "git_commit": git_commit,
        "dependency_hash": dependency_hash,
        "source_tree_hash": "unregistered",
        "experiment_config_hash": config_hash,
        "experiment_dependency_hash": dependency_hash,
        "experiment_seed": seed,
    }


def _majority(values: Iterable[Any]) -> Any:
    counter = Counter(values)
    if not counter:
        return None
    return sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))[0][0]


def _evidence_snapshot(
    auditor_input: Mapping[str, Any],
    crypto_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    snapshot = {
        key: auditor_input[key]
        for key in (
            "schema_version", "case_id", "arm", "mechanism", "transferable_evidence",
            "publisher_identity", "trusted_genesis_anchor", "committed_records",
            "presented_checkpoints", "subscriber_deliveries",
            "publisher_completion_observations", "session_mac_observations",
            "trusted_latest_anchor", "witness_policy", "witness_receipts",
        )
    }
    snapshot["crypto_artifact"] = dict(crypto_artifact)
    return snapshot


def _summarise_e7(
    cases: list[dict[str, Any]],
    *,
    metadata: Mapping[str, Any],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        grouped[(case["arm"], case["scenario"], case["context_id"])].append(case)

    rows: list[dict[str, Any]] = []
    for (arm, scenario, context_id), members in sorted(grouped.items()):
        aware = [member["aware"] for member in members]
        truths = [member["truth"] for member in members]
        semantic_status = _majority(truth["semantic_status"] for truth in truths)
        evidence_violation = any(truth["evidence_integrity_violation"] for truth in truths)
        detected_count = sum(1 for result in aware if result["detected"])
        inconclusive_count = sum(1 for result in aware if result["inconclusive"])
        attributions = [result["attribution"] for result in aware]
        false_positive_count = sum(
            1 for result, truth in zip(aware, truths)
            if result["detected"]
            and truth["semantic_status"] == "compliant"
            and not truth["evidence_integrity_violation"]
        )
        false_negative_count = sum(
            1 for result, truth in zip(aware, truths)
            if not result["detected"]
            and (truth["semantic_status"] == "violation" or truth["evidence_integrity_violation"])
        )
        attr_correct = sum(
            1 for result, truth in zip(aware, truths)
            if result["attribution"] is not None
            and result["attribution"] == truth["protocol_responsible_party"]
        )
        rows.append({
            **metadata,
            "arm": arm,
            "scenario": scenario,
            "scenario_class": members[0]["scenario_class"],
            "context_id": context_id,
            "publisher_qos": members[0]["context"]["publisher_qos"],
            "subscription_requested_qos": members[0]["context"]["requested_qos"],
            "effective_qos": members[0]["context"]["effective_qos"],
            "session_mode": members[0]["context"]["session_mode"],
            "subscriber_connected": members[0]["context"]["subscriber_connected"],
            "semantic_status": semantic_status,
            "evidence_integrity_violation": evidence_violation,
            "detection_rate": round(detected_count / len(members), 6),
            "inconclusive_rate": round(inconclusive_count / len(members), 6),
            "majority_attribution": _majority(attributions),
            "attribution_rate": round(sum(value is not None for value in attributions) / len(members), 6),
            "attribution_correct_rate": round(attr_correct / len(members), 6),
            "false_positive_rate": round(false_positive_count / len(members), 6),
            "false_negative_rate": round(false_negative_count / len(members), 6),
            "n_repetitions": len(members),
            "reason_codes": "|".join(sorted({code for result in aware for code in result["reason_codes"]})),
            "observed_evidence": "trace_projected_evidence_bundle",
            "trust_assumptions": json.dumps(members[0]["auditor_input"]["trust_assumptions"], sort_keys=True),
            "audit_evidence_transferable": bool(members[0]["auditor_input"]["transferable_evidence"]),
        })
    return rows


def _summarise_e11(
    cases: list[dict[str, Any]],
    *,
    metadata: Mapping[str, Any],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        grouped[(case["arm"], case["scenario"], case["context_id"])].append(case)
    rows: list[dict[str, Any]] = []
    for (arm, scenario, context_id), members in sorted(grouped.items()):
        truths = [member["truth"] for member in members]
        aware = [member["aware"] for member in members]
        agnostic = [member["agnostic"] for member in members]

        def fp_count(results: list[Mapping[str, Any]]) -> int:
            return sum(
                1 for result, truth in zip(results, truths)
                if result["detected"]
                and truth["semantic_status"] == "compliant"
                and not truth["evidence_integrity_violation"]
            )

        def fn_count(results: list[Mapping[str, Any]]) -> int:
            return sum(
                1 for result, truth in zip(results, truths)
                if not result["detected"]
                and (truth["semantic_status"] == "violation" or truth["evidence_integrity_violation"])
            )

        aware_fp, agnostic_fp = fp_count(aware), fp_count(agnostic)
        aware_fn, agnostic_fn = fn_count(aware), fn_count(agnostic)
        n = len(members)
        rows.append({
            **metadata,
            "arm": arm,
            "scenario": scenario,
            "context_id": context_id,
            "effective_qos": members[0]["context"]["effective_qos"],
            "session_mode": members[0]["context"]["session_mode"],
            "qos_aware_decision": _majority(result["decision"] for result in aware),
            "qos_agnostic_decision": _majority(result["decision"] for result in agnostic),
            "qos_aware_attribution": _majority(result["attribution"] for result in aware),
            "qos_agnostic_attribution": _majority(result["attribution"] for result in agnostic),
            "qos_aware_detection_rate": round(sum(result["detected"] for result in aware) / n, 6),
            "qos_agnostic_detection_rate": round(sum(result["detected"] for result in agnostic) / n, 6),
            "qos_aware_false_positive_rate": round(aware_fp / n, 6),
            "qos_agnostic_false_positive_rate": round(agnostic_fp / n, 6),
            "false_positive_rate_delta": round((agnostic_fp - aware_fp) / n, 6),
            "qos_aware_false_negative_rate": round(aware_fn / n, 6),
            "qos_agnostic_false_negative_rate": round(agnostic_fn / n, 6),
            "false_negative_rate_delta": round((agnostic_fn - aware_fn) / n, 6),
            "qos_aware_inconclusive_rate": round(sum(result["inconclusive"] for result in aware) / n, 6),
            "qos_agnostic_inconclusive_rate": round(sum(result["inconclusive"] for result in agnostic) / n, 6),
            "n_repetitions": n,
            "same_evidence_input": True,
            "agnostic_policy": "withhold_qos_session_interpretation_no_actor_default",
        })
    return rows


# Deterministic capability ablation matrix: one row per (dimension, arm,
# scenario, context, trust profile, level).  The matrix intrinsically spans
# hash-chain (A3) and Merkle (A4) commitments, witnessed quorum (A6), and the
# session-MAC negative control (A2), so those arms must be present for the
# suite to produce a complete ablation.
_ABLATION_DEFINITIONS = (
    ("trusted_registry", "A4", "tamper", "q2_connected_persistent", TrustProfile(), "present"),
    ("trusted_registry", "A4", "tamper", "q2_connected_persistent", TrustProfile(registry_present=False), "absent"),
    ("latest_anchor", "A4", "tail_truncation", "q2_connected_persistent", TrustProfile(), "present_fresh"),
    ("latest_anchor", "A4", "tail_truncation", "q2_connected_persistent", TrustProfile(latest_anchor_present=False), "absent"),
    ("witness_quorum", "A6", "clean", "q2_connected_persistent", TrustProfile(available_witnesses=0), "unavailable"),
    ("witness_quorum", "A6", "clean", "q2_connected_persistent", TrustProfile(available_witnesses=1), "below_quorum"),
    ("witness_quorum", "A6", "clean", "q2_connected_persistent", TrustProfile(available_witnesses=2), "satisfied"),
    ("transferability", "A2", "tamper", "q2_connected_persistent", TrustProfile(), "session_mac"),
    ("transferability", "A4", "tamper", "q2_connected_persistent", TrustProfile(), "transferable_signature"),
    ("commitment", "A3", "delete", "q2_connected_persistent", TrustProfile(), "hash_chain"),
    ("commitment", "A4", "delete", "q2_connected_persistent", TrustProfile(), "merkle"),
    ("qos_semantics", "A4", "qos0_loss", "q0_connected_clean", TrustProfile(), "aware"),
    ("qos_semantics", "A4", "qos0_loss", "q0_connected_clean", TrustProfile(), "agnostic"),
)
ABLATION_REQUIRED_ARMS = frozenset(arm for _dim, arm, *_rest in _ABLATION_DEFINITIONS)

# The formal QoS corpus is defined over the full arm set; any non-all-arm
# configuration is rejected (scenario coverage, ablation, and transferability
# all assume the complete set).  A5 (SLH-DSA) is an optional coverage point that
# does not enter the Cartesian corpus.
FORMAL_CORPUS_ARMS = frozenset({"A0", "A1", "A2", "A3", "A4", "A6"})


def derive_expected_corpus(
    *,
    seed: int,
    repetitions: int = 1,
    arms: Iterable[str] = FORMAL_CORPUS_ARMS,
) -> dict[str, dict[str, Any]]:
    """Re-derive the authoritative corpus grid from generation definitions.

    Returns ``{case_id: {scenario, scenario_class, context_id, arm, repetition}}``.
    The package validator uses this to assert the corpus spans exactly the
    required ``scenario × context × arm`` grid at the sealed seed, without
    trusting any runner-authored row count or scenario label: each ``case_id``
    is cryptographically bound to (seed, repetition, scenario, context, arm) via
    :func:`trace_corpus.case_id_for`.
    """

    selected = frozenset(arm for arm in arms if arm in ARM_CAPABILITIES)
    if selected != FORMAL_CORPUS_ARMS:
        raise ValueError(
            "expected corpus is defined only over the full formal arm set "
            f"{sorted(FORMAL_CORPUS_ARMS)}; got {sorted(selected)}"
        )
    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    context_map = contexts_by_id(representative_contexts())
    expected: dict[str, dict[str, Any]] = {}
    for scenario in ALL_SCENARIOS:
        for context_id in SCENARIO_CONTEXTS[scenario]:
            context = context_map[context_id]
            for arm in _scenario_arms(scenario, sorted(selected)):
                for repetition in range(repetitions):
                    cid = case_id_for(
                        seed=seed,
                        repetition=repetition,
                        scenario=scenario,
                        context=context,
                        arm=arm,
                    )
                    expected[cid] = {
                        "scenario": scenario,
                        "scenario_class": _scenario_class(scenario),
                        "context_id": context_id,
                        "arm": arm,
                        "repetition": repetition,
                    }
    return expected


def _run_ablation_cases(
    *,
    seed: int,
    context_map: Mapping[str, QoSContext],
    metadata: Mapping[str, Any],
    crypto_templates: Mapping[str, Any],
) -> list[dict[str, Any]]:
    definitions = _ABLATION_DEFINITIONS
    rows = []
    for index, (dimension, arm, scenario, context_id, profile, level) in enumerate(definitions):
        generated = generate_trace(
            scenario=scenario, context=context_map[context_id], arm=arm,
            seed=seed + 50_000, repetition=index,
        )
        trace = bind_trace_to_crypto(generated.trace, crypto_templates[arm])
        crypto_artifact = verify_real_crypto_case(
            trace,
            crypto_templates[arm],
            include_registry=profile.registry_present,
            include_latest_anchor=profile.latest_anchor_present,
            witness_receipt_limit=(profile.available_witnesses if arm == "A6" else None),
        )
        auditor_input = construct_auditor_input(
            trace,
            trust_profile=profile,
            crypto_artifact=crypto_artifact,
        )
        aware = level != "agnostic"
        result = audit_evidence(auditor_input, qos_aware=aware)
        rows.append({
            **metadata,
            "ablation_dimension": dimension,
            "ablation_level": level,
            "case_id": generated.trace["case_id"],
            "arm": arm,
            "context_id": context_id,
            "decision": result["decision"],
            "detected": result["detected"],
            "attribution": result["attribution"],
            "inconclusive": result["inconclusive"],
            "reason_codes": "|".join(result["reason_codes"]),
            "selective_proof_supported": arm in ("A0", "A4", "A6"),
            "auditor_mode": result["auditor_mode"],
        })
    return rows


def _transferability_rows(
    *,
    seed: int,
    arms: Iterable[str],
    context_map: Mapping[str, QoSContext],
    metadata: Mapping[str, Any],
    crypto_templates: Mapping[str, Any],
) -> list[dict[str, Any]]:
    rows = []
    for index, arm in enumerate(arms):
        generated = generate_trace(
            scenario="tamper", context=context_map["q2_connected_persistent"],
            arm=arm, seed=seed + 70_000, repetition=index,
        )
        trace = bind_trace_to_crypto(generated.trace, crypto_templates[arm])
        crypto_artifact = verify_real_crypto_case(trace, crypto_templates[arm])
        auditor_input = construct_auditor_input(trace, crypto_artifact=crypto_artifact)
        result = audit_evidence(auditor_input, qos_aware=True)
        rows.append({
            **metadata,
            "case_id": generated.trace["case_id"],
            "arm": arm,
            "mechanism": auditor_input["mechanism"],
            "offline_inputs": "evidence_bundle+trusted_registry+allowed_anchor",
            "online_participant_access": False,
            "offline_verifiable": result["decision"] in ("accept", "detect", "reject"),
            "transferable_attribution": bool(result["attributable"]),
            "decision": result["decision"],
            "detected": result["detected"],
            "attribution": result["attribution"],
            "reason_codes": "|".join(result["reason_codes"]),
            "capability_statement": (
                "online_session_integrity_only"
                if arm == "A2" else "third_party_verifiable_publisher_commitment"
            ),
        })
    return rows


def run_qos_experiment_suite(
    *,
    result_dir: str | os.PathLike[str],
    provenance: Any | None = None,
    write_csv_func: Any | None = None,
    arms: Iterable[str] = ("A0", "A1", "A2", "A3", "A4", "A6"),
    repetitions: int = 30,
    seed: int | None = None,
    n_records: int = 8,
    checkpoint_interval: int = 4,
) -> dict[str, Any]:
    """Generate authoritative raw cases and all E7/E11 derived summaries."""

    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    if seed is None:
        provenance_seed = getattr(provenance, "seed", None)
        seed = int(provenance_seed) if provenance_seed is not None else DEFAULT_CORPUS_SEED
    selected_arms = tuple(arm for arm in arms if arm in ARM_CAPABILITIES)
    if not selected_arms:
        raise ValueError("at least one supported arm is required")
    if set(selected_arms) != FORMAL_CORPUS_ARMS:
        raise ValueError(
            "qos experiment suite only runs the full all-arm formal corpus "
            f"{sorted(FORMAL_CORPUS_ARMS)}; got {sorted(set(selected_arms))}.  "
            "Non-all-arm subsets are not a supported formal configuration — its "
            "deterministic ablation, transferability, and scenario coverage all "
            "assume the complete arm set.  Drop the arms filter to use the "
            "canonical corpus."
        )
    contexts = representative_contexts()
    context_map = contexts_by_id(contexts)
    config = {
        "schema_version": QOS_EXPERIMENT_SCHEMA_VERSION,
        "seed": seed,
        "arms": selected_arms,
        "repetitions": repetitions,
        "n_records": n_records,
        "checkpoint_interval": checkpoint_interval,
        "contexts": [context.to_dict() for context in contexts],
        "scenario_contexts": SCENARIO_CONTEXTS,
        "manipulation_coverage_status": MANIPULATION_COVERAGE_STATUS,
        "scenarios": ALL_SCENARIOS,
        "auditor_modes": ["qos_aware", "qos_agnostic"],
    }
    config_hash = hashlib.sha256(canonical_json_bytes(config)).hexdigest()
    dependency_hash, dependencies = _dependency_fingerprint()
    git_commit = _git_commit()
    metadata = _metadata(
        provenance=provenance, seed=seed, config_hash=config_hash,
        git_commit=git_commit, dependency_hash=dependency_hash,
    )
    crypto_templates = {
        arm: build_crypto_template(
            arm,
            n_records=n_records,
            checkpoint_interval=checkpoint_interval,
            witness_count=3,
        )
        for arm in selected_arms
    }

    trace_rows: list[dict[str, Any]] = []
    truth_rows: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    input_rows: list[dict[str, Any]] = []
    result_rows: list[dict[str, Any]] = []
    joined_cases: list[dict[str, Any]] = []

    for scenario in ALL_SCENARIOS:
        for context_id in SCENARIO_CONTEXTS[scenario]:
            context = context_map[context_id]
            for arm in _scenario_arms(scenario, selected_arms):
                for repetition in range(repetitions):
                    generated = generate_trace(
                        scenario=scenario,
                        context=context,
                        arm=arm,
                        seed=seed,
                        repetition=repetition,
                        n_records=n_records,
                        checkpoint_interval=checkpoint_interval,
                    )
                    trace = bind_trace_to_crypto(generated.trace, crypto_templates[arm])
                    assert_trace_has_no_expected_labels(trace)
                    truth = semantic_oracle(trace, context)
                    truth.update({
                        "scenario": generated.scenario_id,
                        "scenario_class": generated.scenario_class,
                    })
                    crypto_artifact = verify_real_crypto_case(
                        trace,
                        crypto_templates[arm],
                        stale_anchor=scenario == "stale_anchor",
                    )
                    auditor_input = construct_auditor_input(
                        trace,
                        crypto_artifact=crypto_artifact,
                    )
                    assert_auditor_input_is_blind(auditor_input)
                    aware = audit_evidence(auditor_input, qos_aware=True)
                    agnostic = audit_evidence(auditor_input, qos_aware=False)

                    trace_rows.append({**metadata, **trace})
                    truth_rows.append({**metadata, **truth})
                    evidence_rows.append({
                        **metadata,
                        **_evidence_snapshot(auditor_input, crypto_artifact),
                    })
                    input_rows.append({**metadata, **auditor_input})
                    result_rows.extend(({**metadata, **aware}, {**metadata, **agnostic}))
                    joined_cases.append({
                        "arm": arm,
                        "scenario": scenario,
                        "scenario_class": generated.scenario_class,
                        "context_id": context_id,
                        "context": context.to_dict(),
                        "truth": truth,
                        "auditor_input": auditor_input,
                        "aware": aware,
                        "agnostic": agnostic,
                    })

    output_dir = Path(result_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(output_dir / "trace_corpus.jsonl", trace_rows)
    _write_jsonl(output_dir / "ground_truth.jsonl", truth_rows)
    _write_jsonl(output_dir / "evidence_observations.jsonl", evidence_rows)
    _write_jsonl(output_dir / "auditor_inputs.jsonl", input_rows)
    _write_jsonl(output_dir / "auditor_results.jsonl", result_rows)

    config_document = {
        **config,
        "config_hash": config_hash,
        "git_commit": git_commit,
        "dependency_hash": dependency_hash,
        "dependencies": dependencies,
    }
    (output_dir / "qos_experiment_config.json").write_bytes(canonical_json_bytes(config_document) + b"\n")

    e7_rows = _summarise_e7(joined_cases, metadata=metadata)
    e11_rows = _summarise_e11(joined_cases, metadata=metadata)
    ablation_rows = _run_ablation_cases(
        seed=seed,
        context_map=context_map,
        metadata=metadata,
        crypto_templates=crypto_templates,
    )
    transferability_rows = _transferability_rows(
        seed=seed,
        arms=selected_arms,
        context_map=context_map,
        metadata=metadata,
        crypto_templates=crypto_templates,
    )

    if write_csv_func is None:
        import csv

        def write_csv_func(path: str, rows: list[Mapping[str, Any]], _provenance: Any) -> list[dict[str, Any]]:
            if not rows:
                return []
            with open(path, "w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            return [dict(row) for row in rows]

    # Rows already carry provenance so the shared writer merely normalises it.
    written_e7 = write_csv_func(str(output_dir / "e7_qos_auditability.csv"), e7_rows, provenance)
    written_e11 = write_csv_func(str(output_dir / "e11_qos_auditor_comparison.csv"), e11_rows, provenance)
    written_ablation = write_csv_func(str(output_dir / "qos_capability_ablation.csv"), ablation_rows, provenance)
    written_transferability = write_csv_func(
        str(output_dir / "transferability_results.csv"), transferability_rows, provenance
    )

    return {
        "config_hash": config_hash,
        "seed": seed,
        "case_count": len(trace_rows),
        "auditor_result_count": len(result_rows),
        "e7_rows": written_e7,
        "e11_rows": written_e11,
        "ablation_rows": written_ablation,
        "transferability_rows": written_transferability,
        "core_files": [str(output_dir / name) for name in CORE_CORPUS_FILES],
    }


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def validate_corpus_package(data_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Replay the oracle and both auditors from raw package inputs."""

    root = Path(data_dir)
    errors: list[str] = []
    try:
        traces = _load_jsonl(root / "trace_corpus.jsonl")
        truths = {row["case_id"]: row for row in _load_jsonl(root / "ground_truth.jsonl")}
        inputs = {row["case_id"]: row for row in _load_jsonl(root / "auditor_inputs.jsonl")}
        results = {
            (row["case_id"], row["auditor_mode"]): row
            for row in _load_jsonl(root / "auditor_results.jsonl")
        }
        config_document = json.loads(
            (root / "qos_experiment_config.json").read_text(encoding="utf-8")
        )
    except Exception as exc:
        return {"valid": False, "errors": [f"package read failure: {exc}"]}

    config_fields = (
        "schema_version", "seed", "arms", "repetitions", "n_records",
        "checkpoint_interval", "contexts", "scenario_contexts",
        "manipulation_coverage_status", "scenarios", "auditor_modes",
    )
    config_core = {field: config_document.get(field) for field in config_fields}
    if config_core["schema_version"] != QOS_EXPERIMENT_SCHEMA_VERSION:
        errors.append("qos experiment schema version is not canonical")
    if config_core["contexts"] != [context.to_dict() for context in representative_contexts()]:
        errors.append("qos context definitions are not canonical")
    if config_core["scenario_contexts"] != {
        key: list(value) for key, value in SCENARIO_CONTEXTS.items()
    }:
        errors.append("scenario-context coverage is not canonical")
    if config_core["manipulation_coverage_status"] != MANIPULATION_COVERAGE_STATUS:
        errors.append("manipulation coverage classification is not canonical")
    recomputed_config_hash = hashlib.sha256(canonical_json_bytes(config_core)).hexdigest()
    if recomputed_config_hash != config_document.get("config_hash"):
        errors.append("qos experiment config hash mismatch")

    replay_fields = ("decision", "detected", "attribution", "inconclusive", "reason_codes", "observed_facts")
    oracle_fields = (
        "semantic_status", "semantic_violation", "evidence_integrity_violation",
        "physical_actor", "protocol_responsible_party", "witness_status", "reason_codes",
    )
    for trace in traces:
        case_id = trace.get("case_id")
        try:
            assert_trace_has_no_expected_labels(trace)
            replay_truth = semantic_oracle(trace)
            stored_truth = truths[case_id]
            for field in oracle_fields:
                if replay_truth.get(field) != stored_truth.get(field):
                    errors.append(f"{case_id}: ground truth mismatch for {field}")
            auditor_input = inputs[case_id]
            assert_auditor_input_is_blind(auditor_input)
            for aware, mode in ((True, "qos_aware"), (False, "qos_agnostic")):
                replay = audit_evidence(auditor_input, qos_aware=aware)
                stored = results[(case_id, mode)]
                for field in replay_fields:
                    if replay.get(field) != stored.get(field):
                        errors.append(f"{case_id}/{mode}: auditor mismatch for {field}")
        except Exception as exc:
            errors.append(f"{case_id}: replay failure: {exc}")

    expected_ids = {trace["case_id"] for trace in traces}
    try:
        canonical_cases = derive_expected_corpus(
            seed=int(config_document["seed"]),
            repetitions=int(config_document["repetitions"]),
            arms=tuple(config_document["arms"]),
        )
        if expected_ids != set(canonical_cases):
            errors.append("trace corpus does not match canonical scenario-context-arm grid")
    except Exception as exc:
        errors.append(f"cannot derive canonical trace grid: {exc}")
    if set(truths) != expected_ids or set(inputs) != expected_ids:
        errors.append("case-id coverage mismatch across trace/truth/input files")
    if set(results) != {(case_id, mode) for case_id in expected_ids for mode in ("qos_aware", "qos_agnostic")}:
        errors.append("auditor result coverage mismatch")
    return {"valid": not errors, "errors": errors, "case_count": len(traces)}
