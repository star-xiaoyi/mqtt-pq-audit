"""Regression tests for the authoritative real-crypto QoS experiment suite that
now backs E7 and E11.

The suite must emit a single shared corpus (separated generator -> semantic
oracle -> real evidence bridge -> answer-blind auditor), with fully aligned case
IDs, no answer leakage in auditor inputs, A2 non-transferable, and benign QoS
faults not attributed to the broker without basis.  Non-all-arm subsets must be
rejected with a readable error rather than an opaque KeyError.
"""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIR = ROOT / "experiments" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from qos_experiments import (  # noqa: E402
    ABLATION_REQUIRED_ARMS,
    MANIPULATION_COVERAGE_STATUS,
    SCENARIO_CONTEXTS,
    build_crypto_template,
    run_qos_experiment_suite,
    validate_corpus_package,
)
from trace_corpus import generate_trace  # noqa: E402
from crypto_evidence_bridge import bind_trace_to_crypto, verify_real_crypto_case  # noqa: E402
from evidence_auditor import construct_auditor_input, audit_evidence  # noqa: E402
from qos_semantics import representative_contexts, contexts_by_id, semantic_oracle  # noqa: E402
from stream_identity import canonical_stream_id  # noqa: E402
from trusted_registry import TrustedRegistry  # noqa: E402

# Keys that would leak the intended answer into the auditor's blind input.
_FORBIDDEN_INPUT_KEYS = {
    "attack",
    "attack_name",
    "scenario",
    "scenario_class",
    "ground_truth",
    "truth",
    "expected",
    "expected_decision",
    "matches_expected",
}


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    # Drop any provenance comment rows (leading '#').
    return [r for r in rows if not next(iter(r.values()), "").startswith("#")]


@pytest.fixture(scope="module")
def suite(tmp_path_factory):
    out = tmp_path_factory.mktemp("qos_suite")
    summary = run_qos_experiment_suite(
        result_dir=out,
        provenance=None,
        write_csv_func=None,
        repetitions=1,
        seed=20260710,
        n_records=8,
        checkpoint_interval=4,
    )
    return out, summary


def test_suite_emits_single_shared_corpus_with_aligned_case_ids(suite):
    out, summary = suite
    trace = _read_jsonl(out / "trace_corpus.jsonl")
    truth = _read_jsonl(out / "ground_truth.jsonl")
    inputs = _read_jsonl(out / "auditor_inputs.jsonl")
    evidence = _read_jsonl(out / "evidence_observations.jsonl")
    results = _read_jsonl(out / "auditor_results.jsonl")

    n = len(trace)
    assert n > 0
    assert len(truth) == len(inputs) == len(evidence) == n
    # Two auditor results (qos_aware + qos_agnostic) per case.
    assert len(results) == 2 * n
    assert summary["case_count"] == n
    assert summary["auditor_result_count"] == 2 * n

    trace_ids = {r["case_id"] for r in trace}
    assert trace_ids == {r["case_id"] for r in truth}
    assert trace_ids == {r["case_id"] for r in inputs}
    assert trace_ids == {r["case_id"] for r in evidence}

    # Every case is audited under exactly the two auditor modes, once each.
    modes_by_case: dict[str, set[str]] = {}
    for r in results:
        modes_by_case.setdefault(r["case_id"], set()).add(r["auditor_mode"])
    assert set(modes_by_case) == trace_ids
    assert all(m == {"qos_aware", "qos_agnostic"} for m in modes_by_case.values())


def test_full_corpus_detection_and_attribution_envelope_is_locked(suite):
    out, _ = suite
    aware = [
        row for row in _read_jsonl(out / "auditor_results.jsonl")
        if row["auditor_mode"] == "qos_aware"
    ]
    assert len(aware) == 396
    assert sum(row["decision"] == "accept" for row in aware) == 104
    assert sum(row["decision"] == "inconclusive" for row in aware) == 96
    detected = [row for row in aware if row["detected"]]
    assert len(detected) == 196
    assert sum(row["attribution"] == "broker" for row in detected) == 176
    assert sum(row["attribution"] is None for row in detected) == 20


def test_auditor_inputs_are_answer_blind(suite):
    out, _ = suite
    inputs = _read_jsonl(out / "auditor_inputs.jsonl")
    for record in inputs:
        leaked = _FORBIDDEN_INPUT_KEYS.intersection(record.keys())
        assert not leaked, f"auditor input leaked answer keys: {sorted(leaked)}"


def test_a6_witness_quorum_ablation_distinguishes_satisfied_from_below(suite):
    out, _ = suite
    ablation = _read_csv(out / "qos_capability_ablation.csv")
    quorum_rows = {r["ablation_level"]: r for r in ablation if r["ablation_dimension"] == "witness_quorum"}
    assert {"satisfied", "below_quorum", "unavailable"} <= set(quorum_rows)
    # A satisfied distinct trusted quorum must reach ACCEPT (the signature_valid
    # fix); below-quorum / unavailable must fail closed to INCONCLUSIVE.
    assert quorum_rows["satisfied"]["decision"] == "accept"
    assert quorum_rows["below_quorum"]["decision"] == "inconclusive"
    assert quorum_rows["unavailable"]["decision"] == "inconclusive"



def test_independent_corpus_validator_passes(suite):
    out, _ = suite
    report = validate_corpus_package(out)
    assert report["valid"], report["errors"]
    assert report["case_count"] == len(_read_jsonl(out / "trace_corpus.jsonl"))


def test_independent_corpus_validator_rejects_synchronised_coverage_relabel(
    suite, tmp_path
):
    source, _ = suite
    copied = tmp_path / "corpus"
    shutil.copytree(source, copied)
    config_path = copied / "qos_experiment_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["manipulation_coverage_status"]["tamper"]["q0_connected_clean"] = "Equivalent"
    hash_fields = (
        "schema_version", "seed", "arms", "repetitions", "n_records",
        "checkpoint_interval", "contexts", "scenario_contexts",
        "manipulation_coverage_status", "scenarios", "auditor_modes",
    )
    core = {field: config[field] for field in hash_fields}
    config["config_hash"] = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    config_path.write_text(
        json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    report = validate_corpus_package(copied)
    assert not report["valid"]
    assert any("coverage classification" in error for error in report["errors"])


def test_a2_is_always_nontransferable(suite):
    out, _ = suite
    transfer = _read_csv(out / "transferability_results.csv")
    a2_rows = [r for r in transfer if r["arm"] == "A2"]
    assert a2_rows, "expected A2 rows in transferability output"
    for r in a2_rows:
        assert r["transferable_attribution"] in ("False", "false", "0")
        assert r["capability_statement"] == "online_session_integrity_only"


def test_benign_qos0_loss_not_attributed_to_broker_when_qos_aware(suite):
    out, _ = suite
    ablation = _read_csv(out / "qos_capability_ablation.csv")
    qos_rows = {r["ablation_level"]: r for r in ablation if r["ablation_dimension"] == "qos_semantics"}
    assert {"aware", "agnostic"} <= set(qos_rows)
    aware = qos_rows["aware"]
    # A benign QoS0 loss must not be flagged/attributed to the broker by the
    # QoS-aware auditor; the QoS-agnostic auditor is allowed to over-flag it.
    assert aware["detected"] in ("False", "false", "0")
    assert aware["attribution"] != "broker"
    assert qos_rows["agnostic"]["detected"] in ("True", "true", "1")


@pytest.mark.parametrize(
    "subset",
    [
        ("A2", "A4", "A6"),            # missing A0, A1, A3
        ("A2", "A3", "A4", "A6"),      # contains every ablation arm but not A0/A1
        ("A0", "A1", "A2", "A3", "A4"),  # missing A6
    ],
)
def test_non_all_arm_subset_is_rejected_with_readable_error(tmp_path, subset):
    # Any non-all-arm configuration must fail closed with a clear message, not
    # silently generate a partial corpus.
    with pytest.raises(ValueError) as excinfo:
        run_qos_experiment_suite(
            result_dir=tmp_path,
            provenance=None,
            write_csv_func=None,
            arms=subset,
            repetitions=1,
            seed=20260710,
        )
    message = str(excinfo.value).lower()
    assert "subset" in message or "all-arm" in message


def test_ablation_required_arms_cover_matrix():
    # Guardrail: the declared requirement set must include the commitment arms.
    assert {"A2", "A3", "A4", "A6"} <= set(ABLATION_REQUIRED_ARMS)


def _timeline_checkpoint_events(timeline):
    return [
        e for e in timeline
        if e.get("event") in ("checkpoint_created", "checkpoint_presented") and "stream_id" in e
    ]


def test_trace_and_bridge_use_canonical_stream_id():
    ctx = contexts_by_id(representative_contexts())["q2_connected_persistent"]
    gen = generate_trace(
        scenario="clean", context=ctx, arm="A4",
        seed=20260710, repetition=0, n_records=8, checkpoint_interval=4,
    )
    # The raw generator must emit canonical (UTF-8 length-prefixed) stream ids,
    # never the ambiguous bare "client:topic" form.
    raw_events = _timeline_checkpoint_events(gen.trace["timeline"])
    assert raw_events
    for event in raw_events:
        assert event["stream_id"] == canonical_stream_id("publisher-001", event["topic"])
        assert event["stream_id"] != f"publisher-001:{event['topic']}"

    # After binding to real crypto the topic is rebound; every embedded stream
    # id — checkpoints, trusted_latest_anchor, AND witness_receipt — must be
    # recomputed to stay canonical and consistent with the new topic (a single
    # A6 trace must not mix arm-specific and stale base-topic ids).
    template = build_crypto_template("A4", n_records=8, checkpoint_interval=4, witness_count=3)
    bound = bind_trace_to_crypto(gen.trace, template)
    bound_events = _timeline_checkpoint_events(bound["timeline"])
    assert bound_events
    for event in bound_events:
        assert event["topic"] == template.topic
        assert event["stream_id"] == canonical_stream_id("publisher-001", template.topic)

    # No stream-bearing event of any kind may keep a stale identity.
    a6_template = build_crypto_template("A6", n_records=8, checkpoint_interval=4, witness_count=3)
    a6_gen = generate_trace(
        scenario="clean", context=ctx, arm="A6",
        seed=20260710, repetition=0, n_records=8, checkpoint_interval=4,
    )
    a6_bound = bind_trace_to_crypto(a6_gen.trace, a6_template)
    want = canonical_stream_id("publisher-001", a6_template.topic)
    stream_events = [e for e in a6_bound["timeline"] if "stream_id" in e]
    assert {e["event"] for e in stream_events} >= {
        "checkpoint_created", "trusted_latest_anchor", "witness_receipt",
    }
    for event in stream_events:
        assert event["stream_id"] == want, event["event"]


def _audit_real_case(arm, scenario, context_id, *, n_records=8, ckpt=4, qos_aware=True):
    template = build_crypto_template(arm, n_records=n_records, checkpoint_interval=ckpt, witness_count=3)
    ctx = contexts_by_id(representative_contexts())[context_id]
    gen = generate_trace(
        scenario=scenario, context=ctx, arm=arm,
        seed=20260710, repetition=0, n_records=n_records, checkpoint_interval=ckpt,
    )
    trace = bind_trace_to_crypto(gen.trace, template)
    artifact = verify_real_crypto_case(trace, template)
    result = audit_evidence(construct_auditor_input(trace, crypto_artifact=artifact), qos_aware=qos_aware)
    return result, artifact["stream_verdict"]["outcome"]


def _generated_case(scenario, context_id, *, arm="A4"):
    ctx = contexts_by_id(representative_contexts())[context_id]
    generated = generate_trace(
        scenario=scenario, context=ctx, arm=arm,
        seed=20260710, repetition=0, n_records=8, checkpoint_interval=4,
    )
    return ctx, generated.trace


def test_repaired_manipulation_coverage_contains_every_must_instantiate_cell():
    required = {
        ("tamper", "q0_connected_clean"),
        ("delete", "q1_persistent_offline"),
        ("delete", "q1_clean_offline"),
        ("inject", "q0_connected_clean"),
        ("replay", "q0_connected_clean"),
        ("cross_epoch_replay", "q0_connected_clean"),
        ("cross_epoch_replay", "q1_connected_persistent"),
    }
    instantiated = {
        (scenario, context)
        for scenario, contexts in SCENARIO_CONTEXTS.items()
        for context in contexts
    }
    assert required <= instantiated
    statuses = [
        status
        for row in MANIPULATION_COVERAGE_STATUS.values()
        for status in row.values()
    ]
    assert statuses.count("Instantiated") == 44
    assert statuses.count("Scope-excluded") == 12
    assert set(statuses) == {"Instantiated", "Scope-excluded"}


def test_qos0_ordered_topic_reorder_is_a_violation_and_detected():
    ctx, trace = _generated_case("reorder", "q0_connected_clean")
    truth = semantic_oracle(trace, ctx)
    assert truth["semantic_status"] == "violation"
    assert "ORDERED_FLOW_VIOLATED" in truth["reason_codes"]
    result, _ = _audit_real_case("A4", "reorder", "q0_connected_clean")
    assert result["detected"] is True
    assert result["attribution"] == "broker"


def test_qos1_delivery_gap_detects_but_abstains_on_physical_actor():
    # First-hop completion plus an honest subscriber establishes a due-delivery
    # gap, but the projected evidence cannot distinguish a broker omission from
    # an independent second-hop network drop.
    ctx, trace = _generated_case("qos0_loss", "q1_connected_persistent")
    truth = semantic_oracle(trace, ctx)
    result, _ = _audit_real_case("A4", "qos0_loss", "q1_connected_persistent")
    assert truth["semantic_status"] == "violation"
    assert truth["physical_actor"] == "network"
    assert result["detected"] is True
    assert result["attribution"] is None
    assert "DELIVERY_GAP_ACTOR_NOT_ISOLATED_FROM_LINK_FAILURE" in result["reason_codes"]


def test_qos1_application_duplicate_does_not_depend_on_dup_or_packet_id():
    ctx, trace = _generated_case("duplicate", "q1_connected_persistent")
    deliveries = [e for e in trace["timeline"] if e.get("event") == "subscriber_delivery"]
    duplicate = next(
        item for item in deliveries
        if sum((d["epoch"], d["seq"]) == (item["epoch"], item["seq"]) for d in deliveries) > 1
        and item.get("packet_id") == 50_000
    )
    assert duplicate["dup"] is False
    assert duplicate["retransmission"] is False
    assert semantic_oracle(trace, ctx)["semantic_status"] == "compliant"
    result, _ = _audit_real_case("A4", "duplicate", "q1_connected_persistent")
    assert result["detected"] is False
    assert "APPLICATION_DUPLICATE_PERMITTED_BY_TWO_HOP_QOS" in result["reason_codes"]


def test_qos1_to_qos0_duplicate_is_permitted_but_qos2_to_qos0_is_not():
    q10, q10_trace = _generated_case("qos1_to_qos0_duplicate", "q1_to_q0_subscription")
    assert semantic_oracle(q10_trace, q10)["semantic_status"] == "compliant"
    q10_result, _ = _audit_real_case(
        "A4", "qos1_to_qos0_duplicate", "q1_to_q0_subscription"
    )
    assert q10_result["detected"] is False

    q20, q20_trace = _generated_case("duplicate", "q2_to_q0_subscription")
    assert semantic_oracle(q20_trace, q20)["semantic_status"] == "violation"
    q20_result, _ = _audit_real_case("A4", "duplicate", "q2_to_q0_subscription")
    assert q20_result["detected"] is True


def test_late_qos1_retransmission_explains_sequence_regression():
    ctx, trace = _generated_case(
        "qos1_reconnect_late_duplicate", "q1_persistent_reconnected"
    )
    deliveries = [e for e in trace["timeline"] if e.get("event") == "subscriber_delivery"]
    seqs = [(int(item["epoch"]), int(item["seq"])) for item in deliveries]
    assert any(seqs[index] < seqs[index - 1] for index in range(1, len(seqs)))
    assert semantic_oracle(trace, ctx)["semantic_status"] == "compliant"
    result, _ = _audit_real_case(
        "A4", "qos1_reconnect_late_duplicate", "q1_persistent_reconnected"
    )
    assert result["detected"] is False
    assert result["observed_facts"]["explained_sequence_regressions"] == 1
    assert result["observed_facts"]["cross_epoch_replay_observations"] == 0

    # A1 advances its cryptographic checkpoint epoch per message.  Application
    # epoch/freshness is a domain policy derived from seq ranges and must remain
    # arm-independent, so the same legal control cannot turn into a false
    # cross-epoch replay under A1.
    a1_result, _ = _audit_real_case(
        "A1", "qos1_reconnect_late_duplicate", "q1_persistent_reconnected"
    )
    assert a1_result["detected"] is False
    assert a1_result["observed_facts"]["cross_epoch_replay_observations"] == 0


def test_ordinary_and_cross_epoch_replay_have_distinct_observable_shapes():
    ordinary_ctx, ordinary = _generated_case("replay", "q1_connected_persistent")
    cross_ctx, cross = _generated_case("cross_epoch_replay", "q1_connected_persistent")
    ordinary_seq = [
        (int(e["epoch"]), int(e["seq"]))
        for e in ordinary["timeline"] if e.get("event") == "subscriber_delivery"
    ]
    cross_seq = [
        (int(e["epoch"]), int(e["seq"]))
        for e in cross["timeline"] if e.get("event") == "subscriber_delivery"
    ]
    assert ordinary_seq != cross_seq
    assert max(epoch for epoch, _seq in ordinary_seq[:4]) == ordinary_ctx.initial_epoch
    assert cross_seq[-1][0] < max(epoch for epoch, _seq in cross_seq[:-1])
    assert semantic_oracle(ordinary, ordinary_ctx)["semantic_status"] == "compliant"
    assert semantic_oracle(cross, cross_ctx)["semantic_status"] == "violation"

    ordinary_result, _ = _audit_real_case("A4", "replay", "q1_connected_persistent")
    cross_result, _ = _audit_real_case("A4", "cross_epoch_replay", "q1_connected_persistent")
    assert ordinary_result["detected"] is False
    assert cross_result["detected"] is True
    assert "CROSS_EPOCH_FRESHNESS_VIOLATED" in cross_result["reason_codes"]
    a1_ordinary, _ = _audit_real_case("A1", "replay", "q1_connected_persistent")
    a1_cross, _ = _audit_real_case("A1", "cross_epoch_replay", "q1_connected_persistent")
    assert a1_ordinary["detected"] is False
    assert a1_cross["detected"] is True


@pytest.mark.parametrize(
    ("context_id", "expected_status"),
    [
        ("q1_persistent_offline", "ambiguous"),
        ("q1_clean_offline", "compliant"),
    ],
)
def test_offline_delete_is_a_pre_reconnect_boundary_not_a_broker_deletion_proof(
    context_id, expected_status
):
    ctx, trace = _generated_case("delete", context_id)
    assert ctx.audit_phase == "before_reconnect"
    assert semantic_oracle(trace, ctx)["semantic_status"] == expected_status
    visible = [
        e for e in trace["timeline"]
        if e.get("event") == "subscriber_delivery" and e.get("auditor_visible", True)
    ]
    assert visible and max(int(item["seq"]) for item in visible) <= 4
    result, _ = _audit_real_case("A4", "delete", context_id)
    assert result["detected"] is False
    assert result["attribution"] is None


def test_a6_clean_reaches_accept_with_witness_quorum():
    # The distinct trusted witness quorum must count validly-signed receipts, so
    # a clean A6 case reaches ACCEPT rather than being stranded at INCONCLUSIVE.
    result, stream_outcome = _audit_real_case("A6", "clean", "q2_connected_persistent")
    assert stream_outcome == "accept"
    assert result["decision"] == "accept"
    facts = result["observed_facts"]
    assert facts["witness_quorum"] >= 1
    assert facts["distinct_trusted_witnesses"] >= facts["witness_quorum"]


def test_a4_clean_reaches_accept():
    result, stream_outcome = _audit_real_case("A4", "clean", "q2_connected_persistent")
    assert stream_outcome == "accept"
    assert result["decision"] == "accept"


def test_a1_clean_stays_inconclusive_not_accept():
    # A1 authenticates each message but cannot bind a unique stream history; the
    # auditor must not upgrade the inconclusive crypto verdict to ACCEPT.
    result, stream_outcome = _audit_real_case("A1", "clean", "q2_connected_persistent")
    assert stream_outcome == "inconclusive"
    assert result["decision"] == "inconclusive"
    assert "STREAM_HISTORY_BINDING_UNPROVEN" in result["reason_codes"]


def test_authoritative_crypto_reject_never_upgraded_to_accept():
    # Fail-closed: if the authoritative offline verifier REJECTS the transferable
    # stream (here: the trusted witness policy is absent), the answer-blind
    # auditor must not return ACCEPT.
    template = build_crypto_template("A6", n_records=8, checkpoint_interval=4, witness_count=3)
    full = template.registry
    template.registry = TrustedRegistry(
        publishers=full.publishers,
        witnesses=full.witnesses,
        witness_policies=[],  # policy deleted -> verifier fails closed
        registry_id="no-witness-policy",
    )
    ctx = contexts_by_id(representative_contexts())["q2_connected_persistent"]
    gen = generate_trace(
        scenario="clean", context=ctx, arm="A6",
        seed=20260710, repetition=0, n_records=8, checkpoint_interval=4,
    )
    trace = bind_trace_to_crypto(gen.trace, template)
    artifact = verify_real_crypto_case(trace, template)
    assert artifact["stream_verdict"]["outcome"] == "reject"
    result = audit_evidence(construct_auditor_input(trace, crypto_artifact=artifact), qos_aware=True)
    assert result["decision"] != "accept"
    assert "CRYPTO_STREAM_REJECTED" in result["reason_codes"]


def _a6_two_checkpoint_case():
    template = build_crypto_template("A6", n_records=8, checkpoint_interval=4, witness_count=3)
    ctx = contexts_by_id(representative_contexts())["q2_connected_persistent"]
    gen = generate_trace(
        scenario="clean", context=ctx, arm="A6",
        seed=20260710, repetition=0, n_records=8, checkpoint_interval=4,
    )
    trace = bind_trace_to_crypto(gen.trace, template)
    return template, trace


@pytest.mark.parametrize("pattern", [[False, True], [True, False]])
def test_witness_signature_validity_is_bound_per_receipt(pattern):
    # Two receipts from one witness across different checkpoints must not
    # collapse to a single validity in the auditor projection.
    template, trace = _a6_two_checkpoint_case()
    artifact = verify_real_crypto_case(trace, template)
    facts = artifact["witness_receipt_signatures"]
    from collections import Counter

    witness = next(w for w, n in Counter(f["witness_id"] for f in facts).items() if n >= 2)
    w_facts = [f for f in facts if f["witness_id"] == witness]
    assert len(w_facts) >= 2
    w_facts[0]["signature_valid"] = pattern[0]
    w_facts[1]["signature_valid"] = pattern[1]

    ai = construct_auditor_input(trace, crypto_artifact=artifact)
    projected = {
        r["anchor"]: r["signature_valid"]
        for r in ai["witness_receipts"] if r["witness_id"] == witness
    }
    expected = {f["checkpoint_anchor_hex"]: f["signature_valid"] for f in w_facts}
    assert projected == expected
    assert set(projected.values()) == {False, True}  # both preserved, not collapsed


@pytest.mark.parametrize("pattern", [[True, False], [False, True]])
def test_two_receipts_same_witness_same_checkpoint_do_not_collapse(pattern):
    # Two receipts from one witness on the SAME checkpoint (differing only in
    # signature) must key by distinct RECOMPUTED receipt_id and keep independent
    # validity.  The auditor recomputes the id from body/signature/public key and
    # never trusts the stored value, so facts are keyed by the recomputed id.
    from aapa_mqtt import receipt_id_from_dict

    template, trace = _a6_two_checkpoint_case()
    artifact = verify_real_crypto_case(trace, template)
    ev0 = artifact["bundle"]["evidence"][0]
    base = dict(ev0["witness_receipts"][0])
    dup = dict(base)
    dup["signature_hex"] = "00" * (len(base["signature_hex"]) // 2)
    base_id = receipt_id_from_dict(base)
    dup_id = receipt_id_from_dict(dup)
    base["receipt_id"] = base_id
    dup["receipt_id"] = dup_id
    assert dup_id != base_id  # distinct body/signature -> distinct recomputed id
    ev0["witness_receipts"] = [base, dup]
    artifact["witness_receipt_signatures"] = [
        {"receipt_id": base_id, "signature_valid": pattern[0]},
        {"receipt_id": dup_id, "signature_valid": pattern[1]},
    ]
    ai = construct_auditor_input(trace, crypto_artifact=artifact)
    validities = [
        r["signature_valid"] for r in ai["witness_receipts"]
        if r["witness_id"] == base["witness_id"] and r["anchor"] == base["checkpoint_anchor_hex"]
    ]
    assert len(validities) == 2
    assert set(validities) == {True, False}  # not collapsed to a single value


def test_auditor_ignores_tampered_stored_receipt_id():
    # Security property (T4.4): the auditor recomputes receipt_id from the signed
    # body and does not trust the packaged value.  A receipt whose stored
    # receipt_id is tampered to point at a valid fact must still fail closed.
    from aapa_mqtt import receipt_id_from_dict

    template, trace = _a6_two_checkpoint_case()
    artifact = verify_real_crypto_case(trace, template)
    ev0 = artifact["bundle"]["evidence"][0]
    receipt = dict(ev0["witness_receipts"][0])
    true_id = receipt_id_from_dict(receipt)
    receipt["receipt_id"] = "e" * 64  # tampered self-reported id
    ev0["witness_receipts"] = [receipt]
    # The (only) fact is keyed by the tampered id and claims validity.
    artifact["witness_receipt_signatures"] = [
        {"receipt_id": "e" * 64, "signature_valid": True}
    ]
    ai = construct_auditor_input(trace, crypto_artifact=artifact)
    matches = [
        r["signature_valid"] for r in ai["witness_receipts"]
        if r["witness_id"] == receipt["witness_id"] and r["anchor"] == receipt["checkpoint_anchor_hex"]
    ]
    assert matches, "receipt should be projected"
    assert all(v is False for v in matches)  # tampered id not trusted -> fail closed
    assert "e" * 64 != true_id


def test_witness_key_substitution_rejected_through_full_pipeline():
    # Key substitution must be caught along bridge -> construct -> auditor, not
    # only by a direct verify_signature call.
    import oqs

    template = build_crypto_template("A6", n_records=8, checkpoint_interval=4, witness_count=3)
    receipt = template.evidence[0].witness_receipts[0]
    with oqs.Signature("ML-DSA-65") as attacker:
        attacker_pub = attacker.generate_keypair()
        attacker_sig = attacker.sign(receipt.serialize())
    receipt.public_key = attacker_pub  # self-consistent, but not registry-authorized
    receipt.signature = attacker_sig
    substituted_anchor = receipt.checkpoint_anchor.hex()
    substituted_witness = receipt.witness_id

    ctx = contexts_by_id(representative_contexts())["q2_connected_persistent"]
    gen = generate_trace(
        scenario="clean", context=ctx, arm="A6",
        seed=20260710, repetition=0, n_records=8, checkpoint_interval=4,
    )
    trace = bind_trace_to_crypto(gen.trace, template)
    artifact = verify_real_crypto_case(trace, template)
    ai = construct_auditor_input(trace, crypto_artifact=artifact)

    substituted = [
        r for r in ai["witness_receipts"]
        if r["witness_id"] == substituted_witness and r["anchor"] == substituted_anchor
    ]
    assert substituted and all(not r["signature_valid"] for r in substituted)
    assert audit_evidence(ai, qos_aware=True)["decision"] != "accept"


def test_auditor_accepts_only_on_exact_crypto_accept():
    # Any authoritative outcome other than exactly "accept" (here a malformed
    # value) must fail closed rather than ACCEPT.
    template = build_crypto_template("A4", n_records=8, checkpoint_interval=4, witness_count=3)
    ctx = contexts_by_id(representative_contexts())["q2_connected_persistent"]
    gen = generate_trace(
        scenario="clean", context=ctx, arm="A4",
        seed=20260710, repetition=0, n_records=8, checkpoint_interval=4,
    )
    trace = bind_trace_to_crypto(gen.trace, template)
    artifact = verify_real_crypto_case(trace, template)
    assert artifact["stream_verdict"]["outcome"] == "accept"  # baseline accepts
    artifact["stream_verdict"]["outcome"] = "unexpected"
    result = audit_evidence(construct_auditor_input(trace, crypto_artifact=artifact), qos_aware=True)
    assert result["decision"] != "accept"
    assert "CRYPTO_STREAM_OUTCOME_UNRECOGNIZED" in result["reason_codes"]


@pytest.mark.parametrize("arm", ["A0", "A1", "A2", "A3", "A4", "A6"])
def test_delayed_delivery_benign_oracle_and_auditor_agree(arm):
    # A benign delayed delivery preserves order: the message is recorded as a
    # network delay (delay_steps) without reordering, the oracle marks it
    # compliant, and the QoS-aware auditor raises no broker ordering violation.
    ctx = contexts_by_id(representative_contexts())["q1_connected_persistent"]
    template = build_crypto_template(arm, n_records=8, checkpoint_interval=4, witness_count=3)
    gen = generate_trace(
        scenario="delayed_delivery", context=ctx, arm=arm,
        seed=20260710, repetition=0, n_records=8, checkpoint_interval=4,
    )
    trace = bind_trace_to_crypto(gen.trace, template)

    actions = {e.get("action") for e in trace["timeline"] if e.get("event") == "causal_action"}
    assert "delay_delivery" in actions
    deliveries = [e for e in trace["timeline"] if e.get("event") == "subscriber_delivery"]
    assert any(int(d.get("delay_steps", 0)) > 0 for d in deliveries)
    seqs = [int(d["seq"]) for d in deliveries]
    assert seqs == sorted(seqs)  # delivery order preserved, no reorder

    assert semantic_oracle(trace, ctx)["semantic_status"] == "compliant"
    result = audit_evidence(construct_auditor_input(trace, crypto_artifact=verify_real_crypto_case(trace, template)), qos_aware=True)
    assert result["decision"] != "detect"
    assert "ORDERED_FLOW_VIOLATED" not in result["reason_codes"]
