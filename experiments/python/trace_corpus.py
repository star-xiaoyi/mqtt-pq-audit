#!/usr/bin/env python3
"""Deterministic MQTT audit trace corpus generator.

The generator owns scenario construction only.  It does not decide whether a
timeline is semantically legal and it does not audit evidence.  A generated
case keeps its scenario identifier outside the serialised raw trace; the
auditor receives an even narrower projection built by ``evidence_auditor``.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from typing import Any, Mapping

from qos_semantics import QoSContext
from stream_identity import canonical_stream_id


TRACE_SCHEMA_VERSION = "mqtt-trace-corpus-v2"
DEFAULT_CORPUS_SEED = 20260710

MALICIOUS_SCENARIOS = (
    "tamper",
    "delete",
    "inject",
    "duplicate",
    "replay",
    "reorder",
    "cross_epoch_replay",
)

FAILURE_GRID_SCENARIOS = (
    "checkpoint_splice",
    "rollback",
    "middle_truncation",
    "tail_truncation",
    "split_view",
    "witness_unavailable",
    "below_quorum",
    "stale_anchor",
)

BENIGN_SCENARIOS = (
    "clean",
    "qos0_loss",
    "qos1_duplicate",
    "qos1_to_qos0_duplicate",
    "qos1_reconnect_late_duplicate",
    "subscriber_disconnect",
    "delayed_delivery",
)

ALL_SCENARIOS = MALICIOUS_SCENARIOS + FAILURE_GRID_SCENARIOS + BENIGN_SCENARIOS


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest_payload(seed: int, epoch: int, seq: int, suffix: str = "") -> str:
    material = f"trace:{seed}:epoch:{epoch}:seq:{seq}:{suffix}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _checkpoint_anchor(prev_anchor: str, records: list[Mapping[str, Any]]) -> str:
    body = {
        "prev_anchor": prev_anchor,
        "records": [
            {"epoch": record["epoch"], "seq": record["seq"], "digest": record["digest"]}
            for record in records
        ],
    }
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


@dataclass(frozen=True)
class GeneratedTraceCase:
    """A raw timeline plus generator-only labels kept out of auditor input."""

    scenario_id: str
    scenario_class: str
    trace: dict[str, Any]


def _scenario_class(scenario: str) -> str:
    if scenario in MALICIOUS_SCENARIOS:
        return "malicious_manipulation"
    if scenario in FAILURE_GRID_SCENARIOS:
        return "evidence_or_availability_failure"
    return "benign_control"


def _renumber_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        item = dict(event)
        item["time_index"] = index
        output.append(item)
    return output


def case_id_for(
    *,
    seed: int,
    repetition: int,
    scenario: str,
    context: QoSContext,
    arm: str,
) -> str:
    """Deterministic case identifier binding seed, repetition, scenario, context, arm.

    Sole source of truth for the corpus case identifier: the generator and the
    independent package validator both derive the identifier from this function,
    so a re-derived expected grid can be compared byte-for-byte against the
    corpus and any tampered arm/context/scenario/seed is detected.
    """

    case_material = {
        "seed": seed,
        "repetition": repetition,
        "scenario": scenario,
        "context": context.to_dict(),
        "arm": arm,
    }
    return hashlib.sha256(canonical_json_bytes(case_material)).hexdigest()[:24]


def generate_trace(
    *,
    scenario: str,
    context: QoSContext,
    arm: str,
    seed: int = DEFAULT_CORPUS_SEED,
    repetition: int = 0,
    n_records: int = 8,
    checkpoint_interval: int = 4,
) -> GeneratedTraceCase:
    """Generate one deterministic complete causal trace.

    The serialised trace contains raw events but no ``scenario``/``attack`` or
    expected verdict field.  Hidden causal events are retained for the
    independent semantic oracle; ``construct_auditor_input`` strips them.
    """

    if scenario not in ALL_SCENARIOS:
        raise ValueError(f"unsupported scenario: {scenario}")
    if n_records < 4 or checkpoint_interval < 2:
        raise ValueError("n_records >= 4 and checkpoint_interval >= 2 are required")
    if checkpoint_interval != context.application_epoch_span:
        raise ValueError("checkpoint_interval must match context.application_epoch_span")

    local_seed = int.from_bytes(
        hashlib.sha256(f"{seed}:{repetition}:{scenario}:{context.context_id}:{arm}".encode()).digest()[:8],
        "big",
    )
    rng = random.Random(local_seed)
    topic = "telemetry/audit"

    publisher_records: list[dict[str, Any]] = []
    deliveries: list[dict[str, Any]] = []
    for seq in range(1, n_records + 1):
        epoch = context.initial_epoch + (seq - 1) // checkpoint_interval
        packet_id = (1000 + seq) if context.effective_qos > 0 else None
        record = {
            "epoch": epoch,
            "seq": seq,
            "digest": _digest_payload(local_seed, epoch, seq),
            "topic": topic,
        }
        publisher_records.append(record)
        deliveries.append({
            **record,
            "qos": context.effective_qos,
            "dup": False,
            "packet_id": packet_id,
            "retransmission": False,
            "inflight_retransmission": False,
            "reconnect_resend": False,
            "ack_observed_after_delivery": context.effective_qos > 0,
            "view_id": "primary",
            "auditor_visible": True,
        })

    prev_anchor = "0" * 64
    checkpoints: list[dict[str, Any]] = []
    for offset in range(0, n_records, checkpoint_interval):
        batch = publisher_records[offset:offset + checkpoint_interval]
        anchor = _checkpoint_anchor(prev_anchor, batch)
        checkpoints.append({
            "stream_id": canonical_stream_id("publisher-001", topic),
            "client_id": "publisher-001",
            "topic": topic,
            "key_id": "publisher-key-001",
            "epoch": batch[0]["epoch"],
            "seq_start": batch[0]["seq"],
            "seq_end": batch[-1]["seq"],
            "prev_anchor": prev_anchor,
            "end_anchor": anchor,
            "signature_valid": True,
            "auditor_visible": True,
        })
        prev_anchor = anchor

    actions: list[dict[str, Any]] = []

    def causal(action: str, actor: str, **details: Any) -> None:
        actions.append({"event": "causal_action", "action": action, "actor": actor, **details})

    middle = rng.randrange(1, n_records - 1)
    disconnect_cut = max(1, n_records - checkpoint_interval)
    if scenario == "tamper":
        target = deliveries[middle]
        target["digest"] = _digest_payload(local_seed, target["epoch"], target["seq"], "tampered")
        causal("modify_payload", "broker", seq=target["seq"])
    elif scenario == "delete":
        if context.audit_phase == "before_reconnect":
            middle = max(disconnect_cut, middle)
        target = deliveries.pop(middle)
        causal("drop_record", "broker", seq=target["seq"])
    elif scenario == "inject":
        injected_seq = n_records + 10_000
        deliveries.insert(middle, {
            "epoch": context.initial_epoch,
            "seq": injected_seq,
            "digest": _digest_payload(local_seed, context.initial_epoch, injected_seq, "injected"),
            "topic": topic,
            "qos": context.effective_qos,
            "dup": False,
            "packet_id": 60_000 if context.effective_qos else None,
            "retransmission": False,
            "view_id": "primary",
            "auditor_visible": True,
        })
        causal("inject_record", "broker", seq=injected_seq)
    elif scenario == "duplicate":
        duplicate = dict(deliveries[middle])
        duplicate["dup"] = False
        duplicate["packet_id"] = 50_000 if context.effective_qos else None
        deliveries.insert(middle + 1, duplicate)
        causal("duplicate_record", "broker", seq=duplicate["seq"])
    elif scenario == "replay":
        replayed = dict(deliveries[0])
        replayed["dup"] = False
        replayed["packet_id"] = 50_001 if context.effective_qos else None
        # Ordinary replay remains within the first checkpoint epoch.  In QoS 1
        # evidence it is observationally indistinguishable from a late
        # application duplicate; cross-epoch replay is generated separately.
        deliveries.insert(min(checkpoint_interval - 1, len(deliveries)), replayed)
        causal("replay_record", "broker", seq=replayed["seq"])
    elif scenario == "reorder":
        deliveries[middle - 1], deliveries[middle] = deliveries[middle], deliveries[middle - 1]
        causal("reorder_delivery", "broker", seq_a=deliveries[middle - 1]["seq"], seq_b=deliveries[middle]["seq"])
    elif scenario == "cross_epoch_replay":
        old = dict(deliveries[0])
        old["dup"] = False
        old["packet_id"] = 50_002 if context.effective_qos else None
        deliveries.append(old)
        causal("cross_epoch_replay", "broker", replay_epoch=old["epoch"], current_epoch=checkpoints[-1]["epoch"])
    elif scenario == "checkpoint_splice":
        if len(checkpoints) > 1:
            checkpoints[1]["stream_id"] = canonical_stream_id("publisher-001", "telemetry/other")
            checkpoints[1]["topic"] = "telemetry/other"
            checkpoints[1]["prev_anchor"] = "f" * 64
        causal("checkpoint_splice", "broker")
    elif scenario == "rollback":
        for checkpoint in checkpoints[-1:]:
            checkpoint["auditor_visible"] = False
            for delivery in deliveries:
                if checkpoint["seq_start"] <= delivery["seq"] <= checkpoint["seq_end"]:
                    delivery["auditor_visible"] = False
        causal("checkpoint_rollback", "broker")
    elif scenario == "middle_truncation":
        if len(checkpoints) > 1:
            first = checkpoints[0]
            first["auditor_visible"] = False
            for delivery in deliveries:
                if first["seq_start"] <= delivery["seq"] <= first["seq_end"]:
                    delivery["auditor_visible"] = False
        causal("omit_middle_checkpoint", "broker")
    elif scenario == "tail_truncation":
        last = checkpoints[-1]
        last["auditor_visible"] = False
        for delivery in deliveries:
            if last["seq_start"] <= delivery["seq"] <= last["seq_end"]:
                delivery["auditor_visible"] = False
        causal("omit_tail_checkpoint", "broker")
    elif scenario == "split_view":
        forked = [dict(delivery) for delivery in deliveries]
        forked[-1]["view_id"] = "secondary"
        forked[-1]["digest"] = _digest_payload(
            local_seed, forked[-1]["epoch"], forked[-1]["seq"], "split-view"
        )
        deliveries.extend(forked)
        causal("split_view", "broker")
    elif scenario == "witness_unavailable":
        causal("withhold_witness_receipts", "witness")
    elif scenario == "below_quorum":
        causal("below_witness_quorum", "witness")
    elif scenario == "stale_anchor":
        causal("stale_anchor", "external_anchor")
    elif scenario == "qos0_loss":
        target = deliveries.pop(middle)
        causal("drop_record", "network", seq=target["seq"])
    elif scenario == "qos1_duplicate":
        duplicate = dict(deliveries[middle])
        duplicate["dup"] = True
        duplicate["retransmission"] = True
        duplicate["inflight_retransmission"] = True
        deliveries.insert(middle + 1, duplicate)
        causal("legitimate_retransmission", "broker", seq=duplicate["seq"])
    elif scenario == "qos1_to_qos0_duplicate":
        duplicate = dict(deliveries[middle])
        # MQTT 3.1.1 permits a QoS 1 publication to be delivered more than once
        # to a QoS 0 subscriber.  The outgoing QoS 0 PUBLISH has no Packet
        # Identifier and DUP is not an application-message identity oracle.
        duplicate["qos"] = 0
        duplicate["dup"] = False
        duplicate["packet_id"] = None
        duplicate["retransmission"] = False
        duplicate["inflight_retransmission"] = False
        duplicate["ack_observed_after_delivery"] = False
        deliveries.insert(middle + 1, duplicate)
        causal("legitimate_qos_downgrade_duplicate", "broker", seq=duplicate["seq"])
    elif scenario == "qos1_reconnect_late_duplicate":
        # A legal retransmission can arrive after a later message following a
        # reconnect, creating a local sequence regression without crossing an
        # application epoch boundary.
        source_index = min(1, len(deliveries) - 1)
        duplicate = dict(deliveries[source_index])
        duplicate["dup"] = True
        duplicate["retransmission"] = True
        duplicate["inflight_retransmission"] = True
        duplicate["reconnect_resend"] = True
        deliveries.insert(min(checkpoint_interval - 1, len(deliveries)), duplicate)
        actions.append({
            "event": "session_state", "actor": "subscriber",
            "state": "disconnected", "after_seq": duplicate["seq"],
            "pending_packet_id": duplicate["packet_id"],
            "inflight_state": "awaiting_puback_or_ack_state_unknown",
        })
        actions.append({
            "event": "session_state", "actor": "subscriber",
            "state": "reconnected", "session_present": True,
            "inflight_state": "resend_pending_publish",
        })
        causal("legitimate_late_retransmission", "broker", seq=duplicate["seq"])
    elif scenario == "subscriber_disconnect":
        for delivery in deliveries[disconnect_cut:]:
            delivery["auditor_visible"] = False
        causal("subscriber_disconnect", "subscriber", after_seq=disconnect_cut)
        causal("delivery_not_observed", "subscriber", after_seq=disconnect_cut)
    elif scenario == "delayed_delivery":
        # Benign latency: MQTT preserves per-topic ordering, so a delayed message
        # is still delivered in sequence.  We annotate the added delay only and
        # do NOT reorder the delivery stream — reordering is a distinct,
        # non-benign scenario handled by "reorder".
        deliveries[middle]["delay_steps"] = checkpoint_interval
        causal("delay_delivery", "network", seq=deliveries[middle]["seq"])

    if context.audit_phase == "before_reconnect" and scenario != "subscriber_disconnect":
        for delivery in deliveries:
            if int(delivery["seq"]) > disconnect_cut:
                delivery["auditor_visible"] = False
        actions.append({
            "event": "session_state", "actor": "subscriber",
            "state": "disconnected", "after_seq": disconnect_cut,
            "audit_phase": "before_reconnect",
            "queue_obligation": (
                "pending_until_reconnect"
                if context.session_mode == "persistent"
                else "not_retained_by_clean_session"
            ),
        })
    if context.audit_phase == "after_reconnect" and not any(
        event.get("event") == "session_state" for event in actions
    ):
        actions.extend((
            {
                "event": "session_state", "actor": "subscriber",
                "state": "disconnected", "audit_phase": "before_reconnect",
            },
            {
                "event": "session_state", "actor": "subscriber",
                "state": "reconnected", "session_present": context.session_present,
                "audit_phase": "after_reconnect",
            },
        ))

    timeline: list[dict[str, Any]] = []
    timeline.extend(actions)
    for record in publisher_records:
        timeline.append({"event": "publisher_publish", "actor": "publisher", **record})
        timeline.append({
            "event": "broker_accept",
            "actor": "broker",
            "epoch": record["epoch"],
            "seq": record["seq"],
            "publisher_qos": context.publisher_qos,
            "completion_observed": context.publisher_qos > 0,
        })
    for checkpoint in checkpoints:
        timeline.append({"event": "checkpoint_created", "actor": "publisher", **checkpoint})
        if checkpoint["auditor_visible"]:
            timeline.append({"event": "checkpoint_presented", "actor": "broker", **checkpoint})
    for order, delivery in enumerate(deliveries):
        timeline.append({
            "event": "subscriber_delivery",
            "actor": "subscriber",
            "delivery_order": order,
            **delivery,
        })

    latest = checkpoints[-1]
    timeline.append({
        "event": "trusted_latest_anchor",
        "actor": "external_anchor",
        "stream_id": latest["stream_id"],
        "epoch": latest["epoch"],
        "seq_end": latest["seq_end"],
        "anchor": latest["end_anchor"],
        "age_seconds": 86_401 if scenario == "stale_anchor" else 1,
    })
    for checkpoint in checkpoints:
        for witness_index in range(3):
            timeline.append({
                "event": "witness_receipt",
                "actor": "witness",
                "witness_id": f"witness-{witness_index + 1}",
                "key_id": f"witness-key-{witness_index + 1}",
                "stream_id": checkpoint["stream_id"],
                "epoch": checkpoint["epoch"],
                "seq_end": checkpoint["seq_end"],
                "anchor": checkpoint["end_anchor"],
                "signature_valid": True,
            })

    case_id = case_id_for(
        seed=seed,
        repetition=repetition,
        scenario=scenario,
        context=context,
        arm=arm,
    )
    trace = {
        "schema_version": TRACE_SCHEMA_VERSION,
        "case_id": case_id,
        "seed": seed,
        "case_seed": local_seed,
        "repetition": repetition,
        "arm": arm,
        "qos_context": context.to_dict(),
        "timeline": _renumber_timeline(timeline),
    }
    return GeneratedTraceCase(
        scenario_id=scenario,
        scenario_class=_scenario_class(scenario),
        trace=trace,
    )


def assert_trace_has_no_expected_labels(trace: Mapping[str, Any]) -> None:
    """Guard against runner-authored answers entering the raw corpus."""

    forbidden = {"expected", "matches_expected", "ground_truth", "verdict", "attribution_label"}

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            overlap = forbidden & set(value)
            if overlap:
                raise ValueError(f"raw trace contains forbidden expected-label fields: {sorted(overlap)}")
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(trace)
