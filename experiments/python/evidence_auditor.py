#!/usr/bin/env python3
"""Scenario-blind evidence projection and QoS-aware/agnostic auditors.

The auditor accepts only the allowlisted schema produced by
``construct_auditor_input``.  It cannot read causal actions, scenario names,
ground truth, or runner-authored expected values.  The same input is evaluated
by the aware and agnostic modes; the latter merely withholds QoS/session
interpretation and never maps every anomaly to the broker by construction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import math
import struct
from typing import Any, Mapping


AUDITOR_INPUT_SCHEMA_VERSION = "mqtt-auditor-input-v2"
AUDITOR_RESULT_SCHEMA_VERSION = "mqtt-auditor-result-v2"
WITNESS_SIGNING_DOMAIN = b"AAPA-MQTT-WITNESS-V2|"


def _recompute_receipt_id(receipt: Mapping[str, Any]) -> str | None:
    """Recompute the canonical witness receipt_id from the receipt's own fields.

    Mirrors ``aapa_mqtt.WitnessReceipt.serialize`` + ``receipt_id`` without
    importing the crypto stack, so the auditor binds per-receipt validity to a
    re-derived ``sha256(body ‖ signature ‖ public_key)`` and never trusts the
    bundle-stored ``receipt_id``.  Returns ``None`` for a malformed receipt so the
    join fails closed.
    """
    try:
        wid = str(receipt["witness_id"]).encode("utf-8")
        stream = str(receipt["stream_id"]).encode("utf-8")
        prev_anchor = bytes.fromhex(receipt["prev_witnessed_anchor_hex"])
        end_anchor = bytes.fromhex(receipt["checkpoint_anchor_hex"])
        ts_witness = float(receipt["ts_witness"])
        if not math.isfinite(ts_witness):
            return None
        body = (
            WITNESS_SIGNING_DOMAIN
            + struct.pack(">H", len(wid)) + wid
            + struct.pack(">H", len(stream)) + stream
            + struct.pack(">I", int(receipt["checkpoint_epoch"]))
            + struct.pack(">I", int(receipt["seq_start"]))
            + struct.pack(">I", int(receipt["seq_end"]))
            + struct.pack(">H", len(prev_anchor)) + prev_anchor
            + struct.pack(">H", len(end_anchor)) + end_anchor
            + struct.pack(">d", ts_witness)
        )
        signature = bytes.fromhex(receipt.get("signature_hex", ""))
        public_key = bytes.fromhex(receipt.get("public_key_hex", ""))
    except (KeyError, ValueError, TypeError):
        return None
    return hashlib.sha256(body + signature + public_key).hexdigest()

FORBIDDEN_AUDITOR_KEYS = {
    "attack",
    "scenario",
    "scenario_id",
    "scenario_class",
    "expected",
    "expected_result",
    "ground_truth",
    "matches_expected",
    "semantic_violation",
    "physical_actor",
    "protocol_responsible_party",
    "causal_action",
}


ARM_CAPABILITIES: dict[str, dict[str, Any]] = {
    "A0": {"mechanism": "classical_merkle_checkpoint", "transferable": True, "pq": False},
    "A1": {"mechanism": "per_message_ml_dsa", "transferable": True, "pq": True},
    "A2": {"mechanism": "ml_kem_session_mac", "transferable": False, "pq": True},
    "A3": {"mechanism": "hash_chain_ml_dsa_checkpoint", "transferable": True, "pq": True},
    "A4": {"mechanism": "merkle_ml_dsa_checkpoint", "transferable": True, "pq": True},
    "A6": {"mechanism": "witnessed_merkle_ml_dsa_checkpoint", "transferable": True, "pq": True},
}


@dataclass(frozen=True)
class TrustProfile:
    registry_present: bool = True
    publisher_key_trusted: bool = True
    publisher_authorized_for_stream: bool = True
    trusted_genesis_present: bool = True
    latest_anchor_present: bool = True
    anchor_max_age_seconds: int = 86_400
    witness_registry_present: bool = True
    witness_quorum_required: int = 2
    available_witnesses: int = 3
    honest_subscriber: bool = True
    cross_epoch_freshness_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def with_changes(self, **changes: Any) -> "TrustProfile":
        return replace(self, **changes)


def _events(trace: Mapping[str, Any], event_type: str) -> list[Mapping[str, Any]]:
    return [event for event in trace.get("timeline", ()) if event.get("event") == event_type]


def _actions(trace: Mapping[str, Any]) -> set[str]:
    return {
        str(event.get("action"))
        for event in trace.get("timeline", ())
        if event.get("event") == "causal_action"
    }


def _record_projection(event: Mapping[str, Any], *, delivery: bool = False) -> dict[str, Any]:
    projected = {
        "epoch": int(event["epoch"]),
        "seq": int(event["seq"]),
        "digest": str(event["digest"]),
        "topic": str(event["topic"]),
    }
    if delivery:
        projected.update({
            "delivery_order": int(event.get("delivery_order", 0)),
            "qos": int(event.get("qos", 0)),
            "dup": bool(event.get("dup", False)),
            "packet_id": event.get("packet_id"),
            "retransmission": bool(event.get("retransmission", False)),
            "inflight_retransmission": bool(event.get("inflight_retransmission", False)),
            "reconnect_resend": bool(event.get("reconnect_resend", False)),
            "ack_observed_after_delivery": bool(event.get("ack_observed_after_delivery", False)),
            "view_id": str(event.get("view_id") or "primary"),
        })
    return projected


def construct_auditor_input(
    trace: Mapping[str, Any],
    *,
    trust_profile: TrustProfile | None = None,
    crypto_artifact: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project a full trace into the only information available to an auditor."""

    profile = trust_profile or TrustProfile()
    arm = str(trace.get("arm"))
    if arm not in ARM_CAPABILITIES:
        raise ValueError(f"unknown arm: {arm}")
    capability = ARM_CAPABILITIES[arm]
    actions = _actions(trace)

    presented_checkpoints = _events(trace, "checkpoint_presented")
    presented_ranges = [
        (int(checkpoint["seq_start"]), int(checkpoint["seq_end"]))
        for checkpoint in presented_checkpoints
    ]

    bundle_omits_history = bool(actions & {
        "checkpoint_rollback", "omit_middle_checkpoint", "omit_tail_checkpoint"
    })
    publisher_records = _events(trace, "publisher_publish")
    if bundle_omits_history:
        publisher_records = [
            record
            for record in publisher_records
            if any(start <= int(record["seq"]) <= end for start, end in presented_ranges)
        ]

    committed_records = [_record_projection(record) for record in publisher_records]
    deliveries = [
        _record_projection(event, delivery=True)
        for event in _events(trace, "subscriber_delivery")
        if bool(event.get("auditor_visible", True))
    ]

    publisher_map = {
        (record["epoch"], record["seq"]): record["digest"]
        for record in [_record_projection(event) for event in _events(trace, "publisher_publish")]
    }
    mac_results = []
    for delivered in deliveries:
        expected_digest = publisher_map.get((delivered["epoch"], delivered["seq"]))
        mac_results.append({
            "epoch": delivered["epoch"],
            "seq": delivered["seq"],
            "valid": expected_digest == delivered["digest"],
            "accepted_by_subscriber": expected_digest == delivered["digest"],
        })

    checkpoint_projection = []
    for checkpoint in presented_checkpoints:
        checkpoint_projection.append({
            "stream_id": str(checkpoint["stream_id"]),
            "client_id": str(checkpoint["client_id"]),
            "topic": str(checkpoint["topic"]),
            "key_id": str(checkpoint["key_id"]),
            "epoch": int(checkpoint["epoch"]),
            "seq_start": int(checkpoint["seq_start"]),
            "seq_end": int(checkpoint["seq_end"]),
            "prev_anchor": str(checkpoint["prev_anchor"]),
            "end_anchor": str(checkpoint["end_anchor"]),
        })

    anchor_events = _events(trace, "trusted_latest_anchor")
    anchor = None
    if profile.latest_anchor_present and anchor_events:
        event = anchor_events[-1]
        anchor = {
            "stream_id": str(event["stream_id"]),
            "epoch": int(event["epoch"]),
            "seq_end": int(event["seq_end"]),
            "anchor": str(event["anchor"]),
            "age_seconds": int(event.get("age_seconds", 0)),
            "max_age_seconds": int(profile.anchor_max_age_seconds),
        }

    receipt_events = _events(trace, "witness_receipt") if arm == "A6" else []
    available_count = profile.available_witnesses
    if "withhold_witness_receipts" in actions:
        available_count = 0
    elif "below_witness_quorum" in actions:
        available_count = min(1, max(0, profile.witness_quorum_required - 1))
    receipts = []
    for event in receipt_events[:available_count]:
        receipts.append({
            "witness_id": str(event["witness_id"]),
            "key_id": str(event["key_id"]),
            "stream_id": str(event["stream_id"]),
            "epoch": int(event["epoch"]),
            "seq_end": int(event["seq_end"]),
            "anchor": str(event["anchor"]),
            "signature_valid": bool(event.get("signature_valid", False)),
            "registry_trusted": bool(profile.witness_registry_present),
        })

    completed = {
        (int(event["epoch"]), int(event["seq"]))
        for event in _events(trace, "broker_accept")
        if bool(event.get("completion_observed"))
    }

    trusted_genesis_anchor = "0" * 64 if profile.trusted_genesis_present else None
    crypto_verification: dict[str, Any] = {
        "performed": False,
        "artifact_id": None,
        "stream_outcome": "inconclusive",
        "reason_codes": ["REAL_CRYPTO_EVIDENCE_NOT_BOUND"],
        "verified_checkpoints": 0,
        "verified_records": 0,
    }
    if crypto_artifact is not None:
        bundle = crypto_artifact.get("bundle")
        registry_document = crypto_artifact.get("trusted_registry")
        anchor_document = crypto_artifact.get("trusted_anchors")
        stream_verdict = dict(crypto_artifact.get("stream_verdict") or {})
        crypto_verification = {
            "performed": True,
            "artifact_id": crypto_artifact.get("artifact_id"),
            "stream_outcome": stream_verdict.get("outcome"),
            "reason_codes": list(stream_verdict.get("reason_codes") or []),
            "verified_checkpoints": int(stream_verdict.get("verified_checkpoints", 0)),
            "verified_records": int(stream_verdict.get("verified_records", 0)),
            "tail_complete": bool(stream_verdict.get("tail_complete", False)),
            "verification_time_ms": float(stream_verdict.get("verification_time_ms", 0.0)),
        }
        session_mac_rows = list(crypto_artifact.get("wire_verification") or [])
        mac_results = [
            {
                "epoch": row.get("epoch"),
                "seq": row.get("seq"),
                "valid": bool(row.get("valid")),
                "accepted_by_subscriber": bool(row.get("valid")),
                "reason_code": row.get("reason_code"),
            }
            for row in session_mac_rows
        ]
        if isinstance(bundle, Mapping):
            committed_records = []
            checkpoint_projection = []
            receipts = []
            trusted_witness_ids = {
                str(row.get("witness_id"))
                for row in (registry_document or {}).get("witnesses", ())
            } if isinstance(registry_document, Mapping) else set()
            # Observed per-receipt signature validity comes from the crypto
            # bridge, keyed by a stable receipt_id (SHA-256 over signed body +
            # signature + public key) so two receipts from one witness on one
            # checkpoint cannot collapse to a single validity.
            witness_signature_valid = {
                str(fact.get("receipt_id")): bool(fact.get("signature_valid"))
                for fact in crypto_artifact.get("witness_receipt_signatures", ())
            }
            for evidence_row in bundle.get("evidence", ()):
                checkpoint = evidence_row["checkpoint"]
                checkpoint_projection.append({
                    "stream_id": bundle.get("stream_id"),
                    "client_id": checkpoint["client_id"],
                    "topic": checkpoint["topic"],
                    "key_id": None,
                    "epoch": int(checkpoint["epoch"]),
                    "seq_start": int(checkpoint["seq_start"]),
                    "seq_end": int(checkpoint["seq_end"]),
                    "prev_anchor": checkpoint["prev_anchor_hex"],
                    "end_anchor": checkpoint["end_anchor_hex"],
                })
                for raw_hex in evidence_row.get("records_hex", ()):
                    raw = bytes.fromhex(raw_hex)
                    seq = struct.unpack(">I", raw[:4])[0]
                    committed_records.append({
                        "epoch": int(checkpoint["epoch"]),
                        "seq": seq,
                        "digest": hashlib.sha256(raw).hexdigest(),
                        "topic": checkpoint["topic"],
                    })
                for receipt in evidence_row.get("witness_receipts", ()):
                    receipts.append({
                        "witness_id": receipt["witness_id"],
                        "key_id": hashlib.sha256(bytes.fromhex(receipt["public_key_hex"])).hexdigest(),
                        "stream_id": receipt["stream_id"],
                        "epoch": int(receipt["checkpoint_epoch"]),
                        "seq_end": int(receipt["seq_end"]),
                        "anchor": receipt["checkpoint_anchor_hex"],
                        "registry_trusted": receipt["witness_id"] in trusted_witness_ids,
                        "signature_valid": witness_signature_valid.get(_recompute_receipt_id(receipt), False),
                    })
        if isinstance(anchor_document, Mapping):
            streams = list(anchor_document.get("streams") or [])
            genesis = streams[0].get("genesis") if streams else None
            trusted_genesis_anchor = genesis.get("anchor_hex") if genesis else None
            latest = streams[0].get("latest") if streams else None
            if latest is not None:
                anchor = {
                    "stream_id": streams[0]["stream_id"],
                    "epoch": int(latest["epoch"]),
                    "seq_end": int(latest["seq_end"]),
                    "anchor": latest["anchor_hex"],
                    "age_seconds": max(0, int(crypto_artifact.get("audit_time", 0) - latest.get("observed_at", 0))),
                    "max_age_seconds": int(profile.anchor_max_age_seconds),
                }
        identity_registry_present = isinstance(registry_document, Mapping)
        identity_registry_match = (
            identity_registry_present
            and bool(registry_document.get("publishers"))
            and not any(
                code in crypto_verification["reason_codes"]
                for code in ("PUBLISHER_KEY_SUBSTITUTION", "PUBLISHER_NOT_AUTHORIZED")
            )
        )
    else:
        identity_registry_present = profile.registry_present
        identity_registry_match = profile.publisher_key_trusted

    value = {
        "schema_version": AUDITOR_INPUT_SCHEMA_VERSION,
        "case_id": str(trace["case_id"]),
        "arm": arm,
        "mechanism": capability["mechanism"],
        "transferable_evidence": bool(capability["transferable"]),
        "real_crypto_evidence": crypto_artifact is not None,
        "crypto_verification": crypto_verification,
        "qos_context": dict(trace["qos_context"]),
        "trust_assumptions": profile.to_dict(),
        "publisher_identity": {
            "client_id": "publisher-001",
            "key_id": "publisher-key-001",
            "registry_present": identity_registry_present,
            "registry_key_match": identity_registry_match,
            "authorized_for_stream": profile.publisher_authorized_for_stream,
        },
        "trusted_genesis_anchor": trusted_genesis_anchor,
        "committed_records": committed_records if capability["transferable"] else [],
        "presented_checkpoints": checkpoint_projection if capability["transferable"] else [],
        "subscriber_deliveries": deliveries,
        "publisher_completion_observations": [
            {"epoch": epoch, "seq": seq} for epoch, seq in sorted(completed)
        ],
        "session_mac_observations": mac_results if arm == "A2" else [],
        "trusted_latest_anchor": anchor,
        "witness_policy": {
            "required": arm == "A6",
            "quorum": profile.witness_quorum_required if arm == "A6" else 0,
        },
        "witness_receipts": receipts,
    }
    assert_auditor_input_is_blind(value)
    return value


def assert_auditor_input_is_blind(value: Mapping[str, Any]) -> None:
    """Reject direct or nested leakage of generator/oracle labels."""

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            overlap = FORBIDDEN_AUDITOR_KEYS & set(item)
            if overlap:
                raise ValueError(f"auditor input leaks forbidden fields: {sorted(overlap)}")
            for nested in item.values():
                walk(nested)
        elif isinstance(item, list):
            for nested in item:
                walk(nested)

    walk(value)


def _final_result(
    evidence: Mapping[str, Any],
    *,
    mode: str,
    decision: str,
    detected: bool,
    attribution: str | None,
    reason_codes: list[str],
    observed_facts: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": AUDITOR_RESULT_SCHEMA_VERSION,
        "case_id": evidence["case_id"],
        "auditor_mode": mode,
        "decision": decision,
        "detected": bool(detected),
        "attributable": attribution is not None,
        "attribution": attribution,
        "inconclusive": decision == "inconclusive",
        "reason_codes": sorted(set(reason_codes)),
        "observed_facts": dict(observed_facts),
    }


def audit_evidence(evidence: Mapping[str, Any], *, qos_aware: bool = True) -> dict[str, Any]:
    """Audit one evidence projection without scenario or expected-result access."""

    assert_auditor_input_is_blind(evidence)
    if evidence.get("schema_version") != AUDITOR_INPUT_SCHEMA_VERSION:
        raise ValueError("unsupported auditor input schema")
    mode = "qos_aware" if qos_aware else "qos_agnostic"
    reasons: list[str] = []
    facts: dict[str, Any] = {}
    arm = str(evidence["arm"])

    if not evidence.get("transferable_evidence"):
        mac_observations = list(evidence.get("session_mac_observations", ()))
        facts["session_mac_valid_count"] = sum(1 for item in mac_observations if item.get("valid"))
        facts["session_mac_invalid_count"] = sum(1 for item in mac_observations if not item.get("valid"))
        reasons.append("SESSION_MAC_NOT_TRANSFERABLE")
        if facts["session_mac_invalid_count"]:
            reasons.append("ONLINE_SESSION_INTEGRITY_FAILURE_REPORTED")
        return _final_result(
            evidence, mode=mode, decision="inconclusive", detected=False,
            attribution=None, reason_codes=reasons, observed_facts=facts,
        )

    crypto = evidence.get("crypto_verification", {})
    if not evidence.get("real_crypto_evidence") or not crypto.get("performed"):
        return _final_result(
            evidence, mode=mode, decision="inconclusive", detected=False,
            attribution=None, reason_codes=["REAL_CRYPTO_EVIDENCE_REQUIRED"],
            observed_facts={"real_crypto_verification_performed": False},
        )
    crypto_reasons = list(crypto.get("reason_codes") or [])
    crypto_outcome = str(crypto.get("stream_outcome") or "inconclusive")
    facts.update({
        "real_crypto_verification_performed": True,
        "crypto_stream_outcome": crypto_outcome,
        "crypto_verified_checkpoints": int(crypto.get("verified_checkpoints", 0)),
        "crypto_verified_records": int(crypto.get("verified_records", 0)),
    })
    trust_or_availability_reasons = {
        "REGISTRY_REQUIRED", "ANCHOR_SET_REQUIRED", "GENESIS_ANCHOR_REQUIRED",
        "LATEST_ANCHOR_MISSING", "TAIL_COMPLETENESS_UNPROVABLE", "LATEST_ANCHOR_STALE",
        "WITNESS_BELOW_QUORUM", "WITNESS_POLICY_MISSING", "WITNESS_UNTRUSTED",
    }
    crypto_integrity_failure = (
        crypto_outcome == "reject"
        and not set(crypto_reasons).issubset(trust_or_availability_reasons)
    )
    reasons.extend(f"CRYPTO_{reason}" for reason in crypto_reasons)

    identity = evidence.get("publisher_identity", {})
    if not identity.get("registry_present"):
        return _final_result(
            evidence, mode=mode, decision="inconclusive", detected=False,
            attribution=None, reason_codes=["TRUSTED_PUBLISHER_REGISTRY_MISSING"],
            observed_facts={"publisher_identity_bound": False},
        )
    if not identity.get("registry_key_match") or not identity.get("authorized_for_stream"):
        return _final_result(
            evidence, mode=mode, decision="reject", detected=True,
            attribution=None, reason_codes=["PUBLISHER_IDENTITY_OR_KEY_BINDING_REJECTED"],
            observed_facts={"publisher_identity_bound": False},
        )

    checkpoints = list(evidence.get("presented_checkpoints", ()))
    committed = list(evidence.get("committed_records", ()))
    deliveries = sorted(
        list(evidence.get("subscriber_deliveries", ())),
        key=lambda item: int(item.get("delivery_order", 0)),
    )
    facts.update({
        "publisher_identity_bound": True,
        "checkpoint_count": len(checkpoints),
        "committed_record_count": len(committed),
        "delivered_record_count": len(deliveries),
    })

    checkpoint_failure = crypto_integrity_failure
    if not evidence.get("trusted_genesis_anchor"):
        reasons.append("TRUSTED_GENESIS_MISSING")
    elif checkpoints:
        expected_prev = str(evidence["trusted_genesis_anchor"])
        expected_stream = checkpoints[0].get("stream_id")
        expected_topic = checkpoints[0].get("topic")
        previous_epoch = -1
        previous_end = 0
        for checkpoint in checkpoints:
            if checkpoint.get("prev_anchor") != expected_prev:
                checkpoint_failure = True
                reasons.append("CHECKPOINT_PREDECESSOR_MISMATCH")
            if checkpoint.get("stream_id") != expected_stream or checkpoint.get("topic") != expected_topic:
                checkpoint_failure = True
                reasons.append("CHECKPOINT_STREAM_SPLICE")
            if int(checkpoint.get("epoch", -1)) <= previous_epoch and previous_epoch >= 0:
                checkpoint_failure = True
                reasons.append("CHECKPOINT_EPOCH_NOT_MONOTONIC")
            if int(checkpoint.get("seq_start", 0)) != previous_end + 1:
                checkpoint_failure = True
                reasons.append("CHECKPOINT_COVERAGE_GAP_OR_OVERLAP")
            expected_prev = str(checkpoint.get("end_anchor"))
            previous_epoch = int(checkpoint.get("epoch", -1))
            previous_end = int(checkpoint.get("seq_end", 0))
    else:
        reasons.append("NO_TRANSFERABLE_CHECKPOINT_PRESENTED")

    latest_anchor = evidence.get("trusted_latest_anchor")
    latest_anchor_valid = False
    if latest_anchor:
        if int(latest_anchor.get("age_seconds", 0)) > int(latest_anchor.get("max_age_seconds", 0)):
            reasons.append("TRUSTED_LATEST_ANCHOR_STALE")
        elif not checkpoints:
            checkpoint_failure = True
            reasons.append("LATEST_ANCHOR_WITHOUT_PRESENTED_HISTORY")
        else:
            last = checkpoints[-1]
            latest_anchor_valid = (
                latest_anchor.get("anchor") == last.get("end_anchor")
                and int(latest_anchor.get("epoch", -1)) == int(last.get("epoch", -2))
                and int(latest_anchor.get("seq_end", -1)) == int(last.get("seq_end", -2))
            )
            if not latest_anchor_valid:
                checkpoint_failure = True
                reasons.append("LATEST_ANCHOR_MISMATCH_OR_ROLLBACK")
    else:
        reasons.append("TAIL_COMPLETENESS_UNPROVEN_NO_LATEST_ANCHOR")
    facts["latest_anchor_valid"] = latest_anchor_valid

    if arm == "A6":
        policy = evidence.get("witness_policy", {})
        receipts = list(evidence.get("witness_receipts", ()))
        trusted_identities: set[str] = set()
        trusted_keys: set[str] = set()
        valid_receipts = 0
        for receipt in receipts:
            witness_id = str(receipt.get("witness_id"))
            key_id = str(receipt.get("key_id"))
            if (
                receipt.get("registry_trusted")
                and receipt.get("signature_valid")
                and witness_id not in trusted_identities
                and key_id not in trusted_keys
            ):
                trusted_identities.add(witness_id)
                trusted_keys.add(key_id)
                valid_receipts += 1
        quorum = int(policy.get("quorum", 0))
        facts["distinct_trusted_witnesses"] = valid_receipts
        facts["witness_quorum"] = quorum
        if valid_receipts < quorum:
            reasons.append("DISTINCT_TRUSTED_WITNESS_QUORUM_NOT_MET")

    committed_by_key = {
        (int(item["epoch"]), int(item["seq"])): str(item["digest"])
        for item in committed
    }
    delivered_by_key: dict[tuple[int, int], list[Mapping[str, Any]]] = {}
    for item in deliveries:
        key = (int(item["epoch"]), int(item["seq"]))
        delivered_by_key.setdefault(key, []).append(item)

    uncommitted = []
    digest_mismatch = []
    for key, presented in delivered_by_key.items():
        expected_digest = committed_by_key.get(key)
        if expected_digest is None:
            uncommitted.append(key)
        elif any(str(item["digest"]) != expected_digest for item in presented):
            digest_mismatch.append(key)
    missing = sorted(set(committed_by_key) - set(delivered_by_key))
    duplicate_groups = {
        key: items for key, items in delivered_by_key.items() if len(items) > 1
    }
    context = evidence.get("qos_context", {})
    application_epoch_span = int(context.get("application_epoch_span", 4))
    initial_application_epoch = int(context.get("initial_epoch", 0))

    def application_position(item: Mapping[str, Any]) -> tuple[int, int]:
        seq = int(item["seq"])
        return (
            initial_application_epoch + (seq - 1) // application_epoch_span,
            seq,
        )

    delivered_sequence = [application_position(item) for item in deliveries]
    regression_indexes = [
        index for index in range(1, len(delivered_sequence))
        if delivered_sequence[index] < delivered_sequence[index - 1]
    ]
    sequence_regression = bool(regression_indexes)

    effective_qos = int(context.get("effective_qos", 0))
    publisher_qos = int(context.get("publisher_qos", effective_qos))
    application_duplicate_permitted = (
        effective_qos == 1
        or (publisher_qos == 1 and effective_qos == 0)
    )
    seen_delivery_keys: set[tuple[int, int]] = set()
    max_epoch_seen = -1
    cross_epoch_replay_indexes: list[int] = []
    explained_regressions: list[int] = []
    for index, item in enumerate(deliveries):
        commitment_key = (int(item["epoch"]), int(item["seq"]))
        semantic_key = application_position(item)
        is_repeat = commitment_key in seen_delivery_keys
        crosses_epoch = is_repeat and semantic_key[0] < max_epoch_seen
        if crosses_epoch:
            cross_epoch_replay_indexes.append(index)
        if (
            index in regression_indexes
            and is_repeat
            and application_duplicate_permitted
            and not crosses_epoch
        ):
            explained_regressions.append(index)
        seen_delivery_keys.add(commitment_key)
        max_epoch_seen = max(max_epoch_seen, semantic_key[0])
    unexplained_regressions = sorted(set(regression_indexes) - set(explained_regressions))
    divergent_views = [
        key for key, items in delivered_by_key.items()
        if len({str(item["digest"]) for item in items}) > 1
    ]
    facts.update({
        "uncommitted_records": len(uncommitted),
        "digest_mismatches": len(digest_mismatch),
        "missing_committed_records": len(missing),
        "duplicate_record_groups": len(duplicate_groups),
        "sequence_regression": sequence_regression,
        "explained_sequence_regressions": len(explained_regressions),
        "unexplained_sequence_regressions": len(unexplained_regressions),
        "cross_epoch_replay_observations": len(cross_epoch_replay_indexes),
        "divergent_views": len(divergent_views),
    })

    detected = checkpoint_failure
    attribution: str | None = "broker" if checkpoint_failure else None
    if uncommitted or digest_mismatch or divergent_views:
        detected = True
        attribution = "broker"
        if uncommitted:
            reasons.append("UNCOMMITTED_RECORD_PRESENTED")
        if digest_mismatch:
            reasons.append("PUBLISHER_COMMITMENT_DIGEST_MISMATCH")
        if divergent_views:
            reasons.append("DIVERGENT_SUBSCRIBER_VIEWS")

    honest_subscriber = bool(evidence.get("trust_assumptions", {}).get("honest_subscriber"))
    completion_keys = {
        (int(item["epoch"]), int(item["seq"]))
        for item in evidence.get("publisher_completion_observations", ())
    }

    if missing:
        if not qos_aware:
            detected = True
            reasons.append("DELIVERY_GAP_WITHOUT_QOS_INTERPRETATION")
        else:
            connected = bool(context.get("subscriber_connected"))
            session_mode = str(context.get("session_mode"))
            if effective_qos == 0:
                reasons.append("LOSS_PERMITTED_AT_EFFECTIVE_QOS0")
            elif not connected and session_mode == "clean":
                reasons.append("CLEAN_SESSION_HAS_NO_OFFLINE_QUEUE_OBLIGATION")
            elif not connected and session_mode == "persistent":
                reasons.append("PERSISTENT_SESSION_DELIVERY_PENDING_RECONNECT")
            else:
                detected = True
                reasons.append("QOS_DELIVERY_COMMITMENT_NOT_OBSERVED")
                completion_supported = all(key in completion_keys for key in missing)
                if not honest_subscriber or not completion_supported:
                    reasons.append("DELIVERY_GAP_ATTRIBUTION_REQUIRES_ENDPOINT_ASSUMPTIONS")
                else:
                    # A trusted first-hop completion and an honest subscriber
                    # establish a second-hop delivery gap, but do not distinguish
                    # a broker omission from an independent link failure.  The
                    # current evidence schema carries no authenticated second-hop
                    # path receipt that rules out that alternative, so physical
                    # actor attribution must remain empty.
                    reasons.append("DELIVERY_GAP_ACTOR_NOT_ISOLATED_FROM_LINK_FAILURE")

    if duplicate_groups:
        if qos_aware and application_duplicate_permitted:
            reasons.append("APPLICATION_DUPLICATE_PERMITTED_BY_TWO_HOP_QOS")
        else:
            detected = True
            reasons.append(
                "DUPLICATE_WITHOUT_QOS_SESSION_INTERPRETATION"
                if not qos_aware else "UNPERMITTED_DUPLICATE_DELIVERY"
            )
            if qos_aware and honest_subscriber:
                attribution = "broker"

    freshness_required = bool(
        evidence.get("trust_assumptions", {}).get("cross_epoch_freshness_required", True)
    )
    if qos_aware and freshness_required and cross_epoch_replay_indexes:
        detected = True
        reasons.append("CROSS_EPOCH_FRESHNESS_VIOLATED")
        if honest_subscriber:
            attribution = "broker"

    if unexplained_regressions:
        if not qos_aware or bool(context.get("ordered_topic", True)):
            detected = True
            reasons.append(
                "ORDER_ANOMALY_WITHOUT_QOS_SESSION_INTERPRETATION"
                if not qos_aware else "ORDERED_FLOW_VIOLATED"
            )
            if qos_aware and honest_subscriber:
                attribution = "broker"
        else:
            reasons.append("TOPIC_ORDERING_NOT_ASSUMED")
    elif explained_regressions:
        reasons.append("SEQUENCE_REGRESSION_EXPLAINED_BY_PERMITTED_DUPLICATE")

    quorum_missing = (
        arm == "A6"
        and facts.get("distinct_trusted_witnesses", 0) < facts.get("witness_quorum", 0)
    )
    freshness_unproven = (
        latest_anchor is None
        or "TRUSTED_LATEST_ANCHOR_STALE" in reasons
        or not evidence.get("trusted_genesis_anchor")
    )
    # Fail closed: only an explicit authoritative ACCEPT lets the auditor
    # ACCEPT.  Reject, inconclusive, missing, or any unrecognised outcome blocks.
    crypto_verification = evidence.get("crypto_verification", {})
    crypto_performed = bool(crypto_verification.get("performed"))
    crypto_outcome = crypto_verification.get("stream_outcome")
    crypto_blocks_accept = crypto_performed and crypto_outcome != "accept"
    if crypto_performed:
        if crypto_outcome == "reject" and bool(evidence.get("transferable_evidence")):
            if "CRYPTO_STREAM_REJECTED" not in reasons:
                reasons.append("CRYPTO_STREAM_REJECTED")
        elif crypto_outcome == "inconclusive":
            if "STREAM_HISTORY_BINDING_UNPROVEN" not in reasons:
                reasons.append("STREAM_HISTORY_BINDING_UNPROVEN")
        elif crypto_outcome not in ("accept", "reject", "inconclusive"):
            if "CRYPTO_STREAM_OUTCOME_UNRECOGNIZED" not in reasons:
                reasons.append("CRYPTO_STREAM_OUTCOME_UNRECOGNIZED")
    if detected:
        decision = "detect"
    elif quorum_missing or freshness_unproven or crypto_blocks_accept or not checkpoints:
        decision = "inconclusive"
    else:
        decision = "accept"
        reasons.append("EVIDENCE_VALID_WITHIN_STATED_TRUST_ASSUMPTIONS")

    if not detected and decision == "inconclusive":
        attribution = None
    if detected and attribution is None:
        reasons.append("ANOMALY_DETECTED_BUT_ACTOR_NOT_TRANSFERABLY_ATTRIBUTABLE")

    return _final_result(
        evidence,
        mode=mode,
        decision=decision,
        detected=detected,
        attribution=attribution,
        reason_codes=reasons,
        observed_facts=facts,
    )
