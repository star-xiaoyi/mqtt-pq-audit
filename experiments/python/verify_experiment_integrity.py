#!/usr/bin/env python3
"""Smoke tests for experiment evidence semantics.

This script does not contact the MQTT broker. It checks the local evidence
generation and verifier contracts that the measurement runners depend on.
"""

import copy

from aapa_mqtt import create_arm, make_payload, make_topic, Record
from audit_verify import (
    AuditOutcome,
    anchors_for_generated_evidence,
    audit_all,
    audit_evidence,
    audit_stream,
    checkpoint_sequence_valid,
)
from trusted_registry import registry_for_generated_evidence


def build_arm(arm_id: str, n_records: int = 7, N: int = 3):
    topic = make_topic(arm_id)
    arm = create_arm(arm_id, topic, N=N)
    for i in range(n_records):
        rec = Record.make(i + 1, topic, make_payload(32), ts=1700000000.0 + i)
        arm.add_record(rec)
    arm.flush()
    return arm


def corrupt_signature(evidence):
    bad = copy.deepcopy(evidence)
    if bad.signature:
        bad.signature = bytes([bad.signature[0] ^ 0x01]) + bad.signature[1:]
    return bad


def corrupt_chain_value(evidence):
    bad = copy.deepcopy(evidence)
    if bad.chain_values:
        bad.chain_values[-1] = bytes([bad.chain_values[-1][0] ^ 0x01]) + bad.chain_values[-1][1:]
    return bad


def corrupt_witness_receipt(evidence):
    bad = copy.deepcopy(evidence)
    if bad.witness_receipts and bad.witness_receipts[0].signature:
        sig = bad.witness_receipts[0].signature
        bad.witness_receipts[0].signature = bytes([sig[0] ^ 0x01]) + sig[1:]
    return bad


def run():
    for arm_id in ["A0", "A1", "A3", "A4", "A6"]:
        arm = build_arm(arm_id)
        assert arm.checkpoints, f"{arm_id}: expected checkpoint evidence"
        assert checkpoint_sequence_valid(arm.checkpoints), f"{arm_id}: checkpoint chain broken"

        witness_quorum = None
        if arm_id == "A6":
            witness_quorum = len(arm.checkpoints[0].witness_receipts or [])
        registry = registry_for_generated_evidence(
            arm.checkpoints,
            arm_id,
            witness_quorum=witness_quorum,
            registry_id=f"integrity-smoke-{arm_id}",
        )
        anchors = anchors_for_generated_evidence(
            arm.checkpoints,
            anchor_set_id=f"integrity-smoke-{arm_id}",
        )

        verdicts = audit_all(arm.checkpoints, arm_id, registry)
        assert all(v.records_valid and v.accepted for v in verdicts), f"{arm_id}: valid evidence rejected"
        stream_verdict = audit_stream(arm.checkpoints, arm_id, registry, anchors)
        expected_stream_outcome = (
            AuditOutcome.INCONCLUSIVE if arm_id == "A1" else AuditOutcome.ACCEPT
        )
        assert stream_verdict.outcome == expected_stream_outcome, (
            f"{arm_id}: valid stream rejected: {stream_verdict.reason_codes}"
        )
        assert all(len(ev.serialize(include_records=True)) > 0 for ev in arm.checkpoints), f"{arm_id}: empty evidence serialization"

        bad_sig = audit_evidence(corrupt_signature(arm.checkpoints[0]), arm_id, registry)
        assert not bad_sig.records_valid, f"{arm_id}: corrupted signature accepted"

        if arm_id == "A3":
            bad_chain = audit_evidence(corrupt_chain_value(arm.checkpoints[0]), arm_id, registry)
            assert not bad_chain.records_valid, "A3: corrupted chain value accepted"

        if arm_id == "A6":
            assert arm.checkpoints[0].witness_receipts, "A6: expected witness receipts"
            bad_receipt = audit_evidence(
                corrupt_witness_receipt(arm.checkpoints[0]), arm_id, registry
            )
            assert not bad_receipt.records_valid, "A6: corrupted witness receipt accepted"

        if hasattr(arm, "free"):
            arm.free()

    a2 = build_arm("A2")
    assert not a2.checkpoints, "A2: session-MAC-only arm should not emit checkpoint evidence"
    if hasattr(a2, "free"):
        a2.free()

    print("experiment integrity smoke test: PASS")


if __name__ == "__main__":
    run()
