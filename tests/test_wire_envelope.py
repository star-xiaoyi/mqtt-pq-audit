from __future__ import annotations

import hashlib
import hmac
import sys
from dataclasses import replace
from pathlib import Path

import pytest


PYTHON_DIR = Path(__file__).resolve().parents[1] / "experiments" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from aapa_mqtt import (  # noqa: E402
    CHECKPOINT_SIGNING_DOMAIN,
    WITNESS_SIGNING_DOMAIN,
    Checkpoint,
    Record,
    WireEnvelope,
    WitnessReceipt,
    create_arm,
    make_payload,
    make_topic,
)


def test_record_round_trip_and_trailing_bytes_rejected():
    record = Record.make(7, "aapa/test", b"payload", ts=1_700_000_000.5)
    assert Record.deserialize(record.serialize()) == record

    try:
        Record.deserialize(record.serialize() + b"x")
    except ValueError:
        pass
    else:
        raise AssertionError("trailing record bytes were accepted")


def test_signed_objects_are_domain_separated_and_reject_nonfinite_time():
    checkpoint = Checkpoint(
        client_id="p", topic="t", epoch=0, seq_start=1, seq_end=1,
        prev_anchor=b"0" * 32, end_anchor=b"1" * 32, ts_ckpt=1.0,
    )
    receipt = WitnessReceipt(
        witness_id="w", stream_id="1:p1:t", checkpoint_epoch=0,
        seq_start=1, seq_end=1, prev_witnessed_anchor=b"0" * 32,
        checkpoint_anchor=b"1" * 32, ts_witness=1.0,
    )
    assert checkpoint.serialize().startswith(CHECKPOINT_SIGNING_DOMAIN)
    assert receipt.serialize().startswith(WITNESS_SIGNING_DOMAIN)
    assert CHECKPOINT_SIGNING_DOMAIN != WITNESS_SIGNING_DOMAIN

    with pytest.raises(ValueError, match="finite"):
        replace(checkpoint, ts_ckpt=float("nan")).serialize()
    with pytest.raises(ValueError, match="finite"):
        replace(receipt, ts_witness=float("inf")).serialize()
    with pytest.raises(ValueError, match="finite"):
        Record.make(1, "t", b"x", ts=float("nan")).serialize()


def test_a2_wire_mac_is_verified_and_replay_is_rejected():
    topic = make_topic("A2")
    arm = create_arm("A2", topic)
    try:
        record = Record.make(1, topic, make_payload(32), ts=1_700_000_000.0)
        arm.add_record(record)
        payload = arm.latest_wire_payload()
        parsed = WireEnvelope.parse(payload)
        assert parsed.record == record.serialize()
        assert parsed.algorithm == "HMAC-SHA256"
        assert parsed.key_id
        assert parsed.session_id

        verifier = arm.new_subscriber_verifier()
        assert verifier.verify(payload).reason_code == "VALID"
        assert verifier.verify(payload).reason_code == "REPLAY_DUPLICATE"
    finally:
        arm.free()


def test_a2_wire_rejects_tamper_truncation_wrong_key_and_epoch_jump():
    topic = make_topic("A2")
    arm = create_arm("A2", topic)
    try:
        arm.add_record(Record.make(1, topic, b"one", ts=1_700_000_000.0))
        valid_payload = arm.latest_wire_payload()

        tampered = bytearray(valid_payload)
        tampered[-1] ^= 1
        assert arm.new_subscriber_verifier().verify(bytes(tampered)).reason_code == "AUTHENTICATOR_INVALID"
        assert arm.new_subscriber_verifier().verify(valid_payload[:-1]).reason_code == "WIRE_MALFORMED"

        envelope = WireEnvelope.parse(valid_payload)
        wrong_key = replace(envelope, key_id="unknown-key")
        assert arm.new_subscriber_verifier().verify(wrong_key.serialize()).reason_code == "KEY_ID_MISMATCH"

        verifier = arm.new_subscriber_verifier()
        assert verifier.verify(valid_payload).valid
        jumped = replace(
            envelope,
            epoch=2,
            seq=2,
            record=Record.make(2, topic, b"two", ts=1_700_000_001.0).serialize(),
            authenticator=b"",
        )
        jumped = replace(
            jumped,
            authenticator=hmac.new(arm.K_epoch, jumped.unsigned_bytes(), hashlib.sha256).digest(),
        )
        assert verifier.verify(jumped.serialize()).reason_code == "EPOCH_JUMP"
    finally:
        arm.free()


def test_all_core_arms_emit_authenticated_wire_envelopes():
    for arm_id in ("A0", "A1", "A2", "A3", "A4", "A6"):
        topic = make_topic(arm_id)
        arm = create_arm(arm_id, topic, N=2)
        try:
            arm.add_record(Record.make(1, topic, b"value", ts=1_700_000_000.0))
            payload = arm.latest_wire_payload()
            result = arm.new_subscriber_verifier().verify(payload)
            assert result.valid, (arm_id, result.reason_code)
            assert result.record is not None and result.record.seq == 1
        finally:
            if hasattr(arm, "free"):
                arm.free()
