"""Wire-path regression tests: the online MQTT publish path must carry
authenticated envelopes, and the subscriber must count only messages that
authenticate against a fresh (epoch, seq).

These tests are broker-free: they exercise the arm wire API
(``latest_wire_payload`` / ``new_subscriber_verifier``) and the runner's
subscriber accounting helper directly, so they are deterministic and fast.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIR = ROOT / "experiments" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from aapa_mqtt import create_arm, make_payload, make_topic, Record  # noqa: E402
from run_optimized import _make_verifying_on_message, _new_verification_counts  # noqa: E402


MAC_ARMS = ["A0", "A2", "A4", "A6"]
ALL_ARMS = ["A0", "A1", "A2", "A4", "A6"]


class _Msg:
    """Minimal stand-in for a paho MQTTMessage (only .payload is read)."""

    def __init__(self, payload: bytes):
        self.payload = payload


def _one_record_arm(arm_id: str):
    topic = make_topic(arm_id)
    arm = create_arm(arm_id, topic, N=4, witness_count=1)
    rec = Record.make(1, topic, make_payload(64))
    arm.add_record(rec)
    return arm, rec


@pytest.mark.parametrize("arm_id", ALL_ARMS)
def test_wire_payload_is_authenticated_and_differs_from_raw_record(arm_id):
    arm, rec = _one_record_arm(arm_id)
    try:
        wire = arm.latest_wire_payload()
        raw = rec.serialize()
        # The online payload must be the authenticated envelope, never the bare
        # record: it is strictly larger (metadata + authenticator tag).
        assert wire != raw
        assert len(wire) > len(raw)
        # And it must authenticate under a subscriber verifier derived from the
        # same arm, exposing the parsed envelope seq for latency mapping.
        result = arm.new_subscriber_verifier().verify(wire)
        assert result.valid and result.reason_code == "VALID"
        assert result.envelope is not None and result.envelope.seq == rec.seq
    finally:
        if hasattr(arm, "free"):
            arm.free()


def test_a2_mac_and_a1_signature_both_carry_tags():
    # A2 (ML-KEM session MAC negative control) and A1 (per-message ML-DSA) must
    # both appear on the authenticated wire path, with the signature envelope
    # substantially larger than the MAC envelope.
    a2, a2_rec = _one_record_arm("A2")
    a1, a1_rec = _one_record_arm("A1")
    try:
        a2_wire = a2.latest_wire_payload()
        a1_wire = a1.latest_wire_payload()
        assert len(a2_wire) - len(a2_rec.serialize()) >= 32          # HMAC-SHA256 tag
        assert len(a1_wire) - len(a1_rec.serialize()) > 1000         # ML-DSA-65 signature
    finally:
        for arm in (a1, a2):
            if hasattr(arm, "free"):
                arm.free()


@pytest.mark.parametrize("arm_id", ALL_ARMS)
def test_tamper_wrongkey_and_replay_are_rejected(arm_id):
    arm, _rec = _one_record_arm(arm_id)
    other, _ = _one_record_arm(arm_id)  # independent key material, same arm kind
    try:
        wire = arm.latest_wire_payload()

        # Tampered authenticator byte.
        tampered = bytearray(wire)
        tampered[-1] ^= 0xFF
        assert arm.new_subscriber_verifier().verify(bytes(tampered)).reason_code == (
            "AUTHENTICATOR_INVALID"
        )

        # Wrong key: a verifier bound to a different arm's key material rejects
        # before any replay-state update.
        assert other.new_subscriber_verifier().verify(wire).reason_code == "KEY_ID_MISMATCH"

        # Replay: the same authenticated payload twice on one verifier.
        verifier = arm.new_subscriber_verifier()
        assert verifier.verify(wire).valid
        assert verifier.verify(wire).reason_code == "REPLAY_DUPLICATE"
    finally:
        for a in (arm, other):
            if hasattr(a, "free"):
                a.free()


def test_verifying_callback_counts_only_valid_unique():
    arm_id = "A4"
    topic = make_topic(arm_id)
    arm = create_arm(arm_id, topic, N=8, witness_count=1)
    other = create_arm(arm_id, topic, N=8, witness_count=1)
    try:
        payloads = []
        for seq in (1, 2, 3):
            arm.add_record(Record.make(seq, topic, make_payload(64)))
            payloads.append(arm.latest_wire_payload())
        other.add_record(Record.make(1, topic, make_payload(64)))
        wrong_key = other.latest_wire_payload()
        tampered = bytearray(payloads[0]); tampered[-1] ^= 0xFF

        counts = _new_verification_counts()
        recv_seqs: set[int] = set()
        recv_times: dict[int, float] = {}
        on_msg = _make_verifying_on_message(
            arm.new_subscriber_verifier(), counts, recv_times=recv_times, recv_seqs=recv_seqs
        )

        # valid(1), replay(1), valid(2), tampered, wrong-key, valid(3)
        for payload in (payloads[0], payloads[0], payloads[1], bytes(tampered), wrong_key, payloads[2]):
            on_msg(None, None, _Msg(payload))

        assert counts["received"] == 6
        assert counts["valid"] == 3                      # only the 3 distinct valid seqs
        assert counts["invalid"] == 3
        assert counts["replay"] == 1
        assert recv_seqs == {1, 2, 3}
        assert set(recv_times) == {1, 2, 3}
        assert counts["reasons"]["REPLAY_DUPLICATE"] == 1
        assert counts["reasons"]["AUTHENTICATOR_INVALID"] == 1
        assert counts["reasons"]["KEY_ID_MISMATCH"] == 1
    finally:
        for a in (arm, other):
            if hasattr(a, "free"):
                a.free()
