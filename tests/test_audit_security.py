"""Adversarial regression tests for the independent offline auditor."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIR = ROOT / "experiments" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from aapa_mqtt import Checkpoint, CheckpointWitness, Record, create_arm, make_payload  # noqa: E402
from stream_identity import canonical_stream_id  # noqa: E402
from audit_verify import (  # noqa: E402
    ANCHOR_SCHEMA_VERSION,
    BUNDLE_SCHEMA_VERSION,
    AnchorPosition,
    AnchorSet,
    AuditOutcome,
    ReasonCode,
    StreamAnchors,
    audit_evidence,
    audit_stream,
    bundle_to_dict,
    export_offline_audit_artifacts,
    load_evidence_bundle_v2,
    main as auditor_main,
    verify_witness_receipts,
)
from trusted_registry import (  # noqa: E402
    PublisherAuthorization,
    TrustedRegistry,
    registry_for_generated_evidence,
)


def _build_arm(arm_id: str, topic: str, *, n_records: int = 6, interval: int = 2, **kwargs):
    arm = create_arm(arm_id, topic, N=interval, **kwargs)
    for seq in range(1, n_records + 1):
        arm.add_record(
            Record.make(seq, topic, make_payload(24, bytes([seq % 251])), ts=1_700_000_000.0 + seq)
        )
    arm.flush()
    return arm


def _anchors_for(evidence, *, include_latest: bool = True, valid_until=None) -> AnchorSet:
    first = evidence[0].checkpoint
    last = evidence[-1].checkpoint
    stream_id = TrustedRegistry.stream_id(first.client_id, first.topic)
    return AnchorSet(
        streams=[
            StreamAnchors(
                stream_id=stream_id,
                genesis=AnchorPosition(anchor=b"\x00" * 32, epoch=0, seq=1),
                latest=AnchorPosition(
                    anchor=last.end_anchor,
                    epoch=last.epoch,
                    seq=last.seq_end,
                    observed_at=1_700_000_100.0,
                    valid_until=valid_until,
                )
                if include_latest
                else None,
            )
        ],
        anchor_set_id="test-anchor-set",
    )


@pytest.fixture(scope="module")
def a0_material():
    topic = "security/a0"
    legitimate = _build_arm("A0", topic)
    attacker = _build_arm("A0", topic)
    registry = registry_for_generated_evidence(legitimate.checkpoints, "A0")
    anchors = _anchors_for(legitimate.checkpoints)
    try:
        yield legitimate, attacker, registry, anchors
    finally:
        if hasattr(legitimate, "free"):
            legitimate.free()
        if hasattr(attacker, "free"):
            attacker.free()


def test_clean_stream_accepts_with_external_registry_and_latest_anchor(a0_material):
    legitimate, _attacker, registry, anchors = a0_material
    verdict = audit_stream(legitimate.checkpoints, "A0", registry, anchors)
    assert verdict.outcome == AuditOutcome.ACCEPT
    assert verdict.tail_complete
    assert verdict.reason_codes == [ReasonCode.VERIFIED.value]
    json.dumps(verdict.to_dict())


def test_missing_registry_fails_closed(a0_material):
    legitimate, _attacker, _registry, _anchors = a0_material
    verdict = audit_evidence(legitimate.checkpoints[0], "A0")
    assert verdict.outcome == AuditOutcome.REJECT
    assert ReasonCode.REGISTRY_REQUIRED.value in verdict.reason_codes


def test_self_signed_publisher_is_rejected(a0_material):
    _legitimate, attacker, registry, _anchors = a0_material
    attacker_anchors = _anchors_for(attacker.checkpoints)
    verdict = audit_stream(attacker.checkpoints, "A0", registry, attacker_anchors)
    assert verdict.outcome == AuditOutcome.REJECT
    assert ReasonCode.PUBLISHER_KEY_SUBSTITUTION.value in verdict.reason_codes


def test_bundle_key_substitution_is_rejected_even_when_signature_is_valid(a0_material):
    legitimate, attacker, registry, _anchors = a0_material
    substituted = copy.deepcopy(legitimate.checkpoints[0])
    substituted.public_key = attacker.checkpoints[0].public_key
    verdict = audit_evidence(substituted, "A0", registry)
    assert verdict.outcome == AuditOutcome.REJECT
    assert ReasonCode.PUBLISHER_KEY_SUBSTITUTION.value in verdict.reason_codes


def test_tail_without_latest_anchor_is_inconclusive(a0_material):
    legitimate, _attacker, registry, _anchors = a0_material
    anchors = _anchors_for(legitimate.checkpoints, include_latest=False)
    verdict = audit_stream(legitimate.checkpoints[:-1], "A0", registry, anchors)
    assert verdict.outcome == AuditOutcome.INCONCLUSIVE
    assert ReasonCode.TAIL_COMPLETENESS_UNPROVABLE.value in verdict.reason_codes


def test_tail_truncation_against_latest_anchor_is_rejected_as_rollback(a0_material):
    legitimate, _attacker, registry, anchors = a0_material
    verdict = audit_stream(legitimate.checkpoints[:-1], "A0", registry, anchors)
    assert verdict.outcome == AuditOutcome.REJECT
    assert ReasonCode.ROLLBACK_DETECTED.value in verdict.reason_codes


def test_middle_truncation_is_rejected(a0_material):
    legitimate, _attacker, registry, anchors = a0_material
    truncated = [legitimate.checkpoints[0], legitimate.checkpoints[2]]
    verdict = audit_stream(truncated, "A0", registry, anchors)
    assert verdict.outcome == AuditOutcome.REJECT
    assert ReasonCode.MIDDLE_TRUNCATION.value in verdict.reason_codes
    assert ReasonCode.EPOCH_GAP.value in verdict.reason_codes


def test_checkpoint_reorder_is_rejected(a0_material):
    legitimate, _attacker, registry, anchors = a0_material
    reordered = [legitimate.checkpoints[0], legitimate.checkpoints[2], legitimate.checkpoints[1]]
    verdict = audit_stream(reordered, "A0", registry, anchors)
    assert verdict.outcome == AuditOutcome.REJECT
    assert ReasonCode.EPOCH_REORDER.value in verdict.reason_codes


def test_checkpoint_splice_is_rejected(a0_material):
    legitimate, _attacker, registry, anchors = a0_material
    spliced = copy.deepcopy(legitimate.checkpoints)
    spliced[1].checkpoint.prev_anchor = b"\xa5" * 32
    verdict = audit_stream(spliced, "A0", registry, anchors)
    assert verdict.outcome == AuditOutcome.REJECT
    assert ReasonCode.SPLICE_OR_FORK.value in verdict.reason_codes
    assert ReasonCode.PREV_ANCHOR_MISMATCH.value in verdict.reason_codes


def test_duplicate_and_cross_epoch_replay_are_rejected(a0_material):
    legitimate, _attacker, registry, anchors = a0_material
    replayed = [
        legitimate.checkpoints[0],
        legitimate.checkpoints[1],
        copy.deepcopy(legitimate.checkpoints[0]),
        legitimate.checkpoints[2],
    ]
    verdict = audit_stream(replayed, "A0", registry, anchors)
    assert verdict.outcome == AuditOutcome.REJECT
    assert ReasonCode.DUPLICATE_CHECKPOINT.value in verdict.reason_codes
    assert ReasonCode.CROSS_EPOCH_REPLAY.value in verdict.reason_codes


def test_expired_latest_anchor_degrades_to_inconclusive(a0_material):
    legitimate, _attacker, registry, _anchors = a0_material
    anchors = _anchors_for(legitimate.checkpoints, valid_until=1_700_000_200.0)
    verdict = audit_stream(
        legitimate.checkpoints,
        "A0",
        registry,
        anchors,
        audit_time=1_700_000_201.0,
    )
    assert verdict.outcome == AuditOutcome.INCONCLUSIVE
    assert ReasonCode.LATEST_ANCHOR_STALE.value in verdict.reason_codes


def test_authorized_key_transition_and_unauthorized_transition():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    topic = "security/key-transition"
    arm = create_arm("A0", topic, N=2)
    for seq in (1, 2):
        arm.add_record(Record.make(seq, topic, b"before", ts=1_700_000_000.0 + seq))
    first_key = arm.sig_pk_bytes
    arm._sig_priv = ed25519.Ed25519PrivateKey.generate()
    arm.sig_pk_bytes = arm._sig_priv.public_key().public_bytes_raw()
    second_key = arm.sig_pk_bytes
    for seq in (3, 4):
        arm.add_record(Record.make(seq, topic, b"after", ts=1_700_000_000.0 + seq))
    arm.flush()
    stream_id = TrustedRegistry.stream_id(arm.checkpoints[0].checkpoint.client_id, topic)
    registry = TrustedRegistry(
        publishers=[
            PublisherAuthorization(
                client_id=arm.checkpoints[0].checkpoint.client_id,
                topic=topic,
                epoch_start=0,
                epoch_end=0,
                public_key=first_key,
                signature_scheme="Ed25519",
            ),
            PublisherAuthorization(
                client_id=arm.checkpoints[0].checkpoint.client_id,
                topic=topic,
                epoch_start=1,
                epoch_end=1,
                public_key=second_key,
                signature_scheme="Ed25519",
            ),
        ]
    )
    anchors = _anchors_for(arm.checkpoints)
    try:
        accepted = audit_stream(arm.checkpoints, "A0", registry, anchors)
        assert accepted.outcome == AuditOutcome.ACCEPT
        assert ReasonCode.AUTHORIZED_KEY_TRANSITION.value in accepted.reason_codes

        first_key_only = TrustedRegistry(publishers=[registry.publishers[0]])
        rejected = audit_stream(arm.checkpoints, "A0", first_key_only, anchors)
        assert rejected.outcome == AuditOutcome.REJECT
        assert ReasonCode.KEY_TRANSITION_UNAUTHORIZED.value in rejected.reason_codes
        assert rejected.stream_id == stream_id
    finally:
        if hasattr(arm, "free"):
            arm.free()


def test_distinct_trusted_witness_quorum_rejects_duplicate_receipt():
    arm = _build_arm("A6", "security/a6", n_records=2, interval=2, witness_count=2)
    registry = registry_for_generated_evidence(
        arm.checkpoints, "A6", witness_quorum=2
    )
    duplicated = copy.deepcopy(arm.checkpoints[0])
    duplicated.witness_receipts = [
        copy.deepcopy(duplicated.witness_receipts[0]),
        copy.deepcopy(duplicated.witness_receipts[0]),
    ]
    try:
        verdict = audit_evidence(duplicated, "A6", registry)
        assert verdict.outcome == AuditOutcome.REJECT
        assert ReasonCode.WITNESS_DUPLICATE_ID.value in verdict.reason_codes
        assert ReasonCode.WITNESS_BELOW_QUORUM.value in verdict.reason_codes
    finally:
        arm.free()


def test_untrusted_witness_does_not_count_toward_quorum():
    arm = _build_arm("A6", "security/a6-untrusted", n_records=2, interval=2, witness_count=2)
    registry = registry_for_generated_evidence(
        arm.checkpoints, "A6", witness_quorum=2
    )
    modified = copy.deepcopy(arm.checkpoints[0])
    modified.witness_receipts[1].witness_id = "attacker-witness"
    try:
        verdict = audit_evidence(modified, "A6", registry)
        assert verdict.outcome == AuditOutcome.REJECT
        assert ReasonCode.WITNESS_UNTRUSTED.value in verdict.reason_codes
        assert ReasonCode.WITNESS_BELOW_QUORUM.value in verdict.reason_codes
    finally:
        arm.free()


def test_witness_bundle_key_substitution_is_rejected():
    arm = _build_arm("A6", "security/a6-key-substitution", n_records=2, interval=2, witness_count=1)
    registry = registry_for_generated_evidence(
        arm.checkpoints, "A6", witness_quorum=1
    )
    modified = copy.deepcopy(arm.checkpoints[0])
    modified.witness_receipts[0].public_key = b"\x5a" * len(
        modified.witness_receipts[0].public_key
    )
    try:
        verdict = audit_evidence(modified, "A6", registry)
        assert verdict.outcome == AuditOutcome.REJECT
        assert ReasonCode.WITNESS_KEY_SUBSTITUTION.value in verdict.reason_codes
    finally:
        arm.free()


def test_a1_records_verify_but_stream_history_remains_inconclusive():
    arm = _build_arm("A1", "security/a1", n_records=2, interval=1)
    registry = registry_for_generated_evidence(arm.checkpoints, "A1")
    anchors = _anchors_for(arm.checkpoints)
    try:
        verdict = audit_stream(arm.checkpoints, "A1", registry, anchors)
        assert all(item.accepted for item in verdict.checkpoint_verdicts)
        assert verdict.outcome == AuditOutcome.INCONCLUSIVE
        assert ReasonCode.HISTORY_BINDING_UNAVAILABLE.value in verdict.reason_codes
    finally:
        arm.free()


def test_a1_signature_binds_checkpoint_epoch():
    arm = _build_arm("A1", "security/a1-epoch-binding", n_records=2, interval=1)
    registry = registry_for_generated_evidence(arm.checkpoints, "A1")
    modified = copy.deepcopy(arm.checkpoints[0])
    modified.checkpoint.epoch = 1
    try:
        verdict = audit_evidence(modified, "A1", registry)
        assert verdict.outcome == AuditOutcome.REJECT
        assert ReasonCode.PUBLISHER_SIGNATURE_INVALID.value in verdict.reason_codes
    finally:
        arm.free()


def test_v2_bundle_cli_and_legacy_schema_rejection(a0_material, tmp_path, capsys):
    legitimate, _attacker, registry, anchors = a0_material
    bundle_path = tmp_path / "bundle.json"
    registry_path = tmp_path / "registry.json"
    anchors_path = tmp_path / "anchors.json"
    verdict_path = tmp_path / "verdict.json"
    bundle_path.write_text(
        json.dumps(bundle_to_dict("A0", legitimate.checkpoints)), encoding="utf-8"
    )
    registry_path.write_text(json.dumps(registry.to_dict()), encoding="utf-8")
    anchors_path.write_text(json.dumps(anchors.to_dict()), encoding="utf-8")

    assert auditor_main(
        [
            "--bundle",
            str(bundle_path),
            "--registry",
            str(registry_path),
            "--anchors",
            str(anchors_path),
            "--output",
            str(verdict_path),
        ]
    ) == 0
    assert json.loads(verdict_path.read_text(encoding="utf-8"))["outcome"] == "accept"
    assert json.loads(bundle_path.read_text(encoding="utf-8"))["schema_version"] == BUNDLE_SCHEMA_VERSION
    assert json.loads(anchors_path.read_text(encoding="utf-8"))["schema_version"] == ANCHOR_SCHEMA_VERSION
    capsys.readouterr()

    legacy_path = tmp_path / "legacy.json"
    legacy_path.write_text(json.dumps({"arm_id": "A0", "evidence": []}), encoding="utf-8")
    with pytest.raises(ValueError, match=ReasonCode.BUNDLE_SCHEMA_UNSUPPORTED.value):
        load_evidence_bundle_v2(legacy_path)


def test_result_package_security_artifact_export(a0_material, tmp_path):
    legitimate, _attacker, registry, anchors = a0_material
    exported = export_offline_audit_artifacts(
        tmp_path / "security",
        {"a0-clean": ("A0", legitimate.checkpoints)},
        registry,
        anchors,
    )
    assert Path(exported["registry"]).name == "trusted_registry.json"
    assert Path(exported["anchors"]).name == "trusted_anchors.json"
    assert exported["streams"]["a0-clean"]["outcome"] == "accept"
    bundle_path = Path(exported["streams"]["a0-clean"]["bundle"])
    verdict_path = Path(exported["streams"]["a0-clean"]["verdict"])
    assert bundle_path.parent.name == "bundles"
    assert verdict_path.parent.name == "verdicts"
    assert json.loads(verdict_path.read_text(encoding="utf-8"))["accepted"] is True


def _checkpoint(client_id: str, topic: str) -> Checkpoint:
    return Checkpoint(
        client_id=client_id,
        topic=topic,
        epoch=1,
        seq_start=1,
        seq_end=1,
        prev_anchor=b"\x00" * 32,
        end_anchor=b"\x11" * 32,
        ts_ckpt=1_700_000_000.0,
    )


def test_canonical_stream_id_is_collision_free_across_colon_boundaries():
    # A naive client_id + ":" + topic renders both of these as "a:b:c", letting a
    # witness receipt for one stream satisfy the registry policy of another.
    left = canonical_stream_id("a:b", "c")
    right = canonical_stream_id("a", "b:c")
    assert left != right
    assert left == "3:a:b1:c"
    assert right == "1:a3:b:c"


def test_canonical_stream_id_uses_utf8_byte_lengths():
    # Non-ASCII components must be length-prefixed by UTF-8 byte length, not by
    # Unicode code-point count, so that Python and C++ agree byte-for-byte.
    client = "dev-温度"          # "dev-温度": 4 ASCII + 2*3 UTF-8 bytes = 10
    topic = "☃/telemetry"            # "☃/telemetry": 3 + 10 = 13 bytes
    assert canonical_stream_id(client, topic) == f"10:{client}13:{topic}"

    # Distinct code points with equal byte length must still not collide.
    assert canonical_stream_id("温", "x") != canonical_stream_id("abc", "x")


def test_stream_identity_helpers_agree():
    # registry, witness, and the raw helper must derive one identical identity.
    checkpoint = _checkpoint("publisher-001", "aapa/xcheck/telemetry")
    expected = canonical_stream_id(checkpoint.client_id, checkpoint.topic)
    assert TrustedRegistry.stream_id(checkpoint.client_id, checkpoint.topic) == expected
    assert CheckpointWitness.stream_id_for(checkpoint) == expected
    assert ":" in expected and expected != f"{checkpoint.client_id}:{checkpoint.topic}"

def _a6_arm_with_witnesses(n_witness: int):
    topic = "security/e8-a6"
    arm = create_arm("A6", topic, N=4, witness_count=n_witness)
    for seq in range(1, 7):
        arm.add_record(
            Record.make(seq, topic, make_payload(24, bytes([seq % 251])), ts=1_700_000_000.0 + seq)
        )
    arm.flush()
    return arm


def test_e8_a6_witness_quorum_verifies_with_registry_and_fails_closed_without():
    arm = _a6_arm_with_witnesses(2)
    try:
        ev = arm.checkpoints[0]
        registry = registry_for_generated_evidence(arm.checkpoints, "A6", witness_quorum=2)
        accepted, valid_distinct, total, _details = verify_witness_receipts(
            ev, registry=registry, min_receipts=2
        )
        assert accepted
        assert valid_distinct == 2
        assert total == 2
        # The E8 auditor path must fail closed when no external registry is
        # supplied; the bundle's own witness keys are never a trust root.
        accepted_no_registry = verify_witness_receipts(ev, registry=None, min_receipts=2)[0]
        assert not accepted_no_registry
    finally:
        if hasattr(arm, "free"):
            arm.free()


def test_e8_a6_duplicate_receipt_cannot_reach_quorum():
    arm = _a6_arm_with_witnesses(2)
    try:
        registry = registry_for_generated_evidence(arm.checkpoints, "A6", witness_quorum=2)
        ev = copy.deepcopy(arm.checkpoints[0])
        # Two copies of one witness's receipt are a single distinct identity and
        # must not satisfy a quorum of two.
        ev.witness_receipts = [
            ev.witness_receipts[0],
            copy.deepcopy(ev.witness_receipts[0]),
        ]
        accepted, valid_distinct, _total, _details = verify_witness_receipts(
            ev, registry=registry, min_receipts=2
        )
        assert not accepted
        assert valid_distinct < 2
    finally:
        if hasattr(arm, "free"):
            arm.free()


def test_e8_a3_verification_compares_full_chain_values_not_just_head():
    # Drive the *production* E8 A3 verifier, not an in-test reimplementation, so
    # a head-only regression would actually fail this test.
    from run_optimized import _verify_a3_chain_evidence

    topic = "security/e8-a3"
    arm = create_arm("A3", topic, N=8)
    for seq in range(1, 9):
        arm.add_record(
            Record.make(seq, topic, make_payload(24, bytes([seq % 251])), ts=1_700_000_000.0 + seq)
        )
    arm.flush()
    try:
        registry = registry_for_generated_evidence(arm.checkpoints, "A3")
        ev = arm.checkpoints[0]
        auth = registry.publisher_for(ev.checkpoint.client_id, ev.checkpoint.topic, ev.checkpoint.epoch)

        # Honest evidence verifies.
        assert _verify_a3_chain_evidence(ev, auth) is True

        # Forge an intermediate chain value while leaving the final head correct.
        # A head-only check would still accept; the production verifier compares
        # the full C_0..C_n vector and must reject.
        forged = copy.deepcopy(ev)
        assert len(forged.chain_values) >= 3
        forged.chain_values[1] = b"\x00" * len(forged.chain_values[1])
        assert forged.checkpoint.end_anchor == ev.checkpoint.end_anchor  # head unchanged
        assert _verify_a3_chain_evidence(forged, auth) is False
    finally:
        if hasattr(arm, "free"):
            arm.free()


def test_e8_a6_witness_key_substitution_fails_against_authorized_key():
    # The witness quorum is bound to the registry-authorized public key: a
    # substituted key (self-consistently signed) must not verify against the
    # authorized key, so the crypto bridge marks it signature-invalid and it
    # cannot count toward a quorum.
    import oqs
    from audit_verify import verify_signature

    arm = _a6_arm_with_witnesses(2)
    try:
        registry = registry_for_generated_evidence(arm.checkpoints, "A6", witness_quorum=2)
        receipt = arm.checkpoints[0].witness_receipts[0]
        auth = registry.witness_for_id(receipt.witness_id)
        # Genuine receipt: carried key is the authorized key and verifies.
        assert receipt.public_key == auth.public_key
        assert verify_signature(
            auth.public_key, receipt.serialize(), receipt.signature, auth.signature_scheme
        )
        # Attacker re-signs the same receipt body with a different key.
        with oqs.Signature("ML-DSA-65") as attacker:
            attacker_pub = attacker.generate_keypair()
            attacker_sig = attacker.sign(receipt.serialize())
        assert attacker_pub != auth.public_key
        assert not verify_signature(
            auth.public_key, receipt.serialize(), attacker_sig, auth.signature_scheme
        )
    finally:
        if hasattr(arm, "free"):
            arm.free()
