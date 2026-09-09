#!/usr/bin/env python3
"""Independent, fail-closed offline verifier for AAPA-MQTT evidence.

Trust never comes from an evidence bundle.  The public API requires a
separately provisioned :class:`TrustedRegistry`; complete-stream claims also
require an explicit lower (genesis/prefix) anchor and, for tail completeness,
a trusted latest anchor.

CLI example::

    python experiments/python/audit_verify.py \
        --bundle evidence.json --registry registry.json --anchors anchors.json

The CLI accepts only the versioned v2 bundle schema.  It performs no network
access and does not contact the publisher, broker, subscriber, or witnesses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple

from experiment_paths import add_liboqs_python_to_path

add_liboqs_python_to_path()
import oqs

from aapa_mqtt import (
    Checkpoint,
    CheckpointEvidence,
    MerkleTree,
    SIG_ALG_PQC,
    WIRE_AUTH_SIGNATURE,
    WireEnvelope,
    WitnessReceipt,
)
from trusted_registry import (
    PublisherAuthorization,
    RegistryError,
    TrustedRegistry,
)


BUNDLE_SCHEMA_VERSION = "aapa-evidence-bundle-v2"
ANCHOR_SCHEMA_VERSION = "aapa-anchor-set-v1"
ZERO_ANCHOR = b"\x00" * 32

EXPECTED_SCHEME_BY_ARM = {
    "A0": "Ed25519",
    "A1": "ML-DSA-65",
    "A3": "ML-DSA-65",
    "A4": "ML-DSA-65",
    "A5": "SLH_DSA_PURE_SHA2_128F",
    "A6": "ML-DSA-65",
}


class AuditOutcome(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    INCONCLUSIVE = "inconclusive"


class ReasonCode(str, Enum):
    VERIFIED = "VERIFIED"
    REGISTRY_REQUIRED = "REGISTRY_REQUIRED"
    ANCHOR_SET_REQUIRED = "ANCHOR_SET_REQUIRED"
    BUNDLE_SCHEMA_UNSUPPORTED = "BUNDLE_SCHEMA_UNSUPPORTED"
    BUNDLE_MALFORMED = "BUNDLE_MALFORMED"
    BUNDLE_COUNT_MISMATCH = "BUNDLE_COUNT_MISMATCH"
    EMPTY_EVIDENCE = "EMPTY_EVIDENCE"
    ARM_UNSUPPORTED = "ARM_UNSUPPORTED"
    ARM_SCHEME_MISMATCH = "ARM_SCHEME_MISMATCH"
    NON_TRANSFERABLE_ARM = "NON_TRANSFERABLE_ARM"
    PUBLISHER_NOT_AUTHORIZED = "PUBLISHER_NOT_AUTHORIZED"
    PUBLISHER_KEY_SUBSTITUTION = "PUBLISHER_KEY_SUBSTITUTION"
    PUBLISHER_SIGNATURE_INVALID = "PUBLISHER_SIGNATURE_INVALID"
    AUTHORIZED_KEY_TRANSITION = "AUTHORIZED_KEY_TRANSITION"
    KEY_TRANSITION_UNAUTHORIZED = "KEY_TRANSITION_UNAUTHORIZED"
    CHECKPOINT_RANGE_INVALID = "CHECKPOINT_RANGE_INVALID"
    RECORD_PARSE_ERROR = "RECORD_PARSE_ERROR"
    RECORD_COUNT_MISMATCH = "RECORD_COUNT_MISMATCH"
    RECORD_SEQUENCE_MISMATCH = "RECORD_SEQUENCE_MISMATCH"
    RECORD_TOPIC_MISMATCH = "RECORD_TOPIC_MISMATCH"
    RECORD_COMMITMENT_INVALID = "RECORD_COMMITMENT_INVALID"
    PROOF_COUNT_MISMATCH = "PROOF_COUNT_MISMATCH"
    MERKLE_PROOF_INVALID = "MERKLE_PROOF_INVALID"
    HASH_CHAIN_INVALID = "HASH_CHAIN_INVALID"
    HISTORY_BINDING_UNAVAILABLE = "HISTORY_BINDING_UNAVAILABLE"
    WITNESS_POLICY_MISSING = "WITNESS_POLICY_MISSING"
    WITNESS_BELOW_QUORUM = "WITNESS_BELOW_QUORUM"
    WITNESS_UNTRUSTED = "WITNESS_UNTRUSTED"
    WITNESS_NOT_AUTHORIZED = "WITNESS_NOT_AUTHORIZED"
    WITNESS_KEY_SUBSTITUTION = "WITNESS_KEY_SUBSTITUTION"
    WITNESS_DUPLICATE_ID = "WITNESS_DUPLICATE_ID"
    WITNESS_DUPLICATE_KEY = "WITNESS_DUPLICATE_KEY"
    WITNESS_FIELDS_MISMATCH = "WITNESS_FIELDS_MISMATCH"
    WITNESS_SIGNATURE_INVALID = "WITNESS_SIGNATURE_INVALID"
    MIXED_STREAM = "MIXED_STREAM"
    GENESIS_ANCHOR_REQUIRED = "GENESIS_ANCHOR_REQUIRED"
    GENESIS_ANCHOR_MISMATCH = "GENESIS_ANCHOR_MISMATCH"
    EPOCH_GAP = "EPOCH_GAP"
    EPOCH_DUPLICATE = "EPOCH_DUPLICATE"
    EPOCH_REORDER = "EPOCH_REORDER"
    EPOCH_ROLLBACK = "EPOCH_ROLLBACK"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    SEQUENCE_DUPLICATE = "SEQUENCE_DUPLICATE"
    SEQUENCE_REORDER = "SEQUENCE_REORDER"
    PREV_ANCHOR_MISMATCH = "PREV_ANCHOR_MISMATCH"
    DUPLICATE_CHECKPOINT = "DUPLICATE_CHECKPOINT"
    SPLICE_OR_FORK = "SPLICE_OR_FORK"
    MIDDLE_TRUNCATION = "MIDDLE_TRUNCATION"
    CROSS_EPOCH_REPLAY = "CROSS_EPOCH_REPLAY"
    LATEST_ANCHOR_MISSING = "LATEST_ANCHOR_MISSING"
    TAIL_COMPLETENESS_UNPROVABLE = "TAIL_COMPLETENESS_UNPROVABLE"
    LATEST_ANCHOR_MISMATCH = "LATEST_ANCHOR_MISMATCH"
    ROLLBACK_DETECTED = "ROLLBACK_DETECTED"
    EVIDENCE_AFTER_LATEST_ANCHOR = "EVIDENCE_AFTER_LATEST_ANCHOR"
    LATEST_ANCHOR_STALE = "LATEST_ANCHOR_STALE"


def _unique_reason_values(reasons: Iterable[ReasonCode | str]) -> list[str]:
    result: list[str] = []
    for reason in reasons:
        value = reason.value if isinstance(reason, ReasonCode) else str(reason)
        if value not in result:
            result.append(value)
    return result


def verify_signature(pk_bytes: bytes, message: bytes, signature: bytes, scheme: str) -> bool:
    """Verify a signature with an externally trusted key."""
    if not pk_bytes or not signature:
        return False
    if scheme == "Ed25519":
        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
            pk.verify(signature, message)
            return True
        except Exception:
            return False
    try:
        with oqs.Signature(scheme) as verifier:
            return bool(verifier.verify(message, signature, pk_bytes))
    except Exception:
        return False


@dataclass(frozen=True)
class ParsedRecord:
    seq: int
    timestamp: float
    topic: str
    payload: bytes


def parse_record(record: bytes) -> ParsedRecord:
    """Strictly parse the deterministic Record serialization."""
    try:
        if len(record) < 4 + 8 + 2 + 4:
            raise ValueError("record is shorter than the fixed header")
        offset = 0
        seq = struct.unpack_from(">I", record, offset)[0]
        offset += 4
        timestamp = struct.unpack_from(">d", record, offset)[0]
        offset += 8
        topic_len = struct.unpack_from(">H", record, offset)[0]
        offset += 2
        if offset + topic_len + 4 > len(record):
            raise ValueError("record topic length exceeds record")
        topic = record[offset : offset + topic_len].decode("utf-8")
        offset += topic_len
        payload_len = struct.unpack_from(">I", record, offset)[0]
        offset += 4
        if offset + payload_len != len(record):
            raise ValueError("record payload length is non-canonical")
        return ParsedRecord(seq=seq, timestamp=timestamp, topic=topic, payload=record[offset:])
    except (UnicodeDecodeError, struct.error, ValueError) as exc:
        raise ValueError(f"invalid serialized record: {exc}") from exc


def parse_record_seq(record: bytes) -> int:
    try:
        return parse_record(record).seq
    except ValueError:
        return -1


def _record_structure_reasons(evidence: CheckpointEvidence) -> list[ReasonCode]:
    checkpoint = evidence.checkpoint
    reasons: list[ReasonCode] = []
    if checkpoint.seq_end < checkpoint.seq_start:
        reasons.append(ReasonCode.CHECKPOINT_RANGE_INVALID)
        return reasons
    expected_count = checkpoint.seq_end - checkpoint.seq_start + 1
    if expected_count <= 0 or len(evidence.records) != expected_count:
        reasons.append(ReasonCode.RECORD_COUNT_MISMATCH)
    parsed: list[ParsedRecord] = []
    for raw in evidence.records:
        try:
            parsed.append(parse_record(raw))
        except ValueError:
            reasons.append(ReasonCode.RECORD_PARSE_ERROR)
            break
    if len(parsed) == len(evidence.records):
        expected_sequences = list(range(checkpoint.seq_start, checkpoint.seq_end + 1))
        if [record.seq for record in parsed] != expected_sequences:
            reasons.append(ReasonCode.RECORD_SEQUENCE_MISMATCH)
        if any(record.topic != checkpoint.topic for record in parsed):
            reasons.append(ReasonCode.RECORD_TOPIC_MISMATCH)
    return reasons


def sequence_coverage_valid(evidence: CheckpointEvidence) -> bool:
    return not _record_structure_reasons(evidence)


def checkpoint_sequence_valid(evidence_list: Sequence[CheckpointEvidence]) -> bool:
    """Structural helper for locally generated complete streams.

    This helper establishes no trust.  Security-sensitive callers should use
    :func:`audit_stream`, which also verifies identities, signatures, proofs,
    witness policy, and explicit external anchors.
    """
    if not evidence_list:
        return False
    first = evidence_list[0].checkpoint
    stream = (first.client_id, first.topic)
    previous_anchor = ZERO_ANCHOR
    expected_epoch = 0
    expected_seq = 1
    for evidence in evidence_list:
        checkpoint = evidence.checkpoint
        if (checkpoint.client_id, checkpoint.topic) != stream:
            return False
        if checkpoint.epoch != expected_epoch or checkpoint.seq_start != expected_seq:
            return False
        if checkpoint.prev_anchor != previous_anchor or checkpoint.seq_end < checkpoint.seq_start:
            return False
        previous_anchor = checkpoint.end_anchor
        expected_epoch += 1
        expected_seq = checkpoint.seq_end + 1
    return True


@dataclass
class AuditVerdict:
    checkpoint: Checkpoint
    sig_valid: bool
    records_valid: bool
    total_records: int
    valid_records: int
    verification_time_ms: float
    proof_size_bytes: int
    details: str = ""
    accepted: bool = False
    outcome: AuditOutcome = AuditOutcome.REJECT
    reason_codes: list[str] = field(default_factory=list)
    publisher_key_id: Optional[str] = None
    valid_witnesses: int = 0
    required_witnesses: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "accepted": self.accepted,
            "reason_codes": list(self.reason_codes),
            "stream_id": TrustedRegistry.stream_id(
                self.checkpoint.client_id, self.checkpoint.topic
            ),
            "epoch": self.checkpoint.epoch,
            "seq_start": self.checkpoint.seq_start,
            "seq_end": self.checkpoint.seq_end,
            "sig_valid": self.sig_valid,
            "records_valid": self.records_valid,
            "total_records": self.total_records,
            "valid_records": self.valid_records,
            "verification_time_ms": self.verification_time_ms,
            "proof_size_bytes": self.proof_size_bytes,
            "publisher_key_id": self.publisher_key_id,
            "valid_witnesses": self.valid_witnesses,
            "required_witnesses": self.required_witnesses,
            "details": self.details,
        }


def _rejected_evidence_verdict(
    evidence: CheckpointEvidence,
    reasons: Iterable[ReasonCode | str],
    *,
    elapsed_ms: float = 0.0,
    sig_valid: bool = False,
    valid_records: int = 0,
    proof_size: int = 0,
    publisher_key_id: Optional[str] = None,
    valid_witnesses: int = 0,
    required_witnesses: int = 0,
) -> AuditVerdict:
    reason_values = _unique_reason_values(reasons)
    return AuditVerdict(
        checkpoint=evidence.checkpoint,
        sig_valid=sig_valid,
        records_valid=False,
        total_records=len(evidence.records),
        valid_records=valid_records,
        verification_time_ms=elapsed_ms,
        proof_size_bytes=proof_size,
        details=",".join(reason_values),
        accepted=False,
        outcome=AuditOutcome.REJECT,
        reason_codes=reason_values,
        publisher_key_id=publisher_key_id,
        valid_witnesses=valid_witnesses,
        required_witnesses=required_witnesses,
    )


def _publisher_authorization(
    evidence: CheckpointEvidence,
    arm_id: str,
    registry: Optional[TrustedRegistry],
) -> tuple[Optional[PublisherAuthorization], list[ReasonCode]]:
    if registry is None:
        return None, [ReasonCode.REGISTRY_REQUIRED]
    checkpoint = evidence.checkpoint
    authorization = registry.publisher_for(checkpoint.client_id, checkpoint.topic, checkpoint.epoch)
    if authorization is None:
        return None, [ReasonCode.PUBLISHER_NOT_AUTHORIZED, ReasonCode.KEY_TRANSITION_UNAUTHORIZED]
    reasons: list[ReasonCode] = []
    expected_scheme = EXPECTED_SCHEME_BY_ARM.get(arm_id)
    if expected_scheme is None:
        reasons.append(ReasonCode.ARM_UNSUPPORTED)
    elif authorization.signature_scheme != expected_scheme:
        reasons.append(ReasonCode.ARM_SCHEME_MISMATCH)
    if evidence.public_key and evidence.public_key != authorization.public_key:
        reasons.append(ReasonCode.PUBLISHER_KEY_SUBSTITUTION)
    return authorization, reasons


def _audit_merkle(
    evidence: CheckpointEvidence,
    authorization: PublisherAuthorization,
) -> tuple[bool, bool, int, int, list[ReasonCode]]:
    reasons = _record_structure_reasons(evidence)
    signature_ok = verify_signature(
        authorization.public_key,
        evidence.checkpoint.serialize(),
        evidence.signature,
        authorization.signature_scheme,
    )
    if not signature_ok:
        reasons.append(ReasonCode.PUBLISHER_SIGNATURE_INVALID)
    proofs = evidence.merkle_proofs or []
    total = len(evidence.records)
    if total == 0:
        reasons.append(ReasonCode.EMPTY_EVIDENCE)
    if len(proofs) != total:
        reasons.append(ReasonCode.PROOF_COUNT_MISMATCH)
    valid_count = 0
    for index, raw in enumerate(evidence.records):
        if index >= len(proofs):
            continue
        leaf = hashlib.sha256(MerkleTree.LEAF_PREFIX + raw).digest()
        if MerkleTree.verify_proof(leaf, proofs[index], evidence.checkpoint.end_anchor):
            valid_count += 1
    if valid_count != total:
        reasons.append(ReasonCode.MERKLE_PROOF_INVALID)
    proof_size = sum(len(sibling) + 1 for proof in proofs for sibling, _ in proof) + len(evidence.signature)
    return signature_ok, not reasons, valid_count, proof_size, reasons


def _audit_a1(
    evidence: CheckpointEvidence,
    authorization: PublisherAuthorization,
) -> tuple[bool, bool, int, int, list[ReasonCode]]:
    reasons = _record_structure_reasons(evidence)
    if len(evidence.records) != 1:
        reasons.append(ReasonCode.RECORD_COUNT_MISMATCH)
    raw = evidence.records[0] if evidence.records else b""
    try:
        parsed = parse_record(raw)
        signed_body = WireEnvelope(
            auth_kind=WIRE_AUTH_SIGNATURE,
            algorithm=SIG_ALG_PQC,
            key_id="sig-" + hashlib.sha256(authorization.public_key).hexdigest(),
            session_id="",
            epoch=evidence.checkpoint.epoch,
            seq=parsed.seq,
            record=raw,
        ).unsigned_bytes()
    except ValueError:
        signed_body = b""
    signature_ok = verify_signature(
        authorization.public_key,
        signed_body,
        evidence.signature,
        authorization.signature_scheme,
    )
    if not signature_ok:
        reasons.append(ReasonCode.PUBLISHER_SIGNATURE_INVALID)
    commitment_ok = bool(raw) and hashlib.sha256(raw).digest() == evidence.checkpoint.end_anchor
    if not commitment_ok:
        reasons.append(ReasonCode.RECORD_COMMITMENT_INVALID)
    return signature_ok, not reasons, 1 if not reasons else 0, len(evidence.signature), reasons


def _audit_hash_chain(
    evidence: CheckpointEvidence,
    authorization: PublisherAuthorization,
) -> tuple[bool, bool, int, int, list[ReasonCode]]:
    reasons = _record_structure_reasons(evidence)
    signature_ok = verify_signature(
        authorization.public_key,
        evidence.checkpoint.serialize(),
        evidence.signature,
        authorization.signature_scheme,
    )
    if not signature_ok:
        reasons.append(ReasonCode.PUBLISHER_SIGNATURE_INVALID)
    values = evidence.chain_values or []
    seed = evidence.chain_seed
    chain_ok = seed is not None and len(values) == len(evidence.records) + 1
    if chain_ok:
        computed = [hashlib.sha256(seed).digest()]
        current = computed[0]
        for raw in evidence.records:
            current = hashlib.sha256(current + raw).digest()
            computed.append(current)
        chain_ok = computed == values and computed[-1] == evidence.checkpoint.end_anchor
    if not chain_ok:
        reasons.append(ReasonCode.HASH_CHAIN_INVALID)
    proof_size = sum(len(value) for value in values) + len(evidence.signature)
    valid_count = len(evidence.records) if chain_ok else 0
    return signature_ok, not reasons, valid_count, proof_size, reasons


@dataclass
class WitnessVerification:
    accepted: bool
    valid_distinct: int
    total_receipts: int
    required: int
    reason_codes: list[str]
    details: str


def _verify_witness_receipts_detailed(
    evidence: CheckpointEvidence,
    registry: Optional[TrustedRegistry],
    *,
    min_receipts: Optional[int] = None,
) -> WitnessVerification:
    receipts = evidence.witness_receipts or []
    if registry is None:
        return WitnessVerification(
            False, 0, len(receipts), min_receipts or 0,
            [ReasonCode.REGISTRY_REQUIRED.value], ReasonCode.REGISTRY_REQUIRED.value,
        )
    checkpoint = evidence.checkpoint
    stream_id = TrustedRegistry.stream_id(checkpoint.client_id, checkpoint.topic)
    policy = registry.witness_policy_for(stream_id)
    if policy is None:
        return WitnessVerification(
            False, 0, len(receipts), min_receipts or 0,
            [ReasonCode.WITNESS_POLICY_MISSING.value], ReasonCode.WITNESS_POLICY_MISSING.value,
        )
    required = max(policy.quorum, min_receipts or 0)
    reasons: list[ReasonCode] = []
    seen_ids: set[str] = set()
    seen_keys: set[str] = set()
    valid = 0
    for receipt in receipts:
        if receipt.witness_id in seen_ids:
            reasons.append(ReasonCode.WITNESS_DUPLICATE_ID)
            continue
        seen_ids.add(receipt.witness_id)
        authorization = registry.witness_for_id(receipt.witness_id)
        if authorization is None or receipt.witness_id not in policy.authorized_witness_ids:
            reasons.append(ReasonCode.WITNESS_UNTRUSTED)
            continue
        if not authorization.authorizes(stream_id, checkpoint.epoch):
            reasons.append(ReasonCode.WITNESS_NOT_AUTHORIZED)
            continue
        if authorization.key_id in seen_keys:
            reasons.append(ReasonCode.WITNESS_DUPLICATE_KEY)
            continue
        seen_keys.add(authorization.key_id)
        if receipt.public_key and receipt.public_key != authorization.public_key:
            reasons.append(ReasonCode.WITNESS_KEY_SUBSTITUTION)
            continue
        fields_match = (
            receipt.stream_id == stream_id
            and receipt.checkpoint_epoch == checkpoint.epoch
            and receipt.seq_start == checkpoint.seq_start
            and receipt.seq_end == checkpoint.seq_end
            and receipt.prev_witnessed_anchor == checkpoint.prev_anchor
            and receipt.checkpoint_anchor == checkpoint.end_anchor
        )
        if not fields_match:
            reasons.append(ReasonCode.WITNESS_FIELDS_MISMATCH)
            continue
        if not verify_signature(
            authorization.public_key,
            receipt.serialize(),
            receipt.signature,
            authorization.signature_scheme,
        ):
            reasons.append(ReasonCode.WITNESS_SIGNATURE_INVALID)
            continue
        valid += 1
    if valid < required:
        reasons.append(ReasonCode.WITNESS_BELOW_QUORUM)
    accepted = valid >= required and not reasons
    values = _unique_reason_values(reasons)
    details = f"witness_valid={valid}/{len(receipts)}, required={required}"
    if values:
        details += "; " + ",".join(values)
    return WitnessVerification(accepted, valid, len(receipts), required, values, details)


def verify_witness_receipts(
    evidence: CheckpointEvidence,
    *,
    registry: Optional[TrustedRegistry] = None,
    min_receipts: Optional[int] = None,
    scheme: Optional[str] = None,
) -> tuple[bool, int, int, str]:
    """Verify a distinct trusted witness quorum.

    ``scheme`` is retained for source compatibility but is never trusted; each
    witness scheme comes from the external registry.
    """
    del scheme
    result = _verify_witness_receipts_detailed(evidence, registry, min_receipts=min_receipts)
    return result.accepted, result.valid_distinct, result.total_receipts, result.details


def audit_evidence(
    evidence: CheckpointEvidence,
    arm_id: str,
    registry: Optional[TrustedRegistry] = None,
    *,
    witness_quorum: Optional[int] = None,
) -> AuditVerdict:
    """Verify one checkpoint against a separately supplied trust registry.

    Omitting ``registry`` is a fail-closed rejection.  Bundle-carried publisher
    and witness keys are compared with the registry but never used as roots of
    trust.
    """
    started = time.perf_counter()
    authorization, authorization_reasons = _publisher_authorization(evidence, arm_id, registry)
    if authorization is None or authorization_reasons:
        return _rejected_evidence_verdict(
            evidence,
            authorization_reasons,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            publisher_key_id=authorization.key_id if authorization else None,
        )
    if arm_id in ("A0", "A4", "A5", "A6"):
        signature_ok, records_ok, valid_count, proof_size, reasons = _audit_merkle(
            evidence, authorization
        )
    elif arm_id == "A1":
        signature_ok, records_ok, valid_count, proof_size, reasons = _audit_a1(
            evidence, authorization
        )
    elif arm_id == "A3":
        signature_ok, records_ok, valid_count, proof_size, reasons = _audit_hash_chain(
            evidence, authorization
        )
    elif arm_id == "A2":
        return _rejected_evidence_verdict(
            evidence,
            [ReasonCode.NON_TRANSFERABLE_ARM],
            elapsed_ms=(time.perf_counter() - started) * 1000,
            publisher_key_id=authorization.key_id,
        )
    else:
        return _rejected_evidence_verdict(
            evidence,
            [ReasonCode.ARM_UNSUPPORTED],
            elapsed_ms=(time.perf_counter() - started) * 1000,
            publisher_key_id=authorization.key_id,
        )

    witness_result: Optional[WitnessVerification] = None
    if arm_id == "A6":
        witness_result = _verify_witness_receipts_detailed(
            evidence, registry, min_receipts=witness_quorum
        )
        if not witness_result.accepted:
            reasons.extend(ReasonCode(reason) for reason in witness_result.reason_codes)
            records_ok = False
        proof_size += sum(
            len(receipt.serialize()) + len(receipt.signature)
            for receipt in (evidence.witness_receipts or [])
        )

    elapsed = (time.perf_counter() - started) * 1000
    if reasons or not records_ok:
        return _rejected_evidence_verdict(
            evidence,
            reasons or [ReasonCode.RECORD_COMMITMENT_INVALID],
            elapsed_ms=elapsed,
            sig_valid=signature_ok,
            valid_records=valid_count,
            proof_size=proof_size,
            publisher_key_id=authorization.key_id,
            valid_witnesses=witness_result.valid_distinct if witness_result else 0,
            required_witnesses=witness_result.required if witness_result else 0,
        )
    detail = "cryptographic evidence verified against external registry"
    if witness_result:
        detail += f"; {witness_result.details}"
    return AuditVerdict(
        checkpoint=evidence.checkpoint,
        sig_valid=True,
        records_valid=True,
        total_records=len(evidence.records),
        valid_records=valid_count,
        verification_time_ms=elapsed,
        proof_size_bytes=proof_size,
        details=detail,
        accepted=True,
        outcome=AuditOutcome.ACCEPT,
        reason_codes=[ReasonCode.VERIFIED.value],
        publisher_key_id=authorization.key_id,
        valid_witnesses=witness_result.valid_distinct if witness_result else 0,
        required_witnesses=witness_result.required if witness_result else 0,
    )


def audit_all(
    evidence_list: Sequence[CheckpointEvidence],
    arm_id: str,
    registry: Optional[TrustedRegistry] = None,
    *,
    witness_quorum: Optional[int] = None,
) -> list[AuditVerdict]:
    """Verify individual evidence items; use :func:`audit_stream` for history claims."""
    return [
        audit_evidence(item, arm_id, registry, witness_quorum=witness_quorum)
        for item in evidence_list
    ]


@dataclass(frozen=True)
class AnchorPosition:
    anchor: bytes
    epoch: int
    seq: int
    observed_at: Optional[float] = None
    valid_until: Optional[float] = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, latest: bool) -> "AnchorPosition":
        try:
            anchor = bytes.fromhex(str(data["anchor_hex"]))
            epoch_field = "epoch" if latest else "next_epoch"
            seq_field = "seq_end" if latest else "next_seq"
            epoch = data[epoch_field]
            seq = data[seq_field]
        except (KeyError, ValueError) as exc:
            raise ValueError(f"malformed {'latest' if latest else 'genesis'} anchor") from exc
        if len(anchor) != 32:
            raise ValueError("anchors must be 32 bytes")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise ValueError(f"{epoch_field} must be a non-negative integer")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < (0 if latest else 1):
            raise ValueError(f"{seq_field} is outside its allowed range")
        observed = data.get("observed_at")
        valid_until = data.get("valid_until")
        if observed is not None and (
            isinstance(observed, bool)
            or not isinstance(observed, (int, float))
            or not math.isfinite(float(observed))
        ):
            raise ValueError("observed_at must be numeric")
        if valid_until is not None and (
            isinstance(valid_until, bool)
            or not isinstance(valid_until, (int, float))
            or not math.isfinite(float(valid_until))
        ):
            raise ValueError("valid_until must be numeric")
        if observed is not None and valid_until is not None and valid_until < observed:
            raise ValueError("valid_until precedes observed_at")
        return cls(
            anchor=anchor,
            epoch=epoch,
            seq=seq,
            observed_at=float(observed) if observed is not None else None,
            valid_until=float(valid_until) if valid_until is not None else None,
        )

    def to_dict(self, *, latest: bool) -> dict[str, Any]:
        data: dict[str, Any] = {"anchor_hex": self.anchor.hex()}
        if latest:
            data.update({"epoch": self.epoch, "seq_end": self.seq})
        else:
            data.update({"next_epoch": self.epoch, "next_seq": self.seq})
        if self.observed_at is not None:
            data["observed_at"] = self.observed_at
        if self.valid_until is not None:
            data["valid_until"] = self.valid_until
        return data


@dataclass(frozen=True)
class StreamAnchors:
    stream_id: str
    genesis: AnchorPosition
    latest: Optional[AnchorPosition] = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "StreamAnchors":
        stream_id = data.get("stream_id")
        if not isinstance(stream_id, str) or not stream_id:
            raise ValueError("anchor stream_id must be a non-empty string")
        genesis_data = data.get("genesis")
        if not isinstance(genesis_data, dict):
            raise ValueError("each stream requires an explicit genesis anchor")
        latest_data = data.get("latest")
        if latest_data is not None and not isinstance(latest_data, dict):
            raise ValueError("latest anchor must be an object or null")
        return cls(
            stream_id=stream_id,
            genesis=AnchorPosition.from_dict(genesis_data, latest=False),
            latest=AnchorPosition.from_dict(latest_data, latest=True) if latest_data else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "stream_id": self.stream_id,
            "genesis": self.genesis.to_dict(latest=False),
            "latest": self.latest.to_dict(latest=True) if self.latest else None,
        }


@dataclass
class AnchorSet:
    streams: list[StreamAnchors]
    anchor_set_id: str = ""

    def __post_init__(self) -> None:
        ids = [stream.stream_id for stream in self.streams]
        if len(ids) != len(set(ids)):
            raise ValueError("anchor set contains duplicate stream_id entries")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AnchorSet":
        if data.get("schema_version") != ANCHOR_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported anchor schema {data.get('schema_version')!r}; "
                f"expected {ANCHOR_SCHEMA_VERSION!r}"
            )
        streams = data.get("streams")
        if not isinstance(streams, list) or not streams:
            raise ValueError("anchor set streams must be a non-empty list")
        if not all(isinstance(row, Mapping) for row in streams):
            raise ValueError("each anchor stream must be an object")
        return cls(
            streams=[StreamAnchors.from_dict(row) for row in streams],
            anchor_set_id=str(data.get("anchor_set_id", "")),
        )

    @classmethod
    def load(cls, path: str | Path) -> "AnchorSet":
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("anchor JSON root must be an object")
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ANCHOR_SCHEMA_VERSION,
            "anchor_set_id": self.anchor_set_id,
            "streams": [stream.to_dict() for stream in self.streams],
        }

    def for_stream(self, stream_id: str) -> Optional[StreamAnchors]:
        return next((stream for stream in self.streams if stream.stream_id == stream_id), None)

    @classmethod
    def combine(
        cls,
        anchor_sets: Iterable["AnchorSet"],
        *,
        anchor_set_id: str = "combined-anchor-set",
    ) -> "AnchorSet":
        streams = [stream for anchor_set in anchor_sets for stream in anchor_set.streams]
        return cls(streams=streams, anchor_set_id=anchor_set_id)


def anchors_for_generated_evidence(
    evidence: Sequence[CheckpointEvidence],
    *,
    include_latest: bool = True,
    genesis_anchor: bytes = ZERO_ANCHOR,
    next_epoch: int = 0,
    next_seq: int = 1,
    observed_at: Optional[float] = None,
    valid_until: Optional[float] = None,
    anchor_set_id: str = "generated-test-anchors",
) -> AnchorSet:
    """Create explicit anchors for locally generated runner/test evidence.

    A production auditor must obtain these values through its external trust
    process; this helper merely serializes the experiment runner's declared
    trust assumption into the same input consumed by the independent CLI.
    """
    if not evidence:
        raise ValueError("cannot construct anchors for empty evidence")
    first = evidence[0].checkpoint
    last = evidence[-1].checkpoint
    stream_id = TrustedRegistry.stream_id(first.client_id, first.topic)
    return AnchorSet(
        streams=[
            StreamAnchors(
                stream_id=stream_id,
                genesis=AnchorPosition(
                    anchor=genesis_anchor,
                    epoch=next_epoch,
                    seq=next_seq,
                ),
                latest=AnchorPosition(
                    anchor=last.end_anchor,
                    epoch=last.epoch,
                    seq=last.seq_end,
                    observed_at=observed_at,
                    valid_until=valid_until,
                )
                if include_latest
                else None,
            )
        ],
        anchor_set_id=anchor_set_id,
    )


@dataclass
class StreamAuditVerdict:
    outcome: AuditOutcome
    reason_codes: list[str]
    stream_id: Optional[str]
    checkpoint_verdicts: list[AuditVerdict]
    verified_checkpoints: int
    verified_records: int
    tail_complete: bool
    started_from_trusted_anchor: bool
    ended_at_trusted_latest: bool
    verification_time_ms: float
    limitations: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.outcome == AuditOutcome.ACCEPT

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "accepted": self.accepted,
            "reason_codes": list(self.reason_codes),
            "stream_id": self.stream_id,
            "verified_checkpoints": self.verified_checkpoints,
            "verified_records": self.verified_records,
            "tail_complete": self.tail_complete,
            "started_from_trusted_anchor": self.started_from_trusted_anchor,
            "ended_at_trusted_latest": self.ended_at_trusted_latest,
            "verification_time_ms": self.verification_time_ms,
            "limitations": list(self.limitations),
            "checkpoint_verdicts": [verdict.to_dict() for verdict in self.checkpoint_verdicts],
        }


def _stream_reject(
    started: float,
    reasons: Iterable[ReasonCode | str],
    *,
    stream_id: Optional[str],
    verdicts: Optional[list[AuditVerdict]] = None,
    started_from_anchor: bool = False,
) -> StreamAuditVerdict:
    checkpoint_verdicts = verdicts or []
    return StreamAuditVerdict(
        outcome=AuditOutcome.REJECT,
        reason_codes=_unique_reason_values(reasons),
        stream_id=stream_id,
        checkpoint_verdicts=checkpoint_verdicts,
        verified_checkpoints=sum(1 for verdict in checkpoint_verdicts if verdict.accepted),
        verified_records=sum(verdict.valid_records for verdict in checkpoint_verdicts if verdict.accepted),
        tail_complete=False,
        started_from_trusted_anchor=started_from_anchor,
        ended_at_trusted_latest=False,
        verification_time_ms=(time.perf_counter() - started) * 1000,
    )


def audit_stream(
    evidence_list: Sequence[CheckpointEvidence],
    arm_id: str,
    registry: Optional[TrustedRegistry],
    anchors: Optional[AnchorSet],
    *,
    audit_time: Optional[float] = None,
    witness_quorum: Optional[int] = None,
) -> StreamAuditVerdict:
    """Verify a complete, ordered evidence stream against external trust state.

    A cryptographically valid suffix without a trusted latest anchor returns
    ``inconclusive`` because tail deletion/rollback is observationally
    indistinguishable from a stream that legitimately ended there.
    """
    started = time.perf_counter()
    if arm_id == "A2":
        return _stream_reject(started, [ReasonCode.NON_TRANSFERABLE_ARM], stream_id=None)
    if registry is None:
        return _stream_reject(started, [ReasonCode.REGISTRY_REQUIRED], stream_id=None)
    if anchors is None:
        return _stream_reject(started, [ReasonCode.ANCHOR_SET_REQUIRED], stream_id=None)
    if not evidence_list:
        return _stream_reject(started, [ReasonCode.EMPTY_EVIDENCE], stream_id=None)

    first_checkpoint = evidence_list[0].checkpoint
    stream_id = TrustedRegistry.stream_id(first_checkpoint.client_id, first_checkpoint.topic)
    stream_anchors = anchors.for_stream(stream_id)
    if stream_anchors is None:
        return _stream_reject(
            started, [ReasonCode.GENESIS_ANCHOR_REQUIRED], stream_id=stream_id
        )

    genesis = stream_anchors.genesis
    expected_prev = genesis.anchor
    expected_epoch = genesis.epoch
    expected_seq = genesis.seq
    previous_key_id: Optional[str] = None
    seen_epochs: set[int] = set()
    seen_ranges: set[tuple[int, int]] = set()
    seen_anchors: set[bytes] = {genesis.anchor}
    seen_record_hashes: set[bytes] = set()
    verdicts: list[AuditVerdict] = []
    stream_reasons: list[ReasonCode] = []

    presented_epochs = [item.checkpoint.epoch for item in evidence_list]
    presented_starts = [item.checkpoint.seq_start for item in evidence_list]
    if len(presented_epochs) != len(set(presented_epochs)):
        stream_reasons.extend([ReasonCode.EPOCH_DUPLICATE, ReasonCode.DUPLICATE_CHECKPOINT])
    if any(right < left for left, right in zip(presented_epochs, presented_epochs[1:])):
        stream_reasons.append(ReasonCode.EPOCH_REORDER)
    if any(right < left for left, right in zip(presented_starts, presented_starts[1:])):
        stream_reasons.append(ReasonCode.SEQUENCE_REORDER)
    presented_anchors = [item.checkpoint.end_anchor for item in evidence_list]
    presented_record_hashes = [
        hashlib.sha256(raw).digest() for item in evidence_list for raw in item.records
    ]
    if (
        len(presented_anchors) != len(set(presented_anchors))
        or len(presented_record_hashes) != len(set(presented_record_hashes))
    ):
        stream_reasons.append(ReasonCode.CROSS_EPOCH_REPLAY)

    for evidence in evidence_list:
        checkpoint = evidence.checkpoint
        current_stream = TrustedRegistry.stream_id(checkpoint.client_id, checkpoint.topic)
        if current_stream != stream_id:
            stream_reasons.extend([ReasonCode.MIXED_STREAM, ReasonCode.SPLICE_OR_FORK])
            break
        if checkpoint.seq_end < checkpoint.seq_start:
            stream_reasons.append(ReasonCode.CHECKPOINT_RANGE_INVALID)
        if checkpoint.epoch != expected_epoch:
            if checkpoint.epoch in seen_epochs:
                stream_reasons.extend([ReasonCode.EPOCH_DUPLICATE, ReasonCode.DUPLICATE_CHECKPOINT])
            elif checkpoint.epoch < expected_epoch:
                stream_reasons.extend([ReasonCode.EPOCH_REORDER, ReasonCode.EPOCH_ROLLBACK])
            else:
                stream_reasons.extend([ReasonCode.EPOCH_GAP, ReasonCode.MIDDLE_TRUNCATION])
        if checkpoint.seq_start != expected_seq:
            if (checkpoint.seq_start, checkpoint.seq_end) in seen_ranges:
                stream_reasons.extend([ReasonCode.SEQUENCE_DUPLICATE, ReasonCode.DUPLICATE_CHECKPOINT])
            elif checkpoint.seq_start < expected_seq:
                stream_reasons.append(ReasonCode.SEQUENCE_REORDER)
            else:
                stream_reasons.extend([ReasonCode.SEQUENCE_GAP, ReasonCode.MIDDLE_TRUNCATION])
        if checkpoint.prev_anchor != expected_prev:
            stream_reasons.extend([ReasonCode.PREV_ANCHOR_MISMATCH, ReasonCode.SPLICE_OR_FORK])
            if not verdicts:
                stream_reasons.append(ReasonCode.GENESIS_ANCHOR_MISMATCH)
        record_hashes = [hashlib.sha256(raw).digest() for raw in evidence.records]
        if checkpoint.end_anchor in seen_anchors or any(digest in seen_record_hashes for digest in record_hashes):
            stream_reasons.append(ReasonCode.CROSS_EPOCH_REPLAY)
        if any(reason != ReasonCode.AUTHORIZED_KEY_TRANSITION for reason in stream_reasons):
            break

        verdict = audit_evidence(
            evidence, arm_id, registry, witness_quorum=witness_quorum
        )
        verdicts.append(verdict)
        if not verdict.accepted:
            stream_reasons.extend(ReasonCode(reason) for reason in verdict.reason_codes)
            break
        authorization = registry.publisher_for(
            checkpoint.client_id, checkpoint.topic, checkpoint.epoch
        )
        if authorization is None:
            stream_reasons.append(ReasonCode.KEY_TRANSITION_UNAUTHORIZED)
            break
        if previous_key_id is not None and authorization.key_id != previous_key_id:
            stream_reasons.append(ReasonCode.AUTHORIZED_KEY_TRANSITION)
        previous_key_id = authorization.key_id
        seen_epochs.add(checkpoint.epoch)
        seen_ranges.add((checkpoint.seq_start, checkpoint.seq_end))
        seen_anchors.add(checkpoint.end_anchor)
        seen_record_hashes.update(record_hashes)
        expected_prev = checkpoint.end_anchor
        expected_epoch = checkpoint.epoch + 1
        expected_seq = checkpoint.seq_end + 1

    fatal_reasons = [reason for reason in stream_reasons if reason != ReasonCode.AUTHORIZED_KEY_TRANSITION]
    if fatal_reasons:
        return _stream_reject(
            started,
            stream_reasons,
            stream_id=stream_id,
            verdicts=verdicts,
            started_from_anchor=True,
        )

    latest = stream_anchors.latest
    limitations: list[str] = []
    if latest is None:
        return StreamAuditVerdict(
            outcome=AuditOutcome.INCONCLUSIVE,
            reason_codes=_unique_reason_values(
                stream_reasons
                + [ReasonCode.LATEST_ANCHOR_MISSING, ReasonCode.TAIL_COMPLETENESS_UNPROVABLE]
            ),
            stream_id=stream_id,
            checkpoint_verdicts=verdicts,
            verified_checkpoints=len(verdicts),
            verified_records=sum(verdict.valid_records for verdict in verdicts),
            tail_complete=False,
            started_from_trusted_anchor=True,
            ended_at_trusted_latest=False,
            verification_time_ms=(time.perf_counter() - started) * 1000,
            limitations=["tail deletion and rollback cannot be decided without a trusted latest anchor"],
        )

    last = evidence_list[-1].checkpoint
    if last.epoch < latest.epoch or last.seq_end < latest.seq:
        return _stream_reject(
            started,
            stream_reasons + [ReasonCode.LATEST_ANCHOR_MISMATCH, ReasonCode.ROLLBACK_DETECTED],
            stream_id=stream_id,
            verdicts=verdicts,
            started_from_anchor=True,
        )
    if last.epoch > latest.epoch or last.seq_end > latest.seq:
        return _stream_reject(
            started,
            stream_reasons + [ReasonCode.EVIDENCE_AFTER_LATEST_ANCHOR],
            stream_id=stream_id,
            verdicts=verdicts,
            started_from_anchor=True,
        )
    if last.end_anchor != latest.anchor:
        return _stream_reject(
            started,
            stream_reasons + [ReasonCode.LATEST_ANCHOR_MISMATCH, ReasonCode.SPLICE_OR_FORK],
            stream_id=stream_id,
            verdicts=verdicts,
            started_from_anchor=True,
        )
    now = time.time() if audit_time is None else audit_time
    if latest.valid_until is not None and now > latest.valid_until:
        return StreamAuditVerdict(
            outcome=AuditOutcome.INCONCLUSIVE,
            reason_codes=_unique_reason_values(stream_reasons + [ReasonCode.LATEST_ANCHOR_STALE]),
            stream_id=stream_id,
            checkpoint_verdicts=verdicts,
            verified_checkpoints=len(verdicts),
            verified_records=sum(verdict.valid_records for verdict in verdicts),
            tail_complete=False,
            started_from_trusted_anchor=True,
            ended_at_trusted_latest=True,
            verification_time_ms=(time.perf_counter() - started) * 1000,
            limitations=["latest anchor expired before the requested audit time"],
        )

    if arm_id == "A1":
        return StreamAuditVerdict(
            outcome=AuditOutcome.INCONCLUSIVE,
            reason_codes=_unique_reason_values(
                stream_reasons + [ReasonCode.HISTORY_BINDING_UNAVAILABLE]
            ),
            stream_id=stream_id,
            checkpoint_verdicts=verdicts,
            verified_checkpoints=len(verdicts),
            verified_records=sum(verdict.valid_records for verdict in verdicts),
            tail_complete=True,
            started_from_trusted_anchor=True,
            ended_at_trusted_latest=True,
            verification_time_ms=(time.perf_counter() - started) * 1000,
            limitations=[
                "per-message signatures authenticate records but do not cryptographically bind one history view"
            ],
        )

    return StreamAuditVerdict(
        outcome=AuditOutcome.ACCEPT,
        reason_codes=_unique_reason_values(stream_reasons + [ReasonCode.VERIFIED]),
        stream_id=stream_id,
        checkpoint_verdicts=verdicts,
        verified_checkpoints=len(verdicts),
        verified_records=sum(verdict.valid_records for verdict in verdicts),
        tail_complete=True,
        started_from_trusted_anchor=True,
        ended_at_trusted_latest=True,
        verification_time_ms=(time.perf_counter() - started) * 1000,
        limitations=limitations,
    )


def audit_selective_disclosure(
    evidence: CheckpointEvidence,
    arm_id: str,
    disclosed_indices: Sequence[int],
    registry: Optional[TrustedRegistry] = None,
    *,
    witness_quorum: Optional[int] = None,
) -> AuditVerdict:
    """Verify selected Merkle records against an externally trusted publisher key."""
    started = time.perf_counter()
    if arm_id not in ("A0", "A4", "A5", "A6"):
        return _rejected_evidence_verdict(evidence, [ReasonCode.ARM_UNSUPPORTED])
    authorization, reasons = _publisher_authorization(evidence, arm_id, registry)
    if authorization is None or reasons:
        return _rejected_evidence_verdict(evidence, reasons)
    signature_ok = verify_signature(
        authorization.public_key,
        evidence.checkpoint.serialize(),
        evidence.signature,
        authorization.signature_scheme,
    )
    if not signature_ok:
        reasons.append(ReasonCode.PUBLISHER_SIGNATURE_INVALID)
    valid_count = 0
    proof_size = len(evidence.signature)
    seen: set[int] = set()
    for index in disclosed_indices:
        if index in seen or index < 0 or index >= len(evidence.records):
            reasons.append(ReasonCode.RECORD_SEQUENCE_MISMATCH)
            continue
        seen.add(index)
        proofs = evidence.merkle_proofs or []
        if index >= len(proofs):
            reasons.append(ReasonCode.PROOF_COUNT_MISMATCH)
            continue
        proof = proofs[index]
        leaf = hashlib.sha256(MerkleTree.LEAF_PREFIX + evidence.records[index]).digest()
        if MerkleTree.verify_proof(leaf, proof, evidence.checkpoint.end_anchor):
            valid_count += 1
        else:
            reasons.append(ReasonCode.MERKLE_PROOF_INVALID)
        proof_size += sum(len(sibling) + 1 for sibling, _ in proof)
    witness_result: Optional[WitnessVerification] = None
    if arm_id == "A6":
        witness_result = _verify_witness_receipts_detailed(
            evidence,
            registry,
            min_receipts=witness_quorum,
        )
        if not witness_result.accepted:
            reasons.extend(ReasonCode(reason) for reason in witness_result.reason_codes)
        proof_size += sum(
            len(receipt.serialize()) + len(receipt.signature)
            for receipt in (evidence.witness_receipts or [])
        )
    elapsed = (time.perf_counter() - started) * 1000
    if reasons or valid_count != len(disclosed_indices):
        return _rejected_evidence_verdict(
            evidence,
            reasons or [ReasonCode.MERKLE_PROOF_INVALID],
            elapsed_ms=elapsed,
            sig_valid=signature_ok,
            valid_records=valid_count,
            proof_size=proof_size,
            publisher_key_id=authorization.key_id,
            valid_witnesses=witness_result.valid_distinct if witness_result else 0,
            required_witnesses=witness_result.required if witness_result else 0,
        )
    return AuditVerdict(
        checkpoint=evidence.checkpoint,
        sig_valid=True,
        records_valid=True,
        total_records=len(disclosed_indices),
        valid_records=valid_count,
        verification_time_ms=elapsed,
        proof_size_bytes=proof_size,
        details="selective disclosure verified against external registry",
        accepted=True,
        outcome=AuditOutcome.ACCEPT,
        reason_codes=[ReasonCode.VERIFIED.value],
        publisher_key_id=authorization.key_id,
        valid_witnesses=witness_result.valid_distinct if witness_result else 0,
        required_witnesses=witness_result.required if witness_result else 0,
    )


def _require_hex(data: Mapping[str, Any], name: str, *, length: Optional[int] = None) -> bytes:
    value = data.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a hexadecimal string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} is not valid hexadecimal") from exc
    if length is not None and len(decoded) != length:
        raise ValueError(f"{name} must decode to {length} bytes")
    return decoded


def _require_json_int(
    data: Mapping[str, Any],
    name: str,
    *,
    minimum: int = 0,
) -> int:
    value = data.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def _require_json_float(data: Mapping[str, Any], name: str) -> float:
    value = data.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    return result


def checkpoint_from_dict(data: Mapping[str, Any]) -> Checkpoint:
    required = ("client_id", "topic", "epoch", "seq_start", "seq_end", "ts_ckpt")
    if any(name not in data for name in required):
        raise ValueError("checkpoint is missing required fields")
    return Checkpoint(
        client_id=str(data["client_id"]),
        topic=str(data["topic"]),
        epoch=_require_json_int(data, "epoch"),
        seq_start=_require_json_int(data, "seq_start", minimum=1),
        seq_end=_require_json_int(data, "seq_end", minimum=1),
        prev_anchor=_require_hex(data, "prev_anchor_hex", length=32),
        end_anchor=_require_hex(data, "end_anchor_hex", length=32),
        ts_ckpt=_require_json_float(data, "ts_ckpt"),
    )


def evidence_from_dict(data: Mapping[str, Any]) -> CheckpointEvidence:
    checkpoint_data = data.get("checkpoint")
    if not isinstance(checkpoint_data, dict):
        raise ValueError("evidence checkpoint must be an object")
    records = data.get("records_hex")
    if not isinstance(records, list) or not all(isinstance(item, str) for item in records):
        raise ValueError("evidence records_hex must be a hexadecimal string list")
    proof_rows = data.get("merkle_proofs")
    proofs: Optional[list[list[Tuple[bytes, bool]]]] = None
    if proof_rows is not None:
        if not isinstance(proof_rows, list):
            raise ValueError("merkle_proofs must be a list")
        proofs = []
        for proof_row in proof_rows:
            if not isinstance(proof_row, list):
                raise ValueError("each Merkle proof must be a list")
            proof: list[Tuple[bytes, bool]] = []
            for node in proof_row:
                if not isinstance(node, dict) or not isinstance(node.get("current_is_left"), bool):
                    raise ValueError("malformed Merkle proof node")
                proof.append((_require_hex(node, "sibling_hash_hex", length=32), node["current_is_left"]))
            proofs.append(proof)
    witness_rows = data.get("witness_receipts")
    receipts: Optional[list[WitnessReceipt]] = None
    if witness_rows is not None:
        if not isinstance(witness_rows, list):
            raise ValueError("witness_receipts must be a list")
        receipts = []
        for row in witness_rows:
            if not isinstance(row, dict):
                raise ValueError("witness receipt must be an object")
            receipts.append(
                WitnessReceipt(
                    witness_id=str(row["witness_id"]),
                    stream_id=str(row["stream_id"]),
                    checkpoint_epoch=_require_json_int(row, "checkpoint_epoch"),
                    seq_start=_require_json_int(row, "seq_start", minimum=1),
                    seq_end=_require_json_int(row, "seq_end", minimum=1),
                    prev_witnessed_anchor=_require_hex(row, "prev_witnessed_anchor_hex", length=32),
                    checkpoint_anchor=_require_hex(row, "checkpoint_anchor_hex", length=32),
                    ts_witness=_require_json_float(row, "ts_witness"),
                    signature=_require_hex(row, "signature_hex"),
                    public_key=_require_hex(row, "public_key_hex") if "public_key_hex" in row else b"",
                )
            )
    return CheckpointEvidence(
        checkpoint=checkpoint_from_dict(checkpoint_data),
        signature=_require_hex(data, "signature_hex"),
        public_key=_require_hex(data, "public_key_hex") if "public_key_hex" in data else b"",
        records=[bytes.fromhex(item) for item in records],
        merkle_proofs=proofs,
        chain_values=[bytes.fromhex(item) for item in data.get("chain_values_hex", [])]
        if "chain_values_hex" in data
        else None,
        chain_seed=_require_hex(data, "chain_seed_hex") if "chain_seed_hex" in data else None,
        witness_receipts=receipts,
    )


def load_evidence_bundle_v2(path: str | Path) -> tuple[str, list[CheckpointEvidence], dict[str, Any]]:
    """Load only the v2 bundle schema; legacy unversioned bundles are rejected."""
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("evidence bundle JSON root must be an object")
    if data.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise ValueError(
            f"{ReasonCode.BUNDLE_SCHEMA_UNSUPPORTED.value}: got {data.get('schema_version')!r}, "
            f"expected {BUNDLE_SCHEMA_VERSION!r}"
        )
    arm_id = data.get("arm_id")
    if not isinstance(arm_id, str) or arm_id not in EXPECTED_SCHEME_BY_ARM:
        raise ValueError("bundle arm_id is missing or unsupported")
    rows = data.get("evidence")
    if not isinstance(rows, list) or not rows:
        raise ValueError("bundle evidence must be a non-empty list")
    if not all(isinstance(row, Mapping) for row in rows):
        raise ValueError("each evidence item must be an object")
    declared_count = data.get("n_checkpoints")
    if declared_count is not None and declared_count != len(rows):
        raise ValueError(ReasonCode.BUNDLE_COUNT_MISMATCH.value)
    evidence = [evidence_from_dict(row) for row in rows]
    declared_stream = data.get("stream_id")
    actual_stream = TrustedRegistry.stream_id(
        evidence[0].checkpoint.client_id, evidence[0].checkpoint.topic
    )
    if declared_stream is not None and declared_stream != actual_stream:
        raise ValueError("bundle stream_id does not match its first checkpoint")
    return arm_id, evidence, data


def bundle_to_dict(
    arm_id: str,
    evidence: Sequence[CheckpointEvidence],
    *,
    bundle_id: str = "",
) -> dict[str, Any]:
    if not evidence:
        raise ValueError("cannot serialize an empty evidence bundle")
    stream_id = TrustedRegistry.stream_id(
        evidence[0].checkpoint.client_id, evidence[0].checkpoint.topic
    )
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_id": bundle_id,
        "arm_id": arm_id,
        "stream_id": stream_id,
        "n_checkpoints": len(evidence),
        "evidence": [item.to_dict(include_records=True) for item in evidence],
    }


def export_offline_audit_artifacts(
    security_dir: str | Path,
    streams: Mapping[str, tuple[str, Sequence[CheckpointEvidence]]],
    registry: TrustedRegistry,
    anchors: AnchorSet,
    *,
    audit_time: Optional[float] = None,
) -> dict[str, Any]:
    """Export independently replayable security artifacts and verdicts.

    ``streams`` maps a filesystem-safe artifact id to ``(arm_id, evidence)``.
    The resulting layout is the formal result-package contract::

        security/trusted_registry.json
        security/trusted_anchors.json
        security/bundles/<artifact-id>.json
        security/verdicts/<artifact-id>.json

    The function does not derive trust from bundles: callers must construct
    ``registry`` and ``anchors`` separately and pass them explicitly.
    """
    target = Path(security_dir)
    bundles_dir = target / "bundles"
    verdicts_dir = target / "verdicts"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    verdicts_dir.mkdir(parents=True, exist_ok=True)
    registry_path = target / "trusted_registry.json"
    anchors_path = target / "trusted_anchors.json"
    registry_path.write_text(
        json.dumps(registry.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    anchors_path.write_text(
        json.dumps(anchors.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    exported_streams: dict[str, Any] = {}
    for artifact_id, (arm_id, evidence) in streams.items():
        if not re.fullmatch(r"[A-Za-z0-9._-]+", artifact_id):
            raise ValueError(f"unsafe security artifact id: {artifact_id!r}")
        if not evidence:
            raise ValueError(f"security artifact {artifact_id!r} has empty evidence")
        bundle_path = bundles_dir / f"{artifact_id}.json"
        verdict_path = verdicts_dir / f"{artifact_id}.json"
        bundle_path.write_text(
            json.dumps(
                bundle_to_dict(arm_id, evidence, bundle_id=artifact_id),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        verdict = audit_stream(
            evidence,
            arm_id,
            registry,
            anchors,
            audit_time=audit_time,
        )
        verdict_path.write_text(
            json.dumps(verdict.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        exported_streams[artifact_id] = {
            "arm_id": arm_id,
            "bundle": str(bundle_path),
            "verdict": str(verdict_path),
            "outcome": verdict.outcome.value,
        }
    return {
        "registry": str(registry_path),
        "anchors": str(anchors_path),
        "streams": exported_streams,
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Independent offline AAPA-MQTT evidence auditor")
    parser.add_argument("--bundle", required=True, help="v2 evidence bundle JSON")
    parser.add_argument("--registry", required=True, help="external trusted registry JSON")
    parser.add_argument("--anchors", required=True, help="external genesis/latest anchor set JSON")
    parser.add_argument("--output", help="optional path for the machine-readable verdict JSON")
    parser.add_argument("--audit-time", type=float, help="Unix time used for anchor expiry checks")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_argument_parser().parse_args(argv)
    try:
        arm_id, evidence, _bundle = load_evidence_bundle_v2(args.bundle)
        registry = TrustedRegistry.load(args.registry)
        anchors = AnchorSet.load(args.anchors)
        verdict = audit_stream(
            evidence,
            arm_id,
            registry,
            anchors,
            audit_time=args.audit_time,
        )
        output = verdict.to_dict()
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, RegistryError) as exc:
        output = {
            "outcome": AuditOutcome.REJECT.value,
            "accepted": False,
            "reason_codes": [ReasonCode.BUNDLE_MALFORMED.value],
            "error": str(exc),
        }
        exit_code = 1
    else:
        exit_code = 0 if verdict.outcome == AuditOutcome.ACCEPT else (2 if verdict.outcome == AuditOutcome.INCONCLUSIVE else 1)
    rendered = json.dumps(output, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
