#!/usr/bin/env python3
"""
AAPA-MQTT: Authentication & Anchoring Strategies for MQTT Telemetry.

Implements the sealed artifact identifiers.  The paper displays artifact A6 as
public construction A5; artifact A5 is an SLH-DSA primitive-coverage path and is
not part of the formal arm grid.
Provides hash chain, Merkle tree, HMAC, and checkpoint signing logic.

Arms:
  A0 - Classical (X25519 + HMAC + Merkle + Ed25519 ckpt)
  A1 - PQC-naive (ML-KEM-768 + per-msg ML-DSA-65)
  A2 - Session-MAC only (ML-KEM-768 + HMAC, no ckpt)
  A3 - Hash-chain ckpt (ML-KEM-768 + HMAC + chain + ML-DSA-65 ckpt)
  A4 - Merkle ckpt (ML-KEM-768 + HMAC + Merkle + ML-DSA-65 ckpt) ★ main
  A5 - internal legacy ID for optional SLH-DSA coverage (not a paper arm)
  A6 - sealed artifact ID for paper A5, witnessed PQ Merkle checkpoint
"""

import os, hashlib, hmac, struct, time, json, math
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any

from experiment_paths import add_liboqs_python_to_path
from stream_identity import canonical_stream_id

add_liboqs_python_to_path()
import oqs

# ── Crypto Constants (fixed per plan §0) ─────────────────────────────────
KEM_ALG_PQC   = "ML-KEM-768"
SIG_ALG_PQC   = "ML-DSA-65"
SIG_ALG_HASH  = "SLH_DSA_PURE_SHA2_128F"  # A5 optional
HASH_NAME     = "sha256"
CLIENT_ID     = "publisher-001"
CHECKPOINT_SIGNING_DOMAIN = b"AAPA-MQTT-CHECKPOINT-V2|"
WITNESS_SIGNING_DOMAIN = b"AAPA-MQTT-WITNESS-V2|"

# ── Record structure ────────────────────────────────────────────────────
@dataclass
class Record:
    """A single telemetry record unit."""
    seq: int
    ts: float          # unix timestamp
    topic: str
    payload: bytes

    def serialize(self) -> bytes:
        """Serialize as: seq||ts||topic||payload (deterministic)."""
        if not 0 <= self.seq <= 0xFFFFFFFF:
            raise ValueError("record sequence is outside the prototype u32 range")
        if not math.isfinite(self.ts):
            raise ValueError("record timestamp must be finite")
        ts_bytes = struct.pack(">d", self.ts)
        topic_bytes = self.topic.encode("utf-8")
        if len(topic_bytes) > 0xFFFF:
            raise ValueError("record topic is too long")
        if len(self.payload) > 0xFFFFFFFF:
            raise ValueError("record payload is too long")
        return (
            struct.pack(">I", self.seq) +
            ts_bytes +
            struct.pack(">H", len(topic_bytes)) + topic_bytes +
            struct.pack(">I", len(self.payload)) + self.payload
        )

    @staticmethod
    def deserialize(data: bytes) -> "Record":
        """Parse the deterministic record encoding and reject trailing bytes."""
        try:
            offset = 0
            if len(data) < 18:
                raise ValueError("record is too short")
            seq = struct.unpack_from(">I", data, offset)[0]
            offset += 4
            ts = struct.unpack_from(">d", data, offset)[0]
            offset += 8
            if not math.isfinite(ts):
                raise ValueError("record timestamp must be finite")
            topic_len = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            if offset + topic_len + 4 > len(data):
                raise ValueError("record topic length exceeds input")
            topic = data[offset:offset + topic_len].decode("utf-8")
            offset += topic_len
            payload_len = struct.unpack_from(">I", data, offset)[0]
            offset += 4
            if offset + payload_len != len(data):
                raise ValueError("record payload length mismatch")
            payload = data[offset:offset + payload_len]
            return Record(seq=seq, ts=ts, topic=topic, payload=payload)
        except (UnicodeDecodeError, struct.error) as exc:
            raise ValueError("invalid record encoding") from exc

    @staticmethod
    def make(seq: int, topic: str, payload: bytes, ts: Optional[float] = None) -> "Record":
        return Record(seq=seq, ts=time.time() if ts is None else ts, topic=topic, payload=payload)


# ── Hash chain ──────────────────────────────────────────────────────────
class HashChain:
    """Linear hash chain: C_0 = H(seed), C_i = H(C_{i-1} || record)."""

    def __init__(self, seed: bytes):
        self.seed = seed
        self.chain: List[bytes] = [hashlib.sha256(seed).digest()]  # C_0
        self.records: List[bytes] = []

    def append(self, record: bytes) -> bytes:
        """Append a record, return new chain head C_i."""
        prev = self.chain[-1]
        c_i = hashlib.sha256(prev + record).digest()
        self.chain.append(c_i)
        self.records.append(record)
        return c_i

    @property
    def head(self) -> bytes:
        return self.chain[-1]

    @property
    def length(self) -> int:
        return len(self.records)

    def verify_full(self, records: List[bytes], expected_head: bytes) -> bool:
        """Verify entire chain: recompute C_0..C_n, compare final to expected_head."""
        c = hashlib.sha256(self.seed).digest()
        for rec in records:
            c = hashlib.sha256(c + rec).digest()
        return c == expected_head

    def export_chain(self) -> List[bytes]:
        """Return all C_i values for audit evidence."""
        return list(self.chain)


# ── Merkle tree ─────────────────────────────────────────────────────────
class MerkleTree:
    """
    Binary Merkle tree over records.
    leaf_i = SHA256(0x00 || record_i)
    internal = SHA256(0x01 || left || right)
    """

    LEAF_PREFIX   = b"\x00"
    INTERNAL_PREFIX = b"\x01"

    def __init__(self):
        self.leaves: List[bytes] = []      # leaf hashes
        self.records: List[bytes] = []     # raw records
        self.tree: List[List[bytes]] = []  # tree[0]=leaves, tree[h]=root
        self._built = False

    def append(self, record: bytes):
        leaf = hashlib.sha256(self.LEAF_PREFIX + record).digest()
        self.leaves.append(leaf)
        self.records.append(record)
        self._built = False

    def build(self) -> bytes:
        """Build the Merkle tree, return root hash."""
        if not self.leaves:
            return b""
        # Pad to power of 2
        n = len(self.leaves)
        levels = [list(self.leaves)]
        current = list(self.leaves)
        while len(current) > 1:
            # Pad to even
            if len(current) % 2 == 1:
                current.append(current[-1])  # duplicate last
            next_level = []
            for i in range(0, len(current), 2):
                parent = hashlib.sha256(
                    self.INTERNAL_PREFIX + current[i] + current[i + 1]
                ).digest()
                next_level.append(parent)
            levels.append(next_level)
            current = next_level
        self.tree = levels
        self._built = True
        return current[0] if current else b""

    @property
    def root(self) -> bytes:
        if not self._built:
            self.build()
        return self.tree[-1][0] if self.tree else b""

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)

    def get_proof(self, idx: int) -> List[Tuple[bytes, bool]]:
        """
        Generate Merkle inclusion proof for leaf at idx.
        Returns list of (sibling_hash, is_left) pairs from leaf to root.
        """
        if not self._built:
            self.build()
        if idx >= len(self.leaves):
            raise IndexError(f"Leaf index {idx} out of range ({len(self.leaves)})")

        proof = []
        pos = idx
        for level in range(len(self.tree) - 1):
            sibling = pos ^ 1
            if sibling >= len(self.tree[level]):
                sibling = pos  # duplicate last node
            proof.append((self.tree[level][sibling], pos % 2 == 0))  # is_left = my position is even
            pos //= 2
        return proof

    @staticmethod
    def verify_proof(leaf_hash: bytes, proof: List[Tuple[bytes, bool]], root: bytes) -> bool:
        """Verify a Merkle inclusion proof."""
        current = leaf_hash
        for sibling, is_left in proof:
            if is_left:
                current = hashlib.sha256(MerkleTree.INTERNAL_PREFIX + current + sibling).digest()
            else:
                current = hashlib.sha256(MerkleTree.INTERNAL_PREFIX + sibling + current).digest()
        return current == root

    @staticmethod
    def verify_batch(
        records: List[bytes],
        proofs: List[List[Tuple[bytes, bool]]],
        root: bytes
    ) -> List[bool]:
        """Verify multiple records against the same root."""
        results = []
        for rec, proof in zip(records, proofs):
            leaf = hashlib.sha256(MerkleTree.LEAF_PREFIX + rec).digest()
            results.append(MerkleTree.verify_proof(leaf, proof, root))
        return results


# ── Checkpoint structure ────────────────────────────────────────────────
@dataclass
class Checkpoint:
    """A signed checkpoint anchoring a batch of records."""
    client_id: str
    topic: str
    epoch: int
    seq_start: int
    seq_end: int
    prev_anchor: bytes   # C_{start-1} or R_{prev}, or 32 zero bytes for first
    end_anchor: bytes    # C_end or R (root)
    ts_ckpt: float

    def serialize(self) -> bytes:
        """Serialize checkpoint metadata for signing: M = (client_id, topic, epoch,
        seq_start, seq_end, prev_anchor, end_anchor, ts_ckpt)."""
        cid = self.client_id.encode("utf-8")
        topic = self.topic.encode("utf-8")
        if len(cid) > 0xFFFF or len(topic) > 0xFFFF:
            raise ValueError("checkpoint identity field is too long")
        if not 0 <= self.epoch <= 0xFFFFFFFF:
            raise ValueError("checkpoint epoch is outside the u32 range")
        if not (0 <= self.seq_start <= self.seq_end <= 0xFFFFFFFF):
            raise ValueError("checkpoint sequence range is outside the prototype u32 range")
        if not math.isfinite(self.ts_ckpt):
            raise ValueError("checkpoint timestamp must be finite")
        return (
            CHECKPOINT_SIGNING_DOMAIN +
            struct.pack(">H", len(cid)) + cid +
            struct.pack(">H", len(topic)) + topic +
            struct.pack(">I", self.epoch) +
            struct.pack(">I", self.seq_start) +
            struct.pack(">I", self.seq_end) +
            struct.pack(">H", len(self.prev_anchor)) + self.prev_anchor +
            struct.pack(">H", len(self.end_anchor)) + self.end_anchor +
            struct.pack(">d", self.ts_ckpt)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Canonical JSON-friendly checkpoint representation."""
        return {
            "client_id": self.client_id,
            "topic": self.topic,
            "epoch": self.epoch,
            "seq_start": self.seq_start,
            "seq_end": self.seq_end,
            "prev_anchor_hex": self.prev_anchor.hex(),
            "end_anchor_hex": self.end_anchor.hex(),
            "ts_ckpt": self.ts_ckpt,
        }


@dataclass
class WitnessReceipt:
    """Broker-independent witness statement over a checkpoint history state."""
    witness_id: str
    stream_id: str
    checkpoint_epoch: int
    seq_start: int
    seq_end: int
    prev_witnessed_anchor: bytes
    checkpoint_anchor: bytes
    ts_witness: float
    signature: bytes = b""
    public_key: bytes = b""

    def serialize(self) -> bytes:
        """Serialize receipt body for signing; excludes signature/public key."""
        wid = self.witness_id.encode("utf-8")
        stream = self.stream_id.encode("utf-8")
        if len(wid) > 0xFFFF or len(stream) > 0xFFFF:
            raise ValueError("witness identity field is too long")
        if not 0 <= self.checkpoint_epoch <= 0xFFFFFFFF:
            raise ValueError("witness checkpoint epoch is outside the u32 range")
        if not (0 <= self.seq_start <= self.seq_end <= 0xFFFFFFFF):
            raise ValueError("witness sequence range is outside the prototype u32 range")
        if not math.isfinite(self.ts_witness):
            raise ValueError("witness timestamp must be finite")
        return (
            WITNESS_SIGNING_DOMAIN +
            struct.pack(">H", len(wid)) + wid +
            struct.pack(">H", len(stream)) + stream +
            struct.pack(">I", self.checkpoint_epoch) +
            struct.pack(">I", self.seq_start) +
            struct.pack(">I", self.seq_end) +
            struct.pack(">H", len(self.prev_witnessed_anchor)) + self.prev_witnessed_anchor +
            struct.pack(">H", len(self.checkpoint_anchor)) + self.checkpoint_anchor +
            struct.pack(">d", self.ts_witness)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "witness_id": self.witness_id,
            "stream_id": self.stream_id,
            "checkpoint_epoch": self.checkpoint_epoch,
            "seq_start": self.seq_start,
            "seq_end": self.seq_end,
            "prev_witnessed_anchor_hex": self.prev_witnessed_anchor.hex(),
            "checkpoint_anchor_hex": self.checkpoint_anchor.hex(),
            "ts_witness": self.ts_witness,
            "signature_hex": self.signature.hex(),
            "public_key_hex": self.public_key.hex(),
            "receipt_id": self.receipt_id(),
        }

    def receipt_id(self) -> str:
        """Stable per-receipt identity: SHA-256 over the canonical signed body,
        the signature, and the public key.  Two receipts differing in any of
        these (e.g. one valid and one tampered receipt for the same witness on
        the same checkpoint) get distinct ids and never collapse."""
        return hashlib.sha256(self.serialize() + self.signature + self.public_key).hexdigest()


def witness_receipt_from_dict(mapping: Any) -> "WitnessReceipt":
    """Reconstruct a :class:`WitnessReceipt` body from its serialized dict.

    Uses only the receipt's own fields (never a stored ``receipt_id``), so the
    reconstructed object can be used to independently recompute ``receipt_id`` and
    to re-verify the signature against a registry-authorized key.
    """
    return WitnessReceipt(
        witness_id=str(mapping["witness_id"]),
        stream_id=str(mapping["stream_id"]),
        checkpoint_epoch=int(mapping["checkpoint_epoch"]),
        seq_start=int(mapping["seq_start"]),
        seq_end=int(mapping["seq_end"]),
        prev_witnessed_anchor=bytes.fromhex(mapping["prev_witnessed_anchor_hex"]),
        checkpoint_anchor=bytes.fromhex(mapping["checkpoint_anchor_hex"]),
        ts_witness=float(mapping["ts_witness"]),
        signature=bytes.fromhex(mapping.get("signature_hex", "")),
        public_key=bytes.fromhex(mapping.get("public_key_hex", "")),
    )


def receipt_id_from_dict(mapping: Any) -> str:
    """Recompute the canonical receipt_id from a serialized witness-receipt dict.

    Reconstructs the :class:`WitnessReceipt` body from its own fields and returns
    ``sha256(serialize() ‖ signature ‖ public_key)``.  Any stored ``receipt_id``
    is ignored, so a tampered, missing, or mismatched value is detected by
    comparison and never trusted from the package.
    """
    return witness_receipt_from_dict(mapping).receipt_id()


@dataclass
class CheckpointEvidence:
    """Evidence bundle for offline audit."""
    checkpoint: Checkpoint
    signature: bytes
    public_key: bytes
    records: List[bytes]
    # For Merkle: inclusion proofs per record
    merkle_proofs: Optional[List[List[Tuple[bytes, bool]]]] = None
    # For hash chain: full chain (C_0..C_n)
    chain_values: Optional[List[bytes]] = None
    chain_seed: Optional[bytes] = None
    # For witnessed checkpoints: independent receipt signatures over the history state.
    witness_receipts: Optional[List[WitnessReceipt]] = None

    def to_dict(self, include_records: bool = True) -> Dict[str, Any]:
        """Canonical JSON-friendly evidence package.

        The representation intentionally stores Merkle proof direction bits and
        A3 chain values so size measurements and offline replays account for the
        complete evidence needed by the verifier.
        """
        data: Dict[str, Any] = {
            "checkpoint": self.checkpoint.to_dict(),
            "signature_hex": self.signature.hex(),
            "public_key_hex": self.public_key.hex(),
        }
        if include_records:
            data["records_hex"] = [r.hex() for r in self.records]
        if self.merkle_proofs is not None:
            data["merkle_proofs"] = [
                [
                    {
                        "sibling_hash_hex": sibling.hex(),
                        "current_is_left": bool(current_is_left),
                    }
                    for sibling, current_is_left in proof
                ]
                for proof in self.merkle_proofs
            ]
        if self.chain_seed is not None:
            data["chain_seed_hex"] = self.chain_seed.hex()
        if self.chain_values is not None:
            data["chain_values_hex"] = [c.hex() for c in self.chain_values]
        if self.witness_receipts is not None:
            data["witness_receipts"] = [r.to_dict() for r in self.witness_receipts]
        return data

    def serialize(self, include_records: bool = True) -> bytes:
        """Deterministic UTF-8 JSON bytes for experiment accounting."""
        return canonical_json_bytes(self.to_dict(include_records=include_records))

    def component_sizes(self) -> Dict[str, int]:
        """Return raw and serialized component sizes for cost experiments."""
        merkle_raw = sum(
            len(sibling) + 1
            for proof in (self.merkle_proofs or [])
            for sibling, _ in proof
        )
        chain_raw = sum(len(c) for c in (self.chain_values or []))
        records_raw = sum(len(r) for r in self.records)
        witness_raw = sum(
            len(r.serialize()) + len(r.signature) + len(r.public_key)
            for r in (self.witness_receipts or [])
        )
        return {
            "checkpoint_metadata_bytes": len(self.checkpoint.serialize()),
            "signature_bytes": len(self.signature),
            "public_key_bytes": len(self.public_key),
            "records_raw_bytes": records_raw,
            "records_serialized_bytes": len(canonical_json_bytes([r.hex() for r in self.records])),
            "merkle_proofs_raw_bytes": merkle_raw,
            "merkle_proofs_serialized_bytes": len(canonical_json_bytes(self.to_dict(include_records=False).get("merkle_proofs", []))),
            "chain_seed_bytes": len(self.chain_seed or b""),
            "chain_values_raw_bytes": chain_raw,
            "chain_values_serialized_bytes": len(canonical_json_bytes([c.hex() for c in (self.chain_values or [])])),
            "witness_receipts_raw_bytes": witness_raw,
            "witness_receipts_serialized_bytes": len(canonical_json_bytes([r.to_dict() for r in (self.witness_receipts or [])])),
            "full_evidence_bytes": len(self.serialize(include_records=True)),
            "evidence_without_records_bytes": len(self.serialize(include_records=False)),
        }


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic compact JSON bytes used by evidence-size experiments."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── Versioned MQTT wire envelopes ─────────────────────────────────────
WIRE_MAGIC = b"AAPA"
WIRE_VERSION = 1
WIRE_AUTH_MAC = 1
WIRE_AUTH_SIGNATURE = 2


@dataclass(frozen=True)
class WireEnvelope:
    """Authenticated application envelope sent as the MQTT payload.

    The authenticator covers the version, authentication kind, algorithm,
    key/session identifiers, epoch, sequence number, and serialized record.
    Public keys and shared secrets are deliberately not carried on the wire.
    """

    auth_kind: int
    algorithm: str
    key_id: str
    session_id: str
    epoch: int
    seq: int
    record: bytes
    authenticator: bytes = b""
    version: int = WIRE_VERSION

    _HEADER = struct.Struct(">4sBBBBIQHHHI")

    def unsigned_bytes(self) -> bytes:
        algorithm = self.algorithm.encode("ascii")
        key_id = self.key_id.encode("ascii")
        session_id = self.session_id.encode("ascii")
        if self.auth_kind not in (WIRE_AUTH_MAC, WIRE_AUTH_SIGNATURE):
            raise ValueError("unsupported wire authentication kind")
        if not (algorithm and key_id):
            raise ValueError("algorithm and key_id are required")
        if any(len(value) > 65535 for value in (algorithm, key_id, session_id)):
            raise ValueError("wire metadata is too long")
        if not (0 <= self.epoch <= 0xFFFFFFFF and 0 <= self.seq <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("epoch or sequence is out of range")
        header = self._HEADER.pack(
            WIRE_MAGIC,
            self.version,
            self.auth_kind,
            0,
            0,
            self.epoch,
            self.seq,
            len(algorithm),
            len(key_id),
            len(session_id),
            len(self.record),
        )
        return header + algorithm + key_id + session_id + self.record

    def serialize(self) -> bytes:
        if len(self.authenticator) > 65535:
            raise ValueError("wire authenticator is too long")
        return self.unsigned_bytes() + struct.pack(">H", len(self.authenticator)) + self.authenticator

    @classmethod
    def parse(cls, data: bytes) -> "WireEnvelope":
        if len(data) < cls._HEADER.size + 2:
            raise ValueError("wire envelope is too short")
        try:
            (
                magic,
                version,
                auth_kind,
                reserved_a,
                reserved_b,
                epoch,
                seq,
                algorithm_len,
                key_id_len,
                session_id_len,
                record_len,
            ) = cls._HEADER.unpack_from(data, 0)
        except struct.error as exc:
            raise ValueError("invalid wire header") from exc
        if magic != WIRE_MAGIC or version != WIRE_VERSION:
            raise ValueError("unsupported wire envelope version")
        if reserved_a or reserved_b:
            raise ValueError("non-zero reserved wire header fields")
        offset = cls._HEADER.size
        variable_len = algorithm_len + key_id_len + session_id_len + record_len
        if offset + variable_len + 2 > len(data):
            raise ValueError("wire envelope length fields exceed input")
        try:
            algorithm = data[offset:offset + algorithm_len].decode("ascii")
            offset += algorithm_len
            key_id = data[offset:offset + key_id_len].decode("ascii")
            offset += key_id_len
            session_id = data[offset:offset + session_id_len].decode("ascii")
            offset += session_id_len
        except UnicodeDecodeError as exc:
            raise ValueError("wire metadata must be ASCII") from exc
        record = data[offset:offset + record_len]
        offset += record_len
        authenticator_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        if offset + authenticator_len != len(data):
            raise ValueError("wire authenticator length mismatch")
        authenticator = data[offset:]
        return cls(
            version=version,
            auth_kind=auth_kind,
            algorithm=algorithm,
            key_id=key_id,
            session_id=session_id,
            epoch=epoch,
            seq=seq,
            record=record,
            authenticator=authenticator,
        )


@dataclass(frozen=True)
class WireVerification:
    valid: bool
    reason_code: str
    envelope: Optional[WireEnvelope] = None
    record: Optional[Record] = None


class WireEnvelopeVerifier:
    """Stateful subscriber verifier with replay and epoch rollback protection."""

    def __init__(
        self,
        *,
        auth_kind: int,
        algorithm: str,
        key_id: str,
        session_id: str = "",
        mac_key: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
        expected_topic: Optional[str] = None,
    ):
        self.auth_kind = auth_kind
        self.algorithm = algorithm
        self.key_id = key_id
        self.session_id = session_id
        self.mac_key = mac_key
        self.public_key = public_key
        self.expected_topic = expected_topic
        self._seen: set[tuple[int, int]] = set()
        self._max_epoch: Optional[int] = None

    def verify(self, payload: bytes) -> WireVerification:
        try:
            envelope = WireEnvelope.parse(payload)
        except ValueError:
            return WireVerification(False, "WIRE_MALFORMED")
        if envelope.auth_kind != self.auth_kind:
            return WireVerification(False, "AUTH_KIND_MISMATCH", envelope)
        if envelope.algorithm != self.algorithm:
            return WireVerification(False, "ALGORITHM_MISMATCH", envelope)
        if envelope.key_id != self.key_id:
            return WireVerification(False, "KEY_ID_MISMATCH", envelope)
        if envelope.session_id != self.session_id:
            return WireVerification(False, "SESSION_ID_MISMATCH", envelope)
        try:
            record = Record.deserialize(envelope.record)
        except ValueError:
            return WireVerification(False, "RECORD_MALFORMED", envelope)
        if record.seq != envelope.seq:
            return WireVerification(False, "SEQUENCE_BINDING_MISMATCH", envelope, record)
        if self.expected_topic is not None and record.topic != self.expected_topic:
            return WireVerification(False, "TOPIC_MISMATCH", envelope, record)

        if self.auth_kind == WIRE_AUTH_MAC:
            if self.algorithm != "HMAC-SHA256" or self.mac_key is None:
                return WireVerification(False, "MAC_KEY_UNAVAILABLE", envelope, record)
            expected = hmac.new(self.mac_key, envelope.unsigned_bytes(), hashlib.sha256).digest()
            auth_ok = hmac.compare_digest(expected, envelope.authenticator)
        else:
            if self.public_key is None:
                return WireVerification(False, "PUBLIC_KEY_UNAVAILABLE", envelope, record)
            try:
                with oqs.Signature(self.algorithm) as verifier:
                    auth_ok = verifier.verify(
                        envelope.unsigned_bytes(), envelope.authenticator, self.public_key
                    )
            except Exception:
                auth_ok = False
        if not auth_ok:
            return WireVerification(False, "AUTHENTICATOR_INVALID", envelope, record)

        identity = (envelope.epoch, envelope.seq)
        if identity in self._seen:
            return WireVerification(False, "REPLAY_DUPLICATE", envelope, record)
        if self._max_epoch is not None and envelope.epoch < self._max_epoch:
            return WireVerification(False, "EPOCH_ROLLBACK", envelope, record)
        if self._max_epoch is not None and envelope.epoch > self._max_epoch + 1:
            return WireVerification(False, "EPOCH_JUMP", envelope, record)
        self._seen.add(identity)
        self._max_epoch = envelope.epoch if self._max_epoch is None else max(self._max_epoch, envelope.epoch)
        return WireVerification(True, "VALID", envelope, record)


# ── HMAC key derivation ─────────────────────────────────────────────────
def derive_hmac_key(shared_secret: bytes, info: bytes = b"hmac-key") -> bytes:
    """HKDF-like derivation: K_epoch = SHA256(shared_secret || info)."""
    return hashlib.sha256(shared_secret + info).digest()


# ── Proper two-party KEM ────────────────────────────────────────────────
def kem_handshake(kem_alg: str = KEM_ALG_PQC) -> Tuple[bytes, object, object]:
    """
    Perform a proper two-party KEM handshake.
    
    Returns (shared_secret, publisher_kem, subscriber_kem).
    Caller must free() both KEM objects after use.
    
    Protocol:
      1. Subscriber generates keypair, sends pk to Publisher
      2. Publisher encaps to subscriber's pk → (ct, shared_pub)
      3. Publisher sends ct to Subscriber
      4. Subscriber decaps ct → shared_sub
      5. shared_pub == shared_sub == shared_secret
    """
    # Subscriber side: generate keypair
    sub_kem = oqs.KeyEncapsulation(kem_alg)
    sub_pk = sub_kem.generate_keypair()
    
    # Publisher side: encaps to subscriber's pk
    pub_kem = oqs.KeyEncapsulation(kem_alg)
    ct, shared_pub = pub_kem.encap_secret(sub_pk)
    
    # Subscriber side: decaps ct
    shared_sub = sub_kem.decap_secret(ct)
    
    assert shared_pub == shared_sub, "KEM shared secret mismatch!"
    return shared_pub, pub_kem, sub_kem


class CheckpointWitness:
    """Stateful witness that cosigns only monotonic checkpoint histories."""

    def __init__(self, witness_id: str, sig_alg: str = SIG_ALG_PQC):
        self.witness_id = witness_id
        self.sig_alg = sig_alg
        self._signer = oqs.Signature(sig_alg)
        self.public_key = self._signer.generate_keypair()
        self._latest_anchor_by_stream: Dict[str, bytes] = {}

    @staticmethod
    def stream_id_for(checkpoint: Checkpoint) -> str:
        return canonical_stream_id(checkpoint.client_id, checkpoint.topic)

    def issue_receipt(self, checkpoint: Checkpoint, ts: Optional[float] = None) -> WitnessReceipt:
        stream_id = self.stream_id_for(checkpoint)
        prev_seen = self._latest_anchor_by_stream.get(stream_id, b"\x00" * 32)
        if checkpoint.prev_anchor != prev_seen:
            raise ValueError(
                f"witness {self.witness_id}: inconsistent checkpoint history "
                f"for {stream_id}"
            )

        receipt = WitnessReceipt(
            witness_id=self.witness_id,
            stream_id=stream_id,
            checkpoint_epoch=checkpoint.epoch,
            seq_start=checkpoint.seq_start,
            seq_end=checkpoint.seq_end,
            prev_witnessed_anchor=prev_seen,
            checkpoint_anchor=checkpoint.end_anchor,
            ts_witness=time.time() if ts is None else ts,
            public_key=self.public_key,
        )
        receipt.signature = self._signer.sign(receipt.serialize())
        self._latest_anchor_by_stream[stream_id] = checkpoint.end_anchor
        return receipt

    def free(self):
        if hasattr(self, "_signer"):
            self._signer.free()


# ── Arm implementations ─────────────────────────────────────────────────

class ArmBase:
    """Base class for all strategy arms."""
    arm_id: str = ""

    def __init__(self):
        self.records: List[Record] = []
        self.checkpoints: List[CheckpointEvidence] = []
        self.wire_messages: List[bytes] = []
        self._prev_anchor = b"\x00" * 32
        self._wire_auth_kind: Optional[int] = None
        self._wire_algorithm = ""
        self._wire_key_id = ""
        self._wire_session_id = ""
        self._wire_mac_key: Optional[bytes] = None
        self._wire_public_key: Optional[bytes] = None
        self._wire_signer = None

    def add_record(self, record: Record):
        self.records.append(record)

    def get_checkpoints(self) -> List[CheckpointEvidence]:
        return self.checkpoints

    def _configure_mac_wire(self, key: bytes) -> None:
        fingerprint = hashlib.sha256(key).hexdigest()
        self._wire_auth_kind = WIRE_AUTH_MAC
        self._wire_algorithm = "HMAC-SHA256"
        self._wire_key_id = f"mac-{fingerprint[:32]}"
        self._wire_session_id = f"session-{fingerprint[32:64]}"
        self._wire_mac_key = key

    def _configure_signature_wire(self, public_key: bytes, signer: object) -> None:
        fingerprint = hashlib.sha256(public_key).hexdigest()
        self._wire_auth_kind = WIRE_AUTH_SIGNATURE
        self._wire_algorithm = SIG_ALG_PQC
        self._wire_key_id = f"sig-{fingerprint}"
        self._wire_session_id = ""
        self._wire_public_key = public_key
        self._wire_signer = signer

    def _append_wire_envelope(self, record: Record, *, epoch: int) -> WireEnvelope:
        if self._wire_auth_kind is None:
            raise RuntimeError(f"{self.arm_id}: wire authentication is not configured")
        envelope = WireEnvelope(
            auth_kind=self._wire_auth_kind,
            algorithm=self._wire_algorithm,
            key_id=self._wire_key_id,
            session_id=self._wire_session_id,
            epoch=epoch,
            seq=record.seq,
            record=record.serialize(),
        )
        if self._wire_auth_kind == WIRE_AUTH_MAC:
            assert self._wire_mac_key is not None
            authenticator = hmac.new(
                self._wire_mac_key, envelope.unsigned_bytes(), hashlib.sha256
            ).digest()
        else:
            if self._wire_signer is None:
                raise RuntimeError("signature wire signer is unavailable")
            authenticator = self._wire_signer.sign(envelope.unsigned_bytes())
        envelope = WireEnvelope(
            auth_kind=envelope.auth_kind,
            algorithm=envelope.algorithm,
            key_id=envelope.key_id,
            session_id=envelope.session_id,
            epoch=envelope.epoch,
            seq=envelope.seq,
            record=envelope.record,
            authenticator=authenticator,
        )
        self.wire_messages.append(envelope.serialize())
        return envelope

    def latest_wire_payload(self) -> bytes:
        if not self.wire_messages:
            raise RuntimeError(f"{self.arm_id}: no wire payload has been produced")
        return self.wire_messages[-1]

    def new_subscriber_verifier(self) -> WireEnvelopeVerifier:
        if self._wire_auth_kind is None:
            raise RuntimeError(f"{self.arm_id}: wire authentication is not configured")
        return WireEnvelopeVerifier(
            auth_kind=self._wire_auth_kind,
            algorithm=self._wire_algorithm,
            key_id=self._wire_key_id,
            session_id=self._wire_session_id,
            mac_key=self._wire_mac_key,
            public_key=self._wire_public_key,
            expected_topic=getattr(self, "topic", None),
        )


class ArmA0_Classical(ArmBase):
    """A0: X25519 + HMAC + Merkle + Ed25519 checkpoint."""
    arm_id = "A0"

    def __init__(self, topic: str = "test/classical", N: int = 100):
        super().__init__()
        self.topic = topic
        self.N = N
        from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
        # Key establishment
        self._kem_priv = x25519.X25519PrivateKey.generate()
        self._kem_pk = self._kem_priv.public_key()
        # Generate ephemeral "peer" key for KEM
        peer_priv = x25519.X25519PrivateKey.generate()
        peer_pub = peer_priv.public_key()
        shared = self._kem_priv.exchange(peer_pub)
        self.K_epoch = derive_hmac_key(shared)
        self._configure_mac_wire(self.K_epoch)
        # Checkpoint signing key
        self._sig_priv = ed25519.Ed25519PrivateKey.generate()
        self.sig_pk_bytes = self._sig_priv.public_key().public_bytes_raw()
        # Merkle accumulator
        self._merkle = MerkleTree()
        self._epoch = 0
        self._batch_count = 0        # cumulative seq counter (never reset)
        self._epoch_count = 0        # per-epoch record counter (reset after seal)

    def add_record(self, record: Record):
        super().add_record(record)
        raw = record.serialize()
        self._append_wire_envelope(record, epoch=self._epoch)
        self._merkle.append(raw)
        self._batch_count += 1
        self._epoch_count += 1

        if self._epoch_count >= self.N:
            self._seal_checkpoint()

    def _seal_checkpoint(self):
        if self._merkle.leaf_count == 0:
            return
        root = self._merkle.build()
        seq_end = self._batch_count  # cumulative
        seq_start = seq_end - self._merkle.leaf_count + 1
        ckpt = Checkpoint(
            client_id=CLIENT_ID, topic=self.topic, epoch=self._epoch,
            seq_start=seq_start, seq_end=seq_end,
            prev_anchor=self._prev_anchor, end_anchor=root,
            ts_ckpt=time.time(),
        )
        sig = self._sig_priv.sign(ckpt.serialize())
        # Create evidence BEFORE resetting Merkle tree
        evidence = CheckpointEvidence(
            checkpoint=ckpt, signature=sig,
            public_key=self.sig_pk_bytes,
            records=list(self._merkle.records),
            merkle_proofs=[self._merkle.get_proof(i) for i in range(self._merkle.leaf_count)],
        )
        self.checkpoints.append(evidence)
        # Reset per-epoch state AFTER evidence creation
        self._prev_anchor = root
        self._merkle = MerkleTree()
        self._epoch += 1
        self._epoch_count = 0

    def flush(self):
        """Seal any remaining records."""
        if self._epoch_count > 0:
            self._seal_checkpoint()


class ArmA1_PQCnaive(ArmBase):
    """A1: ML-KEM-768 + per-message ML-DSA-65 (no batch anchoring)."""
    arm_id = "A1"

    def __init__(self, topic: str = "test/pqc_naive"):
        super().__init__()
        self.topic = topic
        # Proper two-party KEM (publisher ↔ subscriber)
        shared, self._pub_kem, self._sub_kem = kem_handshake(KEM_ALG_PQC)
        self.K_epoch = derive_hmac_key(shared)
        # Per-msg signature
        self._signer = oqs.Signature(SIG_ALG_PQC)
        self.sig_pk_bytes = self._signer.generate_keypair()
        self._configure_signature_wire(self.sig_pk_bytes, self._signer)
        # Each record gets its own signature (N=1), so checkpoint = per record
        self._signatures: List[bytes] = []  # parallel to records
        self._flushed_count = 0
        self._epoch = 0

    def add_record(self, record: Record):
        super().add_record(record)
        envelope = self._append_wire_envelope(record, epoch=len(self.records) - 1)
        self._signatures.append(envelope.authenticator)

    def flush(self):
        """No batching — each record IS its own checkpoint."""
        for i in range(self._flushed_count, len(self.records)):
            rec = self.records[i]
            sig = self._signatures[i]
            raw = rec.serialize()
            anchor = hashlib.sha256(raw).digest()
            ckpt = Checkpoint(
                client_id=CLIENT_ID, topic=self.topic, epoch=self._epoch,
                seq_start=rec.seq, seq_end=rec.seq,
                prev_anchor=self._prev_anchor,
                end_anchor=anchor,
                ts_ckpt=rec.ts,
            )
            evidence = CheckpointEvidence(
                checkpoint=ckpt, signature=sig,
                public_key=self.sig_pk_bytes,
                records=[raw],
            )
            self.checkpoints.append(evidence)
            self._prev_anchor = anchor
            self._epoch += 1
            self._flushed_count += 1

    def free(self):
        if hasattr(self, '_signer'):
            self._signer.free()
        if hasattr(self, '_pub_kem'):
            self._pub_kem.free()
        if hasattr(self, '_sub_kem'):
            self._sub_kem.free()


class ArmA2_SessionMAC(ArmBase):
    """A2: ML-KEM-768 + HMAC only, NO checkpoint anchoring."""
    arm_id = "A2"

    def __init__(self, topic: str = "test/session_mac"):
        super().__init__()
        self.topic = topic
        shared, self._pub_kem, self._sub_kem = kem_handshake(KEM_ALG_PQC)
        self.K_epoch = derive_hmac_key(shared)
        self._configure_mac_wire(self.K_epoch)
        self._tags: List[bytes] = []
        self._epoch = 0

    def add_record(self, record: Record):
        super().add_record(record)
        envelope = self._append_wire_envelope(record, epoch=self._epoch)
        self._tags.append(envelope.authenticator)

    def flush(self):
        """A2 produces NO checkpoint evidence (no transferable audit)."""
        pass  # intentionally empty — no transferable evidence

    def get_tags(self) -> List[bytes]:
        return self._tags

    def free(self):
        if hasattr(self, '_pub_kem'):
            self._pub_kem.free()
        if hasattr(self, '_sub_kem'):
            self._sub_kem.free()


class ArmA3_HashChain(ArmBase):
    """A3: ML-KEM-768 + HMAC + hash chain + ML-DSA-65 checkpoint."""
    arm_id = "A3"

    def __init__(self, topic: str = "test/hash_chain", N: int = 100):
        super().__init__()
        self.topic = topic
        self.N = N
        # Proper two-party KEM
        shared, self._pub_kem, self._sub_kem = kem_handshake(KEM_ALG_PQC)
        self.K_epoch = derive_hmac_key(shared)
        self._configure_mac_wire(self.K_epoch)
        # Signature
        self._signer = oqs.Signature(SIG_ALG_PQC)
        self.sig_pk_bytes = self._signer.generate_keypair()
        # Hash chain
        epoch_seed = os.urandom(32)
        self._chain = HashChain(epoch_seed)
        self._epoch = 0
        self._batch_count = 0        # cumulative seq counter (never reset)
        self._epoch_count = 0        # per-epoch counter (reset after seal)

    def add_record(self, record: Record):
        super().add_record(record)
        raw = record.serialize()
        self._append_wire_envelope(record, epoch=self._epoch)
        self._chain.append(raw)
        self._batch_count += 1
        self._epoch_count += 1

        if self._epoch_count >= self.N:
            self._seal_checkpoint()

    def _seal_checkpoint(self):
        if self._chain.length == 0:
            return
        seq_end = self._batch_count
        seq_start = seq_end - self._chain.length + 1
        ckpt = Checkpoint(
            client_id=CLIENT_ID, topic=self.topic, epoch=self._epoch,
            seq_start=seq_start, seq_end=seq_end,
            prev_anchor=self._prev_anchor, end_anchor=self._chain.head,
            ts_ckpt=time.time(),
        )
        sig = self._signer.sign(ckpt.serialize())
        evidence = CheckpointEvidence(
            checkpoint=ckpt, signature=sig,
            public_key=self.sig_pk_bytes,
            records=list(self._chain.records),
            chain_values=self._chain.export_chain(),
            chain_seed=self._chain.seed,
        )
        self.checkpoints.append(evidence)
        self._prev_anchor = self._chain.head
        # Reset chain for next epoch
        self._chain = HashChain(os.urandom(32))
        self._epoch += 1
        self._epoch_count = 0

    def flush(self):
        if self._epoch_count > 0:
            self._seal_checkpoint()

    def free(self):
        if hasattr(self, '_signer'):
            self._signer.free()
        if hasattr(self, '_pub_kem'):
            self._pub_kem.free()
        if hasattr(self, '_sub_kem'):
            self._sub_kem.free()


class ArmA4_Merkle(ArmBase):
    """A4: ML-KEM-768 + HMAC + Merkle tree + ML-DSA-65 checkpoint. ★ Main arm."""
    arm_id = "A4"

    def __init__(self, topic: str = "test/merkle", N: int = 100):
        super().__init__()
        self.topic = topic
        self.N = N
        # Proper two-party KEM
        shared, self._pub_kem, self._sub_kem = kem_handshake(KEM_ALG_PQC)
        self.K_epoch = derive_hmac_key(shared)
        self._configure_mac_wire(self.K_epoch)
        # Signature
        self._signer = oqs.Signature(SIG_ALG_PQC)
        self.sig_pk_bytes = self._signer.generate_keypair()
        # Merkle
        self._merkle = MerkleTree()
        self._epoch = 0
        self._batch_count = 0        # cumulative seq counter (never reset)
        self._epoch_count = 0        # per-epoch counter (reset after seal)

    def add_record(self, record: Record):
        super().add_record(record)
        raw = record.serialize()
        self._append_wire_envelope(record, epoch=self._epoch)
        self._merkle.append(raw)
        self._batch_count += 1
        self._epoch_count += 1

        if self._epoch_count >= self.N:
            self._seal_checkpoint()

    def _seal_checkpoint(self):
        if self._merkle.leaf_count == 0:
            return
        root = self._merkle.build()
        seq_end = self._batch_count
        seq_start = seq_end - self._merkle.leaf_count + 1
        ckpt = Checkpoint(
            client_id=CLIENT_ID, topic=self.topic, epoch=self._epoch,
            seq_start=seq_start, seq_end=seq_end,
            prev_anchor=self._prev_anchor, end_anchor=root,
            ts_ckpt=time.time(),
        )
        sig = self._signer.sign(ckpt.serialize())
        evidence = CheckpointEvidence(
            checkpoint=ckpt, signature=sig,
            public_key=self.sig_pk_bytes,
            records=list(self._merkle.records),
            merkle_proofs=[self._merkle.get_proof(i) for i in range(self._merkle.leaf_count)],
        )
        self.checkpoints.append(evidence)
        self._prev_anchor = root
        self._merkle = MerkleTree()
        self._epoch += 1
        self._epoch_count = 0

    def flush(self):
        if self._epoch_count > 0:
            self._seal_checkpoint()

    def free(self):
        if hasattr(self, '_signer'):
            self._signer.free()
        if hasattr(self, '_pub_kem'):
            self._pub_kem.free()
        if hasattr(self, '_sub_kem'):
            self._sub_kem.free()


class ArmA5_SLH_DSA(ArmBase):
    """A5 (optional): Same as A4 but SLH-DSA-SHA2-128f checkpoint signatures."""
    arm_id = "A5"

    def __init__(self, topic: str = "test/slh_dsa", N: int = 100):
        super().__init__()
        self.topic = topic
        self.N = N
        shared, self._pub_kem, self._sub_kem = kem_handshake(KEM_ALG_PQC)
        self.K_epoch = derive_hmac_key(shared)
        self._configure_mac_wire(self.K_epoch)
        self._signer = oqs.Signature(SIG_ALG_HASH)
        self.sig_pk_bytes = self._signer.generate_keypair()
        self._merkle = MerkleTree()
        self._epoch = 0
        self._batch_count = 0        # cumulative seq counter (never reset)
        self._epoch_count = 0        # per-epoch counter (reset after seal)

    def add_record(self, record: Record):
        super().add_record(record)
        raw = record.serialize()
        self._append_wire_envelope(record, epoch=self._epoch)
        self._merkle.append(raw)
        self._batch_count += 1
        self._epoch_count += 1
        if self._epoch_count >= self.N:
            self._seal_checkpoint()

    def _seal_checkpoint(self):
        if self._merkle.leaf_count == 0:
            return
        root = self._merkle.build()
        seq_end = self._batch_count
        seq_start = seq_end - self._merkle.leaf_count + 1
        ckpt = Checkpoint(
            client_id=CLIENT_ID, topic=self.topic, epoch=self._epoch,
            seq_start=seq_start, seq_end=seq_end,
            prev_anchor=self._prev_anchor, end_anchor=root,
            ts_ckpt=time.time(),
        )
        sig = self._signer.sign(ckpt.serialize())
        evidence = CheckpointEvidence(
            checkpoint=ckpt, signature=sig,
            public_key=self.sig_pk_bytes,
            records=list(self._merkle.records),
            merkle_proofs=[self._merkle.get_proof(i) for i in range(self._merkle.leaf_count)],
        )
        self.checkpoints.append(evidence)
        self._prev_anchor = root
        self._merkle = MerkleTree()
        self._epoch += 1
        self._epoch_count = 0

    def flush(self):
        if self._epoch_count > 0:
            self._seal_checkpoint()

    def free(self):
        if hasattr(self, '_signer'):
            self._signer.free()
        if hasattr(self, '_pub_kem'):
            self._pub_kem.free()
        if hasattr(self, '_sub_kem'):
            self._sub_kem.free()


class ArmA6_WitnessedMerkle(ArmBase):
    """A6: A4-style Merkle checkpoint plus independent ML-DSA witness receipts."""
    arm_id = "A6"

    def __init__(self, topic: str = "test/witnessed_merkle", N: int = 100, witness_count: int = 1):
        super().__init__()
        self.topic = topic
        self.N = N
        shared, self._pub_kem, self._sub_kem = kem_handshake(KEM_ALG_PQC)
        self.K_epoch = derive_hmac_key(shared)
        self._configure_mac_wire(self.K_epoch)
        self._signer = oqs.Signature(SIG_ALG_PQC)
        self.sig_pk_bytes = self._signer.generate_keypair()
        self._merkle = MerkleTree()
        self._epoch = 0
        self._batch_count = 0
        self._epoch_count = 0
        self._witnesses = [
            CheckpointWitness(f"witness-{i + 1:02d}", SIG_ALG_PQC)
            for i in range(witness_count)
        ]

    def add_record(self, record: Record):
        super().add_record(record)
        raw = record.serialize()
        self._append_wire_envelope(record, epoch=self._epoch)
        self._merkle.append(raw)
        self._batch_count += 1
        self._epoch_count += 1

        if self._epoch_count >= self.N:
            self._seal_checkpoint()

    def _seal_checkpoint(self):
        if self._merkle.leaf_count == 0:
            return
        root = self._merkle.build()
        seq_end = self._batch_count
        seq_start = seq_end - self._merkle.leaf_count + 1
        ckpt = Checkpoint(
            client_id=CLIENT_ID, topic=self.topic, epoch=self._epoch,
            seq_start=seq_start, seq_end=seq_end,
            prev_anchor=self._prev_anchor, end_anchor=root,
            ts_ckpt=time.time(),
        )
        sig = self._signer.sign(ckpt.serialize())
        receipts = [w.issue_receipt(ckpt) for w in self._witnesses]
        evidence = CheckpointEvidence(
            checkpoint=ckpt, signature=sig,
            public_key=self.sig_pk_bytes,
            records=list(self._merkle.records),
            merkle_proofs=[self._merkle.get_proof(i) for i in range(self._merkle.leaf_count)],
            witness_receipts=receipts,
        )
        self.checkpoints.append(evidence)
        self._prev_anchor = root
        self._merkle = MerkleTree()
        self._epoch += 1
        self._epoch_count = 0

    def flush(self):
        if self._epoch_count > 0:
            self._seal_checkpoint()

    def free(self):
        if hasattr(self, '_signer'):
            self._signer.free()
        if hasattr(self, '_pub_kem'):
            self._pub_kem.free()
        if hasattr(self, '_sub_kem'):
            self._sub_kem.free()
        for witness in getattr(self, "_witnesses", []):
            witness.free()


# ── Factory ─────────────────────────────────────────────────────────────
def create_arm(
    arm_id: str,
    topic: str = "test",
    N: int = 100,
    *,
    witness_count: int = 1,
) -> ArmBase:
    """Factory to create a strategy arm by ID."""
    arms = {
        "A0": lambda: ArmA0_Classical(topic, N),
        "A1": lambda: ArmA1_PQCnaive(topic),
        "A2": lambda: ArmA2_SessionMAC(topic),
        "A3": lambda: ArmA3_HashChain(topic, N),
        "A4": lambda: ArmA4_Merkle(topic, N),
        "A5": lambda: ArmA5_SLH_DSA(topic, N),
        "A6": lambda: ArmA6_WitnessedMerkle(topic, N, witness_count=witness_count),
    }
    if arm_id not in arms:
        raise ValueError(f"Unknown arm: {arm_id}. Choose from {list(arms.keys())}")
    return arms[arm_id]()


# ── Utility ─────────────────────────────────────────────────────────────
def make_payload(size: int, pattern: bytes = b"\x00") -> bytes:
    """Create a payload of given size (bytes)."""
    return pattern * size if size > 0 else b""


def make_topic(arm_id: str) -> str:
    return f"aapa/{arm_id.lower()}/telemetry"


if __name__ == "__main__":
    # Quick self-test
    print("AAPA-MQTT module self-test...")
    for arm_id in ["A0", "A1", "A2", "A3", "A4", "A6"]:
        print(f"  Testing {arm_id}...", end=" ", flush=True)
        arm = create_arm(arm_id, make_topic(arm_id), N=10)
        for i in range(25):
            rec = Record.make(seq=i + 1, topic=arm.topic,
                              payload=make_payload(64))
            arm.add_record(rec)
        arm.flush()
        if hasattr(arm, 'free'):
            arm.free()
        n_ckpt = len(arm.checkpoints) if arm_id != "A2" else 0
        print(f"{len(arm.records)} records, {n_ckpt} checkpoints ✓")
    print("All arms OK.")
