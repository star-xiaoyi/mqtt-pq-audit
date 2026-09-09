#!/usr/bin/env python3
"""External trust registry for offline AAPA-MQTT evidence verification.

The registry is deliberately separate from an evidence bundle.  Public keys
carried by a bundle are hints only and never establish trust.  Authorizations
bind a key and signature scheme to one publisher/topic and an explicit epoch
interval.  Witness policies similarly bind a quorum to distinct, named
witnesses authorized for one stream.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from stream_identity import canonical_stream_id  # re-exported for existing importers


REGISTRY_SCHEMA_VERSION = "aapa-trusted-registry-v1"


class RegistryError(ValueError):
    """Raised when a trust registry is malformed or ambiguous."""



def _decode_hex(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise RegistryError(f"{field_name} must be a non-empty hexadecimal string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise RegistryError(f"{field_name} is not valid hexadecimal") from exc
    if not decoded:
        raise RegistryError(f"{field_name} must not decode to an empty key")
    return decoded


def _require_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{field_name} must be a non-empty string")
    return value


def _require_nonnegative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RegistryError(f"{field_name} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class PublisherAuthorization:
    client_id: str
    topic: str
    epoch_start: int
    epoch_end: Optional[int]
    public_key: bytes
    signature_scheme: str
    key_id: str = ""

    def __post_init__(self) -> None:
        if not self.client_id or not self.topic or not self.signature_scheme:
            raise RegistryError("publisher authorization contains an empty identity or scheme")
        if self.epoch_start < 0:
            raise RegistryError("publisher epoch_start must be non-negative")
        if self.epoch_end is not None and self.epoch_end < self.epoch_start:
            raise RegistryError("publisher epoch_end precedes epoch_start")
        if not self.public_key:
            raise RegistryError("publisher public key must not be empty")
        fingerprint = hashlib.sha256(self.public_key).hexdigest()
        if self.key_id and self.key_id != fingerprint:
            raise RegistryError("publisher key_id must equal SHA-256(public_key)")
        if not self.key_id:
            object.__setattr__(self, "key_id", fingerprint)

    def authorizes_epoch(self, epoch: int) -> bool:
        return epoch >= self.epoch_start and (self.epoch_end is None or epoch <= self.epoch_end)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PublisherAuthorization":
        end = data.get("epoch_end")
        if end is not None:
            end = _require_nonnegative_int(end, "publishers[].epoch_end")
        return cls(
            client_id=_require_nonempty_string(data.get("client_id"), "publishers[].client_id"),
            topic=_require_nonempty_string(data.get("topic"), "publishers[].topic"),
            epoch_start=_require_nonnegative_int(data.get("epoch_start"), "publishers[].epoch_start"),
            epoch_end=end,
            public_key=_decode_hex(data.get("public_key_hex"), "publishers[].public_key_hex"),
            signature_scheme=_require_nonempty_string(
                data.get("signature_scheme"), "publishers[].signature_scheme"
            ),
            key_id=str(data.get("key_id", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "topic": self.topic,
            "epoch_start": self.epoch_start,
            "epoch_end": self.epoch_end,
            "public_key_hex": self.public_key.hex(),
            "signature_scheme": self.signature_scheme,
            "key_id": self.key_id,
        }


@dataclass(frozen=True)
class WitnessAuthorization:
    witness_id: str
    public_key: bytes
    signature_scheme: str
    authorized_streams: tuple[str, ...]
    epoch_start: int = 0
    epoch_end: Optional[int] = None
    key_id: str = ""

    def __post_init__(self) -> None:
        if not self.witness_id or not self.signature_scheme:
            raise RegistryError("witness authorization contains an empty identity or scheme")
        if not self.public_key:
            raise RegistryError("witness public key must not be empty")
        if not self.authorized_streams or any(not stream for stream in self.authorized_streams):
            raise RegistryError("witness must name at least one authorized stream")
        if len(set(self.authorized_streams)) != len(self.authorized_streams):
            raise RegistryError("witness authorized_streams contains duplicates")
        if self.epoch_start < 0:
            raise RegistryError("witness epoch_start must be non-negative")
        if self.epoch_end is not None and self.epoch_end < self.epoch_start:
            raise RegistryError("witness epoch_end precedes epoch_start")
        fingerprint = hashlib.sha256(self.public_key).hexdigest()
        if self.key_id and self.key_id != fingerprint:
            raise RegistryError("witness key_id must equal SHA-256(public_key)")
        if not self.key_id:
            object.__setattr__(self, "key_id", fingerprint)

    def authorizes(self, stream_id: str, epoch: int) -> bool:
        return (
            stream_id in self.authorized_streams
            and epoch >= self.epoch_start
            and (self.epoch_end is None or epoch <= self.epoch_end)
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WitnessAuthorization":
        streams = data.get("authorized_streams")
        if not isinstance(streams, list) or not all(isinstance(item, str) for item in streams):
            raise RegistryError("witnesses[].authorized_streams must be a string list")
        end = data.get("epoch_end")
        if end is not None:
            end = _require_nonnegative_int(end, "witnesses[].epoch_end")
        return cls(
            witness_id=_require_nonempty_string(data.get("witness_id"), "witnesses[].witness_id"),
            public_key=_decode_hex(data.get("public_key_hex"), "witnesses[].public_key_hex"),
            signature_scheme=_require_nonempty_string(
                data.get("signature_scheme"), "witnesses[].signature_scheme"
            ),
            authorized_streams=tuple(streams),
            epoch_start=_require_nonnegative_int(data.get("epoch_start", 0), "witnesses[].epoch_start"),
            epoch_end=end,
            key_id=str(data.get("key_id", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "witness_id": self.witness_id,
            "public_key_hex": self.public_key.hex(),
            "signature_scheme": self.signature_scheme,
            "authorized_streams": list(self.authorized_streams),
            "epoch_start": self.epoch_start,
            "epoch_end": self.epoch_end,
            "key_id": self.key_id,
        }


@dataclass(frozen=True)
class WitnessPolicy:
    stream_id: str
    quorum: int
    authorized_witness_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.stream_id:
            raise RegistryError("witness policy stream_id must not be empty")
        if self.quorum <= 0:
            raise RegistryError("witness policy quorum must be positive")
        if not self.authorized_witness_ids:
            raise RegistryError("witness policy must explicitly list authorized witnesses")
        if len(set(self.authorized_witness_ids)) != len(self.authorized_witness_ids):
            raise RegistryError("witness policy authorized_witness_ids contains duplicates")
        if self.quorum > len(self.authorized_witness_ids):
            raise RegistryError("witness policy quorum exceeds its authorized witness set")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WitnessPolicy":
        witness_ids = data.get("authorized_witness_ids")
        if not isinstance(witness_ids, list) or not all(isinstance(item, str) for item in witness_ids):
            raise RegistryError("witness_policies[].authorized_witness_ids must be a string list")
        quorum = data.get("quorum")
        if isinstance(quorum, bool) or not isinstance(quorum, int):
            raise RegistryError("witness_policies[].quorum must be an integer")
        return cls(
            stream_id=_require_nonempty_string(data.get("stream_id"), "witness_policies[].stream_id"),
            quorum=quorum,
            authorized_witness_ids=tuple(witness_ids),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "stream_id": self.stream_id,
            "quorum": self.quorum,
            "authorized_witness_ids": list(self.authorized_witness_ids),
        }


@dataclass
class TrustedRegistry:
    publishers: list[PublisherAuthorization] = field(default_factory=list)
    witnesses: list[WitnessAuthorization] = field(default_factory=list)
    witness_policies: list[WitnessPolicy] = field(default_factory=list)
    registry_id: str = ""

    def __post_init__(self) -> None:
        self._validate_unambiguous()

    @staticmethod
    def stream_id(client_id: str, topic: str) -> str:
        return canonical_stream_id(client_id, topic)

    def _validate_unambiguous(self) -> None:
        seen_witnesses: set[str] = set()
        for witness in self.witnesses:
            if witness.witness_id in seen_witnesses:
                raise RegistryError(f"duplicate witness_id: {witness.witness_id}")
            seen_witnesses.add(witness.witness_id)

        seen_policies: set[str] = set()
        for policy in self.witness_policies:
            if policy.stream_id in seen_policies:
                raise RegistryError(f"duplicate witness policy for stream: {policy.stream_id}")
            seen_policies.add(policy.stream_id)
            unknown = set(policy.authorized_witness_ids) - seen_witnesses
            if unknown:
                raise RegistryError(
                    f"witness policy {policy.stream_id} names unknown witnesses: {sorted(unknown)}"
                )
            for witness_id in policy.authorized_witness_ids:
                witness = self.witness_for_id(witness_id)
                if policy.stream_id not in witness.authorized_streams:
                    raise RegistryError(
                        f"witness {witness_id} is not authorized for policy stream {policy.stream_id}"
                    )

        grouped: dict[tuple[str, str], list[PublisherAuthorization]] = {}
        for authorization in self.publishers:
            grouped.setdefault((authorization.client_id, authorization.topic), []).append(authorization)
        for identity, authorizations in grouped.items():
            ordered = sorted(authorizations, key=lambda auth: auth.epoch_start)
            for left, right in zip(ordered, ordered[1:]):
                left_end = left.epoch_end
                if left_end is None or right.epoch_start <= left_end:
                    raise RegistryError(
                        f"overlapping publisher epoch authorizations for {identity[0]}:{identity[1]}"
                    )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TrustedRegistry":
        if data.get("schema_version") != REGISTRY_SCHEMA_VERSION:
            raise RegistryError(
                f"unsupported registry schema: {data.get('schema_version')!r}; "
                f"expected {REGISTRY_SCHEMA_VERSION!r}"
            )
        publisher_rows = data.get("publishers")
        witness_rows = data.get("witnesses", [])
        policy_rows = data.get("witness_policies", [])
        if not isinstance(publisher_rows, list) or not publisher_rows:
            raise RegistryError("registry publishers must be a non-empty list")
        if not isinstance(witness_rows, list) or not isinstance(policy_rows, list):
            raise RegistryError("registry witnesses and witness_policies must be lists")
        if not all(isinstance(row, Mapping) for row in publisher_rows):
            raise RegistryError("each publisher authorization must be an object")
        if not all(isinstance(row, Mapping) for row in witness_rows):
            raise RegistryError("each witness authorization must be an object")
        if not all(isinstance(row, Mapping) for row in policy_rows):
            raise RegistryError("each witness policy must be an object")
        return cls(
            publishers=[PublisherAuthorization.from_dict(row) for row in publisher_rows],
            witnesses=[WitnessAuthorization.from_dict(row) for row in witness_rows],
            witness_policies=[WitnessPolicy.from_dict(row) for row in policy_rows],
            registry_id=str(data.get("registry_id", "")),
        )

    @classmethod
    def load(cls, path: str | Path) -> "TrustedRegistry":
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise RegistryError("registry JSON root must be an object")
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "registry_id": self.registry_id,
            "publishers": [entry.to_dict() for entry in self.publishers],
            "witnesses": [entry.to_dict() for entry in self.witnesses],
            "witness_policies": [entry.to_dict() for entry in self.witness_policies],
        }

    @classmethod
    def combine(
        cls,
        registries: Iterable["TrustedRegistry"],
        *,
        registry_id: str = "combined-registry",
    ) -> "TrustedRegistry":
        """Combine independently constructed stream registries.

        Duplicate authorizations are removed only when byte-for-byte
        equivalent.  Conflicting witness identities and overlapping publisher
        epochs are rejected by the normal registry validation.
        """
        publishers: list[PublisherAuthorization] = []
        witnesses: list[WitnessAuthorization] = []
        policies: list[WitnessPolicy] = []
        publisher_seen: set[tuple[Any, ...]] = set()
        witness_seen: set[tuple[Any, ...]] = set()
        policy_seen: set[tuple[Any, ...]] = set()
        for registry in registries:
            for entry in registry.publishers:
                identity = (
                    entry.client_id,
                    entry.topic,
                    entry.epoch_start,
                    entry.epoch_end,
                    entry.public_key,
                    entry.signature_scheme,
                    entry.key_id,
                )
                if identity not in publisher_seen:
                    publisher_seen.add(identity)
                    publishers.append(entry)
            for entry in registry.witnesses:
                identity = (
                    entry.witness_id,
                    entry.public_key,
                    entry.signature_scheme,
                    entry.authorized_streams,
                    entry.epoch_start,
                    entry.epoch_end,
                    entry.key_id,
                )
                if identity not in witness_seen:
                    witness_seen.add(identity)
                    witnesses.append(entry)
            for entry in registry.witness_policies:
                identity = (entry.stream_id, entry.quorum, entry.authorized_witness_ids)
                if identity not in policy_seen:
                    policy_seen.add(identity)
                    policies.append(entry)
        return cls(
            publishers=publishers,
            witnesses=witnesses,
            witness_policies=policies,
            registry_id=registry_id,
        )

    def publisher_for(self, client_id: str, topic: str, epoch: int) -> Optional[PublisherAuthorization]:
        matches = [
            authorization
            for authorization in self.publishers
            if authorization.client_id == client_id
            and authorization.topic == topic
            and authorization.authorizes_epoch(epoch)
        ]
        if len(matches) > 1:
            raise RegistryError(f"ambiguous publisher authorization for {client_id}:{topic} epoch {epoch}")
        return matches[0] if matches else None

    def witness_for_id(self, witness_id: str) -> Optional[WitnessAuthorization]:
        return next((witness for witness in self.witnesses if witness.witness_id == witness_id), None)

    def witness_policy_for(self, stream_id: str) -> Optional[WitnessPolicy]:
        return next((policy for policy in self.witness_policies if policy.stream_id == stream_id), None)


def registry_for_generated_evidence(
    evidence: Iterable[Any],
    arm_id: str,
    *,
    witness_quorum: Optional[int] = None,
    registry_id: str = "generated-test-registry",
) -> TrustedRegistry:
    """Build an explicit registry from locally generated evidence for tests/runners.

    This adapter is intentionally named to discourage treating it as an offline
    trust-establishment mechanism.  A production auditor must load a registry
    provisioned independently of the evidence bundle.
    """
    evidence_list = list(evidence)
    if not evidence_list:
        raise RegistryError("cannot build a generated-evidence registry from an empty list")
    first = evidence_list[0]
    client_id = first.checkpoint.client_id
    topic = first.checkpoint.topic
    publisher_keys = {item.public_key for item in evidence_list}
    if len(publisher_keys) != 1:
        raise RegistryError("generated evidence contains a publisher key transition; declare it explicitly")
    scheme_by_arm = {
        "A0": "Ed25519",
        "A1": "ML-DSA-65",
        "A3": "ML-DSA-65",
        "A4": "ML-DSA-65",
        "A5": "SLH_DSA_PURE_SHA2_128F",
        "A6": "ML-DSA-65",
    }
    if arm_id not in scheme_by_arm:
        raise RegistryError(f"arm {arm_id} has no transferable publisher authorization")
    publishers = [
        PublisherAuthorization(
            client_id=client_id,
            topic=topic,
            epoch_start=min(item.checkpoint.epoch for item in evidence_list),
            epoch_end=max(item.checkpoint.epoch for item in evidence_list),
            public_key=first.public_key,
            signature_scheme=scheme_by_arm[arm_id],
        )
    ]
    witnesses: list[WitnessAuthorization] = []
    seen: set[str] = set()
    stream_id = TrustedRegistry.stream_id(client_id, topic)
    for item in evidence_list:
        for receipt in item.witness_receipts or []:
            if receipt.witness_id in seen:
                continue
            witnesses.append(
                WitnessAuthorization(
                    witness_id=receipt.witness_id,
                    public_key=receipt.public_key,
                    signature_scheme="ML-DSA-65",
                    authorized_streams=(stream_id,),
                )
            )
            seen.add(receipt.witness_id)
    policies: list[WitnessPolicy] = []
    if arm_id == "A6":
        quorum = witness_quorum if witness_quorum is not None else len(witnesses)
        policies.append(
            WitnessPolicy(
                stream_id=stream_id,
                quorum=quorum,
                authorized_witness_ids=tuple(witness.witness_id for witness in witnesses),
            )
        )
    return TrustedRegistry(
        publishers=publishers,
        witnesses=witnesses,
        witness_policies=policies,
        registry_id=registry_id,
    )
