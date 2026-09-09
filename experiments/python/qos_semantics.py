#!/usr/bin/env python3
"""MQTT two-hop QoS/session model and an experiment ground-truth oracle.

This module deliberately contains no evidence-auditing policy.  It evaluates a
complete generated timeline, including causal events that are *not* available
to an offline auditor.  Keeping this oracle separate from ``evidence_auditor``
prevents scenario labels from leaking into measured audit results.
"""

from __future__ import annotations

from dataclasses import MISSING, asdict, dataclass
from typing import Any, Iterable, Mapping


SEMANTICS_SCHEMA_VERSION = "qos-semantics-v2"


@dataclass(frozen=True)
class QoSContext:
    """Representative state for the two MQTT delivery hops.

    ``publisher_qos`` describes publisher -> broker.  ``requested_qos`` is the
    subscription maximum and ``effective_qos`` is the QoS on broker ->
    subscriber for this trace.  The explicit effective value lets the corpus
    represent a QoS 2 publication delivered through a QoS 0 subscription.
    """

    context_id: str
    publisher_qos: int
    requested_qos: int
    effective_qos: int
    session_mode: str
    session_present: bool
    subscriber_connected: bool
    reconnects: bool
    initial_epoch: int = 0
    application_epoch_span: int = 4
    ordered_topic: bool = True
    audit_phase: str = "connected"

    def __post_init__(self) -> None:
        for field_name in ("publisher_qos", "requested_qos", "effective_qos"):
            value = getattr(self, field_name)
            if value not in (0, 1, 2):
                raise ValueError(f"{field_name} must be 0, 1, or 2")
        if self.effective_qos > min(self.publisher_qos, self.requested_qos):
            raise ValueError("effective_qos cannot exceed either hop's QoS maximum")
        if self.session_mode not in ("clean", "persistent"):
            raise ValueError("session_mode must be clean or persistent")
        if self.session_mode == "clean" and self.session_present:
            raise ValueError("a clean session cannot begin with session_present=true")
        if self.audit_phase not in ("connected", "before_reconnect", "after_reconnect"):
            raise ValueError("audit_phase must be connected, before_reconnect, or after_reconnect")
        if self.audit_phase == "before_reconnect" and self.subscriber_connected:
            raise ValueError("before_reconnect requires subscriber_connected=false")
        if self.audit_phase == "after_reconnect" and not self.subscriber_connected:
            raise ValueError("after_reconnect requires subscriber_connected=true")
        if self.application_epoch_span < 1:
            raise ValueError("application_epoch_span must be positive")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "QoSContext":
        fields: dict[str, Any] = {}
        for name, field in cls.__dataclass_fields__.items():
            if name in value:
                fields[name] = value[name]
            elif field.default is not MISSING:
                fields[name] = field.default
            else:
                raise KeyError(name)
        return cls(**fields)


def representative_contexts() -> tuple[QoSContext, ...]:
    """Return a small set in which every member changes an audit conclusion.

    This is intentionally not a Cartesian product.  It covers the three
    effective delivery contracts, a two-hop downgrade, and the clean versus
    persistent offline-session distinction.
    """

    return (
        QoSContext("q0_connected_clean", 0, 2, 0, "clean", False, True, False),
        QoSContext("q1_connected_persistent", 1, 1, 1, "persistent", True, True, False),
        QoSContext("q2_connected_persistent", 2, 2, 2, "persistent", True, True, False),
        QoSContext("q1_to_q0_subscription", 1, 0, 0, "persistent", True, True, False),
        QoSContext("q2_to_q0_subscription", 2, 0, 0, "persistent", True, True, False),
        QoSContext(
            "q1_persistent_reconnected", 1, 1, 1, "persistent", True, True, True,
            audit_phase="after_reconnect",
        ),
        QoSContext(
            "q1_persistent_offline", 1, 1, 1, "persistent", True, False, True,
            audit_phase="before_reconnect",
        ),
        QoSContext(
            "q1_clean_offline", 1, 1, 1, "clean", False, False, True,
            audit_phase="before_reconnect",
        ),
    )


def _events(trace: Mapping[str, Any], event_type: str) -> list[Mapping[str, Any]]:
    return [event for event in trace.get("timeline", ()) if event.get("event") == event_type]


def _has_action(trace: Mapping[str, Any], action: str) -> bool:
    return any(
        event.get("event") == "causal_action" and event.get("action") == action
        for event in trace.get("timeline", ())
    )


def _causal_actors(trace: Mapping[str, Any]) -> list[str]:
    actors: list[str] = []
    for event in trace.get("timeline", ()):
        if event.get("event") != "causal_action":
            continue
        actor = str(event.get("actor") or "unknown")
        if actor not in actors:
            actors.append(actor)
    return actors


def semantic_oracle(
    trace: Mapping[str, Any],
    qos_context: QoSContext | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive ground truth from a full causal trace, not from expected labels.

    The returned MQTT status is separate from evidence-integrity and witness
    availability.  For example, checkpoint splicing is an evidence violation,
    not itself an MQTT delivery-semantics violation.
    """

    context = qos_context or trace.get("qos_context")
    if not isinstance(context, QoSContext):
        if not isinstance(context, Mapping):
            raise ValueError("trace is missing qos_context")
        context = QoSContext.from_mapping(context)

    actions = {
        str(event.get("action"))
        for event in trace.get("timeline", ())
        if event.get("event") == "causal_action"
    }
    actors = _causal_actors(trace)
    reasons: list[str] = []
    semantic_status = "compliant"
    evidence_integrity_violation = False

    if actions & {"modify_payload", "inject_record"}:
        semantic_status = "violation"
        reasons.append("UNAUTHORISED_CONTENT")

    if "replay_record" in actions:
        if (
            context.effective_qos == 1
            or (context.publisher_qos == 1 and context.effective_qos == 0)
        ):
            reasons.append("REPLAY_INDISTINGUISHABLE_FROM_PERMITTED_APPLICATION_DUPLICATE")
        else:
            semantic_status = "violation"
            reasons.append("REPLAY_VIOLATES_DELIVERY_CONTRACT")

    if "cross_epoch_replay" in actions:
        semantic_status = "violation"
        reasons.append("CROSS_EPOCH_FRESHNESS_VIOLATED")

    if "reorder_delivery" in actions:
        if context.ordered_topic:
            semantic_status = "violation"
            reasons.append("ORDERED_FLOW_VIOLATED")
        elif semantic_status == "compliant":
            semantic_status = "ambiguous"
            reasons.append("TOPIC_ORDERING_NOT_ASSUMED")

    drops = {"drop_record", "delivery_not_observed"} & actions
    if drops:
        if context.effective_qos == 0:
            if semantic_status == "compliant":
                reasons.append("LOSS_PERMITTED_AT_EFFECTIVE_QOS0")
        elif not context.subscriber_connected:
            if context.session_mode == "persistent":
                if semantic_status == "compliant":
                    semantic_status = "ambiguous"
                reasons.append("PERSISTENT_SESSION_DELIVERY_PENDING_RECONNECT")
            else:
                if semantic_status == "compliant":
                    reasons.append("CLEAN_SESSION_HAS_NO_OFFLINE_QUEUE_OBLIGATION")
        else:
            semantic_status = "violation"
            reasons.append("COMPLETED_QOS_DELIVERY_MISSING")

    duplicate_deliveries = _events(trace, "subscriber_delivery")
    seen: dict[tuple[int, int, str], Mapping[str, Any]] = {}
    duplicate_pairs: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for event in duplicate_deliveries:
        seq = int(event.get("seq", -1))
        application_epoch = context.initial_epoch + (seq - 1) // context.application_epoch_span
        key = (application_epoch, seq, str(event.get("digest", "")))
        if key in seen:
            duplicate_pairs.append((seen[key], event))
        else:
            seen[key] = event
    if duplicate_pairs:
        duplicate_permitted = (
            context.effective_qos == 1
            or (context.publisher_qos == 1 and context.effective_qos == 0)
        )
        if duplicate_permitted:
            if semantic_status == "compliant":
                reasons.append("APPLICATION_DUPLICATE_PERMITTED_BY_TWO_HOP_QOS")
        else:
            semantic_status = "violation"
            reasons.append("UNPERMITTED_DUPLICATE_DELIVERY")

    evidence_actions = {
        "checkpoint_splice", "checkpoint_rollback", "omit_middle_checkpoint",
        "omit_tail_checkpoint", "split_view",
    }
    if actions & evidence_actions:
        evidence_integrity_violation = True
        reasons.append("EVIDENCE_HISTORY_MANIPULATED")

    witness_status = "satisfied"
    if "withhold_witness_receipts" in actions:
        witness_status = "unavailable"
        reasons.append("WITNESS_UNAVAILABLE")
    elif "below_witness_quorum" in actions:
        witness_status = "below_quorum"
        reasons.append("WITNESS_QUORUM_NOT_MET")
    if "stale_anchor" in actions:
        reasons.append("LATEST_ANCHOR_STALE")

    if not reasons:
        reasons.append("TRACE_CONFORMS_TO_MODEL")

    physical_actor = actors[0] if len(actors) == 1 else ("multiple" if actors else "none")
    responsible_party = physical_actor if semantic_status == "violation" else "none"
    if semantic_status == "ambiguous":
        responsible_party = "inconclusive"

    return {
        "schema_version": SEMANTICS_SCHEMA_VERSION,
        "case_id": trace.get("case_id"),
        "semantic_status": semantic_status,
        "semantic_violation": (
            True if semantic_status == "violation"
            else False if semantic_status == "compliant"
            else None
        ),
        "evidence_integrity_violation": evidence_integrity_violation,
        "physical_actor": physical_actor,
        "protocol_responsible_party": responsible_party,
        "witness_status": witness_status,
        "reason_codes": sorted(set(reasons)),
    }


def contexts_by_id(contexts: Iterable[QoSContext] | None = None) -> dict[str, QoSContext]:
    selected = tuple(contexts or representative_contexts())
    return {context.context_id: context for context in selected}
