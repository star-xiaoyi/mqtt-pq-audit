#!/usr/bin/env python3
"""Canonical stream identity shared by publisher, witness, registry, anchors,
and the offline auditor.

The identity must be injective in ``(client_id, topic)``.  A naive
``client_id + ":" + topic`` is ambiguous: ``("a:b", "c")`` and ``("a", "b:c")``
both render as ``"a:b:c"``, so a witness receipt for one stream could satisfy a
registry policy for a different stream.  We length-prefix each component with
its UTF-8 byte length, which is unambiguously decodable and byte-identical to
the C++ ``canonical_stream_id`` used by the native benchmark.

This module intentionally has no project dependencies so that both the
low-level crypto module (``aapa_mqtt``) and the high-level policy module
(``trusted_registry``) can import it without a dependency cycle.
"""

from __future__ import annotations


def canonical_stream_id(client_id: str, topic: str) -> str:
    """Return an unambiguous UTF-8 byte-length-prefixed stream identity."""
    client_length = len(client_id.encode("utf-8"))
    topic_length = len(topic.encode("utf-8"))
    return f"{client_length}:{client_id}{topic_length}:{topic}"
