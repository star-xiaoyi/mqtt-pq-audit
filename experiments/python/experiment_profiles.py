#!/usr/bin/env python3
"""Canonical per-mode intensity profiles — the single source of truth for the
quick/full sample sizes, repetitions, and witness quorum.

Both the Stage 4 runner (which seals these into ``protocol_config.json``) and the
independent validator (``validate_profile_canonical``) import this module.  The
validator re-derives the canonical profile HERE and asserts the sealed
``config.python`` / ``config.cpp`` / ``config.e7_corpus`` equal it, so it never
trusts the runner's sealed intensity as its own reference.  This blocks a
synchronously downgraded package — e.g. full's ``e8_lifecycle_reps`` 20->1 or A6
witness 3/2->1/1 with a recomputed ``config_hash`` and fully re-synced provenance.

Zero project imports on purpose (leaf module), so both sides bind the same bytes.
"""

from __future__ import annotations

from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "description": "engineering smoke profile, not manuscript data",
        "python": {
            "e3_msgs": 20,
            "e5_reps": 5,
            "e5_msgs": 50,
            "e5_qos": "0",
            "e6_reps": 3,
            "e6_burst": 2.0,
            "e6_drain_timeout": 3.0,
            "e6_max_inflight": 256,
            "e6_qos": "0",
            "e8_reps": 10,
            "e8_lifecycle_reps": 5,
            "e9_hours": 0.1,
            "e9_max_messages": 10000,
            "a6_witness_count": 1,
            "a6_min_receipts": 1,
        },
        "cpp": {"runs": 50, "audit_runs": 30},
    },
    "full": {
        "description": "manuscript-grade profile with expanded repetitions and QoS latency coverage",
        "python": {
            "e3_msgs": 200,
            "e5_reps": 40,
            "e5_msgs": 50,
            "e5_qos": "0,1,2",
            "e6_reps": 15,
            "e6_burst": 8.0,
            "e6_drain_timeout": 5.0,
            "e6_max_inflight": 512,
            "e6_qos": "0",
            "e8_reps": 200,
            "e8_lifecycle_reps": 20,
            "e9_hours": 2.0,
            "e9_max_messages": 50000,
            "a6_witness_count": 3,
            "a6_min_receipts": 2,
        },
        "cpp": {"runs": 300, "audit_runs": 200},
    },
}

# The fixed producer of the E8 audit-cost table and its raw samples.  The
# validator anchors the expected ``source_script`` to this constant instead of
# reading it back from the (modifiable) E8 CSV, so a synchronised source_script
# swap of both the CSV and the samples still fails closed.
E8_PRODUCER_SOURCE_SCRIPT = "python/run_optimized.py"


def canonical_profile(mode: str) -> dict[str, Any]:
    if mode not in PROFILES:
        raise ValueError(f"unknown mode: {mode}")
    return PROFILES[mode]
