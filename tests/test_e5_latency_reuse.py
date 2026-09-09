"""E5 latency regression: per-cell MQTT client reuse must not hang or leak.

The full E5 run previously created a *fresh* publisher/subscriber pair for every
repetition (reps x cells MQTT clients, each with its own ``loop_start`` thread).
That churn accumulated until the run wedged at ``A2 / QoS1``.  The fix connects a
single pub + sub once per cell and reuses them across all reps, resetting only the
per-rep receipt/seq/timing state and tearing the clients down with bounded cleanup
in a ``finally``.

These tests exercise the real runner against a live broker and assert the fix's
three contracts:
  * QoS1/2 across many cells (incl. the old ``A2`` hang cell) completes — no hang;
  * the process returns to its baseline thread count — no thread/loop leak;
  * exactly one pub + one sub are created per cell (reuse, not per-rep churn);
  * the measured metric口径 (fields, ratios, method) is unchanged.

They are skipped when no MQTT broker is reachable on ``localhost:1883``.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIR = ROOT / "experiments" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

import run_optimized  # noqa: E402

BROKER_HOST = run_optimized.BROKER_HOST
BROKER_PORT = run_optimized.BROKER_PORT

# The measured-metric contract this refactor must not change.
_MEASUREMENT_METHOD = (
    "full_app_update_to_authenticated_receipt_with_mqtt_publish_completion_breakout"
)


def _broker_available(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


requires_broker = pytest.mark.skipif(
    not _broker_available(BROKER_HOST, BROKER_PORT),
    reason=f"no MQTT broker on {BROKER_HOST}:{BROKER_PORT}",
)


@requires_broker
def test_e5_qos12_multi_rep_no_hang_no_leak_stable_metrics(monkeypatch, tmp_path):
    """QoS1/2 over multiple cells and reps must finish quickly, reuse one pub+sub
    per cell, leak no threads, and preserve the measured-metric口径."""
    # Count MQTT client instantiations without altering behaviour: a real-client
    # subclass so connect/subscribe/loop all work exactly as in production.
    real_client_cls = run_optimized.mqtt.Client
    created = {"n": 0}

    class _SpyClient(real_client_cls):
        def __init__(self, *args, **kwargs):
            created["n"] += 1
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(run_optimized.mqtt, "Client", _SpyClient)
    # Keep the produced CSV out of the real result tree.
    monkeypatch.setattr(run_optimized, "RESULT_DIR", str(tmp_path))

    n_reps = 3
    n_msg = 5
    result: dict = {}

    def _worker():
        # Not quick: exercises the full arm set incl. A2 (the old hang cell) and
        # A6 witness signing, but at tiny reps/msgs so the test stays fast.
        result["rows"] = run_optimized.run_e5_optimized(
            n_reps=n_reps,
            n_msg=n_msg,
            qos_list=[1, 2],
            payloads=[128],
            n_values=[10],
        )

    baseline_threads = threading.active_count()
    worker = threading.Thread(target=_worker, name="e5-worker", daemon=True)
    worker.start()
    worker.join(timeout=120)

    # 1) No hang: the run completed within the wall-clock budget.
    assert not worker.is_alive(), (
        "E5 QoS1/2 run did not complete within 120s — a hang regression"
    )
    assert "rows" in result, "E5 worker raised before returning rows"
    rows = result["rows"]
    assert rows, "E5 produced no rows"

    # 2) No thread/loop leak: every per-cell loop thread was joined in teardown.
    time.sleep(0.5)
    assert threading.active_count() <= baseline_threads, (
        f"thread leak: {threading.active_count()} threads vs baseline "
        f"{baseline_threads} — a loop_start was not joined"
    )

    # 3) Reuse contract: exactly one pub + one sub per cell (NOT reps x cells).
    cells = {(r["arm"], r["N"], r["payload_bytes"], r["qos"]) for r in rows}
    assert created["n"] == 2 * len(cells), (
        f"expected {2 * len(cells)} clients (one pub+sub per {len(cells)} cells), "
        f"got {created['n']} — clients are being recreated per rep"
    )

    # 4) Metric口径 unchanged: same fields, same method, and QoS1/2 guaranteed
    #    delivery means completion/receipt ratios pin to 1 with no cross-rep bleed.
    seen = set()
    for r in rows:
        seen.add((r["arm"], r["qos"]))
        assert r["qos"] in (1, 2)
        assert r["n_repetitions"] == n_reps
        assert r["messages_per_repetition"] == n_msg
        assert r["measurement_method"] == _MEASUREMENT_METHOD
        assert r["delivery_scope"] == "subscriber_authenticated_unique_envelope"
        # QoS1/2 acknowledge every publish and deliver every message.
        assert r["publish_completion_ratio"] == 1.0, r
        assert r["message_receipt_ratio_mean"] >= 0.99, r
        assert r["message_receipt_ratio_min"] >= 0.99, r
        # Clean traffic + fresh per-rep keys + drained barrier => no stragglers are
        # mis-verified into the next rep, so nothing is counted invalid/replay.
        assert r["subscriber_verified_invalid_total"] == 0, r
        assert r["subscriber_verified_replay_total"] == 0, r

    # The A2 negative-control cell — where the full run previously hung — is
    # measured at both QoS1 and QoS2.
    assert ("A2", 1) in seen and ("A2", 2) in seen, seen
