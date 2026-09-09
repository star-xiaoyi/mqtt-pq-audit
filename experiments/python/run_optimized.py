#!/usr/bin/env python3
"""
Optimized experiment runner — addresses all statistical and methodological gaps.
============================================================

Improvements over original scripts:
  E3: Real socket-level MQTT wire byte counting (not formula)
  E5: 40 independent repetitions per data point with CI (median/p95/p99)
  E6: 15 independent repetitions per data point with CI
  E7: Attribution confusion matrix + benign fault controls + 3-layer output
       (semantic_violation / cryptographic_detection / attribution_label).
       Deterministic capability matrix — one case per scenario x context x arm
       (repetitions=1, see experiment_grids.E7_CORPUS_CONTRACT); FP is exact
       oracle-compliant-negative counts, no Wilson CI.
  E8: 200 repeated verifications per (N,k) with CI
  E9: Actual disk file writing (not arithmetic) with 1/7/30-day extrapolation
  E10: Security-path boundary table
  E11: QoS-aware vs QoS-agnostic auditor comparison (directly proves C1)
  E5A5: SLH-DSA coverage

Usage:
    python experiments/python/run_optimized.py [--exp E3/E5/E6/E7/E8/E9/E10/E11/all] [--quick]

Quick mode: reduced repetitions for fast testing.
Full mode: protocol-compliant repetitions for the cost/throughput tests (E5/E6/E8);
  E7/E11 are a deterministic capability matrix (repetitions=1), not repeated trials.
"""

import os, time, json, struct, hashlib, random, statistics, math, tempfile, shutil, socket
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass

from experiment_paths import add_liboqs_python_to_path

add_liboqs_python_to_path()
import paho.mqtt.client as mqtt

from aapa_mqtt import (
    create_arm, make_payload, make_topic, Record, Checkpoint, CheckpointEvidence,
    MerkleTree, HashChain, SIG_ALG_PQC, SIG_ALG_HASH,
    ArmA4_Merkle, ArmA5_SLH_DSA,
)
from audit_verify import verify_signature, checkpoint_sequence_valid, verify_witness_receipts
from trusted_registry import registry_for_generated_evidence
from provenance import init_provenance, write_csv
from qos_experiments import run_qos_experiment_suite
from experiment_grids import E7_CORPUS_CONTRACT

BROKER_HOST = "localhost"
BROKER_PORT = 1883
SOURCE_SCRIPT = "python/run_optimized.py"
PROVENANCE = init_provenance(SOURCE_SCRIPT, create_dir=False)
RESULT_DIR = PROVENANCE.result_dir
ENV_ID = PROVENANCE.env_id
_QOS_SUITE_CACHE = None


def _run_qos_suite_once(arms=None):
    """Run the authoritative real-crypto E7/E11 suite once per result package."""
    global _QOS_SUITE_CACHE
    if _QOS_SUITE_CACHE is None:
        selected_arms = tuple(arms or ("A0", "A1", "A2", "A3", "A4", "A6"))
        _QOS_SUITE_CACHE = run_qos_experiment_suite(
            result_dir=RESULT_DIR,
            provenance=PROVENANCE,
            write_csv_func=write_csv,
            arms=selected_arms,
            # The failure grid is a deterministic capability matrix, not a
            # population estimate.  The E7 corpus contract (repetitions=1,
            # n_records=8, checkpoint_interval=4) is the single source of truth in
            # experiment_grids, sealed into protocol_config and cross-checked by
            # the validator; runtime repetitions belong in the cost tests.
            repetitions=E7_CORPUS_CONTRACT["repetitions"],
            seed=PROVENANCE.seed,
            n_records=E7_CORPUS_CONTRACT["n_records"],
            checkpoint_interval=E7_CORPUS_CONTRACT["checkpoint_interval"],
        )
    return _QOS_SUITE_CACHE


# ═══════════════════════════════════════════════════════════════════════════
#  Utility
# ═══════════════════════════════════════════════════════════════════════════

def stats(values):
    """Compute mean, median, P95, std, 95% CI."""
    n = len(values)
    if n < 2:
        m = values[0] if values else 0
        return {"mean": m, "median": m, "p95": m, "std": 0.0,
                "ci95_low": m, "ci95_high": m, "n": n}
    m = statistics.mean(values)
    s = statistics.stdev(values)
    ci = 1.96 * s / math.sqrt(n)
    p95_index = min(n - 1, max(0, math.ceil(0.95 * n) - 1))
    return {
        "mean": round(m, 4), "median": round(statistics.median(values), 4),
        "p95": round(sorted(values)[p95_index], 4),
        "std": round(s, 4), "ci95_low": round(m - ci, 4),
        "ci95_high": round(m + ci, 4), "n": n,
    }


def wilson_ci(successes, total, z=1.96):
    """Wilson score interval for binomial rates, including 0% and 100% cases."""
    if total <= 0:
        return 0.0, 0.0
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    half_width = z * math.sqrt((p * (1 - p) / total) + (z * z / (4 * total * total))) / denom
    return round(max(0.0, center - half_width), 4), round(min(1.0, center + half_width), 4)


def get_proc_mem_mb():
    """Get current process RSS memory in MB."""
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except:
        return 0.0


def get_cpu_percent():
    """Get current process CPU utilization (requires psutil)."""
    try:
        import psutil
        return psutil.Process().cpu_percent(interval=0.1)
    except:
        return -1.0


def capture_profile():
    """Capture CPU and memory snapshot."""
    return {
        "cpu_pct": round(get_cpu_percent(), 1),
        "mem_mb": round(get_proc_mem_mb(), 1),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  E3: Real socket-level MQTT wire byte counting
# ═══════════════════════════════════════════════════════════════════════════

class ByteCountingSocket:
    """Wraps a socket to count actual bytes sent/received."""

    def __init__(self, sock):
        self._sock = sock
        self.bytes_sent = 0
        self.bytes_recv = 0

    def send(self, data, *args, **kwargs):
        n = self._sock.send(data, *args, **kwargs)
        self.bytes_sent += n
        return n

    def sendall(self, data, *args, **kwargs):
        self.bytes_sent += len(data)
        return self._sock.sendall(data, *args, **kwargs)

    def recv(self, *args, **kwargs):
        data = self._sock.recv(*args, **kwargs)
        self.bytes_recv += len(data)
        return data

    def __getattr__(self, name):
        return getattr(self._sock, name)


def _publish_and_drain(client, topic, payload, qos, timeout_s=2.0):
    info = client.publish(topic, payload, qos=qos)
    deadline = time.time() + timeout_s
    while not info.is_published() and time.time() < deadline:
        client.loop(timeout=0.05)
    client.loop(timeout=0.01)
    return info.is_published()


def _publish_with_completion(client, topic, payload, qos, timeout_s=2.0):
    """Publish one message and drive the client until Paho marks it complete."""
    enqueue_t0 = time.perf_counter()
    info = client.publish(topic, payload, qos=qos)
    enqueue_ms = (time.perf_counter() - enqueue_t0) * 1000

    completion_t0 = time.perf_counter()
    deadline = time.time() + timeout_s
    while not info.is_published() and time.time() < deadline:
        client.loop(timeout=0.002)
    client.loop(timeout=0.001)
    completion_ms = (time.perf_counter() - completion_t0) * 1000
    return info.is_published(), enqueue_ms, completion_ms


def _wait_for_subscriber_count(counter, target, timeout_s=5.0):
    """Wait for the subscriber callback to observe the expected message count."""
    deadline = time.time() + timeout_s
    while counter[0] < target and time.time() < deadline:
        time.sleep(0.01)
    return counter[0] >= target


def _wait_for_valid_count(counts, target, timeout_s=5.0):
    """Wait until the subscriber has authenticated ``target`` unique envelopes."""
    deadline = time.time() + timeout_s
    while counts["valid"] < target and time.time() < deadline:
        time.sleep(0.01)
    return counts["valid"] >= target


def _new_verification_counts() -> dict:
    """Fresh subscriber-side authentication tally for one measurement run."""
    return {"received": 0, "valid": 0, "invalid": 0, "replay": 0, "reasons": {}, "verify_ms": []}


def _make_verifying_on_message(verifier, counts, *, recv_times=None, recv_seqs=None):
    """Build a paho on_message that authenticates every delivered payload with
    the arm's stateful subscriber verifier (``WireEnvelopeVerifier``).

    A message counts as a valid delivery only if it authenticates AND carries a
    fresh ``(epoch, seq)``; the verifier rejects malformed, tampered, wrong-key,
    replayed, and epoch-rolled-back payloads, so tampered/replayed traffic never
    inflates the delivery count.  ``recv_times`` maps the *parsed envelope* seq
    (not raw payload bytes) to a receipt timestamp for latency mapping, and
    ``recv_seqs`` collects the distinct delivered seqs for unique-delivery
    counting.  Counters are written only from paho's single network thread; when
    the subscriber is reused across reps the caller must quiesce this callback
    (swap in ``_ignore_on_message``) after the per-rep drain barrier before reading
    the counters on the main thread, so no concurrent mutation is possible."""
    def on_msg(client, userdata, message):
        counts["received"] += 1
        t0 = time.perf_counter()
        result = verifier.verify(message.payload)
        counts["verify_ms"].append((time.perf_counter() - t0) * 1000.0)
        if result.valid:
            counts["valid"] += 1
            env = result.envelope
            if env is not None:
                if recv_times is not None:
                    recv_times[env.seq] = time.time()
                if recv_seqs is not None:
                    recv_seqs.add(env.seq)
        else:
            counts["invalid"] += 1
            if result.reason_code == "REPLAY_DUPLICATE":
                counts["replay"] += 1
            reasons = counts["reasons"]
            reasons[result.reason_code] = reasons.get(result.reason_code, 0) + 1
    return on_msg


def _ignore_on_message(client, userdata, message):
    """Drop callback used to quiesce a reused subscriber loop thread between reps.

    Once a repetition has drained, its callback is swapped for this no-op (a single
    GIL-atomic assignment) so the live network thread cannot mutate that rep's
    ``counts``/``recv_times`` while the main thread reads them, and any post-drain
    straggler is dropped rather than bleeding into the next rep — reproducing the
    old per-rep fresh-subscriber isolation without reconnecting."""
    return


def _drain_receipts(recv_times, target, *, max_wait_s=1.0, idle_gap_s=0.05):
    """Bounded wait for one repetition's receipts to settle before the next rep.

    Returns as soon as ``target`` receipts have arrived (the QoS1/2 fast path) or
    delivery has been idle for ``idle_gap_s`` (a dropped QoS0 message that will
    never arrive), and never blocks longer than ``max_wait_s``.  This replaces the
    old per-rep ``disconnect`` + fixed ``sleep(0.2)``: with the publisher and
    subscriber now reused across reps, we still need an explicit — but hang-proof —
    barrier so a straggler cannot bleed into the next repetition's fresh receipt
    map."""
    deadline = time.time() + max_wait_s
    last_count = -1
    last_change = time.time()
    while time.time() < deadline:
        c = len(recv_times)
        if c >= target:
            break
        if c != last_count:
            last_count = c
            last_change = time.time()
        elif time.time() - last_change >= idle_gap_s:
            break
        time.sleep(0.005)
    time.sleep(0.01)


def _teardown_mqtt_client(client, *, has_loop):
    """Best-effort bounded teardown of a reused E5-cell MQTT client.

    ``disconnect`` is issued first so the DISCONNECT is actually flushed: for the
    subscriber (``has_loop=True``) its network thread sends it and ``loop_stop``
    then joins that thread; for the loop-less publisher we pump ``loop`` a few
    times to push the packet out.  Every step is guarded so cleanup of one client
    never masks a real error or blocks the run, and so no socket/thread leaks even
    when a cell raises mid-repetition."""
    if client is None:
        return
    try:
        client.disconnect()
    except Exception:
        pass
    try:
        if has_loop:
            client.loop_stop()
        else:
            for _ in range(5):
                client.loop(timeout=0.01)
    except Exception:
        pass


def run_e3_optimized(
    arms=None,
    payloads=None,
    qos_list=None,
    n_msg=None,
    quick=False,
    *,
    a6_witness_count=1,
):
    """
    E3: Per-message MQTT overhead — REAL socket-level byte counting.
    Wraps only the publisher's socket to count actual TCP bytes sent.
    """
    if arms is None:
        arms = ["A0", "A1", "A2", "A3", "A4", "A6"]
    if payloads is None:
        payloads = [32, 64, 128, 512, 1024]
    if qos_list is None:
        qos_list = [0, 1, 2]

    if n_msg is None:
        n_msg = 50

    if quick:
        arms = ["A0", "A4", "A6"]
        payloads = [32, 128, 512]
        qos_list = [0]
        n_msg = min(n_msg, 20)

    print("=" * 70)
    print("E3 OPTIMIZED: Real Socket-Level MQTT Wire Bytes")
    print("=" * 70)

    rows = []

    for arm_id in arms:
        for qos in qos_list:
            for psize in payloads:
                print(f"  {arm_id} QoS={qos} {psize}B...", end=" ", flush=True)
                topic = make_topic(arm_id)
                N = min(n_msg, 100)
                arm = create_arm(
                    arm_id,
                    topic,
                    N=N,
                    witness_count=a6_witness_count,
                )

                # Subscriber: passive collector during warm-up, then swapped to
                # the arm's authenticating verifier for the measured phase.
                warm_received = []
                sub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                sub.on_message = lambda c, u, m: warm_received.append(m.payload)
                sub.connect(BROKER_HOST, BROKER_PORT)
                sub.subscribe(topic, qos=qos)
                sub.loop_start()
                time.sleep(0.05)

                pub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                pub.connect(BROKER_HOST, BROKER_PORT)

                # Wrap only the publisher's socket
                pub_sock = pub._sock
                if pub_sock:
                    counter = ByteCountingSocket(pub_sock)
                    pub._sock = counter
                else:
                    counter = None

                # Warm-up: authenticated envelopes from a dedicated warm-up arm.
                # Its distinct key material means these are rejected as
                # KEY_ID_MISMATCH before touching the measured verifier's replay/
                # epoch state, so warm-up cannot pollute measured delivery counts.
                warm_arm = create_arm(arm_id, topic, N=N, witness_count=a6_witness_count)
                for i in range(5):
                    wrec = Record.make(i + 1, topic, make_payload(psize))
                    warm_arm.add_record(wrec)
                    _publish_and_drain(pub, topic, warm_arm.latest_wire_payload(), qos)
                if hasattr(warm_arm, "free"):
                    warm_arm.free()
                time.sleep(0.05)

                # Measured phase: publish authenticated wire envelopes and count
                # subscriber-verified unique deliveries.
                verifier = arm.new_subscriber_verifier()
                counts = _new_verification_counts()
                sub.on_message = _make_verifying_on_message(verifier, counts)

                per_msg_sizes = []
                n_published = 0
                for i in range(n_msg):
                    rec = Record.make(i + 1, topic, make_payload(psize))
                    arm.add_record(rec)
                    before_send = counter.bytes_sent if counter else 0
                    if _publish_and_drain(pub, topic, arm.latest_wire_payload(), qos):
                        n_published += 1
                    after_send = counter.bytes_sent if counter else 0
                    per_msg_sizes.append(after_send - before_send)

                pub.disconnect()
                time.sleep(0.2)
                sub.loop_stop()
                sub.disconnect()
                arm.flush()
                evidence_sizes = [len(ev.serialize(include_records=True)) for ev in arm.checkpoints]
                evidence_package_bytes = sum(evidence_sizes)
                evidence_bytes_per_msg = evidence_package_bytes / n_msg if n_msg else 0
                checkpoint_sequence_ok = checkpoint_sequence_valid(arm.checkpoints) if arm.checkpoints else (arm_id == "A2")

                if per_msg_sizes:
                    s = stats(per_msg_sizes)
                    mqtt_pub_bytes = s["mean"]
                else:
                    s = stats([0])
                    mqtt_pub_bytes = 0

                # Record overhead = serialized record size minus payload
                rec_overhead = 4 + 8 + 2 + len(topic.encode()) + 4
                rows.append({
                    "env_id": ENV_ID, "arm": arm_id, "qos": qos,
                    "payload_bytes": psize,
                    "mqtt_pub_bytes_mean": round(mqtt_pub_bytes, 1),
                    "mqtt_pub_bytes_median": s["median"],
                    "mqtt_pub_bytes_p95": s["p95"],
                    "mqtt_pub_bytes_ci95_low": s["ci95_low"],
                    "mqtt_pub_bytes_ci95_high": s["ci95_high"],
                    "record_overhead_bytes": rec_overhead,
                    "overhead_bytes": round(mqtt_pub_bytes - psize, 1) if mqtt_pub_bytes > 0 else rec_overhead,
                    "deferred_evidence_package_bytes": evidence_package_bytes,
                    "deferred_evidence_bytes_per_msg": round(evidence_bytes_per_msg, 2),
                    "record_plus_deferred_evidence_bytes_per_msg": round(mqtt_pub_bytes + evidence_bytes_per_msg, 2),
                    "n_checkpoints": len(arm.checkpoints),
                    "checkpoint_sequence_valid": checkpoint_sequence_ok,
                    "audit_evidence_transferable": arm_id != "A2",
                    "subscriber_received": counts["received"],
                    "subscriber_verified_valid": counts["valid"],
                    "subscriber_verified_invalid": counts["invalid"],
                    "subscriber_verified_replay": counts["replay"],
                    "publish_path_scope": "authenticated_wire_envelope_online_publish_path",
                    "evidence_scope": "full_serialized_checkpoint_evidence_deferred",
                    "measurement_method": "socket_level_authenticated_wire_envelope_publish_counting_plus_deferred_evidence_serialization",
                    "n_samples": s["n"],
                    "n_published": n_published,
                })
                if hasattr(arm, 'free'):
                    arm.free()
                print(
                    f"wire={mqtt_pub_bytes:.0f}B "
                    f"deferred={evidence_bytes_per_msg:.1f}B/msg"
                )

    path = os.path.join(RESULT_DIR, "e3_online_overhead.csv")
    if rows:
        rows = write_csv(path, rows, PROVENANCE)
        print(f"\n  ✓ Saved {len(rows)} rows → {path}")
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  E5: End-to-end latency — 30 independent repetitions
# ═══════════════════════════════════════════════════════════════════════════

def run_e5_optimized(
    n_reps=30,
    quick=False,
    *,
    n_msg=50,
    qos_list=None,
    payloads=None,
    n_values=None,
    a6_witness_count=1,
):
    """
    E5: E2E latency — 30 independent repetitions per data point.
    Each rep: fresh connection, fresh key material, fresh MQTT session.
    """
    arms = ["A0", "A2", "A3", "A4", "A6"]
    N_vals = n_values or [10, 100]
    payloads = payloads or [32, 128, 512]
    qos_list = qos_list or [0]

    if quick:
        n_reps = 5
        arms = ["A0", "A4", "A6"]
        N_vals = [10]
        payloads = [128]
        qos_list = [0]
        n_msg = min(n_msg, 50)

    print("=" * 70)
    print(f"E5 OPTIMIZED: E2E Latency — {n_reps} independent repetitions")
    print(f"  Arms: {arms}, N: {N_vals}, Payloads: {payloads}B, QoS: {qos_list}, messages/rep: {n_msg}")
    print("=" * 70)

    rows = []
    for arm_id in arms:
        seen_eff_n: set[int] = set()
        for N in N_vals:
            eff_n = 1 if arm_id in ("A1", "A2") else N
            # A1/A2 collapse every N to a single checkpoint, so distinct N values
            # would emit byte-identical (arm, eff_n, payload, qos) rows.  Keep one
            # cell per collapsed size instead of duplicating the measurement.
            if eff_n in seen_eff_n:
                continue
            seen_eff_n.add(eff_n)
            for psize in payloads:
                for qos in qos_list:
                    print(f"\n  {arm_id} N={eff_n} {psize}B QoS={qos}...", flush=True)

                    rep_latencies = []  # full app update -> subscriber receipt
                    rep_mqtt_latencies = []  # publish call -> subscriber receipt
                    rep_update_ms = []
                    rep_publish_call_ms = []
                    rep_publish_completion_ms = []
                    rep_publish_completed = []
                    rep_published_counts = []
                    rep_received_counts = []
                    rep_receipt_ratios = []
                    rep_flush_ms = []
                    rep_verify_ms = []           # subscriber authentication latency
                    rep_valid_counts = []        # verified-valid unique deliveries
                    rep_invalid_counts = []      # rejected (tamper/wrong-key/replay)
                    rep_replay_counts = []
                    verify_reason_totals: Dict[str, int] = {}

                    # One publisher + one subscriber are connected once per cell and
                    # reused across every repetition.  The old code created a fresh
                    # pub/sub pair *per rep* (reps x cells MQTT clients, each with its
                    # own loop_start thread); that churn accumulated until the full run
                    # wedged at A2/QoS1.  Each rep still gets fresh key material, a
                    # fresh verifier and fresh receipt/seq/timing state, so a straggler
                    # from a prior rep is rejected as KEY_ID_MISMATCH and never counts
                    # as a delivery.  Clients are torn down with bounded cleanup in the
                    # finally, so an error in any cell cannot leak sockets or threads.
                    topic = make_topic(arm_id)
                    sub = None
                    pub = None
                    try:
                        sub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                        sub.connect(BROKER_HOST, BROKER_PORT)
                        sub.subscribe(topic, qos=qos)
                        sub.loop_start()
                        pub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                        pub.connect(BROKER_HOST, BROKER_PORT)
                        time.sleep(0.05)

                        for rep in range(n_reps):
                            arm = create_arm(
                                arm_id,
                                topic,
                                N=eff_n,
                                witness_count=a6_witness_count,
                            )

                            send_times = {}
                            mqtt_send_times = {}
                            recv_times = {}

                            # Rebind the reused subscriber callback to this rep's fresh
                            # verifier/counts/receipt map.  The assignment is atomic and
                            # the prior rep was drained to quiescence, so the paho
                            # network thread only ever sees a consistent callback, and
                            # receipt times are keyed by the parsed envelope seq.
                            verifier = arm.new_subscriber_verifier()
                            counts = _new_verification_counts()
                            sub.on_message = _make_verifying_on_message(
                                verifier, counts, recv_times=recv_times
                            )

                            published_count = 0
                            for i in range(n_msg):
                                full_t0_wall = time.time()
                                update_t0 = time.perf_counter()
                                rec = Record.make(i + 1, topic, make_payload(psize))
                                arm.add_record(rec)
                                update_ms = (time.perf_counter() - update_t0) * 1000
                                publish_t0_wall = time.time()
                                published, publish_call_ms, publish_completion_ms = _publish_with_completion(
                                    pub,
                                    topic,
                                    arm.latest_wire_payload(),
                                    qos,
                                )
                                send_times[i + 1] = full_t0_wall
                                mqtt_send_times[i + 1] = publish_t0_wall
                                rep_update_ms.append(update_ms)
                                rep_publish_call_ms.append(publish_call_ms)
                                rep_publish_completion_ms.append(publish_completion_ms)
                                rep_publish_completed.append(1 if published else 0)
                                if published:
                                    published_count += 1

                            # Bounded drain to receipt quiescence: wait until every
                            # published message has been received or delivery goes idle,
                            # capped so a dropped QoS0 message can never block the run.
                            # Replaces the old per-rep disconnect + fixed sleep(0.2).
                            _drain_receipts(recv_times, published_count)
                            # Quiesce the reused subscriber before consuming this
                            # rep's counts: the drop callback (atomic swap) stops the
                            # live loop thread from mutating counts/recv_times during
                            # the main-thread read and drops any post-drain straggler,
                            # so the invalid/replay diagnostic counters keep their old
                            # per-rep-isolated semantics.
                            sub.on_message = _ignore_on_message
                            flush_t0 = time.perf_counter()
                            arm.flush()
                            rep_flush_ms.append((time.perf_counter() - flush_t0) * 1000)

                            lats = []
                            mqtt_lats = []
                            for seq, st in send_times.items():
                                if seq in recv_times:
                                    lt = (recv_times[seq] - st) * 1000
                                    if 0 < lt < 5000:
                                        lats.append(lt)
                                    mqtt_lt = (recv_times[seq] - mqtt_send_times[seq]) * 1000
                                    if 0 < mqtt_lt < 5000:
                                        mqtt_lats.append(mqtt_lt)
                            received_count = len(set(recv_times).intersection(send_times))
                            rep_published_counts.append(published_count)
                            rep_received_counts.append(received_count)
                            rep_receipt_ratios.append(received_count / n_msg if n_msg else 0)

                            # Subscriber authentication accounting for this rep.
                            rep_verify_ms.extend(counts["verify_ms"])
                            rep_valid_counts.append(counts["valid"])
                            rep_invalid_counts.append(counts["invalid"])
                            rep_replay_counts.append(counts["replay"])
                            for reason, n in counts["reasons"].items():
                                verify_reason_totals[reason] = verify_reason_totals.get(reason, 0) + n

                            if lats:
                                rep_latencies.append(statistics.mean(lats))
                            if mqtt_lats:
                                rep_mqtt_latencies.append(statistics.mean(mqtt_lats))

                            if hasattr(arm, 'free'):
                                arm.free()

                            if (rep + 1) % 10 == 0:
                                print(f"    rep {rep+1}/{n_reps}...", end=" ", flush=True)
                    finally:
                        _teardown_mqtt_client(pub, has_loop=False)
                        _teardown_mqtt_client(sub, has_loop=True)

                    if rep_latencies:
                        s = stats(rep_latencies)
                        mqtt_s = stats(rep_mqtt_latencies) if rep_mqtt_latencies else stats([0])
                        update_s = stats(rep_update_ms) if rep_update_ms else stats([0])
                        publish_s = stats(rep_publish_call_ms) if rep_publish_call_ms else stats([0])
                        publish_completion_s = (
                            stats(rep_publish_completion_ms)
                            if rep_publish_completion_ms else stats([0])
                        )
                        receipt_s = stats(rep_receipt_ratios) if rep_receipt_ratios else stats([0])
                        received_s = stats(rep_received_counts) if rep_received_counts else stats([0])
                        published_s = stats(rep_published_counts) if rep_published_counts else stats([0])
                        flush_s = stats(rep_flush_ms) if rep_flush_ms else stats([0])
                        verify_s = stats(rep_verify_ms) if rep_verify_ms else stats([0])
                        valid_s = stats(rep_valid_counts) if rep_valid_counts else stats([0])
                        prof = capture_profile()
                        rows.append({
                            "env_id": ENV_ID, "arm": arm_id, "N": eff_n,
                            "payload_bytes": psize, "qos": qos,
                            "lat_ms_mean": s["mean"], "lat_ms_median": s["median"],
                            "lat_ms_p95": s["p95"], "lat_ms_std": s["std"],
                            "mqtt_only_lat_ms_mean": mqtt_s["mean"],
                            "evidence_update_ms_mean": update_s["mean"],
                            "publish_call_ms_mean": publish_s["mean"],
                            "publish_completion_ms_mean": publish_completion_s["mean"],
                            "publish_completion_ratio": round(
                                sum(rep_publish_completed) / len(rep_publish_completed),
                                4,
                            ) if rep_publish_completed else 0,
                            "message_receipt_ratio_mean": receipt_s["mean"],
                            "message_receipt_ratio_min": round(min(rep_receipt_ratios), 4) if rep_receipt_ratios else 0,
                            "published_messages_mean": published_s["mean"],
                            "received_messages_mean": received_s["mean"],
                            "received_messages_min": min(rep_received_counts) if rep_received_counts else 0,
                            "subscriber_verify_ms_mean": verify_s["mean"],
                            "subscriber_verify_ms_p95": verify_s["p95"],
                            "subscriber_verified_valid_mean": valid_s["mean"],
                            "subscriber_verified_invalid_total": sum(rep_invalid_counts),
                            "subscriber_verified_replay_total": sum(rep_replay_counts),
                            "subscriber_verify_reason_counts": json.dumps(verify_reason_totals, sort_keys=True),
                            "delivery_scope": "subscriber_authenticated_unique_envelope",
                            "flush_ms_mean": flush_s["mean"],
                            "ci95_low": s["ci95_low"], "ci95_high": s["ci95_high"],
                            "n_repetitions": n_reps,
                            "messages_per_repetition": n_msg,
                            "cpu_pct": prof["cpu_pct"], "mem_mb": prof["mem_mb"],
                            "measurement_method": "full_app_update_to_authenticated_receipt_with_mqtt_publish_completion_breakout",
                        })
                        print(f"→ mean={s['mean']:.3f}ms [{s['ci95_low']:.3f}, {s['ci95_high']:.3f}] (n={n_reps})")

    path = os.path.join(RESULT_DIR, "e5_latency.csv")
    rows = write_csv(path, rows, PROVENANCE)
    print(f"\n  ✓ Saved {len(rows)} rows → {path}")
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  E5 A5 coverage: SLH-DSA latency
# ═══════════════════════════════════════════════════════════════════════════

def run_e5_a5_coverage(n_reps=10):
    """E5 coverage of A5 (SLH-DSA). SLH-DSA signing is ~10ms, so fewer reps."""
    print("=" * 70)
    print(f"E5 A5 COVERAGE: SLH-DSA Latency — {n_reps} repetitions")
    print("=" * 70)

    rows = []
    for N in [10]:
        for psize in [128]:
            print(f"\n  A5 N={N} {psize}B...", flush=True)
            rep_latencies = []

            for rep in range(n_reps):
                topic = make_topic("A5")
                arm = create_arm("A5", topic, N=N)
                send_times = {}
                recv_times = {}

                def on_msg(c, u, m):
                    now = time.time()
                    try:
                        seq = struct.unpack(">I", m.payload[:4])[0]
                        recv_times[seq] = now
                    except:
                        pass

                sub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                sub.on_message = on_msg
                sub.connect(BROKER_HOST, BROKER_PORT)
                sub.subscribe(topic, qos=0)
                sub.loop_start()
                time.sleep(0.05)

                pub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                pub.connect(BROKER_HOST, BROKER_PORT)

                n_msg = 20
                for i in range(n_msg):
                    rec = Record.make(i + 1, topic, make_payload(psize))
                    arm.add_record(rec)
                    t0 = time.time()
                    pub.publish(topic, rec.serialize(), qos=0)
                    send_times[i + 1] = t0

                pub.disconnect()
                time.sleep(0.5)
                sub.loop_stop()
                sub.disconnect()
                arm.flush()

                lats = []
                for seq, st in send_times.items():
                    if seq in recv_times:
                        lt = (recv_times[seq] - st) * 1000
                        if 0 < lt < 5000:
                            lats.append(lt)

                if lats:
                    rep_latencies.append(statistics.mean(lats))

                if hasattr(arm, 'free'):
                    arm.free()

                print(f"    rep {rep+1}/{n_reps}...", end=" ", flush=True)

            if rep_latencies:
                s = stats(rep_latencies)
                rows.append({
                    "env_id": ENV_ID, "arm": "A5", "N": N,
                    "payload_bytes": psize, "qos": 0,
                    "lat_ms_mean": s["mean"], "lat_ms_median": s["median"],
                    "lat_ms_p95": s["p95"], "lat_ms_std": s["std"],
                    "ci95_low": s["ci95_low"], "ci95_high": s["ci95_high"],
                    "n_repetitions": n_reps,
                    "measurement_method": "A5_SLH_DSA_coverage",
                })
                print(f"→ mean={s['mean']:.3f}ms [{s['ci95_low']:.3f}, {s['ci95_high']:.3f}]")

    if rows:
        path = os.path.join(RESULT_DIR, "e5_latency_a5.csv")
        rows = write_csv(path, rows, PROVENANCE)
        print(f"\n  ✓ Saved {len(rows)} rows → {path}")
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  E6: Broker throughput — 10 independent repetitions
# ═══════════════════════════════════════════════════════════════════════════

def run_e6_optimized(
    n_reps=10,
    quick=False,
    *,
    payloads=None,
    qos_list=None,
    burst_s=5.0,
    drain_timeout_s=5.0,
    max_inflight_messages=512,
    a6_witness_count=1,
):
    """E6: Broker throughput — 10 independent repetitions per data point."""
    arms = ["A0", "A2", "A3", "A4", "A6"]
    payloads = payloads or [32, 128, 512]
    qos_list = qos_list or [0]

    if quick:
        n_reps = 3
        arms = ["A0", "A4", "A6"]
        payloads = [128]
        qos_list = [0]
        burst_s = 2.0

    print("=" * 70)
    print(f"E6 OPTIMIZED: Broker Throughput — {n_reps} repetitions × {burst_s}s burst")
    print("=" * 70)

    rows = []
    for arm_id in arms:
        for qos in qos_list:
            for psize in payloads:
                print(f"\n  {arm_id} QoS={qos} {psize}B...", flush=True)
                rep_rates = []
                rep_enqueue_rates = []
                rep_subscriber_rates = []
                rep_delivery_ratios = []
                rep_flush_ms = []
                rep_drain_ms = []
                rep_drained = []
                rep_sent_counts = []
                rep_received_counts = []
                rep_verified_counts = []     # subscriber-authenticated unique
                rep_invalid_counts = []      # rejected (tamper/wrong-key/replay)
                rep_replay_counts = []
                verify_reason_totals: Dict[str, int] = {}

                for rep in range(n_reps):
                    topic = make_topic(arm_id)
                    arm = create_arm(
                        arm_id,
                        topic,
                        N=100,
                        witness_count=a6_witness_count,
                    )
                    recv_count = [0]
                    counts = _new_verification_counts()
                    verifier = arm.new_subscriber_verifier()
                    sub = None
                    pub = None

                    def on_msg(c, u, m, _v=verifier, _c=counts, _rc=recv_count):
                        _rc[0] += 1
                        _c["received"] += 1
                        result = _v.verify(m.payload)
                        if result.valid:
                            _c["valid"] += 1
                        else:
                            _c["invalid"] += 1
                            if result.reason_code == "REPLAY_DUPLICATE":
                                _c["replay"] += 1
                            _c["reasons"][result.reason_code] = (
                                _c["reasons"].get(result.reason_code, 0) + 1
                            )

                    try:
                        sub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                        sub.on_message = on_msg
                        sub.connect(BROKER_HOST, BROKER_PORT)
                        sub.subscribe(topic, qos=qos)
                        sub.loop_start()
                        time.sleep(0.05)

                        pub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                        pub.connect(BROKER_HOST, BROKER_PORT)
                        pub.loop_start()

                        sent = 0
                        t0 = time.time()
                        while time.time() - t0 < burst_s:
                            rec = Record.make(sent + 1, topic, make_payload(psize))
                            arm.add_record(rec)
                            pub.publish(topic, arm.latest_wire_payload(), qos=qos)
                            sent += 1
                            # Bound the outstanding verified backlog, not just the
                            # raw received count, so throttle tracks authenticated
                            # progress.
                            while (
                                max_inflight_messages > 0 and
                                sent - counts["valid"] >= max_inflight_messages and
                                time.time() - t0 < burst_s
                            ):
                                time.sleep(0.002)
                        loop_elapsed = time.time() - t0
                        flush_t0 = time.perf_counter()
                        arm.flush()
                        flush_ms = (time.perf_counter() - flush_t0) * 1000
                        evidence_elapsed = time.time() - t0

                        drain_t0 = time.perf_counter()
                        drained = _wait_for_valid_count(
                            counts,
                            sent,
                            timeout_s=drain_timeout_s,
                        )
                        drain_ms = (time.perf_counter() - drain_t0) * 1000
                        total_elapsed = time.time() - t0
                        pub.disconnect()
                        pub.loop_stop()
                        pub = None
                        sub.loop_stop()
                        sub.disconnect()
                        sub = None

                        verified_unique = counts["valid"]
                        enqueue_rate = sent / loop_elapsed if loop_elapsed > 0 else 0
                        evidence_rate = sent / evidence_elapsed if evidence_elapsed > 0 else 0
                        subscriber_rate = verified_unique / total_elapsed if total_elapsed > 0 else 0
                        delivery_ratio = verified_unique / sent if sent > 0 else 0
                        rep_sent_counts.append(sent)
                        rep_received_counts.append(recv_count[0])
                        rep_verified_counts.append(verified_unique)
                        rep_invalid_counts.append(counts["invalid"])
                        rep_replay_counts.append(counts["replay"])
                        for reason, n in counts["reasons"].items():
                            verify_reason_totals[reason] = verify_reason_totals.get(reason, 0) + n
                        rep_enqueue_rates.append(enqueue_rate)
                        rep_rates.append(evidence_rate)
                        rep_subscriber_rates.append(subscriber_rate)
                        rep_delivery_ratios.append(delivery_ratio)
                        rep_flush_ms.append(flush_ms)
                        rep_drain_ms.append(drain_ms)
                        rep_drained.append(1 if drained else 0)
                        print(f"    rep {rep+1}/{n_reps}: {evidence_rate:.0f} msg/s", end="  ", flush=True)
                    finally:
                        if pub is not None:
                            try:
                                pub.loop_stop()
                                pub.disconnect()
                            except Exception:
                                pass
                        if sub is not None:
                            try:
                                sub.loop_stop()
                                sub.disconnect()
                            except Exception:
                                pass

                        if hasattr(arm, 'free'):
                            arm.free()

                if rep_rates:
                    s = stats(rep_rates)
                    enqueue_s = stats(rep_enqueue_rates)
                    sub_s = stats(rep_subscriber_rates)
                    delivery_s = stats(rep_delivery_ratios)
                    flush_s = stats(rep_flush_ms)
                    drain_s = stats(rep_drain_ms)
                    sent_s = stats(rep_sent_counts)
                    received_s = stats(rep_received_counts)
                    verified_s = stats(rep_verified_counts) if rep_verified_counts else stats([0])
                    prof = capture_profile()
                    rows.append({
                        "env_id": ENV_ID, "arm": arm_id, "payload_bytes": psize, "qos": qos,
                        "sustained_msg_per_s_mean": s["mean"],
                        "sustained_msg_per_s_median": s["median"],
                        "sustained_msg_per_s_p95": s["p95"],
                        "publisher_enqueue_msg_per_s_mean": enqueue_s["mean"],
                        "subscriber_msg_per_s_mean": sub_s["mean"],
                        "delivery_ratio_mean": delivery_s["mean"],
                        "delivery_ratio_min": round(min(rep_delivery_ratios), 4) if rep_delivery_ratios else 0,
                        "sent_messages_mean": sent_s["mean"],
                        "sent_messages_min": min(rep_sent_counts) if rep_sent_counts else 0,
                        "received_messages_mean": received_s["mean"],
                        "received_messages_min": min(rep_received_counts) if rep_received_counts else 0,
                        "verified_unique_messages_mean": verified_s["mean"],
                        "verified_unique_messages_min": min(rep_verified_counts) if rep_verified_counts else 0,
                        "subscriber_verified_invalid_total": sum(rep_invalid_counts),
                        "subscriber_verified_replay_total": sum(rep_replay_counts),
                        "subscriber_verify_reason_counts": json.dumps(verify_reason_totals, sort_keys=True),
                        "delivery_scope": "subscriber_authenticated_unique_envelope",
                        "flush_ms_mean": flush_s["mean"],
                        "subscriber_drain_ms_mean": drain_s["mean"],
                        "subscriber_drain_success_ratio": round(
                            sum(rep_drained) / len(rep_drained),
                            4,
                        ) if rep_drained else 0,
                        "subscriber_drain_timeout_s": drain_timeout_s,
                        "max_inflight_messages": max_inflight_messages,
                        "ci95_low": s["ci95_low"], "ci95_high": s["ci95_high"],
                        "n_repetitions": n_reps, "burst_duration_s": burst_s,
                        "cpu_pct": prof["cpu_pct"], "mem_mb": prof["mem_mb"],
                        "measurement_method": (
                            f"{n_reps}_independent_bursts_publisher_enqueue_plus_"
                            "evidence_flush_with_bounded_inflight_and_authenticated_subscriber_drain"
                        ),
                    })
                    print(f"\n   → mean={s['mean']:.0f} msg/s [{s['ci95_low']:.0f}, {s['ci95_high']:.0f}]")

    path = os.path.join(RESULT_DIR, "e6_throughput.csv")
    rows = write_csv(path, rows, PROVENANCE)
    print(f"\n  ✓ Saved {len(rows)} rows → {path}")
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  E7: Clean control group + cross-epoch replay
# ═══════════════════════════════════════════════════════════════════════════

def run_e7_optimized(*args, **kwargs):
    """E7 attribution/auditability is produced by the authoritative
    real-crypto QoS suite: separated scenario generator -> semantic oracle
    -> real evidence bridge (audit_stream / WireEnvelopeVerifier) ->
    answer-blind auditor.  The deterministic capability corpus is generated
    once per result package (coverage matrix, not pseudo-repeated trials);
    legacy attack-name rule tables have been removed."""
    suite = _run_qos_suite_once()
    print(
        f"  E7: {suite['case_count']} deterministic corpus cases, "
        f"{len(suite['e7_rows'])} auditability rows (shared real-crypto corpus)"
    )
    return suite["e7_rows"]


# ═══════════════════════════════════════════════════════════════════════════
#  E8: Audit cost — 100 repeated verifications
# ═══════════════════════════════════════════════════════════════════════════

def _verify_a3_chain_evidence(ev, authorization) -> bool:
    """A3 offline verification exercised by E8 (and its regression test): a
    trusted publisher checkpoint signature plus a full hash-chain replay whose
    complete C_0..C_n vector must equal the presented chain values — not merely
    the final head."""
    if not verify_signature(
        authorization.public_key, ev.checkpoint.serialize(), ev.signature,
        authorization.signature_scheme,
    ):
        return False
    chain = HashChain(ev.chain_seed)
    for rec in ev.records:
        chain.append(rec)
    return chain.head == ev.checkpoint.end_anchor and chain.chain == (ev.chain_values or [])


def run_e8_optimized(
    N_values=None,
    k_values=None,
    n_reps=100,
    quick=False,
    *,
    a6_witness_count=1,
    a6_min_receipts=1,
    lifecycle_reps=5,
):
    """E8: Chain vs Merkle audit cost — 100 repeated verifications per (N,k)."""
    if N_values is None:
        N_values = [10, 50, 100, 500, 1000]
    if k_values is None:
        k_values = [1, 5, 10, 50, 100]
    payload = 128

    if quick:
        n_reps = 10
        N_values = [10, 100]
        k_values = [1, 10]

    print("=" * 70)
    print(f"E8 OPTIMIZED: Audit Cost — {n_reps} repeated verifications")
    print(f"  N: {N_values}, k: {k_values}")
    print("=" * 70)

    rows = []
    sample_rows = []
    a3_done_n: set = set()

    # C3 lifecycle raw timings: generation (create + sign) and evidence serialization,
    # sampled lifecycle_reps times per (arm, N), so the summary reports their
    # distributions (p99/bootstrap) instead of a single-shot number.
    for arm_id in ("A3", "A4", "A6"):
        witness = a6_witness_count if arm_id == "A6" else 1
        for N in N_values:
            gen_times = []
            ser_times = []
            for _ in range(lifecycle_reps):
                lc_topic = make_topic(arm_id)
                g0 = time.perf_counter()
                lc_arm = create_arm(arm_id, lc_topic, N=N, witness_count=witness)
                for i in range(N):
                    lc_arm.add_record(Record.make(seq=i + 1, topic=lc_topic, payload=make_payload(payload)))
                lc_arm.flush()
                gen_times.append((time.perf_counter() - g0) * 1000)
                if lc_arm.checkpoints:
                    s0 = time.perf_counter()
                    lc_arm.checkpoints[0].serialize(include_records=True)
                    ser_times.append((time.perf_counter() - s0) * 1000)
                if hasattr(lc_arm, "free"):
                    lc_arm.free()
            sample_rows.append({"arm": arm_id, "N": N, "k_disclosed": "", "operation": "generation", "n_samples": len(gen_times), "samples_ms": [round(t, 6) for t in gen_times]})
            if ser_times:
                sample_rows.append({"arm": arm_id, "N": N, "k_disclosed": "", "operation": "serialization", "n_samples": len(ser_times), "samples_ms": [round(t, 6) for t in ser_times]})

    for N in N_values:
        for k in k_values:
            if k > N:
                continue

            # ── A3 Hash Chain (full-chain disclosure ignores k; measure once per N) ──
            if N not in a3_done_n:
                a3_done_n.add(N)
                topic = make_topic("A3")
                gen_t0 = time.perf_counter()
                arm_a3 = create_arm("A3", topic, N=N)
                for i in range(N):
                    rec = Record.make(seq=i + 1, topic=topic, payload=make_payload(payload))
                    arm_a3.add_record(rec)
                arm_a3.flush()
                a3_gen_ms = (time.perf_counter() - gen_t0) * 1000

                if arm_a3.checkpoints:
                    ev = arm_a3.checkpoints[0]
                    # Trust root comes from an external registry, never the bundle.
                    registry = registry_for_generated_evidence(arm_a3.checkpoints, "A3")
                    auth = registry.publisher_for(
                        ev.checkpoint.client_id, ev.checkpoint.topic, ev.checkpoint.epoch
                    )
                    chain_times = []
                    for _ in range(n_reps):
                        t0 = time.perf_counter()
                        # Timed scope: trusted publisher signature + full chain replay
                        # compared against the complete C_0..C_n vector (shared with
                        # the E8 A3 regression test).
                        chain_ok = _verify_a3_chain_evidence(ev, auth)
                        chain_times.append((time.perf_counter() - t0) * 1000)
                        if not chain_ok:
                            raise RuntimeError("A3 verification failed during E8 (signature or chain)")

                    s = stats(chain_times)
                    sample_rows.append({"arm": "A3", "N": N, "k_disclosed": N, "operation": "verify", "n_samples": len(chain_times), "samples_ms": [round(t, 6) for t in chain_times]})
                    sizes = ev.component_sizes()
                    chain_proof_bytes = (
                        sizes["chain_values_raw_bytes"] +
                        sizes["chain_seed_bytes"] +
                        sizes["signature_bytes"]
                    )
                    rows.append({
                        "env_id": ENV_ID, "arm": "A3", "N": N,
                        "k_disclosed": N, "proof_bytes": chain_proof_bytes,
                        "ckpt_sig_bytes": len(ev.signature),
                        "full_evidence_bytes": sizes["full_evidence_bytes"],
                        "disclosure_model": "full_chain_requires_all_records",
                        "verify_scope": "full_chain_plus_checkpoint_signature",
                        "verify_signature_count": 1,
                        "chain_records_replayed": len(ev.records),
                        "merkle_proofs_verified": 0,
                        "witness_quorum_verified": 0,
                        "lifecycle_generation_ms": round(a3_gen_ms, 4),
                        "verify_ms_mean": s["mean"], "verify_ms_median": s["median"],
                        "verify_ms_p95": s["p95"], "verify_ms_std": s["std"],
                        "ci95_low": s["ci95_low"], "ci95_high": s["ci95_high"],
                        "n_repetitions": n_reps,
                    })
                if hasattr(arm_a3, 'free'):
                    arm_a3.free()

            # ── A4 Merkle ──
            topic = make_topic("A4")
            gen_t0 = time.perf_counter()
            arm_a4 = create_arm("A4", topic, N=N)
            for i in range(N):
                rec = Record.make(seq=i + 1, topic=topic, payload=make_payload(payload))
                arm_a4.add_record(rec)
            arm_a4.flush()
            a4_gen_ms = (time.perf_counter() - gen_t0) * 1000

            if arm_a4.checkpoints:
                ev = arm_a4.checkpoints[0]
                registry = registry_for_generated_evidence(arm_a4.checkpoints, "A4")
                auth = registry.publisher_for(
                    ev.checkpoint.client_id, ev.checkpoint.topic, ev.checkpoint.epoch
                )
                k_proofs = min(k, len(ev.records), len(ev.merkle_proofs or []))
                merkle_times = []
                for _ in range(n_reps):
                    t0 = time.perf_counter()
                    # Timed scope: trusted publisher signature + k Merkle inclusions.
                    sig_ok = verify_signature(
                        auth.public_key, ev.checkpoint.serialize(), ev.signature,
                        auth.signature_scheme,
                    )
                    proofs_ok = sig_ok
                    for idx in range(k_proofs):
                        leaf = hashlib.sha256(MerkleTree.LEAF_PREFIX + ev.records[idx]).digest()
                        if not MerkleTree.verify_proof(leaf, ev.merkle_proofs[idx], ev.checkpoint.end_anchor):
                            proofs_ok = False
                            break
                    merkle_times.append((time.perf_counter() - t0) * 1000)
                    if not proofs_ok:
                        raise RuntimeError("A4 verification failed during E8 (signature or Merkle proof)")

                s = stats(merkle_times)
                sample_rows.append({"arm": "A4", "N": N, "k_disclosed": k, "operation": "verify", "n_samples": len(merkle_times), "samples_ms": [round(t, 6) for t in merkle_times]})
                sizes = ev.component_sizes()
                merkle_proof_bytes = sum(
                    len(sib) + 1 for proof in (ev.merkle_proofs or [])[:k]
                    for sib, _ in proof
                ) + len(ev.signature)

                rows.append({
                    "env_id": ENV_ID, "arm": "A4", "N": N,
                    "k_disclosed": k, "proof_bytes": merkle_proof_bytes,
                    "ckpt_sig_bytes": len(ev.signature),
                    "full_evidence_bytes": sizes["full_evidence_bytes"],
                    "disclosure_model": "selective_merkle_inclusion",
                    "verify_scope": "selected_merkle_inclusions_plus_checkpoint_signature",
                    "verify_signature_count": 1,
                    "chain_records_replayed": 0,
                    "merkle_proofs_verified": k_proofs,
                    "witness_quorum_verified": 0,
                    "lifecycle_generation_ms": round(a4_gen_ms, 4),
                    "verify_ms_mean": s["mean"], "verify_ms_median": s["median"],
                    "verify_ms_p95": s["p95"], "verify_ms_std": s["std"],
                    "ci95_low": s["ci95_low"], "ci95_high": s["ci95_high"],
                    "n_repetitions": n_reps,
                })
            if hasattr(arm_a4, 'free'):
                arm_a4.free()

            # ── A6 Witnessed Merkle ──
            topic = make_topic("A6")
            gen_t0 = time.perf_counter()
            arm_a6 = create_arm(
                "A6",
                topic,
                N=N,
                witness_count=a6_witness_count,
            )
            for i in range(N):
                rec = Record.make(seq=i + 1, topic=topic, payload=make_payload(payload))
                arm_a6.add_record(rec)
            arm_a6.flush()
            a6_gen_ms = (time.perf_counter() - gen_t0) * 1000

            if arm_a6.checkpoints:
                ev = arm_a6.checkpoints[0]
                # Registry-aware A6 verification: without an external registry the
                # witness quorum fails closed, so we build one explicitly here.
                registry = registry_for_generated_evidence(arm_a6.checkpoints, "A6")
                auth = registry.publisher_for(
                    ev.checkpoint.client_id, ev.checkpoint.topic, ev.checkpoint.epoch
                )
                k_proofs = min(k, len(ev.records), len(ev.merkle_proofs or []))
                merkle_witness_times = []
                for _ in range(n_reps):
                    t0 = time.perf_counter()
                    # Timed scope: publisher signature + k Merkle inclusions +
                    # distinct trusted witness quorum.
                    sig_ok = verify_signature(
                        auth.public_key, ev.checkpoint.serialize(), ev.signature,
                        auth.signature_scheme,
                    )
                    proofs_ok = sig_ok
                    for idx in range(k_proofs):
                        leaf = hashlib.sha256(MerkleTree.LEAF_PREFIX + ev.records[idx]).digest()
                        if not MerkleTree.verify_proof(leaf, ev.merkle_proofs[idx], ev.checkpoint.end_anchor):
                            proofs_ok = False
                            break
                    witness_ok, valid_distinct, _total, _details = verify_witness_receipts(
                        ev,
                        registry=registry,
                        min_receipts=a6_min_receipts,
                    )
                    merkle_witness_times.append((time.perf_counter() - t0) * 1000)
                    if not (proofs_ok and witness_ok):
                        raise RuntimeError(
                            "A6 verification failed during E8 (signature, Merkle proof, or witness quorum)"
                        )

                s = stats(merkle_witness_times)
                sample_rows.append({"arm": "A6", "N": N, "k_disclosed": k, "operation": "verify", "n_samples": len(merkle_witness_times), "samples_ms": [round(t, 6) for t in merkle_witness_times]})
                sizes = ev.component_sizes()
                merkle_proof_bytes = sum(
                    len(sib) + 1 for proof in (ev.merkle_proofs or [])[:k]
                    for sib, _ in proof
                ) + len(ev.signature)
                witness_bytes = sizes.get("witness_receipts_raw_bytes", 0)
                total_proof_bytes = merkle_proof_bytes + witness_bytes

                rows.append({
                    "env_id": ENV_ID, "arm": "A6", "N": N,
                    "k_disclosed": k, "proof_bytes": total_proof_bytes,
                    "merkle_bytes": merkle_proof_bytes,
                    "witness_bytes": witness_bytes,
                    "ckpt_sig_bytes": len(ev.signature),
                    "full_evidence_bytes": sizes["full_evidence_bytes"],
                    "disclosure_model": "selective_merkle_with_witness_receipts",
                    "verify_scope": "selected_merkle_checkpoint_signature_and_witness_quorum",
                    "verify_signature_count": 1,
                    "chain_records_replayed": 0,
                    "merkle_proofs_verified": k_proofs,
                    "witness_quorum_verified": valid_distinct,
                    "witness_count": a6_witness_count,
                    "min_receipts": a6_min_receipts,
                    "lifecycle_generation_ms": round(a6_gen_ms, 4),
                    "verify_ms_mean": s["mean"], "verify_ms_median": s["median"],
                    "verify_ms_p95": s["p95"], "verify_ms_std": s["std"],
                    "ci95_low": s["ci95_low"], "ci95_high": s["ci95_high"],
                    "n_repetitions": n_reps,
                })
            if hasattr(arm_a6, 'free'):
                arm_a6.free()

            print(f"  N={N} k={k}: A4={rows[-2]['verify_ms_mean']:.4f}ms, A6={rows[-1]['verify_ms_mean']:.4f}ms")

    path = os.path.join(RESULT_DIR, "e8_audit_cost.csv")
    rows = write_csv(path, rows, PROVENANCE)
    print(f"\n  ✓ Saved {len(rows)} rows → {path}")

    # Persist raw per-repetition verification timing samples so p99 and fixed-seed
    # bootstrap CIs are derivable after the run (aggregates alone cannot support them).
    samples_path = os.path.join(RESULT_DIR, "e8_audit_cost_samples.jsonl")
    prov_fields = PROVENANCE.fields() if hasattr(PROVENANCE, "fields") else {}
    with open(samples_path, "w", encoding="utf-8", newline="\n") as handle:
        for sample_row in sample_rows:
            handle.write(json.dumps({**prov_fields, **sample_row}, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
    print(f"  ✓ Saved {len(sample_rows)} sample rows → {samples_path}")
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  E9: Storage — actual disk file writing
# ═══════════════════════════════════════════════════════════════════════════

def run_e9_optimized(
    arms=None,
    N_values=None,
    freqs=None,
    quick=False,
    *,
    sim_hours=None,
    max_messages=None,
    a6_witness_count=1,
):
    """E9: Storage growth — actual disk file writing (not arithmetic)."""
    if arms is None:
        arms = ["A0", "A1", "A2", "A3", "A4", "A6"]
    if N_values is None:
        N_values = [10, 50, 100, 500, 1000]
    if freqs is None:
        freqs = [1, 10, 100]
    payload = 128
    sim_hours = 1.0 if sim_hours is None else sim_hours  # Simulate then extrapolate to 24h
    max_messages = 10000 if max_messages is None else max_messages

    if quick:
        arms = ["A0", "A1", "A4", "A6"]
        N_values = [10, 100]
        freqs = [10]
        sim_hours = 0.1  # 6 minutes
        max_messages = min(max_messages, 10000)

    print("=" * 70)
    print(f"E9 OPTIMIZED: Storage Growth — actual disk file writing")
    print(f"  Simulating {sim_hours}h of data, extrapolating to 24h")
    print("=" * 70)

    rows = []
    tmpdir = tempfile.mkdtemp(prefix="e9_storage_")

    try:
        for arm_id in arms:
            for N in N_values:
                eff_n = N if arm_id not in ("A1", "A2") else 1
                for freq in freqs:
                    print(f"  {arm_id} N={eff_n} freq={freq}/s...", end=" ", flush=True)

                    topic = make_topic(arm_id)
                    total_msgs = int(freq * sim_hours * 3600)
                    if total_msgs < 10:
                        total_msgs = 10

                    # Create checkpoint evidence files in temp dir
                    arm_dir = os.path.join(tmpdir, f"{arm_id}_N{eff_n}_freq{freq}")
                    os.makedirs(arm_dir, exist_ok=True)

                    arm = create_arm(
                        arm_id,
                        topic,
                        N=eff_n,
                        witness_count=a6_witness_count,
                    )
                    for i in range(min(total_msgs, max_messages)):
                        rec = Record.make(i + 1, topic, make_payload(payload))
                        arm.add_record(rec)
                    arm.flush()

                    # Serialize checkpoint evidence to disk
                    ckpt_dir = os.path.join(arm_dir, "checkpoints")
                    os.makedirs(ckpt_dir, exist_ok=True)
                    total_disk_bytes = 0
                    component_totals = defaultdict(int)
                    for ci, ckpt_ev in enumerate(arm.checkpoints):
                        ckpt_path = os.path.join(ckpt_dir, f"evidence_{ci:04d}.json")
                        with open(ckpt_path, "wb") as f:
                            f.write(ckpt_ev.serialize(include_records=True))
                        total_disk_bytes += os.path.getsize(ckpt_path)
                        for key, value in ckpt_ev.component_sizes().items():
                            component_totals[key] += value

                    # Extrapolate: if we simulated fewer msgs than total, scale up
                    actual_msgs = min(total_msgs, max_messages)
                    scale_factor = 1.0
                    if actual_msgs < total_msgs:
                        scale_factor = total_msgs / actual_msgs
                        total_disk_bytes = int(total_disk_bytes * scale_factor)
                        for key in list(component_totals):
                            component_totals[key] = int(component_totals[key] * scale_factor)

                    bytes_per_day = total_disk_bytes * (24.0 / sim_hours)

                    rows.append({
                        "env_id": ENV_ID, "arm": arm_id, "N": N,
                        "effective_N": eff_n,
                        "freq": freq, "payload_bytes": payload,
                        "simulated_hours": sim_hours,
                        "bytes_per_day": round(bytes_per_day, 0),
                        "ckpt_files_count": len(arm.checkpoints),
                        "simulated_messages": actual_msgs,
                        "target_messages": total_msgs,
                        "extrapolation_factor": round(scale_factor, 4),
                        "full_evidence_bytes": component_totals["full_evidence_bytes"],
                        "records_raw_bytes": component_totals["records_raw_bytes"],
                        "signature_bytes": component_totals["signature_bytes"],
                        "public_key_bytes": component_totals["public_key_bytes"],
                        "merkle_proofs_raw_bytes": component_totals["merkle_proofs_raw_bytes"],
                        "chain_values_raw_bytes": component_totals["chain_values_raw_bytes"],
                        "measurement_method": "canonical_full_evidence_package_disk_writing",
                    })

                    if hasattr(arm, 'free'):
                        arm.free()
                    print(f"{bytes_per_day / 1e6:.2f} MB/day ({len(arm.checkpoints)} ckpt files)")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    path = os.path.join(RESULT_DIR, "e9_storage.csv")
    rows = write_csv(path, rows, PROVENANCE)
    print(f"\n  ✓ Saved {len(rows)} rows → {path}")
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  E10: Security-path boundary table
# ═══════════════════════════════════════════════════════════════════════════

def run_e10_architecture_boundary():
    """E10: Position this work against PQ-TLS, payload E2E, and PQ authentication.

    This is a deterministic claim-map table rather than a benchmark. It keeps the
    paper's comparison honest: channel or payload confidentiality mechanisms are
    complementary to, not replacements for, transferable offline audit evidence.
    """
    print("=" * 70)
    print("E10: Security-Path Boundary Table")
    print("=" * 70)

    rows = [
        {
            "path_id": "CLASSICAL_TLS_MQTT",
            "path_name": "Classical MQTT over TLS",
            "layer": "transport",
            "representative_stack": "MQTT plus classical TLS",
            "quantum_resistance_scope": "classical_only",
            "client_broker_confidentiality": True,
            "broker_subscriber_confidentiality": True,
            "payload_hidden_from_broker": False,
            "client_identity_authentication": "deployment_dependent",
            "message_content_integrity": "per_hop_tls_record_integrity",
            "transferable_offline_evidence": False,
            "broker_mutation_detection": "not_inherent_after_broker_termination",
            "broker_mutation_attribution": "not_inherent",
            "qos_bounded_attribution": False,
            "audit_verifier_online_dependency": "endpoint_or_broker_logs_required",
            "online_cost_location": "TLS handshake and record protection",
            "deferred_evidence_cost_location": "none",
            "composable_with_payload_encryption": True,
            "measured_in_this_work": False,
            "paper_role": "channel_security_baseline",
            "claim_boundary": "protects links but does not create broker-independent offline evidence",
        },
        {
            "path_id": "PQ_HYBRID_TLS_MQTT",
            "path_name": "Post-quantum or hybrid MQTT over TLS",
            "layer": "transport",
            "representative_stack": "MQTT plus TLS with ML-KEM or hybrid key exchange",
            "quantum_resistance_scope": "channel_handshake",
            "client_broker_confidentiality": True,
            "broker_subscriber_confidentiality": True,
            "payload_hidden_from_broker": False,
            "client_identity_authentication": "deployment_dependent",
            "message_content_integrity": "per_hop_tls_record_integrity",
            "transferable_offline_evidence": False,
            "broker_mutation_detection": "not_inherent_after_broker_termination",
            "broker_mutation_attribution": "not_inherent",
            "qos_bounded_attribution": False,
            "audit_verifier_online_dependency": "endpoint_or_broker_logs_required",
            "online_cost_location": "larger TLS handshake objects plus record protection",
            "deferred_evidence_cost_location": "none",
            "composable_with_payload_encryption": True,
            "measured_in_this_work": False,
            "paper_role": "near_neighbor_channel_security",
            "claim_boundary": "addresses harvest-now-decrypt-later for links but leaves broker-visible plaintext and no transferable audit package",
        },
        {
            "path_id": "PQ_E2E_PAYLOAD_ENCRYPTION",
            "path_name": "Application-layer PQ end-to-end payload encryption",
            "layer": "payload",
            "representative_stack": "ML-KEM key establishment plus AEAD or MAC over MQTT payload",
            "quantum_resistance_scope": "publisher_subscriber_payload_keying",
            "client_broker_confidentiality": False,
            "broker_subscriber_confidentiality": False,
            "payload_hidden_from_broker": True,
            "client_identity_authentication": "endpoint_key_dependent",
            "message_content_integrity": "end_to_end_payload_integrity",
            "transferable_offline_evidence": False,
            "broker_mutation_detection": "receiver_can_reject_invalid_payloads",
            "broker_mutation_attribution": "not_inherent",
            "qos_bounded_attribution": False,
            "audit_verifier_online_dependency": "endpoint_keys_or_endpoint_logs_required",
            "online_cost_location": "payload encryption plus key establishment",
            "deferred_evidence_cost_location": "none",
            "composable_with_payload_encryption": True,
            "measured_in_this_work": False,
            "paper_role": "confidentiality_complement",
            "claim_boundary": "hides payload from the broker but does not by itself give a third-party verifier a portable evidence object",
        },
        {
            "path_id": "PQ_CONNECT_AUTH",
            "path_name": "Post-quantum MQTT CONNECT authentication",
            "layer": "authentication",
            "representative_stack": "ML-DSA client authentication during connection setup",
            "quantum_resistance_scope": "client_identity",
            "client_broker_confidentiality": False,
            "broker_subscriber_confidentiality": False,
            "payload_hidden_from_broker": False,
            "client_identity_authentication": "post_quantum_client_signature",
            "message_content_integrity": "not_inherent_for_published_payloads",
            "transferable_offline_evidence": False,
            "broker_mutation_detection": "not_inherent",
            "broker_mutation_attribution": "not_inherent",
            "qos_bounded_attribution": False,
            "audit_verifier_online_dependency": "broker_authentication_decision_required",
            "online_cost_location": "connection authentication",
            "deferred_evidence_cost_location": "none",
            "composable_with_payload_encryption": True,
            "measured_in_this_work": False,
            "paper_role": "identity_security_neighbor",
            "claim_boundary": "authenticates a client session but does not bind later broker-presented history",
        },
        {
            "path_id": "A2_SESSION_MAC_ONLY",
            "path_name": "ML-KEM-derived session MAC only",
            "layer": "application_session",
            "representative_stack": "ML-KEM-768 plus HMAC on records, no checkpoint",
            "quantum_resistance_scope": "session_key_establishment",
            "client_broker_confidentiality": False,
            "broker_subscriber_confidentiality": False,
            "payload_hidden_from_broker": False,
            "client_identity_authentication": "session_key_dependent",
            "message_content_integrity": "shared_secret_record_mac",
            "transferable_offline_evidence": False,
            "broker_mutation_detection": "endpoint_can_detect_without_public_transferability",
            "broker_mutation_attribution": "not_inherent",
            "qos_bounded_attribution": False,
            "audit_verifier_online_dependency": "shared_secret_or_endpoint_logs_required",
            "online_cost_location": "per-record MAC",
            "deferred_evidence_cost_location": "none",
            "composable_with_payload_encryption": True,
            "measured_in_this_work": True,
            "paper_role": "session_integrity_control",
            "claim_boundary": "shows why session authentication alone is insufficient for transferable offline audit",
        },
        {
            "path_id": "A4_MERKLE_CHECKPOINT",
            "path_name": "Merkle plus ML-DSA checkpoint evidence",
            "layer": "audit_evidence",
            "representative_stack": "ML-KEM-768 session plus Merkle checkpoint signed with ML-DSA-65",
            "quantum_resistance_scope": "audit_checkpoint_signature",
            "client_broker_confidentiality": False,
            "broker_subscriber_confidentiality": False,
            "payload_hidden_from_broker": False,
            "client_identity_authentication": "checkpoint_signer_key",
            "message_content_integrity": "record_commitment_plus_checkpoint_signature",
            "transferable_offline_evidence": True,
            "broker_mutation_detection": "offline_verifier_detects_presented-record_and_checkpointed-history_mutations",
            "broker_mutation_attribution": "bounded_by_mqtt_qos_semantics",
            "qos_bounded_attribution": True,
            "audit_verifier_online_dependency": "offline_after_evidence_package_delivery",
            "online_cost_location": "record commitment updates and deferred checkpoint signing",
            "deferred_evidence_cost_location": "ML-DSA-65 checkpoint plus Merkle proofs",
            "composable_with_payload_encryption": True,
            "measured_in_this_work": True,
            "paper_role": "core_transferable_audit_design",
            "claim_boundary": "characterizes broker mutation evidence while leaving confidentiality to composable channel or payload mechanisms",
        },
        {
            "path_id": "A6_WITNESSED_MERKLE_CHECKPOINT",
            "path_name": "Witnessed Merkle checkpoint evidence",
            "layer": "audit_evidence_freshness",
            "representative_stack": "A4 plus independent ML-DSA-65 witness receipts over checkpoint roots",
            "quantum_resistance_scope": "audit_checkpoint_and_witness_signatures",
            "client_broker_confidentiality": False,
            "broker_subscriber_confidentiality": False,
            "payload_hidden_from_broker": False,
            "client_identity_authentication": "checkpoint_and_witness_keys",
            "message_content_integrity": "record_commitment_checkpoint_signature_and_witness_receipts",
            "transferable_offline_evidence": True,
            "broker_mutation_detection": "offline_verifier_detects_mutation_plus_witness_bounded_rollback_or_split_view_cases",
            "broker_mutation_attribution": "bounded_by_mqtt_qos_semantics_and_witness_freshness_assumptions",
            "qos_bounded_attribution": True,
            "audit_verifier_online_dependency": "offline_after_current_witness_policy_material_is_available",
            "online_cost_location": "record commitment updates plus deferred checkpoint and witness signing",
            "deferred_evidence_cost_location": "ML-DSA-65 checkpoint, Merkle proofs, and witness receipts",
            "composable_with_payload_encryption": True,
            "measured_in_this_work": True,
            "paper_role": "domain_specific_witness_adaptation",
            "claim_boundary": "adapts witnessed checkpoints to MQTT evidence freshness without claiming a new transparency primitive",
        },
    ]

    path = os.path.join(RESULT_DIR, "e10_architecture_boundary.csv")
    rows = write_csv(path, rows, PROVENANCE)
    print(f"\n  ✓ Saved {len(rows)} rows → {path}")
    return rows


# ═══════════════════════════════════════════════════════════════════════════
#  E11: QoS-aware vs QoS-agnostic auditor comparison
# ═══════════════════════════════════════════════════════════════════════════

def run_e11_qos_auditor_comparison(*args, **kwargs):
    """E11 QoS-aware vs QoS-agnostic auditor comparison is derived from the
    same authoritative real-crypto corpus as E7 (one shared corpus per
    package).  The QoS-agnostic auditor only ignores QoS/session context; it
    does not hard-code "all anomalies == broker"."""
    suite = _run_qos_suite_once()
    print(
        f"  E11: {suite['case_count']} shared corpus cases, "
        f"{len(suite['e11_rows'])} aware/agnostic comparison rows"
    )
    return suite["e11_rows"]


# ═══════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="Optimized experiment runner")
    p.add_argument("--exp", type=str, default="all",
                   help="Experiment: E3/E5/E6/E7/E8/E9/E10/E11/E5A5/all")
    p.add_argument("--quick", action="store_true",
                   help="Quick mode: reduced repetitions for testing")
    p.add_argument("--reps", type=int, default=None,
                   help="Override default repetition count")
    p.add_argument("--e3-msgs", type=int, default=None,
                   help="Measured MQTT publishes per E3 arm/QoS/payload cell")
    p.add_argument("--e5-reps", type=int, default=None,
                   help="Independent repetitions per E5 latency cell")
    p.add_argument("--e5-msgs", type=int, default=None,
                   help="Messages per E5 repetition")
    p.add_argument("--e5-qos", default=None,
                   help="Comma-separated QoS values for E5, e.g. 0,1,2")
    p.add_argument("--e6-reps", type=int, default=None,
                   help="Independent burst repetitions per E6 throughput cell")
    p.add_argument("--e6-burst", type=float, default=None,
                   help="Burst duration in seconds for each E6 repetition")
    p.add_argument("--e6-qos", default=None,
                   help="Comma-separated QoS values for E6")
    p.add_argument("--e6-drain-timeout", type=float, default=None,
                   help="Seconds to wait for subscriber drain after each E6 burst")
    p.add_argument("--e6-max-inflight", type=int, default=None,
                   help="Maximum publisher-subscriber backlog allowed during E6 bursts")
    p.add_argument("--e7-reps", type=int, default=None,
                   help="Independent repetitions per E7 attack cell")
    p.add_argument("--e7-msgs", type=int, default=None,
                   help="Source stream records per E7 repetition")
    p.add_argument("--e7-n", type=int, default=None,
                   help="Checkpoint interval for E7")
    p.add_argument("--e8-reps", type=int, default=None,
                   help="Repeated verifier executions per E8 cell")
    p.add_argument("--e8-lifecycle-reps", type=int, default=5,
                   help="Repeated generation/serialization timings per E8 cell (lifecycle raw samples)")
    p.add_argument("--e9-hours", type=float, default=None,
                   help="Simulated storage horizon in hours before daily extrapolation")
    p.add_argument("--e9-max-messages", type=int, default=None,
                   help="Maximum messages materialized per E9 cell before extrapolation")
    p.add_argument("--a6-witness-count", type=int, default=1,
                   help="Independent witness receipts generated by Python A6 arms")
    p.add_argument("--a6-min-receipts", type=int, default=1,
                   help="Minimum A6 witness receipts required by Python verifier experiments")
    p.add_argument("--out-dir", default=None, help="Output directory (or AAPA_RESULT_DIR)")
    args = p.parse_args()

    global PROVENANCE, RESULT_DIR, ENV_ID
    PROVENANCE = init_provenance(
        SOURCE_SCRIPT,
        mode="quick" if args.quick else os.environ.get("AAPA_MODE") or "full",
        out_dir=args.out_dir,
    )
    RESULT_DIR = PROVENANCE.result_dir
    ENV_ID = PROVENANCE.env_id

    print("=" * 70)
    print("OPTIMIZED EXPERIMENT RUNNER")
    print(f"  Mode: {'QUICK (testing only)' if args.quick else 'FULL (protocol-compliant)'}")
    print(f"  Results → {RESULT_DIR}/")
    print("=" * 70)

    def parse_int_list(value, default):
        if value is None:
            return default
        return [int(x.strip()) for x in value.split(",") if x.strip()]

    rep_counts = {
        "E5": args.e5_reps or 40,
        "E6": args.e6_reps or 15,
        "E7": args.e7_reps or 50,
        "E8": args.e8_reps or 200,
        "E5A5": 10,
    }
    e3_msgs = args.e3_msgs or 200
    e5_msgs = args.e5_msgs or 50
    e5_qos = parse_int_list(args.e5_qos, [0, 1, 2])
    e6_burst = args.e6_burst or 8.0
    e6_qos = parse_int_list(args.e6_qos, [0])
    e6_drain_timeout = args.e6_drain_timeout or 5.0
    e6_max_inflight = args.e6_max_inflight or 512
    e7_msgs = args.e7_msgs or 300
    e7_n = args.e7_n or 50
    e9_hours = args.e9_hours or 2.0
    e9_max_messages = args.e9_max_messages or 50000

    if args.quick:
        rep_counts = {k: min(v, 5) for k, v in rep_counts.items()}
        e3_msgs = min(e3_msgs, 20)
        e5_msgs = min(e5_msgs, 50)
        e5_qos = [0]
        e6_burst = min(e6_burst, 2.0)
        e6_drain_timeout = min(e6_drain_timeout, 3.0)
        e6_max_inflight = min(e6_max_inflight, 256)
        e6_qos = [0]
        e7_msgs = min(e7_msgs, 200)
        e9_hours = min(e9_hours, 0.1)
        e9_max_messages = min(e9_max_messages, 10000)
    if args.reps:
        for k in rep_counts:
            rep_counts[k] = args.reps

    experiments = {
        "E3": lambda: run_e3_optimized(
            n_msg=e3_msgs,
            quick=args.quick,
            a6_witness_count=args.a6_witness_count,
        ),
        "E5": lambda: run_e5_optimized(
            n_reps=rep_counts["E5"],
            quick=args.quick,
            n_msg=e5_msgs,
            qos_list=e5_qos,
            a6_witness_count=args.a6_witness_count,
        ),
        "E5A5": lambda: run_e5_a5_coverage(n_reps=rep_counts["E5A5"]),
        "E6": lambda: run_e6_optimized(
            n_reps=rep_counts["E6"],
            quick=args.quick,
            qos_list=e6_qos,
            burst_s=e6_burst,
            drain_timeout_s=e6_drain_timeout,
            max_inflight_messages=e6_max_inflight,
            a6_witness_count=args.a6_witness_count,
        ),
        "E7": lambda: run_e7_optimized(
            n_reps=rep_counts["E7"],
            n_msg=e7_msgs,
            N=e7_n,
            quick=args.quick,
            a6_witness_count=args.a6_witness_count,
        ),
        "E8": lambda: run_e8_optimized(
            n_reps=rep_counts["E8"],
            quick=args.quick,
            a6_witness_count=args.a6_witness_count,
            a6_min_receipts=args.a6_min_receipts,
            lifecycle_reps=args.e8_lifecycle_reps,
        ),
        "E9": lambda: run_e9_optimized(
            quick=args.quick,
            sim_hours=e9_hours,
            max_messages=e9_max_messages,
            a6_witness_count=args.a6_witness_count,
        ),
        "E10": run_e10_architecture_boundary,
        "E11": lambda: run_e11_qos_auditor_comparison(
            n_reps=rep_counts.get("E11", 30),
            n_msg=e7_msgs,
            N=e7_n,
            quick=args.quick,
            a6_witness_count=args.a6_witness_count,
        ),
    }

    main_experiments = ["E3", "E5", "E6", "E7", "E8", "E9", "E10", "E11"]
    exps_to_run = main_experiments if args.exp == "all" else [args.exp]

    failures = []
    for exp_name in exps_to_run:
        if exp_name not in experiments:
            print(f"  Unknown experiment: {exp_name}")
            failures.append(exp_name)
            continue
        print(f"\n{'=' * 70}")
        print(f"  {exp_name}")
        print(f"{'=' * 70}")
        try:
            experiments[exp_name]()
        except Exception as e:
            failures.append(exp_name)
            print(f"  ERROR in {exp_name}: {e}")
            import traceback
            traceback.print_exc()

    if failures:
        raise SystemExit(f"Failed experiment blocks: {', '.join(failures)}")

    print(f"\n{'=' * 70}")
    print("All optimized experiments complete.")
    print(f"Results → {RESULT_DIR}/")
    print(f"{'=' * 70}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
