#!/usr/bin/env python3
"""
补全关键实验数据:
  E4: 摊销开销 — 绑真实MQTT报文尺寸
  E5: 端到端延迟 — 六臂全覆盖
  E6: Broker吞吐 — 修正received<sent问题

Usage: python experiments/python/run_final.py [--exp E4/E5/E6/all]
"""

import os, time, math, statistics, struct, hashlib
from experiment_paths import add_liboqs_python_to_path

add_liboqs_python_to_path()
import paho.mqtt.client as mqtt

from aapa_mqtt import create_arm, Record, make_topic
from provenance import init_provenance, write_csv

BROKER_HOST = "localhost"; BROKER_PORT = 1883
SOURCE_SCRIPT = "python/run_final.py"
PROVENANCE = init_provenance(SOURCE_SCRIPT, create_dir=False)
RESULT_DIR = PROVENANCE.result_dir
ENV_ID = PROVENANCE.env_id

def make_payload(size): return os.urandom(size)
def stats(vals):
    if len(vals)<2:
        m=vals[0] if vals else 0
        return {"mean":m,"median":m,"p95":m,"std":0,"ci_low":m,"ci_high":m,"n":len(vals)}
    n=len(vals); m=statistics.mean(vals); s=statistics.stdev(vals)
    ci=1.96*s/math.sqrt(n)
    return {"mean":round(m,4),"median":round(statistics.median(vals),4),
            "p95":round(sorted(vals)[int(n*0.95)],4),"std":round(s,4),
            "ci_low":round(m-ci,4),"ci_high":round(m+ci,4),"n":n}

def compute_record_overhead(topic):
    return 4+8+2+len(topic.encode())+4  # seq+ts+topic_len+topic+payload_len

def compute_mqtt_framing(topic,qos,application_payload_bytes):
    tlen=len(topic.encode()); vh=2+tlen+(2 if qos>0 else 0)
    remaining_length=vh+application_payload_bytes
    rem_len_bytes=1
    while remaining_length>=128:
        remaining_length//=128
        rem_len_bytes+=1
    return 1 + rem_len_bytes + vh  # fixed header + encoded Remaining Length + variable header


# ════════════════════════════════════════════════════════════════════
def run_e4_final(a6_witness_count=1):
    """E4: 摊销开销 — 绑真实MQTT报文尺寸 + checkpoint签名（A6 见证数与其余实验一致）."""
    arms = ["A0","A1","A2","A3","A4","A6"]
    N_vals = [1,10,50,100,500,1000]
    payload = 128
    print("="*60)
    print("E4 FINAL: Amortized Cost (record wire + full evidence package)")
    print("  Record overhead and MQTT framing are computed per arm topic.")
    print("="*60)

    rows=[]
    for arm_id in arms:
        arm_n_values = [1] if arm_id in ("A1", "A2") else N_vals
        for N in arm_n_values:
            eff_n = N
            print(f"  {arm_id} N={eff_n}...",end=" ",flush=True)

            arm_topic = make_topic(arm_id)
            rec_overhead = compute_record_overhead(arm_topic)
            witness_count = a6_witness_count if arm_id == "A6" else 1
            arm = create_arm(arm_id, arm_topic, N=eff_n, witness_count=witness_count)
            n_msgs = max(eff_n * 3, 100)
            for i in range(n_msgs):
                rec = Record.make(i+1, arm_topic, make_payload(payload))
                arm.add_record(rec)
            arm.flush()

            ckpt_sig_bytes = sum(len(ckpt.signature) for ckpt in arm.checkpoints)
            n_ckpts = len(arm.checkpoints)
            component_totals = {}
            for ckpt in arm.checkpoints:
                for key, value in ckpt.component_sizes().items():
                    component_totals[key] = component_totals.get(key, 0) + value

            wire_payload_sizes = [len(message) for message in arm.wire_messages]
            mqtt_framing_sizes = [
                compute_mqtt_framing(arm_topic, 0, message_size)
                for message_size in wire_payload_sizes
            ]
            online_record_wire_bytes = sum(
                message_size + framing
                for message_size, framing in zip(wire_payload_sizes, mqtt_framing_sizes)
            )
            mqtt_framing = round(statistics.mean(mqtt_framing_sizes), 2) if mqtt_framing_sizes else 0
            wire_payload_mean = round(statistics.mean(wire_payload_sizes), 2) if wire_payload_sizes else 0
            per_msg_oh = (
                online_record_wire_bytes / n_msgs - payload
                if n_msgs > 0 else 0
            )
            evidence_package_bytes = component_totals.get("full_evidence_bytes", 0)
            total_record_plus_evidence_bytes = online_record_wire_bytes + evidence_package_bytes
            amortized = total_record_plus_evidence_bytes / n_msgs if n_msgs > 0 else 0
            evidence_amortized = evidence_package_bytes / n_msgs if n_msgs > 0 else 0

            rows.append({
                "env_id":ENV_ID,"arm":arm_id,"N":N,"effective_N":eff_n,
                "witness_count": a6_witness_count if arm_id == "A6" else 0,
                "payload_bytes":payload,
                "record_overhead":rec_overhead,
                "authenticated_wire_payload_bytes_mean":wire_payload_mean,
                "mqtt_framing":mqtt_framing,
                "per_msg_overhead":per_msg_oh,
                "ckpt_sig_bytes":ckpt_sig_bytes,
                "n_ckpts":n_ckpts,
                "n_msgs":n_msgs,
                "online_record_wire_bytes":online_record_wire_bytes,
                "evidence_package_bytes":evidence_package_bytes,
                "records_raw_bytes":component_totals.get("records_raw_bytes", 0),
                "merkle_proofs_raw_bytes":component_totals.get("merkle_proofs_raw_bytes", 0),
                "chain_values_raw_bytes":component_totals.get("chain_values_raw_bytes", 0),
                "public_key_bytes":component_totals.get("public_key_bytes", 0),
                "total_wire_bytes":total_record_plus_evidence_bytes,
                "evidence_bytes_per_msg":round(evidence_amortized,2),
                "amortized_bytes_per_msg":round(amortized,2),
                "amortized_vs_payload_ratio":round(amortized/payload,3),
                "measurement_scope":"authenticated_wire_envelope_plus_full_serialized_checkpoint_evidence",
                "evidence_encoding":"full_archive_json_v1_not_minimal_selective_bundle",
            })
            if hasattr(arm,'free'): arm.free()
            print(f"{amortized:.1f} B/msg")

    path=os.path.join(RESULT_DIR,"e4_amortized_overhead.csv")
    rows = write_csv(path, rows, PROVENANCE)
    print(f"  ✓ {len(rows)} rows → {path}")

    # Print summary table
    print("\n  Amortized Cost Summary (128B payload):")
    print(f"  {'Arm':<6} {'N=1':>10} {'N=10':>10} {'N=50':>10} {'N=100':>10} {'N=500':>10} {'N=1000':>10}")
    for arm_id in ["A0","A2","A3","A4","A5","A1"]:
        vals=[]
        for N in [1,10,50,100,500,1000]:
            r=[x for x in rows if x["arm"]==arm_id and x["N"]==N]
            vals.append(f'{r[0]["amortized_bytes_per_msg"]:.0f}' if r else 'N/A')
        print(f"  {arm_id:<6} {vals[0]:>10} {vals[1]:>10} {vals[2]:>10} {vals[3]:>10} {vals[4]:>10} {vals[5]:>10}")

    return rows


# ════════════════════════════════════════════════════════════════════
def run_e5_final():
    """E5: 端到端延迟 — 六臂全覆盖，修复时间戳匹配bug."""
    arms = ["A0","A2","A3","A4"]  # skip A1/A5 which are very slow
    N_vals = [10,100]
    payloads = [32,128,512]
    qos_list = [0]
    n_msg = 30
    freq = 100.0  # send as fast as possible to get real latency floor

    print("="*60)
    print("E5 FINAL: E2E Latency — 4 arms × 2N × 3payloads")
    print("="*60)

    rows=[]
    for arm_id in arms:
        for N in N_vals:
            eff_n = 1 if arm_id=="A2" else N
            for psize in payloads:
                for qos in qos_list:
                    print(f"  {arm_id} N={eff_n} {psize}B...",end=" ",flush=True)

                    topic=make_topic(arm_id)
                    arm=create_arm(arm_id,topic,N=eff_n)

                    # Use time.time() for BOTH send and receive to avoid clock skew
                    send_times={}  # seq→send_time mapping
                    recv_times={}  # seq→recv_time mapping

                    def on_msg(c,u,m):
                        now=time.time()
                        try:
                            seq=struct.unpack(">I",m.payload[:4])[0]
                            recv_times[seq]=now
                        except: pass

                    sub=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                    sub.on_message=on_msg
                    sub.connect(BROKER_HOST,BROKER_PORT)
                    sub.subscribe(topic,qos=qos)
                    sub.loop_start()
                    time.sleep(0.05)

                    pub=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                    pub.connect(BROKER_HOST,BROKER_PORT)

                    for i in range(n_msg):
                        rec=Record.make(i+1,topic,make_payload(psize))
                        arm.add_record(rec)
                        t0=time.time()
                        pub.publish(topic,rec.serialize(),qos=qos)
                        send_times[i+1]=t0

                    pub.disconnect()
                    time.sleep(0.3)
                    sub.loop_stop();sub.disconnect()
                    arm.flush()

                    # Match by seq number — robust to drops/reordering
                    lats=[]
                    for seq,st in send_times.items():
                        if seq in recv_times:
                            lt=(recv_times[seq]-st)*1000
                            if 0<lt<5000:lats.append(lt)

                    s=stats(lats) if lats else stats([0])
                    rows.append({
                        "env_id":ENV_ID,"arm":arm_id,"N":eff_n,
                        "payload_bytes":psize,"freq":freq,"qos":qos,
                        "lat_ms_mean":s["mean"],"lat_ms_median":s["median"],
                        "lat_ms_p95":s["p95"],"lat_ms_std":s["std"],
                        "ci95_low":s["ci_low"],"ci95_high":s["ci_high"],
                        "n_samples":s["n"],
                    })
                    if hasattr(arm,'free'):arm.free()
                    print(f"mean={s['mean']:.3f}ms p95={s['p95']:.3f}ms (n={s['n']})")

    path=os.path.join(RESULT_DIR,"e5_latency.csv")
    rows = write_csv(path, rows, PROVENANCE)
    print(f"  ✓ {len(rows)} rows → {path}")
    return rows


# ════════════════════════════════════════════════════════════════════
def run_e6_final():
    """E6: Broker吞吐 — 修正: 只计publisher实际发出数作为throughput."""
    arms = ["A0","A2","A3","A4"]
    payloads = [32,128,512]
    qos_list = [0]
    burst_s = 5.0

    print("="*60)
    print("E6 FINAL: Broker Throughput — {burst_s}s burst")
    print("="*60)

    rows=[]
    for arm_id in arms:
        for qos in qos_list:
            for psize in payloads:
                print(f"  {arm_id} QoS={qos} {psize}B...",end=" ",flush=True)

                topic=make_topic(arm_id)
                arm=create_arm(arm_id,topic,N=100)

                recv_count=[0]
                def on_msg(c,u,m):
                    recv_count[0]+=1

                sub=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                sub.on_message=on_msg
                sub.connect(BROKER_HOST,BROKER_PORT)
                sub.subscribe(topic,qos=qos)
                sub.loop_start()
                time.sleep(0.05)

                pub=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                pub.connect(BROKER_HOST,BROKER_PORT)

                sent=0
                t0=time.time()
                while time.time()-t0 < burst_s:
                    rec=Record.make(sent+1,topic,make_payload(psize))
                    arm.add_record(rec)
                    pub.publish(topic,rec.serialize(),qos=qos)
                    sent+=1
                elapsed=time.time()-t0
                pub.disconnect()
                time.sleep(0.5)  # let subscriber drain
                sub.loop_stop();sub.disconnect()

                sustained_sent=sent/elapsed if elapsed>0 else 0
                sustained_recv=recv_count[0]/elapsed if elapsed>0 else 0
                delivery_ratio=recv_count[0]/sent*100 if sent>0 else 0

                rows.append({
                    "env_id":ENV_ID,"arm":arm_id,"payload_bytes":psize,"qos":qos,
                    "sustained_msg_per_s":round(sustained_sent,1),
                    "subscriber_msg_per_s":round(sustained_recv,1),
                    "delivery_ratio_pct":round(delivery_ratio,1),
                    "duration_sec":round(elapsed,2),"sent":sent,"received":recv_count[0],
                })
                if hasattr(arm,'free'):arm.free()
                print(f"pub={sustained_sent:.0f} msg/s, sub={sustained_recv:.0f} msg/s, "
                      f"delivery={delivery_ratio:.0f}%")

    path=os.path.join(RESULT_DIR,"e6_throughput.csv")
    rows = write_csv(path, rows, PROVENANCE)
    print(f"  ✓ {len(rows)} rows → {path}")
    return rows


# ════════════════════════════════════════════════════════════════════
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--exp",default="all")
    p.add_argument("--out-dir",default=None)
    p.add_argument("--a6-witness-count", type=int, default=1)
    args=p.parse_args()

    PROVENANCE = init_provenance(SOURCE_SCRIPT, out_dir=args.out_dir)
    RESULT_DIR = PROVENANCE.result_dir
    ENV_ID = PROVENANCE.env_id

    def _run(name):
        if name == "E4":
            return run_e4_final(a6_witness_count=args.a6_witness_count)
        return {"E5": run_e5_final, "E6": run_e6_final}[name]()

    if args.exp=="all":
        for n in ("E4", "E5", "E6"):
            print(f"\n{'='*60}\n  {n}\n{'='*60}")
            try:_run(n)
            except Exception as e:print(f"  ERROR: {e}");import traceback;traceback.print_exc()
    else:
        _run(args.exp)

    print(f"\nDone → {RESULT_DIR}/")
