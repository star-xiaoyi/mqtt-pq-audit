#!/usr/bin/env python3
"""Cross-validation guard for the Python and C++ experiment implementations.

The two toolchains share the same audit primitives (record serialization,
Merkle tree, hash chain, checkpoint, witness receipt). If they ever drift, the
evidence-size numbers and verification semantics reported by each side stop
being comparable and the paper's cross-language claim collapses.

This script freezes one canonical input and asserts that both implementations
produce byte-identical deterministic outputs plus identical primitive sizes:

  - Python: exercises the *real* classes in ``python/aapa_mqtt.py`` (not a copy).
  - C++:    runs ``cpp/build/aapa_crypto_bench --selftest`` (a known-answer mode).

Only deterministic quantities are compared -- hashes of serialized structures,
Merkle roots (even and odd leaf counts), the hash-chain head, a checkpoint and
witness-body digest, an inclusion-proof outcome, and fixed liboqs object sizes.
No timings and no randomized signatures are compared, so a green result means
the shared logic is provably identical, and a red result points at the exact
field that diverged.

Exit codes: 0 = all fields match, 1 = mismatch, 2 = setup/build error.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent
PY_DIR = EXPERIMENTS / "python"
CPP_DIR = EXPERIMENTS / "cpp"
CPP_BUILD = CPP_DIR / "build"
CPP_BIN = CPP_BUILD / "aapa_crypto_bench"

sys.path.insert(0, str(PY_DIR))
from experiment_paths import add_liboqs_python_to_path  # noqa: E402

add_liboqs_python_to_path()
import oqs  # noqa: E402
from aapa_mqtt import (  # noqa: E402
    Checkpoint,
    HashChain,
    MerkleTree,
    Record,
    WitnessReceipt,
)
from stream_identity import canonical_stream_id  # noqa: E402

# ── Canonical known-answer input (must match run_selftest() in the C++) ──────
TOPIC = "aapa/xcheck/telemetry"
CLIENT_ID = "publisher-001"
PAYLOAD_BYTES = 64
N = 8
CHAIN_SEED = bytes([0x2A] * 32)
ZERO32 = bytes(32)
EPOCH = 7
TS_BASE = 1700000000.0
TS_CKPT = 1700000042.5
TS_WITNESS = 1700000043.0


def payload_pattern(size: int, seq: int) -> bytes:
    """Byte j = (seq + j) & 0xff -- identical to payload_pattern() in the C++."""
    return bytes((seq + j) & 0xFF for j in range(size))


def python_kat() -> dict:
    """Compute the known-answer vector using the real Python implementation."""
    ser = [
        Record(
            seq=i + 1,
            ts=TS_BASE + i * 0.5,
            topic=TOPIC,
            payload=payload_pattern(PAYLOAD_BYTES, i + 1),
        ).serialize()
        for i in range(N)
    ]

    tree8 = MerkleTree()
    for s in ser:
        tree8.append(s)
    root8 = tree8.build()

    tree5 = MerkleTree()
    for s in ser[:5]:
        tree5.append(s)
    root5 = tree5.build()

    chain = HashChain(CHAIN_SEED)
    for s in ser:
        chain.append(s)

    ckpt = Checkpoint(
        client_id=CLIENT_ID,
        topic=TOPIC,
        epoch=EPOCH,
        seq_start=1,
        seq_end=N,
        prev_anchor=ZERO32,
        end_anchor=root8,
        ts_ckpt=TS_CKPT,
    )

    wr = WitnessReceipt(
        witness_id="witness-1",
        stream_id=canonical_stream_id(CLIENT_ID, TOPIC),
        checkpoint_epoch=EPOCH,
        seq_start=1,
        seq_end=N,
        prev_witnessed_anchor=ZERO32,
        checkpoint_anchor=root8,
        ts_witness=TS_WITNESS,
    )

    proof3 = tree8.get_proof(3)
    leaf3 = hashlib.sha256(MerkleTree.LEAF_PREFIX + ser[3]).digest()
    verify3 = MerkleTree.verify_proof(leaf3, proof3, root8)

    with oqs.Signature("ML-DSA-65") as sig:
        sig_pk = sig.generate_keypair()
        sig_sk = sig.export_secret_key()
        sig_bytes = sig.sign(b"size probe")
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        kem_pk = kem.generate_keypair()
        kem_sk = kem.export_secret_key()
        kem_ct, kem_ss = kem.encap_secret(kem_pk)

    return {
        "record0_ser_sha256": hashlib.sha256(ser[0]).hexdigest(),
        "merkle_root_8": root8.hex(),
        "merkle_root_5": root5.hex(),
        "chain_head_8": chain.head.hex(),
        "checkpoint_ser_sha256": hashlib.sha256(ckpt.serialize()).hexdigest(),
        "witness_body_sha256": hashlib.sha256(wr.serialize()).hexdigest(),
        "merkle_proof_leaf3_verify": bool(verify3),
        "merkle_proof_leaf3_steps": len(proof3),
        "ml_dsa_65_sig_bytes": len(sig_bytes),
        "ml_dsa_65_pk_bytes": len(sig_pk),
        "ml_dsa_65_sk_bytes": len(sig_sk),
        "ml_kem_768_pk_bytes": len(kem_pk),
        "ml_kem_768_sk_bytes": len(kem_sk),
        "ml_kem_768_ct_bytes": len(kem_ct),
        "ml_kem_768_ss_bytes": len(kem_ss),
    }


def ensure_binary() -> bool:
    """Build the C++ runner when missing or older than its source/configuration."""
    inputs = [CPP_DIR / "aapa_crypto_bench.cpp", CPP_DIR / "CMakeLists.txt"]
    binary_fresh = (
        CPP_BIN.exists()
        and all(CPP_BIN.stat().st_mtime_ns >= path.stat().st_mtime_ns for path in inputs)
    )
    if binary_fresh:
        return True
    reason = "missing" if not CPP_BIN.exists() else "stale"
    print(f"[crosscheck] C++ binary {reason}, configuring + building: {CPP_BIN}")
    try:
        subprocess.run(
            ["cmake", "-S", str(CPP_DIR), "-B", str(CPP_BUILD),
             "-DCMAKE_BUILD_TYPE=Release"],
            check=True,
        )
        subprocess.run(["cmake", "--build", str(CPP_BUILD), "-j"], check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"[crosscheck] build failed: {exc}")
        return False
    return CPP_BIN.exists()


def cpp_kat() -> dict:
    """Run the C++ known-answer mode and parse its JSON line."""
    proc = subprocess.run(
        [str(CPP_BIN), "--selftest"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"C++ --selftest exited {proc.returncode}:\n{proc.stderr}")
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError(f"C++ --selftest produced no output:\n{proc.stderr}")
    return json.loads(lines[-1])


def _fmt(value: object) -> str:
    text = str(value)
    return text if len(text) <= 20 else text[:17] + "..."


def main() -> int:
    if not ensure_binary():
        print("[crosscheck] cannot obtain C++ binary; build it manually:")
        print("    cmake -S experiments/cpp -B experiments/cpp/build "
              "-DCMAKE_BUILD_TYPE=Release")
        print("    cmake --build experiments/cpp/build -j")
        return 2

    try:
        cpp = cpp_kat()
    except (RuntimeError, json.JSONDecodeError) as exc:
        print(f"[crosscheck] {exc}")
        return 2

    py = python_kat()

    field_w = max(len(k) for k in py)
    print(f"liboqs (python-side): {oqs.oqs_version()}")
    print(f"{'field':<{field_w}}  {'python':<20}  {'cpp':<20}  match")
    print("-" * (field_w + 50))

    all_ok = True
    for key in py:
        pv = py[key]
        cv = cpp.get(key, "<missing>")
        ok = cv == pv
        all_ok &= ok
        flag = "ok" if ok else "MISMATCH"
        print(f"{key:<{field_w}}  {_fmt(pv):<20}  {_fmt(cv):<20}  {flag}")
        if not ok:
            print(f"    python: {pv}")
            print(f"    cpp   : {cv}")

    print("-" * (field_w + 50))
    if all_ok:
        print("RESULT: PASS -- Python and C++ implementations are byte-identical.")
        return 0
    print("RESULT: FAIL -- implementations diverged (see MISMATCH rows above).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
