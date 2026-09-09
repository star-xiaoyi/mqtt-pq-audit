#!/usr/bin/env python3
"""
E1: Cryptographic micro-benchmarks (liboqs real execution).
E2: Object sizes (pk/sk/ct/sig).

Measures keygen/encaps/decaps/sign/verify for each primitive,
outputs CSV to experiments/results/.../bench_crypto.csv and object_sizes.csv.

Usage:
    python experiments/python/bench_crypto.py [--runs 100]
"""


import os, time, argparse, statistics
from experiment_paths import add_liboqs_python_to_path

add_liboqs_python_to_path()
import oqs
from provenance import init_provenance, write_csv


# ── Fixed primitives to benchmark (per plan §0) ──────────────────────────
KEMS = [
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
]
SIGS = [
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH_DSA_PURE_SHA2_128F", "SLH_DSA_PURE_SHA2_128S",
    "SLH_DSA_PURE_SHA2_192F", "SLH_DSA_PURE_SHA2_256F",
    "Falcon-512", "Falcon-1024",
]
# Classical reference (via Python cryptography, not liboqs)
CLASSICAL = ["Ed25519", "X25519"]

SOURCE_SCRIPT = "python/bench_crypto.py"
PROVENANCE = init_provenance(SOURCE_SCRIPT, create_dir=False)
RESULT_DIR = PROVENANCE.result_dir


def time_op(func, runs=100, warmup=5):
    """Time a callable, return (mean_ms, median_ms, p95_ms, stdev_ms)."""
    for _ in range(warmup):
        func()
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        func()
        times.append((time.perf_counter() - t0) * 1000)  # ms
    return {
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        
        "p95_ms": _p95(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0.0,
        "n_runs": runs,
    }


def _p95(data):
    data_sorted = sorted(data)
    idx = int(len(data_sorted) * 0.95)
    return data_sorted[min(idx, len(data_sorted) - 1)]


def bench_kem(alg, runs=100):
    """Benchmark a KEM: keygen, encaps, decaps."""
    results = {"primitive": alg, "n_runs": runs}
    with oqs.KeyEncapsulation(alg) as kem:
        # keygen
        pk = None
        def do_keygen():
            nonlocal pk
            pk = kem.generate_keypair()
        r = time_op(do_keygen, runs)
        results.update({f"keygen_{k}": v for k, v in r.items()})

        # encaps
        ct, ss = None, None
        def do_encaps():
            nonlocal ct, ss
            ct, ss = kem.encap_secret(pk)
        r = time_op(do_encaps, runs)
        results.update({f"encaps_{k}": v for k, v in r.items()})

        # decaps
        def do_decaps():
            kem.decap_secret(ct)
        r = time_op(do_decaps, runs)
        results.update({f"decaps_{k}": v for k, v in r.items()})
    return results


def bench_sig(alg, runs=100):
    """Benchmark a signature scheme: keygen, sign, verify."""
    results = {"primitive": alg, "n_runs": runs}
    msg = b"Benchmark message for PQC signature testing."

    with oqs.Signature(alg) as sig:
        # keygen
        pk = None
        def do_keygen():
            nonlocal pk
            pk = sig.generate_keypair()
        r = time_op(do_keygen, runs)
        results.update({f"keygen_{k}": v for k, v in r.items()})

        # sign
        signature = None
        def do_sign():
            nonlocal signature
            signature = sig.sign(msg)
        r = time_op(do_sign, runs)
        results.update({f"sign_{k}": v for k, v in r.items()})

        # verify
        def do_verify():
            sig.verify(msg, signature, pk)
        r = time_op(do_verify, runs)
        results.update({f"verify_{k}": v for k, v in r.items()})
    return results


def classical_bench():
    """Benchmark classical crypto (Ed25519, X25519) via cryptography library."""
    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
    from cryptography.hazmat.primitives import hashes

    results = []
    runs = 100

    # ── Ed25519 ──
    msg = b"Benchmark message for classical crypto."
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    def ed_keygen():
        k = ed25519.Ed25519PrivateKey.generate()
        k.public_key()

    def ed_sign():
        priv.sign(msg)

    signature = priv.sign(msg)
    def ed_verify():
        pub.verify(signature, msg)

    r = time_op(ed_keygen, runs)
    results.append({"primitive": "Ed25519", **{f"keygen_{k}": v for k, v in r.items()}})
    r = time_op(ed_sign, runs)
    results[-1].update({f"sign_{k}": v for k, v in r.items()})
    r = time_op(ed_verify, runs)
    results[-1].update({f"verify_{k}": v for k, v in r.items()})

    # ── X25519 ──
    def x_keygen():
        k = x25519.X25519PrivateKey.generate()
        k.public_key()

    alice_priv = x25519.X25519PrivateKey.generate()
    alice_pub = alice_priv.public_key()
    bob_priv = x25519.X25519PrivateKey.generate()
    bob_pub = bob_priv.public_key()

    def x_encaps():
        bob_priv.exchange(alice_pub)

    def x_decaps():
        alice_priv.exchange(bob_pub)

    r = time_op(x_keygen, runs)
    results.append({"primitive": "X25519", **{f"keygen_{k}": v for k, v in r.items()}})
    r = time_op(x_encaps, runs)
    results[-1].update({f"encaps_{k}": v for k, v in r.items()})
    r = time_op(x_decaps, runs)
    results[-1].update({f"decaps_{k}": v for k, v in r.items()})

    return results


def get_object_sizes():
    """E2: Measure actual pk/sk/ct/sig byte sizes."""
    rows = []

    for alg in KEMS:
        with oqs.KeyEncapsulation(alg) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            ct, ss = kem.encap_secret(pk)
            rows.append({
                "primitive": alg,
                "category": "KEM",
                "pk_bytes": len(pk),
                "sk_bytes": len(sk),
                "ct_bytes": len(ct),
                "ss_bytes": len(ss),
            })

    for alg in SIGS:
        with oqs.Signature(alg) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
            sig_bytes = sig.sign(b"size test")
            rows.append({
                "primitive": alg,
                "category": "SIG",
                "pk_bytes": len(pk),
                "sk_bytes": len(sk),
                "sig_bytes": len(sig_bytes),
            })

    # Classical
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    rows.append({
        "primitive": "Ed25519", "category": "SIG",
        "pk_bytes": 32, "sk_bytes": 32,
        "sig_bytes": len(ed_priv.sign(b"test")),
    })
    x_priv = x25519.X25519PrivateKey.generate()
    rows.append({
        "primitive": "X25519", "category": "KEM",
        "pk_bytes": 32, "sk_bytes": 32,
        "ct_bytes": 32, "ss_bytes": 32,
    })
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=100, help="Repetitions per benchmark")
    parser.add_argument("--sizes-only", action="store_true", help="Only output object sizes (E2)")
    parser.add_argument("--bench-only", action="store_true", help="Only output benchmarks (E1)")
    parser.add_argument("--out-dir", default=None, help="Output directory (or AAPA_RESULT_DIR)")
    args = parser.parse_args()

    global PROVENANCE, RESULT_DIR
    PROVENANCE = init_provenance(SOURCE_SCRIPT, out_dir=args.out_dir)
    RESULT_DIR = PROVENANCE.result_dir

    print("=" * 60)
    print("E1 & E2: Cryptographic Benchmarks & Object Sizes")
    print("=" * 60)

    if not args.sizes_only:
        # ── E1: Micro-benchmarks ──
        print(f"\n[E1] Micro-benchmarks ({args.runs} runs each)...")
        bench_rows = []

        for alg in KEMS:
            print(f"  KEM: {alg}...", end=" ", flush=True)
            row = bench_kem(alg, args.runs)
            bench_rows.append(row)
            print(f"keygen={row['keygen_mean_ms']:.4f}ms, encaps={row['encaps_mean_ms']:.4f}ms")

        for alg in SIGS:
            print(f"  SIG: {alg}...", end=" ", flush=True)
            row = bench_sig(alg, args.runs)
            bench_rows.append(row)
            print(f"keygen={row.get('keygen_mean_ms', 'N/A'):.4f}ms, sign={row.get('sign_mean_ms', 'N/A'):.4f}ms")

        print("  Classical...", end=" ", flush=True)
        bench_rows.extend(classical_bench())
        print("done")

        # Write E1 CSV
        e1_path = os.path.join(RESULT_DIR, "bench_crypto.csv")
        if bench_rows:
            bench_rows = write_csv(e1_path, bench_rows, PROVENANCE)
            print(f"\n[E1] Saved {len(bench_rows)} rows → {e1_path}")

    if not args.bench_only:
        # ── E2: Object sizes ──
        print(f"\n[E2] Object sizes...")
        size_rows = get_object_sizes()
        e2_path = os.path.join(RESULT_DIR, "object_sizes.csv")
        if size_rows:
            size_rows = write_csv(e2_path, size_rows, PROVENANCE)
            print(f"[E2] Saved {len(size_rows)} rows → {e2_path}")
            for r in size_rows:
                if r["category"] == "SIG":
                    print(f"  {r['primitive']}: pk={r['pk_bytes']}B, sig={r.get('sig_bytes','?')}B")
                else:
                    print(f"  {r['primitive']}: pk={r['pk_bytes']}B, ct={r.get('ct_bytes','?')}B")

    print("\nDone.")


if __name__ == "__main__":
    main()
