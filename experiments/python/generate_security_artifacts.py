#!/usr/bin/env python3
"""Generate independently replayable offline-audit artifacts for one run.

The online arm objects are released before separate auditor processes start.
Those processes receive only versioned evidence bundles, an external trusted
registry, and the explicitly allowed anchor set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from aapa_mqtt import Record, create_arm
from audit_verify import (
    AnchorSet,
    anchors_for_generated_evidence,
    export_offline_audit_artifacts,
)
from provenance import init_provenance
from trusted_registry import TrustedRegistry, registry_for_generated_evidence


SOURCE_SCRIPT = "python/generate_security_artifacts.py"
TRANSFERABLE_ARMS = ("A0", "A1", "A3", "A4", "A6")


def _payload(seed: int, arm_id: str, seq: int, size: int) -> bytes:
    material = hashlib.sha256(f"{seed}:{arm_id}:{seq}".encode("ascii")).digest()
    return (material * ((size + len(material) - 1) // len(material)))[:size]


def _build_arm(
    arm_id: str,
    *,
    seed: int,
    n_records: int,
    checkpoint_interval: int,
    payload_bytes: int,
    witness_count: int,
):
    topic = f"aapa/security/{arm_id.lower()}"
    kwargs: dict[str, Any] = {}
    if arm_id == "A6":
        kwargs["witness_count"] = witness_count
    arm = create_arm(arm_id, topic, N=checkpoint_interval, **kwargs)
    for seq in range(1, n_records + 1):
        arm.add_record(
            Record.make(
                seq,
                topic,
                _payload(seed, arm_id, seq, payload_bytes),
                ts=1_700_000_000.0 + seq,
            )
        )
    arm.flush()
    return arm


def generate(
    result_dir: Path,
    *,
    seed: int,
    n_records: int,
    checkpoint_interval: int,
    payload_bytes: int,
    witness_count: int,
    witness_quorum: int,
) -> dict[str, Any]:
    if n_records < 2 or checkpoint_interval < 1:
        raise ValueError("n_records >= 2 and checkpoint_interval >= 1 are required")
    if witness_quorum < 1 or witness_quorum > witness_count:
        raise ValueError("witness quorum must be within 1..witness_count")

    provenance = init_provenance(SOURCE_SCRIPT, out_dir=str(result_dir), create_dir=False)
    security_dir = result_dir / "security"
    if security_dir.exists():
        raise FileExistsError(f"security artifact directory already exists: {security_dir}")

    arms: dict[str, Any] = {}
    registries: list[TrustedRegistry] = []
    anchor_sets: list[AnchorSet] = []
    streams: dict[str, tuple[str, list[Any]]] = {}
    try:
        for arm_id in TRANSFERABLE_ARMS:
            arm = _build_arm(
                arm_id,
                seed=seed,
                n_records=n_records,
                checkpoint_interval=1 if arm_id == "A1" else checkpoint_interval,
                payload_bytes=payload_bytes,
                witness_count=witness_count,
            )
            arms[arm_id] = arm
            if len(arm.checkpoints) < 2:
                raise RuntimeError(f"{arm_id} did not produce a multi-checkpoint stream")
            registries.append(
                registry_for_generated_evidence(
                    arm.checkpoints,
                    arm_id,
                    witness_quorum=witness_quorum if arm_id == "A6" else None,
                    registry_id=f"run-registry-{arm_id.lower()}",
                )
            )
            anchor_sets.append(
                anchors_for_generated_evidence(
                    arm.checkpoints,
                    observed_at=1_700_000_100.0,
                    anchor_set_id=f"run-anchors-{arm_id.lower()}",
                )
            )
            streams[f"{arm_id.lower()}-clean"] = (arm_id, list(arm.checkpoints))

        a2 = _build_arm(
            "A2",
            seed=seed,
            n_records=n_records,
            checkpoint_interval=checkpoint_interval,
            payload_bytes=payload_bytes,
            witness_count=witness_count,
        )
        arms["A2"] = a2

        registry = TrustedRegistry.combine(registries, registry_id="run-trusted-registry")
        anchors = AnchorSet.combine(anchor_sets, anchor_set_id="run-trusted-anchors")
        exported = export_offline_audit_artifacts(
            security_dir,
            streams,
            registry,
            anchors,
        )
        a2_document = {
            "schema_version": "aapa-session-mac-offline-boundary-v1",
            "arm_id": "A2",
            "audit_evidence_transferable": False,
            "offline_verifiable_without_session_key": False,
            "online_participant_access": False,
            "checkpoint_count": 0,
            "wire_envelope_sample_hex": a2.wire_messages[0].hex(),
            "session_key_exported": False,
            "outcome": "inconclusive",
            "reason_codes": ["SESSION_MAC_NOT_TRANSFERABLE"],
        }
        (security_dir / "a2_session_mac_only.json").write_text(
            json.dumps(a2_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    finally:
        for arm in arms.values():
            if hasattr(arm, "free"):
                arm.free()

    # Re-run every bundle in a separate process after all online arm objects
    # have been released.  This is the transferability experiment itself.
    process_rows: list[dict[str, Any]] = []
    auditor_script = Path(__file__).resolve().with_name("audit_verify.py")
    registry_path = security_dir / "trusted_registry.json"
    anchors_path = security_dir / "trusted_anchors.json"
    for artifact_id in sorted(streams):
        bundle_path = security_dir / "bundles" / f"{artifact_id}.json"
        verdict_path = security_dir / "verdicts" / f"{artifact_id}.json"
        command = [
            sys.executable,
            str(auditor_script),
            "--bundle",
            str(bundle_path),
            "--registry",
            str(registry_path),
            "--anchors",
            str(anchors_path),
            "--output",
            str(verdict_path),
        ]
        process = subprocess.run(command, capture_output=True, text=True)
        expected_outcome = "inconclusive" if streams[artifact_id][0] == "A1" else "accept"
        expected_returncode = 2 if expected_outcome == "inconclusive" else 0
        if process.returncode != expected_returncode:
            raise RuntimeError(
                f"independent auditor returned an unexpected status for {artifact_id}: "
                f"rc={process.returncode} stderr={process.stderr[-1000:]}"
            )
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
        if verdict.get("outcome") != expected_outcome:
            raise RuntimeError(
                f"clean {artifact_id} outcome is {verdict.get('outcome')!r}; "
                f"expected {expected_outcome!r}"
            )
        process_rows.append(
            {
                "artifact_id": artifact_id,
                "arm_id": streams[artifact_id][0],
                "returncode": process.returncode,
                "outcome": verdict["outcome"],
                "expected_capability_outcome": expected_outcome,
                "online_participant_access": False,
                "inputs": ["bundle", "trusted_registry", "trusted_anchors"],
            }
        )

    summary = {
        "schema_version": "aapa-security-artifact-export-v1",
        "provenance": provenance.fields(),
        "seed": seed,
        "n_records": n_records,
        "checkpoint_interval": checkpoint_interval,
        "payload_bytes": payload_bytes,
        "witness_count": witness_count,
        "witness_quorum": witness_quorum,
        "transferable_arms": list(TRANSFERABLE_ARMS),
        "negative_control": "A2",
        "independent_processes": process_rows,
        "export": exported,
    }
    (security_dir / "security_export.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--seed", type=int, default=int(__import__("os").environ.get("AAPA_SEED", "20260710")))
    parser.add_argument("--n-records", type=int, default=8)
    parser.add_argument("--checkpoint-interval", type=int, default=4)
    parser.add_argument("--payload-bytes", type=int, default=128)
    parser.add_argument("--witness-count", type=int, default=3)
    parser.add_argument("--witness-quorum", type=int, default=2)
    args = parser.parse_args()
    summary = generate(
        Path(args.out_dir).resolve(),
        seed=args.seed,
        n_records=args.n_records,
        checkpoint_interval=args.checkpoint_interval,
        payload_bytes=args.payload_bytes,
        witness_count=args.witness_count,
        witness_quorum=args.witness_quorum,
    )
    print(json.dumps({"status": "PASS", "streams": summary["transferable_arms"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
