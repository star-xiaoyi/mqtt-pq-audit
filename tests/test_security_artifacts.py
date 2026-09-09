from __future__ import annotations

import json
import sys
from pathlib import Path


PYTHON_DIR = Path(__file__).resolve().parents[1] / "experiments" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from generate_security_artifacts import generate  # noqa: E402
import validate_result_package as vrp  # noqa: E402


def test_independent_offline_artifacts_cover_core_arms(tmp_path, monkeypatch):
    monkeypatch.setenv("AAPA_MODE", "quick")
    monkeypatch.setenv("AAPA_RUN_ID", "pytest-security-export")
    monkeypatch.setenv("AAPA_TIMESTAMP_UTC", "2026-07-10T00:00:00Z")
    monkeypatch.setenv("AAPA_CONFIG_HASH", "a" * 64)
    monkeypatch.setenv("AAPA_SEED", "20260710")
    monkeypatch.setenv("AAPA_GIT_COMMIT", "b" * 40)
    monkeypatch.setenv("AAPA_DEPENDENCY_HASH", "c" * 64)
    monkeypatch.setenv("AAPA_SOURCE_TREE_HASH", "d" * 64)

    summary = generate(
        tmp_path,
        seed=20260710,
        n_records=4,
        checkpoint_interval=2,
        payload_bytes=24,
        witness_count=3,
        witness_quorum=2,
    )
    assert {row["arm_id"] for row in summary["independent_processes"]} == {
        "A0", "A1", "A3", "A4", "A6"
    }
    outcomes = {row["arm_id"]: (row["returncode"], row["outcome"]) for row in summary["independent_processes"]}
    assert outcomes["A1"] == (2, "inconclusive")
    for arm_id in ("A0", "A3", "A4", "A6"):
        assert outcomes[arm_id] == (0, "accept")

    a2 = json.loads((tmp_path / "security" / "a2_session_mac_only.json").read_text())
    assert a2["audit_evidence_transferable"] is False
    assert a2["session_key_exported"] is False
    assert a2["outcome"] == "inconclusive"


def _generate_pkg(root: Path, monkeypatch) -> Path:
    for key, value in {
        "AAPA_MODE": "quick",
        "AAPA_RUN_ID": "pytest-sec",
        "AAPA_TIMESTAMP_UTC": "2026-07-10T00:00:00Z",
        "AAPA_CONFIG_HASH": "a" * 64,
        "AAPA_SEED": "20260710",
        "AAPA_GIT_COMMIT": "b" * 40,
        "AAPA_DEPENDENCY_HASH": "c" * 64,
        "AAPA_SOURCE_TREE_HASH": "d" * 64,
    }.items():
        monkeypatch.setenv(key, value)
    generate(
        root,
        seed=20260710,
        n_records=4,
        checkpoint_interval=2,
        payload_bytes=24,
        witness_count=3,
        witness_quorum=2,
    )
    return root


def _offline_status(data_dir: Path) -> dict[str, str]:
    checks: list = []
    # config=None focuses on the crypto/receipt re-derivation, not provenance.
    vrp.validate_offline_security_artifacts(Path(data_dir), checks, config=None, metadata=None)
    return {c.name: c.status for c in checks}


def test_offline_validator_accepts_clean_artifacts(tmp_path, monkeypatch):
    _generate_pkg(tmp_path, monkeypatch)
    status = _offline_status(tmp_path)
    assert "FAIL" not in status.values(), status
    assert status.get("offline_receipt_id_integrity") == "PASS"
    assert status.get("offline_clean_arms_accept") == "PASS"
    assert status.get("offline_A1_inconclusive") == "PASS"
    assert status.get("offline_A2_boundary") == "PASS"


def test_offline_validator_rejects_receipt_id_tamper(tmp_path, monkeypatch):
    _generate_pkg(tmp_path, monkeypatch)
    bundle_path = tmp_path / "security" / "bundles" / "a6-clean.json"
    bundle = json.loads(bundle_path.read_text())
    bundle["evidence"][0]["witness_receipts"][0]["receipt_id"] = "a" * 64
    bundle_path.write_text(json.dumps(bundle))
    status = _offline_status(tmp_path)
    assert status.get("offline_receipt_id_integrity") == "FAIL", status


def test_offline_validator_rejects_missing_receipt_id(tmp_path, monkeypatch):
    _generate_pkg(tmp_path, monkeypatch)
    bundle_path = tmp_path / "security" / "bundles" / "a6-clean.json"
    bundle = json.loads(bundle_path.read_text())
    bundle["evidence"][0]["witness_receipts"][0].pop("receipt_id", None)
    bundle_path.write_text(json.dumps(bundle))
    status = _offline_status(tmp_path)
    assert status.get("offline_receipt_id_integrity") == "FAIL", status


def test_offline_validator_rejects_signature_tamper(tmp_path, monkeypatch):
    _generate_pkg(tmp_path, monkeypatch)
    bundle_path = tmp_path / "security" / "bundles" / "a4-clean.json"
    bundle = json.loads(bundle_path.read_text())
    sig = bundle["evidence"][0]["signature_hex"]
    bundle["evidence"][0]["signature_hex"] = "00" * (len(sig) // 2)
    bundle_path.write_text(json.dumps(bundle))
    status = _offline_status(tmp_path)
    # A tampered checkpoint signature must flip the re-derived verdict away from
    # accept, so the clean-arm accept gate (or the replay cross-check) fails.
    assert "FAIL" in {status.get("offline_clean_arms_accept"), status.get("offline_security_replay")}, status


def test_offline_validator_rejects_witness_key_substitution(tmp_path, monkeypatch):
    _generate_pkg(tmp_path, monkeypatch)
    bundle_path = tmp_path / "security" / "bundles" / "a6-clean.json"
    bundle = json.loads(bundle_path.read_text())
    pk = bundle["evidence"][0]["witness_receipts"][0]["public_key_hex"]
    substituted = ("00" if pk[:2] != "00" else "11") + pk[2:]
    bundle["evidence"][0]["witness_receipts"][0]["public_key_hex"] = substituted
    bundle_path.write_text(json.dumps(bundle))
    status = _offline_status(tmp_path)
    # Substituting a witness key changes the recomputed receipt_id and breaks the
    # registry-bound quorum, so A6 must no longer accept.
    assert "FAIL" in {
        status.get("offline_receipt_id_integrity"),
        status.get("offline_clean_arms_accept"),
    }, status


def test_offline_validator_fails_closed_without_registry(tmp_path, monkeypatch):
    _generate_pkg(tmp_path, monkeypatch)
    (tmp_path / "security" / "trusted_registry.json").unlink()
    status = _offline_status(tmp_path)
    # No trusted registry -> the offline artifact set is incomplete and the path
    # fails closed rather than accepting bundle-embedded keys.
    assert status.get("offline_security_artifacts") == "FAIL", status
