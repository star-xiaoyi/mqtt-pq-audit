from __future__ import annotations

import sys
from pathlib import Path


PYTHON_DIR = Path(__file__).resolve().parents[1] / "experiments" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from summarize_result_package import (  # noqa: E402
    statistical_methodology_checklist,
    summarize_attribution_scope,
    wilson_interval,
)


def test_wilson_interval_bounds():
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0 and 0.0 <= hi <= 1.0
    lo, hi = wilson_interval(10, 10)
    assert hi == 1.0 and lo < 1.0
    lo, hi = wilson_interval(5, 10)
    assert lo < 0.5 < hi
    # degenerate n=0 must not divide by zero
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_methodology_checklist_items_and_kinds():
    checklist = statistical_methodology_checklist({"capability_boundary": {"deterministic": True}})
    assert len(checklist) == 11
    ids = [item["id"] for item in checklist]
    assert len(set(ids)) == 11
    assert all({"id", "status", "reason", "kind"} <= set(item) for item in checklist)
    # some items are actually verified from data, not just documented
    assert any(item["kind"] == "data_verified" for item in checklist)
    assert any(item["kind"] == "documented" for item in checklist)


def test_methodology_checklist_flags_nondeterministic_ci():
    checklist = statistical_methodology_checklist({"capability_boundary": {"deterministic": False}})
    ci_item = next(item for item in checklist if item["id"] == "01_deterministic_fake_ci")
    assert ci_item["status"] == "REVIEW"
    assert ci_item["kind"] == "data_verified"


def test_attribution_scope_keeps_delivery_match_evaluation_only(tmp_path):
    (tmp_path / "ground_truth.jsonl").write_text(
        "\n".join((
            '{"case_id":"c1","semantic_status":"violation",'
            '"evidence_integrity_violation":false,"protocol_responsible_party":"broker"}',
            '{"case_id":"c2","semantic_status":"compliant",'
            '"evidence_integrity_violation":true,"protocol_responsible_party":"none"}',
            '{"case_id":"c3","semantic_status":"compliant",'
            '"evidence_integrity_violation":false,"protocol_responsible_party":"none"}',
        )) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "auditor_results.jsonl").write_text(
        "\n".join((
            '{"case_id":"c1","auditor_mode":"qos_aware","attribution":"broker"}',
            '{"case_id":"c2","auditor_mode":"qos_aware","attribution":"broker"}',
            '{"case_id":"c3","auditor_mode":"qos_aware","attribution":null}',
            '{"case_id":"c1","auditor_mode":"qos_agnostic","attribution":"broker"}',
        )) + "\n",
        encoding="utf-8",
    )

    summary = summarize_attribution_scope(tmp_path)
    total = summary["rows"][-1]
    assert total["presenter_scope_labels"] == 2
    assert total["verifier_delivery_scope_labels"] == 0
    assert total["delivery_responsibility_matches"] == 1
    assert total["delivery_responsibility_nonmatches"] == 1
    assert "not verifier output" in summary["evaluation_crosscheck"]
