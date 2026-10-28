
from datetime import datetime, timezone
import json
import pytest

from connscope.scenarios import (
    MeasurementRecord,
    aggregate_execution_records,
    render_execution_summary_json,
    render_execution_summary_table,
)

def _make_dummy_record(
    scenario_id: str = "scn_1",
    rep_idx: int = 0,
    status: str = "success",
    duration_ms: float = 100.0,
    handshake_ms: float = 40.0,
    data_transfer_ms: float = 60.0,
    failure_stage: str | None = None,
    target_host: str = "192.0.2.1",
    target_port: int = 443,
    workload_type: str = "http_get_204",
) -> MeasurementRecord:
    now_str = datetime.now(timezone.utc).isoformat()
    metrics = {"total_ms": duration_ms}
    if handshake_ms is not None:
        metrics["handshake_ms"] = handshake_ms
    if data_transfer_ms is not None:
        metrics["data_transfer_ms"] = data_transfer_ms

    return MeasurementRecord(
        scenario_id=scenario_id,
        repetition_index=rep_idx,
        engine_id="xray",
        profile_id="vless_tcp_reality",
        variant_id="baseline",
        adapter_id="xray_vless_tcp_reality",
        node_id="local",
        target={"host": target_host, "port": target_port},
        workload={"workload_type": workload_type, "test_url": "http://cp.cloudflare.com/generate_204"},
        started_at=now_str,
        ended_at=now_str,
        duration_ms=duration_ms,
        status=status,
        metrics=metrics,
        failure_stage=failure_stage,
        tunnel_established=(status == "success"),
        data_transfer_completed=(status == "success"),
    )

def test_aggregate_empty_records():
    summary = aggregate_execution_records(
        records=[],
        planned_count=5,
        excluded_details=[{"scenario_id": "scn_bad", "reason": "missing param"}],
    )
    assert summary.planned_scenarios == 5
    assert summary.executed_scenarios == 0
    assert summary.excluded_scenarios == 1
    assert summary.total_measurements == 0
    assert summary.success_rate == 0.0
    assert summary.timing_stats["median_total_ms"] is None

def test_aggregate_successful_and_failed_records():
    records = [
        _make_dummy_record("scn_1", 0, "success", 100.0, 30.0, 70.0),
        _make_dummy_record("scn_1", 1, "success", 120.0, 40.0, 80.0),
        _make_dummy_record("scn_1", 2, "success", 150.0, 50.0, 100.0),
        _make_dummy_record("scn_2", 0, "success", 200.0, 60.0, 140.0),
        _make_dummy_record("scn_2", 1, "failed", 500.0, 0.0, 0.0, failure_stage="handshake"),
    ]

    summary = aggregate_execution_records(records, planned_count=2)
    assert summary.planned_scenarios == 2
    assert summary.executed_scenarios == 2
    assert summary.succeeded_scenarios == 1
    assert summary.failed_scenarios == 1
    assert summary.total_measurements == 5
    assert summary.successful_measurements == 4
    assert summary.failed_measurements == 1
    assert summary.success_rate == 0.8

    assert summary.timing_stats["min_total_ms"] == 100.0
    assert summary.timing_stats["max_total_ms"] == 200.0
    assert summary.timing_stats["median_total_ms"] == 135.0

    assert summary.failure_stage_distribution == {"handshake": 1}

    assert len(summary.per_scenario_summaries) == 2
    s1 = next(s for s in summary.per_scenario_summaries if s.scenario_id == "scn_1")
    assert s1.successful_repetitions == 3
    assert s1.total_repetitions == 3
    assert s1.success_rate == 1.0
    assert s1.median_total_ms == 120.0

    s2 = next(s for s in summary.per_scenario_summaries if s.scenario_id == "scn_2")
    assert s2.successful_repetitions == 1
    assert s2.total_repetitions == 2
    assert s2.success_rate == 0.5

def test_workload_comparability_check():
    rec_comp = [
        _make_dummy_record("scn_1", 0, target_host="192.0.2.1", workload_type="http_get_204"),
        _make_dummy_record("scn_2", 0, target_host="192.0.2.1", workload_type="http_get_204"),
    ]
    sum_comp = aggregate_execution_records(rec_comp, planned_count=2)
    assert sum_comp.is_comparable is True
    assert len(sum_comp.workload_comparability_notes) == 0

    rec_diff_targets = [
        _make_dummy_record("scn_1", 0, target_host="192.0.2.1", target_port=443),
        _make_dummy_record("scn_2", 0, target_host="198.51.100.2", target_port=443),
    ]
    sum_diff_t = aggregate_execution_records(rec_diff_targets, planned_count=2)
    assert sum_diff_t.is_comparable is False
    assert any("different target endpoints" in n for n in sum_diff_t.workload_comparability_notes)

    rec_diff_workloads = [
        _make_dummy_record("scn_1", 0, workload_type="http_get_204"),
        _make_dummy_record("scn_2", 0, workload_type="bandwidth_stream"),
    ]
    sum_diff_w = aggregate_execution_records(rec_diff_workloads, planned_count=2)
    assert sum_diff_w.is_comparable is False
    assert any("distinct workloads" in n for n in sum_diff_w.workload_comparability_notes)

def test_render_execution_summary_table_and_json():
    records = [
        _make_dummy_record("scn_1", 0, "success", 100.0, 40.0, 60.0),
        _make_dummy_record("scn_1", 1, "failed", 200.0, 0.0, 0.0, failure_stage="handshake"),
    ]
    summary = aggregate_execution_records(
        records,
        planned_count=2,
        excluded_details=[{"scenario_id": "scn_ex", "reason": "catalog only"}],
    )

    table_text = render_execution_summary_table(summary)
    assert "Scenario Matrix Execution Summary" in table_text
    assert "Planned=2" in table_text
    assert "Excluded=1" in table_text
    assert "handshake: 1" in table_text
    assert "scn_ex" in table_text

    json_text = render_execution_summary_json(summary)
    parsed = json.loads(json_text)
    assert parsed["planned_scenarios"] == 2
    assert parsed["executed_scenarios"] == 1
    assert parsed["excluded_scenarios"] == 1
    assert parsed["total_measurements"] == 2
    assert parsed["successful_measurements"] == 1
    assert len(parsed["per_scenario_summaries"]) == 1
