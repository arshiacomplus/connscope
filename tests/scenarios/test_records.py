
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from connscope.core import ProbeResult, ProbeStatus, Target
from connscope.scenarios import (
    MeasurementNode,
    MeasurementRecord,
    MeasurementWorkload,
    Scenario,
    VerificationStatus,
    read_jsonl,
    write_jsonl,
)

SAMPLE_TARGET = Target(host="192.0.2.1", port=443)
SAMPLE_NODE = MeasurementNode(
    node_id="test-node-01",
    name="Test Vantage Point",
    node_type="local",
    route_context={"interface": "eth0", "asn": 12345},
)
SAMPLE_WORKLOAD = MeasurementWorkload(
    workload_type="http_get_204",
    test_url="http://cp.cloudflare.com/generate_204",
    timeout_s=5.0,
    repetitions=3,
    verify_cert=True,
)
SAMPLE_SCENARIO = Scenario(
    scenario_id="scn_xray_vless_tcp_reality_baseline_12345678",
    engine_id="xray",
    profile_id="vless_tcp_reality",
    variant_id="baseline",
    node=SAMPLE_NODE,
    target=SAMPLE_TARGET,
    workload=SAMPLE_WORKLOAD,
    resolved_config={
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
        "server_name": "example.com",
        "short_id": "0123456789abcdef",
    },
    status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
    adapter_id="xray_vless_tcp_reality",
)

def test_measurement_record_construction_from_probe_result():
    start_time = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
    probe_res = ProbeResult(
        probe="xray_vless_tcp_reality",
        target=SAMPLE_TARGET,
        status=ProbeStatus.SUCCESS,
        started_at=start_time,
        duration_ms=125.4,
        metrics={"local_ready_ms": 35.0, "handshake_ms": 45.2, "data_transfer_ms": 45.2, "total_ms": 125.4},
        details={
            "adapter_id": "xray_vless_tcp_reality",
            "tunnel_established": True,
            "tls_verified": True,
            "data_transfer_completed": True,
            "verified_data_transfer": True,
        },
    )

    record = MeasurementRecord.from_probe_result(
        scenario=SAMPLE_SCENARIO,
        result=probe_res,
        repetition_index=1,
        executable_version="26.3.27",
    )

    assert record.schema_version == "1.0"
    assert record.scenario_id == SAMPLE_SCENARIO.scenario_id
    assert record.repetition_index == 1
    assert record.engine_id == "xray"
    assert record.profile_id == "vless_tcp_reality"
    assert record.adapter_id == "xray_vless_tcp_reality"
    assert record.executable_version == "26.3.27"
    assert record.node_id == "test-node-01"
    assert record.route_context["asn"] == 12345
    assert record.target == {"host": "192.0.2.1", "port": 443}
    assert record.status == "success"
    assert record.duration_ms == 125.4
    assert record.tunnel_established is True
    assert record.data_transfer_completed is True
    assert record.metrics["handshake_ms"] == 45.2

    assert record.resolved_config["uuid"] == "[REDACTED]"
    assert record.resolved_config["public_key"] == "[REDACTED]"
    assert record.resolved_config["server_name"] == "example.com"

def test_measurement_record_separate_tunnel_and_data_outcomes():
    start_time = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
    probe_res = ProbeResult(
        probe="xray_vless_tcp_reality",
        target=SAMPLE_TARGET,
        status=ProbeStatus.FAILED,
        started_at=start_time,
        duration_ms=2500.0,
        metrics={"local_ready_ms": 30.0, "handshake_ms": 50.0},
        details={
            "failure_stage": "data_transfer",
            "tunnel_established": True,
            "data_transfer_completed": False,
        },
        error="Gateway timeout reading HTTP response",
    )

    record = MeasurementRecord.from_probe_result(
        scenario=SAMPLE_SCENARIO,
        result=probe_res,
        repetition_index=0,
    )

    assert record.status == "failed"
    assert record.failure_stage == "data_transfer"
    assert record.tunnel_established is True
    assert record.data_transfer_completed is False

def test_measurement_record_secret_redaction_in_errors():
    start_time = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
    leaked_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    probe_res = ProbeResult(
        probe="xray_vless_tcp_reality",
        target=SAMPLE_TARGET,
        status=ProbeStatus.FAILED,
        started_at=start_time,
        duration_ms=10.0,
        details={"failure_stage": "pre_flight"},
        error=f"Authentication failed for user {leaked_uuid}: bad credentials",
    )

    record = MeasurementRecord.from_probe_result(
        scenario=SAMPLE_SCENARIO,
        result=probe_res,
        repetition_index=0,
    )

    assert leaked_uuid not in str(record.error)
    assert "[REDACTED]" in str(record.error)

def test_measurement_record_jsonl_roundtrip(tmp_path: Path):
    start_time = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
    records = []
    for rep in range(3):
        res = ProbeResult(
            probe="xray_vless_tcp_reality",
            target=SAMPLE_TARGET,
            status=ProbeStatus.SUCCESS,
            started_at=start_time,
            duration_ms=100.0 + rep * 10,
            metrics={"total_ms": 100.0 + rep * 10, "handshake_ms": 40.0},
            details={"tunnel_established": True, "data_transfer_completed": True},
        )
        records.append(
            MeasurementRecord.from_probe_result(
                scenario=SAMPLE_SCENARIO,
                result=res,
                repetition_index=rep,
            )
        )

    jsonl_file = tmp_path / "measurements.jsonl"
    count = write_jsonl(records, jsonl_file)
    assert count == 3

    with open(jsonl_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    assert len(lines) == 3
    for l in lines:
        parsed = json.loads(l)
        assert parsed["schema_version"] == "1.0"
        assert parsed["scenario_id"] == SAMPLE_SCENARIO.scenario_id

    restored = read_jsonl(jsonl_file)
    assert len(restored) == 3
    assert [r.repetition_index for r in restored] == [0, 1, 2]
    assert [r.duration_ms for r in restored] == [100.0, 110.0, 120.0]
