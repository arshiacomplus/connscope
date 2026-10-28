from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import socket
import pytest

from connscope.adapters import resolve_safe_executable
from connscope.cli.main import cli_entry
from connscope.core import ProbeStatus, Target
from connscope.scenarios import (
    DEFAULT_DIAGNOSTIC_UUID,
    LocalDiagnosticHarness,
    MeasurementNode,
    MeasurementWorkload,
    ScenarioCoordinator,
    ScenarioGenerator,
    create_default_protocol_catalog,
    write_jsonl,
)

def _find_unbound_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
    return port

def test_e2e_xray_local_diagnostic_full_workflow(tmp_path: Path):
    xray_bin = resolve_safe_executable("xray")
    if not xray_bin:
        pytest.skip("xray binary not available")

    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    coordinator = ScenarioCoordinator(catalog=catalog)

    with LocalDiagnosticHarness(engine_id="xray") as harness:
        workload = MeasurementWorkload(test_url=harness.test_url, timeout_s=5.0, repetitions=1)
        plan = generator.generate_explicit(
            engine_ids=["xray"],
            profile_ids=["vless_tcp_none"],
            variant_ids=["baseline"],
            target=harness.target,
            workload=workload,
            parameter_overrides={"uuid": harness.client_uuid},
        )

        res = asyncio.run(coordinator.execute_plan(plan=plan, execute=True))

        assert res.is_dry_run is False
        assert res.summary.planned_scenarios == 1
        assert res.summary.executed_scenarios == 1
        assert res.summary.succeeded_scenarios == 1
        assert res.summary.failed_scenarios == 0
        assert len(res.records) == 1

        rec = res.records[0]
        assert rec.status == ProbeStatus.SUCCESS.value
        assert rec.engine_id == "xray"
        assert rec.profile_id == "vless_tcp_none"
        assert rec.executable_version == "26.3.27"
        assert rec.tunnel_established is True
        assert rec.data_transfer_completed is True
        assert rec.resolved_config.get("uuid") == "[REDACTED]"
        assert "handshake_ms" in rec.metrics
        assert "data_transfer_ms" in rec.metrics

        jsonl_path = tmp_path / "xray_records.jsonl"
        write_jsonl(res.records, str(jsonl_path))
        assert jsonl_path.exists()

        with open(jsonl_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f]
        assert len(lines) == 1
        assert lines[0]["status"] == "success"
        assert lines[0]["resolved_config"]["uuid"] == "[REDACTED]"

def test_e2e_singbox_local_diagnostic_full_workflow(tmp_path: Path):
    sb_bin = resolve_safe_executable("sing-box")
    if not sb_bin:
        pytest.skip("sing-box binary not available")

    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    coordinator = ScenarioCoordinator(catalog=catalog)

    with LocalDiagnosticHarness(engine_id="sing_box") as harness:
        workload = MeasurementWorkload(test_url=harness.test_url, timeout_s=5.0, repetitions=1)
        plan = generator.generate_explicit(
            engine_ids=["sing_box"],
            profile_ids=["vless_tcp_none"],
            variant_ids=["baseline"],
            target=harness.target,
            workload=workload,
            parameter_overrides={"uuid": harness.client_uuid},
        )

        res = asyncio.run(coordinator.execute_plan(plan=plan, execute=True))

        assert res.is_dry_run is False
        assert res.summary.planned_scenarios == 1
        assert res.summary.executed_scenarios == 1
        assert res.summary.succeeded_scenarios == 1
        assert res.summary.failed_scenarios == 0
        assert len(res.records) == 1

        rec = res.records[0]
        assert rec.status == ProbeStatus.SUCCESS.value
        assert rec.engine_id == "sing_box"
        assert rec.profile_id == "vless_tcp_none"
        assert rec.executable_version == "1.12.12"
        assert rec.tunnel_established is True
        assert rec.data_transfer_completed is True
        assert rec.resolved_config.get("uuid") == "[REDACTED]"

        jsonl_path = tmp_path / "singbox_records.jsonl"
        write_jsonl(res.records, str(jsonl_path))
        assert jsonl_path.exists()

def test_e2e_dry_run_default_spawns_zero_processes():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    coordinator = ScenarioCoordinator(catalog=catalog)

    target = Target(host="127.0.0.1", port=443)
    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_none"],
        variant_ids=["baseline"],
        target=target,
        parameter_overrides={"uuid": DEFAULT_DIAGNOSTIC_UUID},
    )

    res = asyncio.run(coordinator.execute_plan(plan=plan, execute=False))
    assert res.is_dry_run is True
    assert res.summary.planned_scenarios == 1
    assert res.summary.executed_scenarios == 0
    assert len(res.records) == 0

def test_e2e_connection_refused_failure():
    xray_bin = resolve_safe_executable("xray")
    if not xray_bin:
        pytest.skip("xray binary not available")

    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    coordinator = ScenarioCoordinator(catalog=catalog)

    closed_port = _find_unbound_port()
    target = Target(host="127.0.0.1", port=closed_port)
    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_none"],
        variant_ids=["baseline"],
        target=target,
        parameter_overrides={"uuid": DEFAULT_DIAGNOSTIC_UUID},
    )

    res = asyncio.run(coordinator.execute_plan(plan=plan, execute=True))
    assert res.summary.planned_scenarios == 1
    assert res.summary.executed_scenarios == 1
    assert res.summary.succeeded_scenarios == 0
    assert res.summary.failed_scenarios == 1
    assert len(res.records) == 1

    rec = res.records[0]
    assert rec.status == ProbeStatus.FAILED.value
    assert rec.tunnel_established is False
    assert rec.data_transfer_completed is False

def test_e2e_timeout_handling_and_process_cleanup():
    xray_bin = resolve_safe_executable("xray")
    if not xray_bin:
        pytest.skip("xray binary not available")

    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    coordinator = ScenarioCoordinator(catalog=catalog)

    target = Target(host="198.51.100.1", port=443)
    workload = MeasurementWorkload(test_url="http://198.51.100.1/test", timeout_s=0.5, repetitions=1)
    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_none"],
        variant_ids=["baseline"],
        target=target,
        workload=workload,
        parameter_overrides={"uuid": DEFAULT_DIAGNOSTIC_UUID},
    )

    res = asyncio.run(coordinator.execute_plan(plan=plan, execute=True))
    assert res.summary.planned_scenarios == 1
    assert res.summary.executed_scenarios == 1
    assert res.summary.succeeded_scenarios == 0
    assert res.summary.failed_scenarios == 1
    assert len(res.records) == 1

    rec = res.records[0]
    assert rec.status in (ProbeStatus.FAILED.value, ProbeStatus.TIMEOUT.value)
    assert rec.tunnel_established is False

def test_e2e_xray_verify_cert_false_pre_execution_rejection():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    coordinator = ScenarioCoordinator(catalog=catalog)

    target = Target(host="127.0.0.1", port=443)
    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_tls"],
        variant_ids=["baseline"],
        target=target,
        parameter_overrides={"uuid": DEFAULT_DIAGNOSTIC_UUID, "server_name": "example.com", "verify_cert": False},
    )

    res = asyncio.run(coordinator.execute_plan(plan=plan, execute=False))
    assert res.summary.planned_scenarios == 1
    assert res.summary.excluded_scenarios == 1
    assert len(res.summary.excluded_scenarios_detail) == 1
    reason = res.summary.excluded_scenarios_detail[0]["reason"]
    assert "verify_cert=False" in reason
    assert "allowInsecure" in reason

def test_e2e_singbox_unsupported_params_pre_execution_rejection():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    coordinator = ScenarioCoordinator(catalog=catalog)
    target = Target(host="127.0.0.1", port=443)

    plan_uot = generator.generate_explicit(
        engine_ids=["sing_box"],
        profile_ids=["shadowsocks_tcp"],
        variant_ids=["baseline"],
        target=target,
        parameter_overrides={"password": "testpassword", "method": "aes-128-gcm", "uot": True},
    )
    res_uot = asyncio.run(coordinator.execute_plan(plan=plan_uot, execute=False))
    assert res_uot.summary.excluded_scenarios == 1
    assert "uot" in res_uot.summary.excluded_scenarios_detail[0]["reason"].lower()

    plan_mm = generator.generate_explicit(
        engine_ids=["sing_box"],
        profile_ids=["vless_grpc_tls"],
        variant_ids=["baseline"],
        target=target,
        parameter_overrides={"uuid": DEFAULT_DIAGNOSTIC_UUID, "server_name": "example.com", "service_name": "grpc", "multi_mode": True},
    )
    res_mm = asyncio.run(coordinator.execute_plan(plan=plan_mm, execute=False))
    assert res_mm.summary.excluded_scenarios == 1
    assert "multi_mode" in res_mm.summary.excluded_scenarios_detail[0]["reason"].lower()

    plan_pe = generator.generate_explicit(
        engine_ids=["sing_box"],
        profile_ids=["vmess_ws_tls"],
        variant_ids=["baseline"],
        target=target,
        parameter_overrides={"uuid": DEFAULT_DIAGNOSTIC_UUID, "server_name": "example.com", "path": "/ws", "packet_encoding": "none"},
    )
    res_pe = asyncio.run(coordinator.execute_plan(plan=plan_pe, execute=False))
    assert res_pe.summary.excluded_scenarios == 1
    assert "packet_encoding" in res_pe.summary.excluded_scenarios_detail[0]["reason"].lower()

def test_e2e_cli_catalog_check_text_and_json(capsys: pytest.CaptureFixture[str]):
    exit_code = cli_entry(["catalog", "check"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "ConnScope Environment & Protocol Readiness Check" in captured.out
    assert "xray" in captured.out
    assert "sing_box" in captured.out
    assert "Executable Protocol Profiles:" in captured.out
    assert "connscope matrix run" in captured.out

    exit_code_json = cli_entry(["catalog", "check", "--json"])
    assert exit_code_json == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert "engines" in data
    assert "profiles" in data
    assert "xray" in data["engines"]
    assert "sing_box" in data["engines"]
    assert isinstance(data["engines"]["xray"]["is_ready"], bool)
    assert isinstance(data["engines"]["sing_box"]["is_ready"], bool)
    for p in data["profiles"]:
        assert "profile_id" in p
        assert isinstance(p["xray_ready"], bool)
        assert isinstance(p["singbox_ready"], bool)

def test_e2e_cli_matrix_run_local_diagnostic(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    xray_bin = resolve_safe_executable("xray")
    if not xray_bin:
        pytest.skip("xray binary not available")

    jsonl_file = tmp_path / "cli_records.jsonl"
    summary_file = tmp_path / "cli_summary.json"

    args = [
        "matrix",
        "run",
        "--engine",
        "xray",
        "--profile",
        "vless_tcp_none",
        "--local-diagnostic",
        "--execute",
        "--jsonl",
        str(jsonl_file),
        "--summary-file",
        str(summary_file),
    ]

    exit_code = cli_entry(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "SUCCESS" in captured.err or "SUCCESS" in captured.out
    assert "Scenario Matrix Execution Summary" in captured.out
    assert "Success Rate=100.0%" in captured.out

    assert jsonl_file.exists()
    assert summary_file.exists()

    with open(jsonl_file, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f]
    assert len(records) == 1
    assert records[0]["status"] == "success"
    assert isinstance(records[0]["executable_version"], str)
    assert records[0]["evidence_status"] == "local_diagnostic_verified"
    assert records[0]["execution_mode"] == "local_diagnostic"
    assert records[0]["tunnel_established"] is True
    assert records[0]["data_transfer_completed"] is True
    assert records[0]["resolved_config"]["uuid"] == "[REDACTED]"

    with open(summary_file, "r", encoding="utf-8") as f:
        summary_data = json.load(f)
    assert summary_data["succeeded_scenarios"] == 1
    assert summary_data["failed_scenarios"] == 0

def test_e2e_deterministic_result_serialization(tmp_path: Path):
    xray_bin = resolve_safe_executable("xray")
    if not xray_bin:
        pytest.skip("xray binary not available")

    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    coordinator = ScenarioCoordinator(catalog=catalog)

    with LocalDiagnosticHarness(engine_id="xray") as harness:
        workload = MeasurementWorkload(test_url=harness.test_url, timeout_s=5.0, repetitions=1)
        plan = generator.generate_explicit(
            engine_ids=["xray"],
            profile_ids=["vless_tcp_none"],
            variant_ids=["baseline"],
            target=harness.target,
            workload=workload,
            parameter_overrides={"uuid": harness.client_uuid},
        )
        res = asyncio.run(coordinator.execute_plan(plan=plan, execute=True))

        p1 = tmp_path / "run1.jsonl"
        p2 = tmp_path / "run2.jsonl"
        write_jsonl(res.records, str(p1))
        write_jsonl(res.records, str(p2))

        with open(p1, "r", encoding="utf-8") as f1, open(p2, "r", encoding="utf-8") as f2:
            assert f1.read() == f2.read()
