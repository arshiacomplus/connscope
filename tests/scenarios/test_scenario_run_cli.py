
from datetime import datetime, timezone
import io
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest

from connscope.cli.main import ExitCode, cli_entry
from connscope.core import ProbeResult, ProbeStatus, Target
from connscope.scenarios import (
    MeasurementRecord,
    read_jsonl,
)

SAMPLE_UUID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
SAMPLE_PUBKEY = "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk"
VALID_CONFIG_JSON = json.dumps({
    "uuid": SAMPLE_UUID,
    "public_key": SAMPLE_PUBKEY,
    "server_name": "example.com",
    "short_id": "0123456789abcdef",
})

def test_cli_matrix_run_dry_run_default():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(
        ["matrix", "run", "--engine", "xray", "--profile", "vless_tcp_reality", "--config", VALID_CONFIG_JSON],
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.OK
    text = out.getvalue()
    assert "Planning mode only (dry-run)" in text
    assert "0 processes spawned" in text
    assert "--execute" in text
    assert SAMPLE_UUID not in text
    assert SAMPLE_PUBKEY not in text

def test_cli_matrix_run_dry_run_json():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(
        ["matrix", "run", "--engine", "xray", "--profile", "vless_tcp_reality", "--config", VALID_CONFIG_JSON, "--json"],
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.OK
    data = json.loads(out.getvalue())
    assert data["planned_scenarios"] == 4
    assert data["executed_scenarios"] == 0
    assert data["excluded_scenarios"] == 0

def test_cli_matrix_run_execute_opt_in_with_mock(tmp_path: Path):
    out_file = tmp_path / "records.jsonl"
    sum_file = tmp_path / "summary.json"

    async def mock_run(self, target, config=None):
        return ProbeResult(
            probe="xray_vless_tcp_reality",
            target=target,
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=65.0,
            metrics={"local_ready_ms": 15.0, "handshake_ms": 25.0, "data_transfer_ms": 25.0},
            details={"tunnel_established": True, "data_transfer_completed": True},
        )

    out = io.StringIO()
    err = io.StringIO()

    with patch("connscope.adapters.xray.XrayVlessTcpRealityAdapter.run", new=mock_run), \
         patch("connscope.adapters.xray.XrayVlessTcpRealityAdapter.check_executable", return_value=(True, "/usr/bin/xray")):
        code = cli_entry(
            [
                "matrix", "run",
                "--engine", "xray",
                "--profile", "vless_tcp_reality",
                "--variant", "baseline",
                "--config", VALID_CONFIG_JSON,
                "--repetitions", "2",
                "--execute",
                "--output-file", str(out_file),
                "--summary-file", str(sum_file),
            ],
            stdout=out,
            stderr=err,
        )

    assert code == ExitCode.OK
    text = out.getvalue()
    assert "Planning mode only" not in text
    assert "Success Rate=100.0%" in text

    assert out_file.exists()
    records = read_jsonl(out_file)
    assert len(records) == 2
    assert records[0].repetition_index == 0
    assert records[1].repetition_index == 1
    assert records[0].status == "success"

    raw_content = out_file.read_text(encoding="utf-8")
    assert SAMPLE_UUID not in raw_content
    assert SAMPLE_PUBKEY not in raw_content
    assert "[REDACTED]" in raw_content

    assert sum_file.exists()
    sum_data = json.loads(sum_file.read_text(encoding="utf-8"))
    assert sum_data["executed_scenarios"] == 1
    assert sum_data["total_measurements"] == 2
    assert sum_data["successful_measurements"] == 2

def test_cli_matrix_run_failure_policy_stop_on_error(tmp_path: Path):
    async def mock_fail_run(self, target, config=None):
        return ProbeResult(
            probe="xray_vless_tcp_reality",
            target=target,
            status=ProbeStatus.FAILED,
            started_at=datetime.now(timezone.utc),
            duration_ms=20.0,
            details={"failure_stage": "handshake", "tunnel_established": False},
            error="Connection refused",
        )

    out = io.StringIO()
    err = io.StringIO()

    with patch("connscope.adapters.xray.XrayVlessTcpRealityAdapter.run", new=mock_fail_run), \
         patch("connscope.adapters.xray.XrayVlessTcpRealityAdapter.check_executable", return_value=(True, "/usr/bin/xray")):
        code = cli_entry(
            [
                "matrix", "run",
                "--engine", "xray",
                "--profile", "vless_tcp_reality",
                "--variant", "baseline",
                "--config", VALID_CONFIG_JSON,
                "--repetitions", "3",
                "--failure-policy", "stop",
                "--execute",
            ],
            stdout=out,
            stderr=err,
        )

    assert code == ExitCode.FAILED
    text = out.getvalue()
    assert "Failed=1" in text
