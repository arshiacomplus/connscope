from datetime import datetime, timezone, tzinfo
import json
import math
import pytest

from connscope.core import ProbeResult, ProbeStatus, Target
from connscope.cli.output import (
    render_error,
    render_probe_list,
    render_result,
    render_result_json,
    result_to_dict,
)

def test_render_result_success_minimal():
    res = ProbeResult(
        probe="tcp_connect",
        target=Target(host="example.com", port=443),
        status=ProbeStatus.SUCCESS,
        started_at=datetime.now(timezone.utc),
        duration_ms=45.234,
    )
    out = render_result(res)
    assert "Probe:    tcp_connect" in out
    assert "Target:   example.com:443" in out
    assert "Status:   success" in out
    assert "Duration: 45.23 ms" in out
    assert "Metrics:" not in out
    assert "Details:" not in out
    assert "Error:" not in out

def test_render_result_success_full():
    res = ProbeResult(
        probe="dns_resolve",
        target=Target(host="example.com"),
        status=ProbeStatus.SUCCESS,
        started_at=datetime.now(timezone.utc),
        duration_ms=12.5,
        metrics={"resolve_ms": 12.5},
        details={"addresses": ["93.184.216.34", "2606:2800::1"], "family": "both"},
    )
    out = render_result(res)
    assert "Probe:    dns_resolve" in out
    assert "Target:   example.com" in out
    assert "Status:   success" in out
    assert "Duration: 12.50 ms" in out
    assert "Metrics:" in out
    assert "  resolve_ms: 12.50" in out
    assert "Details:" in out
    assert "  addresses: 93.184.216.34, 2606:2800::1" in out
    assert "  family: both" in out

def test_render_result_failed_with_error():
    res = ProbeResult(
        probe="tcp_connect",
        target=Target(host="example.com", port=81),
        status=ProbeStatus.FAILED,
        started_at=datetime.now(timezone.utc),
        duration_ms=105.0,
        error="Connection refused",
    )
    out = render_result(res)
    assert "Status:   failed" in out
    assert "Duration: 105.00 ms" in out
    assert "Error: Connection refused" in out

def test_render_result_timeout():
    res = ProbeResult(
        probe="tls_handshake",
        target=Target(host="2001:db8::1", port=443),
        status=ProbeStatus.TIMEOUT,
        started_at=datetime.now(timezone.utc),
        duration_ms=5000.0,
        error="Operation timed out after 5.0s",
    )
    out = render_result(res)
    assert "Target:   [2001:db8::1]:443" in out
    assert "Status:   timeout" in out
    assert "Error: Operation timed out after 5.0s" in out

def test_render_probe_list():
    names = ("dns_resolve", "http_request", "tcp_connect", "tls_handshake")
    aliases = {
        "tcp": "tcp_connect",
        "dns": "dns_resolve",
        "tls": "tls_handshake",
        "http": "http_request",
    }
    out = render_probe_list(names, aliases)
    lines = out.splitlines()
    assert lines[0] == "Available probes:"
    assert "  dns_resolve (alias: dns)" in lines
    assert "  http_request (alias: http)" in lines
    assert "  tcp_connect (alias: tcp)" in lines
    assert "  tls_handshake (alias: tls)" in lines

def test_render_error():
    assert render_error("Something broke") == "Error: Something broke"

def test_result_to_dict_success():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="tcp_connect",
        target=Target(host="example.com", port=443),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=32.45,
        metrics={"connect_ms": 32.45},
        details={"extra": "value"},
        error=None,
    )
    d = result_to_dict(res)
    assert set(d.keys()) == {
        "probe",
        "target",
        "status",
        "started_at",
        "duration_ms",
        "metrics",
        "details",
        "error",
    }
    assert d["probe"] == "tcp_connect"
    assert d["target"] == {"host": "example.com", "port": 443}
    assert d["status"] == "success"
    assert d["started_at"] == "2026-10-12T12:00:00+00:00"
    assert d["duration_ms"] == 32.45
    assert d["metrics"] == {"connect_ms": 32.45}
    assert d["details"] == {"extra": "value"}
    assert d["error"] is None

def test_result_to_dict_failed():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="tcp_connect",
        target=Target(host="example.com", port=81),
        status=ProbeStatus.FAILED,
        started_at=ts,
        duration_ms=10.0,
        metrics={"connect_ms": 10.0},
        details={},
        error="Connection refused",
    )
    d = result_to_dict(res)
    assert d["status"] == "failed"
    assert d["error"] == "Connection refused"

def test_result_to_dict_timeout():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="dns_resolve",
        target=Target(host="nonexistent.invalid"),
        status=ProbeStatus.TIMEOUT,
        started_at=ts,
        duration_ms=5000.0,
        metrics={},
        details={},
        error="Resolution timed out",
    )
    d = result_to_dict(res)
    assert d["status"] == "timeout"
    assert d["error"] == "Resolution timed out"
    assert d["target"] == {"host": "nonexistent.invalid", "port": None}

def test_result_to_dict_target_port_none():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="dns_resolve",
        target=Target(host="example.com"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=5.0,
    )
    d = result_to_dict(res)
    assert d["target"]["port"] is None

def test_result_to_dict_empty_collections():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=1.0,
    )
    d = result_to_dict(res)
    assert d["metrics"] == {}
    assert d["details"] == {}

def test_result_to_dict_nested_types():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    details = {
        "addresses": ["1.1.1.1", "1.0.0.1"],
        "counts": [1, 2, 3],
        "active": True,
        "inactive": False,
        "nested": {
            "sub_list": [None, 42, 3.14, "hello"],
            "sub_dict": {"k": "v"},
        },
    }
    res = ProbeResult(
        probe="complex",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=1.0,
        details=details,
    )
    d = result_to_dict(res)
    assert d["details"]["addresses"] == ["1.1.1.1", "1.0.0.1"]
    assert d["details"]["counts"] == [1, 2, 3]
    assert d["details"]["active"] is True
    assert d["details"]["inactive"] is False
    assert d["details"]["nested"]["sub_list"] == [None, 42, 3.14, "hello"]

def test_result_to_dict_rejects_timezone_naive():
    naive_ts = datetime(2026, 10, 12, 12, 0, 0)
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=naive_ts,
        duration_ms=1.0,
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        result_to_dict(res)

def test_result_to_dict_rejects_tzinfo_with_none_utcoffset():
    class _NoneOffsetTz(tzinfo):
        def utcoffset(self, dt):
            return None

        def dst(self, dt):
            return None

        def tzname(self, dt):
            return "NONE"

    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=datetime(2026, 10, 12, 12, 0, 0, tzinfo=_NoneOffsetTz()),
        duration_ms=1.0,
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        result_to_dict(res)

def test_result_to_dict_rejects_nan_duration():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=float("nan"),
    )
    with pytest.raises(ValueError, match="finite number"):
        result_to_dict(res)

def test_result_to_dict_rejects_inf_duration():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=float("inf"),
    )
    with pytest.raises(ValueError, match="finite number"):
        result_to_dict(res)

def test_result_to_dict_rejects_nan_metric():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=1.0,
        metrics={"nan_metric": float("nan")},
    )
    with pytest.raises(ValueError, match="Non-finite float value"):
        result_to_dict(res)

def test_result_to_dict_rejects_inf_details():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=1.0,
        details={"inf_val": float("-inf")},
    )
    with pytest.raises(ValueError, match="Non-finite float value"):
        result_to_dict(res)

def test_result_to_dict_rejects_unsupported_object():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=1.0,
        details={"set_value": {1, 2, 3}},
    )
    with pytest.raises(TypeError, match="Unsupported value of type 'set'"):
        result_to_dict(res)

def test_result_to_dict_rejects_non_str_key():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=1.0,
        details={123: "value"},  # type: ignore
    )
    with pytest.raises(TypeError, match="Dictionary key.*must be str"):
        result_to_dict(res)

def test_result_to_dict_immutability():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    metrics = {"m": 1.0}
    details = {"d": ["original"]}
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=1.0,
        metrics=metrics,
        details=details,
    )
    d = result_to_dict(res)
    d["metrics"]["new"] = 2.0
    d["details"]["d"].append("modified")

    assert res.metrics == {"m": 1.0}
    assert res.details == {"d": ["original"]}

def test_render_result_json_valid_json():
    ts = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    res = ProbeResult(
        probe="tcp_connect",
        target=Target(host="example.com", port=443),
        status=ProbeStatus.SUCCESS,
        started_at=ts,
        duration_ms=15.5,
        metrics={"connect_ms": 15.5},
        details={"note": "ok"},
    )
    rendered = render_result_json(res)
    parsed = json.loads(rendered)
    assert parsed["probe"] == "tcp_connect"
    assert parsed["target"] == {"host": "example.com", "port": 443}
    assert parsed["status"] == "success"
    assert parsed["duration_ms"] == 15.5
    assert parsed["error"] is None

    lines = [line.strip().split(":")[0].strip('"') for line in rendered.splitlines() if ":" in line and not line.strip().startswith('"host"') and not line.strip().startswith('"port"')]
    top_level_keys = [k for k in lines if k in parsed]
    assert top_level_keys == sorted(top_level_keys)
