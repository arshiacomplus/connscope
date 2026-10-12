from datetime import datetime, timezone

from connscope.core import ProbeResult, ProbeStatus, Target
from connscope.cli.output import render_error, render_probe_list, render_result


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
