import io
from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from connscope.core import Probe, ProbeRegistry, ProbeResult, ProbeStatus, Target
from connscope.cli.main import ExitCode, cli_entry, create_default_registry, main


class MockProbe(Probe):
    def __init__(self, name: str, status: ProbeStatus, error: str | None = None):
        self.name = name
        self.status = status
        self.error = error
        self.last_target: Target | None = None
        self.last_config: dict | None = None

    async def run(self, target: Target, config=None) -> ProbeResult:
        self.last_target = target
        self.last_config = config
        return ProbeResult(
            probe=self.name,
            target=target,
            status=self.status,
            started_at=datetime.now(timezone.utc),
            duration_ms=15.0,
            metrics={"latency_ms": 15.0},
            details={"dummy": True},
            error=self.error,
        )


def test_cli_help():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["--help"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    assert "usage:" in out.getvalue()


def test_cli_version():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["--version"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    assert "connscope" in out.getvalue()


def test_cli_no_args():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry([], stdout=out, stderr=err)
    assert code == ExitCode.USAGE_ERROR
    assert "usage:" in err.getvalue()


def test_cli_probe_list():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["probe", "list"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    val = out.getvalue()
    assert "Available probes:" in val
    assert "tcp_connect (alias: tcp)" in val
    assert "dns_resolve (alias: dns)" in val
    assert "tls_handshake (alias: tls)" in val
    assert "http_request (alias: http)" in val


def test_cli_list_alias():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["list"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    assert "Available probes:" in out.getvalue()


def test_cli_probe_missing_subcommand():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["probe"], stdout=out, stderr=err)
    assert code == ExitCode.USAGE_ERROR
    assert "Missing probe subcommand" in err.getvalue()


def test_cli_run_success():
    reg = ProbeRegistry()
    mock_tcp = MockProbe("tcp_connect", ProbeStatus.SUCCESS)
    reg.register(mock_tcp)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tcp", "example.com:443"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.OK
    assert mock_tcp.last_target == Target(host="example.com", port=443)
    val = out.getvalue()
    assert "Probe:    tcp_connect" in val
    assert "Status:   success" in val
    assert "Duration: 15.00 ms" in val


def test_cli_run_failed():
    reg = ProbeRegistry()
    mock_tcp = MockProbe("tcp_connect", ProbeStatus.FAILED, error="Connection refused")
    reg.register(mock_tcp)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tcp_connect", "example.com:80"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.FAILED
    val = out.getvalue()
    assert "Status:   failed" in val
    assert "Error: Connection refused" in val


def test_cli_run_timeout():
    reg = ProbeRegistry()
    mock_tls = MockProbe("tls_handshake", ProbeStatus.TIMEOUT, error="Timed out")
    reg.register(mock_tls)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tls", "example.com:443"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.TIMEOUT
    val = out.getvalue()
    assert "Status:   timeout" in val


def test_cli_run_with_timeout_config():
    reg = ProbeRegistry()
    mock_dns = MockProbe("dns_resolve", ProbeStatus.SUCCESS)
    reg.register(mock_dns)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "dns", "example.com", "--timeout", "5.5"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.OK
    assert mock_dns.last_config == {"timeout_s": 5.5}


def test_cli_run_tcp_missing_port():
    reg = create_default_registry()
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tcp", "example.com"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.USAGE_ERROR
    assert "Target port is required for TCP probe" in err.getvalue()


def test_cli_run_dns_with_port_rejected():
    reg = create_default_registry()
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "dns", "example.com:53"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.USAGE_ERROR
    assert "Port is not supported for DNS probe" in err.getvalue()


def test_cli_run_unknown_probe():
    reg = create_default_registry()
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "nonexistent_probe", "example.com"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.USAGE_ERROR
    assert "Unknown probe 'nonexistent_probe'" in err.getvalue()


def test_cli_run_http_url():
    reg = ProbeRegistry()
    mock_http = MockProbe("http_request", ProbeStatus.SUCCESS)
    reg.register(mock_http)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "http", "https://example.com/api?test=1"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.OK
    assert mock_http.last_target == Target(host="example.com", port=443)
    assert mock_http.last_config == {"use_tls": True, "path": "/api?test=1"}


def test_cli_run_http_unsupported_scheme():
    reg = create_default_registry()
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "http", "ftp://example.com"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.USAGE_ERROR
    assert "Unsupported URL scheme 'ftp'" in err.getvalue()


def test_cli_run_invalid_timeout():
    reg = create_default_registry()
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tcp", "example.com:443", "--timeout", "-1"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.USAGE_ERROR
    assert "positive finite number" in err.getvalue()


def test_cli_run_internal_error():
    reg = ProbeRegistry()
    class CrashingProbe(Probe):
        name = "crash"
        async def run(self, target, config=None):
            raise RuntimeError("Boom!")

    reg.register(CrashingProbe())
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "crash", "example.com"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.INTERNAL_ERROR
    assert "Internal error: Boom!" in err.getvalue()


def test_cli_keyboard_interrupt():
    reg = ProbeRegistry()
    class InterruptProbe(Probe):
        name = "interrupt"
        async def run(self, target, config=None):
            raise KeyboardInterrupt()

    reg.register(InterruptProbe())
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "interrupt", "example.com"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.USAGE_ERROR
    assert "Operation cancelled by user." in err.getvalue()


def test_main_calls_sys_exit():
    with patch("sys.exit") as mock_exit, patch("connscope.cli.main.cli_entry", return_value=0):
        main()
        mock_exit.assert_called_once_with(0)
