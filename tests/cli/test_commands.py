import io
import json
from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from connscope.core import Probe, ProbeRegistry, ProbeResult, ProbeStatus, Target
from connscope.cli.main import ExitCode, cli_entry, create_default_registry, main

class MockProbe(Probe):
    def __init__(
        self,
        name: str,
        status: ProbeStatus,
        error: str | None = None,
        metrics: dict | None = None,
        details: dict | None = None,
    ):
        self.name = name
        self.status = status
        self.error = error
        self.metrics = metrics if metrics is not None else {"latency_ms": 15.0}
        self.details = details if details is not None else {"dummy": True}
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
            metrics=dict(self.metrics),
            details=dict(self.details),
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

def test_cli_run_json_success():
    reg = ProbeRegistry()
    mock_tcp = MockProbe("tcp_connect", ProbeStatus.SUCCESS)
    reg.register(mock_tcp)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tcp", "example.com:443", "--json"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.OK
    assert err.getvalue() == ""
    data = json.loads(out.getvalue())
    assert data["probe"] == "tcp_connect"
    assert data["status"] == "success"
    assert data["target"] == {"host": "example.com", "port": 443}
    assert data["duration_ms"] == 15.0
    assert data["metrics"] == {"latency_ms": 15.0}
    assert data["details"] == {"dummy": True}
    assert data["error"] is None

def test_cli_run_json_failed():
    reg = ProbeRegistry()
    mock_tcp = MockProbe("tcp_connect", ProbeStatus.FAILED, error="Connection refused")
    reg.register(mock_tcp)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tcp_connect", "example.com:80", "--json"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.FAILED
    assert err.getvalue() == ""
    data = json.loads(out.getvalue())
    assert data["status"] == "failed"
    assert data["error"] == "Connection refused"

def test_cli_run_json_timeout():
    reg = ProbeRegistry()
    mock_tls = MockProbe("tls_handshake", ProbeStatus.TIMEOUT, error="Handshake timed out")
    reg.register(mock_tls)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tls", "example.com:443", "--json"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.TIMEOUT
    assert err.getvalue() == ""
    data = json.loads(out.getvalue())
    assert data["status"] == "timeout"
    assert data["error"] == "Handshake timed out"

def test_cli_run_json_usage_error_stdout_empty():
    reg = create_default_registry()
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tcp", "example.com", "--json"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.USAGE_ERROR
    assert out.getvalue() == ""
    assert "Target port is required for TCP probe" in err.getvalue()

def test_cli_run_json_serialization_error_stdout_empty():
    reg = ProbeRegistry()
    bad_probe = MockProbe("bad_probe", ProbeStatus.SUCCESS, metrics={"bad": float("nan")})
    reg.register(bad_probe)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "bad_probe", "example.com", "--json"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.INTERNAL_ERROR
    assert out.getvalue() == ""
    assert "Internal error: Non-finite float value" in err.getvalue()

def test_cli_run_json_flag_placement():
    reg = ProbeRegistry()
    mock_dns = MockProbe("dns_resolve", ProbeStatus.SUCCESS)
    reg.register(mock_dns)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "dns", "example.com", "--timeout", "3.0", "--json"], stdout=out, stderr=err, registry=reg)
    assert code == ExitCode.OK
    assert err.getvalue() == ""
    data = json.loads(out.getvalue())
    assert data["probe"] == "dns_resolve"
    assert mock_dns.last_config == {"timeout_s": 3.0}

    out2 = io.StringIO()
    err2 = io.StringIO()
    code2 = cli_entry(["run", "dns", "example.com", "--json", "--timeout", "4.0"], stdout=out2, stderr=err2, registry=reg)
    assert code2 == ExitCode.OK
    assert err2.getvalue() == ""
    data2 = json.loads(out2.getvalue())
    assert data2["probe"] == "dns_resolve"
    assert mock_dns.last_config == {"timeout_s": 4.0}

def test_cli_run_without_json_preserves_text():
    reg = ProbeRegistry()
    mock_tcp = MockProbe("tcp_connect", ProbeStatus.SUCCESS)
    reg.register(mock_tcp)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["run", "tcp", "example.com:443"], stdout=out, stderr=err, registry=reg)

    assert code == ExitCode.OK
    val = out.getvalue()
    assert "Probe:    tcp_connect" in val
    assert "Status:   success" in val
    with pytest.raises(json.JSONDecodeError):
        json.loads(val)

def test_cli_run_tls_with_valid_sni():
    reg = ProbeRegistry()
    mock_tls = MockProbe("tls_handshake", ProbeStatus.SUCCESS)
    reg.register(mock_tls)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(
        ["run", "tls", "example.com:443", "--sni", "custom.sni.org"],
        stdout=out,
        stderr=err,
        registry=reg,
    )
    assert code == ExitCode.OK
    assert err.getvalue() == ""
    assert mock_tls.last_config == {"sni": "custom.sni.org"}

def test_cli_run_tls_with_no_sni():
    reg = ProbeRegistry()
    mock_tls = MockProbe("tls_handshake", ProbeStatus.SUCCESS)
    reg.register(mock_tls)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(
        ["run", "tls", "example.com:443", "--no-sni"],
        stdout=out,
        stderr=err,
        registry=reg,
    )
    assert code == ExitCode.OK
    assert err.getvalue() == ""
    assert mock_tls.last_config == {"no_sni": True}

def test_cli_run_tls_with_sni_and_timeout():
    reg = ProbeRegistry()
    mock_tls = MockProbe("tls_handshake", ProbeStatus.SUCCESS)
    reg.register(mock_tls)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(
        ["run", "tls", "example.com:443", "--timeout", "5.0", "--sni", "custom.sni.org"],
        stdout=out,
        stderr=err,
        registry=reg,
    )
    assert code == ExitCode.OK
    assert mock_tls.last_config == {"timeout_s": 5.0, "sni": "custom.sni.org"}

def test_cli_run_rejects_sni_for_non_tls_probes():
    reg = ProbeRegistry()
    reg.register(MockProbe("tcp_connect", ProbeStatus.SUCCESS))
    reg.register(MockProbe("dns_resolve", ProbeStatus.SUCCESS))
    reg.register(MockProbe("http_request", ProbeStatus.SUCCESS))

    for probe_arg in ["tcp", "dns", "http"]:
        out = io.StringIO()
        err = io.StringIO()
        if probe_arg == "dns":
            target = "example.com"
        elif probe_arg == "http":
            target = "http://example.com"
        else:
            target = "example.com:80"
        code = cli_entry(
            ["run", probe_arg, target, "--sni", "custom.sni.org"],
            stdout=out,
            stderr=err,
            registry=reg,
        )
        assert code == ExitCode.USAGE_ERROR
        assert "--sni is only supported for the TLS probe" in err.getvalue()

def test_cli_run_rejects_no_sni_for_non_tls_probes():
    reg = ProbeRegistry()
    reg.register(MockProbe("tcp_connect", ProbeStatus.SUCCESS))
    reg.register(MockProbe("dns_resolve", ProbeStatus.SUCCESS))
    reg.register(MockProbe("http_request", ProbeStatus.SUCCESS))

    for probe_arg in ["tcp", "dns", "http"]:
        out = io.StringIO()
        err = io.StringIO()
        if probe_arg == "dns":
            target = "example.com"
        elif probe_arg == "http":
            target = "http://example.com"
        else:
            target = "example.com:80"
        code = cli_entry(
            ["run", probe_arg, target, "--no-sni"],
            stdout=out,
            stderr=err,
            registry=reg,
        )
        assert code == ExitCode.USAGE_ERROR
        assert "--no-sni is only supported for the TLS probe" in err.getvalue()

def test_cli_run_rejects_conflicting_sni_and_no_sni():
    reg = ProbeRegistry()
    mock_tls = MockProbe("tls_handshake", ProbeStatus.SUCCESS)
    reg.register(mock_tls)

    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(
        ["run", "tls", "example.com:443", "--sni", "custom.sni.org", "--no-sni"],
        stdout=out,
        stderr=err,
        registry=reg,
    )
    assert code == ExitCode.USAGE_ERROR
    assert "not allowed with argument" in err.getvalue()

def test_cli_run_rejects_invalid_sni_hostname():
    reg = ProbeRegistry()
    mock_tls = MockProbe("tls_handshake", ProbeStatus.SUCCESS)
    reg.register(mock_tls)

    invalid_snis = ["127.0.0.1", "foo bar.com", "bad..com", "--sni=-bad.com"]
    for bad_sni in invalid_snis:
        out = io.StringIO()
        err = io.StringIO()
        args = ["run", "tls", "example.com:443", bad_sni] if bad_sni.startswith("--sni=") else ["run", "tls", "example.com:443", "--sni", bad_sni]
        code = cli_entry(
            args,
            stdout=out,
            stderr=err,
            registry=reg,
        )
        assert code == ExitCode.USAGE_ERROR
        assert "Invalid --sni hostname" in err.getvalue()
