import asyncio
import io
import json
import subprocess
import sys
import urllib.request
import pytest

from connscope.agent.server import AgentServer
from connscope.agent.server_runner import (
    ConfigurationError,
    RunnerConfig,
    load_runner_config,
    main,
    run_server,
)

def test_load_runner_config_defaults() -> None:
    env = {"CONNSCOPE_AUTH_TOKEN": "super-secret-token"}
    config = load_runner_config(env)

    assert config.auth_token == "super-secret-token"
    assert config.host == "127.0.0.1"
    assert config.port == 8088
    assert config.allow_private is False
    assert config.max_concurrency == 10
    assert config.max_connections == 50
    assert config.read_timeout_s == 5.0
    assert config.max_probe_timeout_s == 60.0
    assert config.shutdown_grace_s == 10.0
    assert config.outer_timeout_slack_s == 5.0
    assert config.log_level == "INFO"

def test_runner_config_repr_redacts_auth_token() -> None:
    config = RunnerConfig(auth_token="sensitive-super-secret-value-12345")
    repr_str = repr(config)

    assert "sensitive-super-secret-value-12345" not in repr_str
    assert "auth_token='[REDACTED]'" in repr_str

def test_load_runner_config_missing_or_empty_token() -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        load_runner_config({})
    assert "Missing required environment variable: CONNSCOPE_AUTH_TOKEN" in str(exc_info.value)

    with pytest.raises(ConfigurationError) as exc_info:
        load_runner_config({"CONNSCOPE_AUTH_TOKEN": ""})
    assert "CONNSCOPE_AUTH_TOKEN must be a non-empty string" in str(exc_info.value)

    with pytest.raises(ConfigurationError) as exc_info:
        load_runner_config({"CONNSCOPE_AUTH_TOKEN": "   "})
    assert "CONNSCOPE_AUTH_TOKEN must be a non-empty string" in str(exc_info.value)

def test_token_value_never_in_error_message() -> None:
    secret = "secret-token-xyz-987"
    env = {
        "CONNSCOPE_AUTH_TOKEN": secret,
        "CONNSCOPE_BIND_HOST": "0.0.0.0",
    }
    with pytest.raises(ConfigurationError) as exc_info:
        load_runner_config(env)
    assert secret not in str(exc_info.value)

def test_load_runner_config_valid_loopback_hosts() -> None:
    for host in ("127.0.0.1", "127.0.0.2", "::1", "[::1]"):
        env = {
            "CONNSCOPE_AUTH_TOKEN": "secret",
            "CONNSCOPE_BIND_HOST": host,
        }
        config = load_runner_config(env)
        assert config.host == host.strip("[]") or config.host == host

def test_load_runner_config_rejects_non_loopback_hosts() -> None:
    for bad_host in ("0.0.0.0", "192.168.1.1", "8.8.8.8", "localhost", "example.com", ""):
        env = {
            "CONNSCOPE_AUTH_TOKEN": "secret",
            "CONNSCOPE_BIND_HOST": bad_host,
        }
        with pytest.raises(ConfigurationError) as exc_info:
            load_runner_config(env)
        assert "CONNSCOPE_BIND_HOST" in str(exc_info.value)

def test_load_runner_config_valid_ports() -> None:
    for port_str, expected in [("8088", 8088), ("8000", 8000), ("0", 0), ("65535", 65535)]:
        env = {
            "CONNSCOPE_AUTH_TOKEN": "secret",
            "CONNSCOPE_BIND_PORT": port_str,
        }
        config = load_runner_config(env)
        assert config.port == expected

def test_load_runner_config_rejects_invalid_ports() -> None:
    for bad_port in ("-1", "65536", "70000", "abc", "8088.5", ""):
        env = {
            "CONNSCOPE_AUTH_TOKEN": "secret",
            "CONNSCOPE_BIND_PORT": bad_port,
        }
        with pytest.raises(ConfigurationError) as exc_info:
            load_runner_config(env)
        assert "CONNSCOPE_BIND_PORT" in str(exc_info.value)

def test_load_runner_config_allow_private() -> None:
    for val in ("true", "True", "TRUE", "1", "yes", "YES"):
        env = {"CONNSCOPE_AUTH_TOKEN": "secret", "CONNSCOPE_ALLOW_PRIVATE": val}
        config = load_runner_config(env)
        assert config.allow_private is True

    for val in ("false", "False", "FALSE", "0", "no", "NO", ""):
        env = {"CONNSCOPE_AUTH_TOKEN": "secret", "CONNSCOPE_ALLOW_PRIVATE": val}
        config = load_runner_config(env)
        assert config.allow_private is False

    for invalid in ("maybe", "enabled", "disabled", "2", "none"):
        env = {"CONNSCOPE_AUTH_TOKEN": "secret", "CONNSCOPE_ALLOW_PRIVATE": invalid}
        with pytest.raises(ConfigurationError) as exc_info:
            load_runner_config(env)
        assert "CONNSCOPE_ALLOW_PRIVATE" in str(exc_info.value)

def test_load_runner_config_custom_tunables() -> None:
    env = {
        "CONNSCOPE_AUTH_TOKEN": "secret",
        "CONNSCOPE_MAX_CONCURRENCY": "25",
        "CONNSCOPE_MAX_CONNECTIONS": "100",
        "CONNSCOPE_READ_TIMEOUT_S": "2.5",
        "CONNSCOPE_MAX_PROBE_TIMEOUT_S": "30.0",
        "CONNSCOPE_SHUTDOWN_GRACE_S": "5.0",
        "CONNSCOPE_OUTER_TIMEOUT_SLACK_S": "3.0",
        "CONNSCOPE_LOG_LEVEL": "debug",
    }
    config = load_runner_config(env)
    assert config.max_concurrency == 25
    assert config.max_connections == 100
    assert config.read_timeout_s == 2.5
    assert config.max_probe_timeout_s == 30.0
    assert config.shutdown_grace_s == 5.0
    assert config.outer_timeout_slack_s == 3.0
    assert config.log_level == "DEBUG"

def test_load_runner_config_invalid_tunables() -> None:
    cases = [
        ("CONNSCOPE_MAX_CONCURRENCY", "0"),
        ("CONNSCOPE_MAX_CONCURRENCY", "-5"),
        ("CONNSCOPE_MAX_CONCURRENCY", "abc"),
        ("CONNSCOPE_MAX_CONNECTIONS", "0"),
        ("CONNSCOPE_MAX_CONNECTIONS", "-1"),
        ("CONNSCOPE_READ_TIMEOUT_S", "0"),
        ("CONNSCOPE_READ_TIMEOUT_S", "-1.0"),
        ("CONNSCOPE_READ_TIMEOUT_S", "nan"),
        ("CONNSCOPE_MAX_PROBE_TIMEOUT_S", "0"),
        ("CONNSCOPE_MAX_PROBE_TIMEOUT_S", "inf"),
        ("CONNSCOPE_SHUTDOWN_GRACE_S", "-1.0"),
        ("CONNSCOPE_OUTER_TIMEOUT_SLACK_S", "-0.1"),
        ("CONNSCOPE_LOG_LEVEL", "VERBOSE"),
    ]
    for key, val in cases:
        env = {"CONNSCOPE_AUTH_TOKEN": "secret", key: val}
        with pytest.raises(ConfigurationError) as exc_info:
            load_runner_config(env)
        assert key in str(exc_info.value)

@pytest.mark.asyncio
async def test_run_server_lifecycle_and_health_check() -> None:
    config = RunnerConfig(
        host="127.0.0.1",
        port=0,
        auth_token="test-runner-token",
        allow_private=False,
    )
    stop_event = asyncio.Event()
    ready_event = asyncio.Event()
    server_ref: list[AgentServer] = []

    def on_ready(srv: AgentServer) -> None:
        server_ref.append(srv)
        ready_event.set()

    runner_task = asyncio.create_task(
        run_server(config, stop_event=stop_event, ready_callback=on_ready)
    )

    await asyncio.wait_for(ready_event.wait(), timeout=3.0)
    assert len(server_ref) == 1
    server = server_ref[0]
    assert server.is_running
    assert server.port > 0

    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        req = f"GET /v1/health HTTP/1.1\r\nHost: {server.host}:{server.port}\r\n\r\n".encode("iso-8859-1")
        writer.write(req)
        await writer.drain()
        raw_resp = await reader.read(4096)
    finally:
        writer.close()
        await writer.wait_closed()

    assert b"200 OK" in raw_resp
    assert b'"status": "ok"' in raw_resp or b'"status":"ok"' in raw_resp

    stop_event.set()
    await asyncio.wait_for(runner_task, timeout=3.0)

    assert not server.is_running

def test_main_help_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--help"])
    assert code == 0
    captured = capsys.readouterr()
    assert "ConnScope Agent Server Production Runner" in captured.out
    assert "CONNSCOPE_AUTH_TOKEN" in captured.out

def test_main_unknown_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--unrecognized-option"])
    assert code == 2
    captured = capsys.readouterr()
    assert "unrecognized arguments" in captured.err

def test_main_missing_auth_token(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([], env={})
    assert code == 1
    captured = capsys.readouterr()
    assert "Configuration error: Missing required environment variable: CONNSCOPE_AUTH_TOKEN" in captured.err

def test_main_invalid_host(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([], env={"CONNSCOPE_AUTH_TOKEN": "tok", "CONNSCOPE_BIND_HOST": "invalid-host"})
    assert code == 1
    captured = capsys.readouterr()
    assert "Configuration error: Invalid CONNSCOPE_BIND_HOST" in captured.err

def test_module_execution_help() -> None:
    res = subprocess.run(
        [sys.executable, "-m", "connscope.agent.server_runner", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    assert "CONNSCOPE_AUTH_TOKEN" in res.stdout

def test_module_execution_missing_token() -> None:
    res = subprocess.run(
        [sys.executable, "-m", "connscope.agent.server_runner"],
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 1
    assert "Configuration error: Missing required environment variable: CONNSCOPE_AUTH_TOKEN" in res.stderr
