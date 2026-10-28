import asyncio
import io
import json
import os
from pathlib import Path
import signal
import ssl
import stat
import subprocess
import sys
import time
from unittest.mock import AsyncMock, patch
import pytest

from connscope.adapters import (
    AdapterCapability,
    AdapterStatus,
    EngineType,
    ExecutableRequirement,
    FailureStage,
    ProtocolType,
    SecurityType,
    SingBoxVlessTcpRealityAdapter,
    TransportType,
    generate_singbox_client_config,
)
from connscope.adapters.process import (
    TunnelVerificationResult,
    read_bounded_stream,
    terminate_process_tree,
    verify_tunnel_and_data_transfer,
)
from connscope.agent import AgentServer
from connscope.agent.execution import UnsupportedProbeError, prepare_probe_config
from connscope.cli.main import ExitCode, cli_entry
from connscope.core import ProbeRegistry, ProbeResult, ProbeStatus, Target
from connscope.serialization import result_to_dict

FAKE_SINGBOX_SCRIPT = """#!/usr/bin/env python3
import sys
import json
import socket
import time
import os
import signal

mode = os.environ.get("FAKE_SINGBOX_MODE", "success")

if mode == "crash":
    secret_uuid = os.environ.get("TEST_UUID", "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")
    secret_pubkey = os.environ.get("TEST_PUBKEY", "pubkey1234567890abcdef")
    sys.stderr.write(f"FATAL[0000] parse config: invalid reality public_key={secret_pubkey} uuid={secret_uuid}\\n")
    sys.exit(2)

if mode == "hang":
    time.sleep(300)
    sys.exit(0)

if "check" in sys.argv:
    cfg_path = None
    for i, arg in enumerate(sys.argv):
        if arg == "-c" and i + 1 < len(sys.argv):
            cfg_path = sys.argv[i + 1]
            break
    if not cfg_path or not os.path.isfile(cfg_path):
        sys.stderr.write("Config file missing\\n")
        sys.exit(1)
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if "outbounds" not in cfg or not cfg["outbounds"]:
        sys.stderr.write("FATAL missing outbounds\\n")
        sys.exit(1)
    sys.stdout.write("Configuration OK.\\n")
    sys.exit(0)

cfg_path = None
for i, arg in enumerate(sys.argv):
    if arg == "-c" and i + 1 < len(sys.argv):
        cfg_path = sys.argv[i + 1]
        break

if not cfg_path or not os.path.isfile(cfg_path):
    sys.stderr.write("Config file missing\\n")
    sys.exit(1)

with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

socks_port = None
for inbound in cfg.get("inbounds", []):
    if inbound.get("type") == "socks":
        socks_port = inbound.get("listen_port")
        break

if not socks_port:
    sys.stderr.write("FATAL: no socks inbound found\\n")
    sys.exit(1)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", socks_port))
srv.listen(10)

def handle_sigterm(signum, frame):
    try:
        srv.close()
    except Exception:
        pass
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)

while True:
    try:
        conn, addr = srv.accept()
    except Exception:
        break
    try:
        greeting = conn.recv(3)
        if not greeting:
            conn.close()
            continue
        conn.sendall(bytes([5, 0]))

        cmd = conn.recv(256)
        if not cmd:
            conn.close()
            continue

        if mode == "handshake_fail":
            conn.sendall(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]))
            conn.close()
            continue

        conn.sendall(bytes([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]))

        if mode == "data_transfer_fail":
            req = conn.recv(1024)
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n")
            conn.close()
            continue

        req = conn.recv(1024)
        conn.sendall(b"HTTP/1.1 204 No Content\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n")
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
"""

@pytest.fixture
def fake_singbox_binary(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    sb_path = bin_dir / "sing-box"
    sb_path.write_text(FAKE_SINGBOX_SCRIPT, encoding="utf-8")
    os.chmod(sb_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return str(sb_path)

@pytest.fixture
def valid_singbox_config():
    return {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "pubkey1234567890abcdef1234567890abcdef123=",
        "short_id": "0123456789abcdef",
        "server_name": "target.domain.com",
        "fingerprint": "chrome",
        "flow": "xtls-rprx-vision",
        "timeout_s": 5.0,
        "startup_timeout_s": 2.0,
    }

@pytest.mark.asyncio
async def test_singbox_execution_success(fake_singbox_binary, valid_singbox_config, monkeypatch):
    monkeypatch.setenv("FAKE_SINGBOX_MODE", "success")
    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)):
        result = await adapter.run(target, config=valid_singbox_config)

    assert result.status == ProbeStatus.SUCCESS
    assert result.error is None
    assert result.details["tunnel_established"] is True
    assert result.details["data_transfer_completed"] is True
    assert result.details["http_status"] == 204
    assert result.details["failure_stage"] is None

    assert "local_ready_ms" in result.metrics
    assert "handshake_ms" in result.metrics
    assert "data_transfer_ms" in result.metrics
    assert "total_ms" in result.metrics
    assert result.metrics["total_ms"] > 0

    redacted = result.details["redacted_config"]
    assert redacted["uuid"] == "[REDACTED]"
    assert redacted["public_key"] == "[REDACTED]"
    assert redacted["short_id"] == "[REDACTED]"
    assert redacted["server_name"] == "target.domain.com"

@pytest.mark.asyncio
async def test_singbox_execution_handshake_failure(fake_singbox_binary, valid_singbox_config, monkeypatch):
    monkeypatch.setenv("FAKE_SINGBOX_MODE", "handshake_fail")
    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)):
        result = await adapter.run(target, config=valid_singbox_config)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False
    assert "Tunnel establishment failed" in result.error
    assert "handshake_ms" in result.metrics

@pytest.mark.asyncio
async def test_singbox_execution_data_transfer_failure(fake_singbox_binary, valid_singbox_config, monkeypatch):
    monkeypatch.setenv("FAKE_SINGBOX_MODE", "data_transfer_fail")
    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)):
        result = await adapter.run(target, config=valid_singbox_config)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.DATA_TRANSFER.value
    assert result.details["tunnel_established"] is True
    assert result.details["data_transfer_completed"] is False
    assert result.details["http_status"] == 502
    assert "Data transfer failed with HTTP 502" in result.error
    assert "data_transfer_ms" in result.metrics

@pytest.mark.asyncio
async def test_singbox_execution_startup_crash_and_secret_redaction(fake_singbox_binary, valid_singbox_config, monkeypatch):
    monkeypatch.setenv("FAKE_SINGBOX_MODE", "crash")
    monkeypatch.setenv("TEST_UUID", valid_singbox_config["uuid"])
    monkeypatch.setenv("TEST_PUBKEY", valid_singbox_config["public_key"])

    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)):
        result = await adapter.run(target, config=valid_singbox_config)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.PROCESS_SPAWN.value
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False

    assert valid_singbox_config["uuid"] not in result.error
    assert valid_singbox_config["public_key"] not in result.error
    assert "[REDACTED]" in result.error

@pytest.mark.asyncio
async def test_singbox_execution_startup_hang_timeout(fake_singbox_binary, valid_singbox_config, monkeypatch):
    monkeypatch.setenv("FAKE_SINGBOX_MODE", "hang")
    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    short_timeout_cfg = dict(valid_singbox_config)
    short_timeout_cfg["timeout_s"] = 0.5
    short_timeout_cfg["startup_timeout_s"] = 0.3

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)):
        result = await adapter.run(target, config=short_timeout_cfg)

    assert result.status in (ProbeStatus.FAILED, ProbeStatus.TIMEOUT)
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False

@pytest.mark.asyncio
async def test_singbox_concurrent_executions_no_port_collision(fake_singbox_binary, valid_singbox_config, monkeypatch):
    monkeypatch.setenv("FAKE_SINGBOX_MODE", "success")
    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)):
        results = await asyncio.gather(
            adapter.run(target, config=valid_singbox_config),
            adapter.run(target, config=valid_singbox_config),
            adapter.run(target, config=valid_singbox_config),
        )

    ports = [r.details["local_port"] for r in results]
    assert len(set(ports)) == 3, f"Port collision detected among concurrent runs: {ports}"
    for r in results:
        assert r.status == ProbeStatus.SUCCESS
        assert r.details["tunnel_established"] is True
        assert r.details["data_transfer_completed"] is True

@pytest.mark.asyncio
async def test_singbox_invalid_target_and_config():
    adapter = SingBoxVlessTcpRealityAdapter()

    result = await adapter.run(Target(host="example.com", port=None), config={"uuid": "123"})
    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.CONFIG_GENERATION.value
    assert "Target port is required" in result.error

    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        Target(host="example.com", port=99999)

    result = await adapter.run(Target(host="example.com", port=443), config=None)
    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.CONFIG_GENERATION.value

@pytest.mark.asyncio
async def test_singbox_remote_agent_isolation_rejects_external_adapters():
    target = Target(host="example.com", port=443)

    with pytest.raises(UnsupportedProbeError, match="Unsupported probe 'singbox_vless_tcp_reality'"):
        prepare_probe_config("singbox_vless_tcp_reality", target, config={})

    custom_reg = ProbeRegistry()
    adapter = SingBoxVlessTcpRealityAdapter()
    custom_reg.register(adapter)

    async with AgentServer(port=0, auth_token="agent-token", resolver=lambda _: ["93.184.216.34"]) as server:
        server.engine.registry.register(adapter)

        payload = {
            "protocol_version": 1,
            "probe": "singbox_vless_tcp_reality",
            "target": {"host": "example.com", "port": 443},
            "config": {"uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"},
        }
        body = json.dumps(payload).encode("utf-8")
        raw_req = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization: Bearer agent-token\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("iso-8859-1") + body

        reader, writer = await asyncio.open_connection(server.host, server.port)
        writer.write(raw_req)
        await writer.drain()
        resp_data = await reader.read(4096)
        writer.close()
        await writer.wait_closed()

        parts = resp_data.split(b"\r\n\r\n", 1)
        status_line = parts[0].split(b"\r\n")[0].decode()
        assert "404" in status_line
        data = json.loads(parts[1].decode("utf-8"))
        assert data["error"] == "unknown_probe"

def test_singbox_cli_execution_with_config_option(fake_singbox_binary, valid_singbox_config, monkeypatch):
    monkeypatch.setenv("FAKE_SINGBOX_MODE", "success")
    adapter = SingBoxVlessTcpRealityAdapter()
    reg = ProbeRegistry()
    reg.register(adapter)

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)):
        out = io.StringIO()
        err = io.StringIO()
        cfg_str = json.dumps(valid_singbox_config)
        code = cli_entry(
            ["run", "singbox_vless_tcp_reality", "target.domain.com:443", "--config", cfg_str, "--json"],
            stdout=out,
            stderr=err,
            registry=reg,
        )

        assert code == ExitCode.OK
        val = json.loads(out.getvalue())
        assert val["probe"] == "singbox_vless_tcp_reality"
        assert val["status"] == "success"
        assert val["details"]["tunnel_established"] is True
        assert val["details"]["data_transfer_completed"] is True
        assert val["details"]["redacted_config"]["uuid"] == "[REDACTED]"

@pytest.mark.asyncio
async def test_singbox_endpoint_semantics_separation(tmp_path, valid_singbox_config):
    custom_script = """#!/usr/bin/env python3
import sys, json, socket, signal, os

cfg_path = sys.argv[sys.argv.index("-c") + 1]
with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

with open(os.environ["LOG_CFG"], "w", encoding="utf-8") as f:
    json.dump(cfg, f)

socks_port = None
for inb in cfg["inbounds"]:
    if inb["type"] == "socks":
        socks_port = inb["listen_port"]
        break

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", socks_port))
srv.listen(5)

def on_term(s, f):
    try:
        srv.close()
    except Exception:
        pass
    sys.exit(0)
signal.signal(signal.SIGTERM, on_term)

while True:
    try:
        conn, _ = srv.accept()
    except Exception:
        break
    try:
        g = conn.recv(3)
        conn.sendall(bytes([5, 0]))
        cmd = conn.recv(512)
        with open(os.environ["LOG_CMD"], "wb") as f:
            f.write(cmd)
        conn.sendall(bytes([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]))
        req = conn.recv(2048)
        with open(os.environ["LOG_REQ"], "wb") as f:
            f.write(req)
        conn.sendall(b"HTTP/1.1 204 No Content\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n")
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
"""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    sb_bin = bin_dir / "sing-box"
    sb_bin.write_text(custom_script, encoding="utf-8")
    os.chmod(sb_bin, 0o755)

    log_cfg = tmp_path / "cfg.json"
    log_cmd = tmp_path / "cmd.bin"
    log_req = tmp_path / "req.bin"

    monkeypatch_env = {
        "LOG_CFG": str(log_cfg),
        "LOG_CMD": str(log_cmd),
        "LOG_REQ": str(log_req),
    }

    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="remote.singbox-vless-node.com", port=8443)
    test_cfg = dict(valid_singbox_config)
    test_cfg["test_url"] = "http://probe-dest.example.org:9000/v1/ping"

    with patch.dict(os.environ, monkeypatch_env), patch.object(adapter, "check_executable", return_value=(True, str(sb_bin))):
        result = await adapter.run(target, config=test_cfg)

    assert result.status == ProbeStatus.SUCCESS
    assert result.details["tunnel_established"] is True
    assert result.details["data_transfer_completed"] is True

    with open(log_cfg, "r", encoding="utf-8") as f:
        cfg_data = json.load(f)
    vless_out = cfg_data["outbounds"][0]
    assert vless_out["type"] == "vless"
    assert vless_out["server"] == "remote.singbox-vless-node.com"
    assert vless_out["server_port"] == 8443

    with open(log_cmd, "rb") as f:
        cmd_bytes = f.read()
    assert cmd_bytes[0] == 0x05
    assert cmd_bytes[1] == 0x01
    assert cmd_bytes[3] == 0x03
    domain_len = cmd_bytes[4]
    domain = cmd_bytes[5 : 5 + domain_len].decode("ascii")
    port = int.from_bytes(cmd_bytes[5 + domain_len : 5 + domain_len + 2], "big")
    assert domain == "probe-dest.example.org"
    assert port == 9000

    with open(log_req, "rb") as f:
        req_bytes = f.read()
    assert req_bytes.startswith(b"GET /v1/ping HTTP/1.1\r\n")
    assert b"Host: probe-dest.example.org:9000\r\n" in req_bytes

@pytest.mark.asyncio
async def test_singbox_port_collision_bounded_retry(fake_singbox_binary, valid_singbox_config, monkeypatch):
    monkeypatch.setenv("FAKE_SINGBOX_MODE", "success")
    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    call_count = 0
    from connscope.adapters import singbox as sb_mod
    orig_wait = sb_mod.wait_for_proxy_ready

    async def mock_wait_retry(host, port, proc, timeout_s):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return False
        return await orig_wait(host, port, proc, timeout_s)

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)), patch(
        "connscope.adapters.singbox.wait_for_proxy_ready", side_effect=mock_wait_retry
    ):
        result = await adapter.run(target, config=valid_singbox_config)

    assert result.status == ProbeStatus.SUCCESS
    assert call_count == 2
    assert result.details["tunnel_established"] is True

    call_count = 0
    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)), patch(
        "connscope.adapters.singbox.wait_for_proxy_ready", return_value=False
    ):
        fail_result = await adapter.run(target, config=valid_singbox_config)

    assert fail_result.status == ProbeStatus.FAILED
    assert fail_result.details["failure_stage"] == FailureStage.PROCESS_SPAWN.value

@pytest.mark.asyncio
async def test_singbox_https_adapter_run_failure_reporting(fake_singbox_binary, valid_singbox_config, monkeypatch):
    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    cfg = dict(valid_singbox_config)
    cfg["test_url"] = "https://untrusted.server.com/status"

    mock_res = TunnelVerificationResult(
        tunnel_established=True,
        data_transfer_completed=False,
        handshake_ms=25.0,
        data_transfer_ms=0.0,
        http_status=None,
        error_message="TLS certificate verification failed: self-signed certificate",
        tls_verified=False,
        tls_handshake_ms=15.0,
    )

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)), patch(
        "connscope.adapters.singbox.wait_for_proxy_ready", return_value=True
    ), patch(
        "connscope.adapters.singbox.verify_tunnel_and_data_transfer", return_value=mock_res
    ):
        result = await adapter.run(target, config=cfg)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.details["tunnel_established"] is True
    assert result.details["tls_verified"] is False
    assert result.details["verify_cert"] is True
    assert result.details["tls_verification_mode"] == "enforced"
    assert result.details["verified_data_transfer"] is False
    assert result.details["data_transfer_completed"] is False
    assert "TLS certificate verification failed" in result.error
    assert result.metrics["handshake_ms"] == 25.0
    assert result.metrics["tls_handshake_ms"] == 15.0

@pytest.mark.asyncio
async def test_singbox_https_adapter_run_verify_cert_false_success(fake_singbox_binary, valid_singbox_config, monkeypatch):
    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    cfg = dict(valid_singbox_config)
    cfg["test_url"] = "https://self-signed.server.com/status"
    cfg["verify_cert"] = False

    mock_res = TunnelVerificationResult(
        tunnel_established=True,
        data_transfer_completed=True,
        handshake_ms=30.0,
        data_transfer_ms=45.0,
        http_status=200,
        error_message=None,
        tls_verified=False,
        tls_handshake_ms=18.0,
        tls_handshake_completed=True,
    )

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)), patch(
        "connscope.adapters.singbox.wait_for_proxy_ready", return_value=True
    ), patch(
        "connscope.adapters.singbox.verify_tunnel_and_data_transfer", return_value=mock_res
    ):
        result = await adapter.run(target, config=cfg)

    assert result.status == ProbeStatus.SUCCESS
    assert result.error is None
    assert result.details["failure_stage"] is None
    assert result.details["tunnel_established"] is True
    assert result.details["data_transfer_completed"] is True
    assert result.details["verified_data_transfer"] is False
    assert result.details["verify_cert"] is False
    assert result.details["tls_verification_mode"] == "disabled"
    assert result.details["tls_verified"] is False
    assert result.details["http_status"] == 200
    assert result.metrics["handshake_ms"] == 30.0
    assert result.metrics["tls_handshake_ms"] == 18.0
    assert result.metrics["data_transfer_ms"] == 45.0

@pytest.mark.asyncio
async def test_singbox_https_adapter_run_verify_cert_true_success(fake_singbox_binary, valid_singbox_config, monkeypatch):
    adapter = SingBoxVlessTcpRealityAdapter()
    target = Target(host="target.domain.com", port=443)

    cfg = dict(valid_singbox_config)
    cfg["test_url"] = "https://trusted.server.com/status"
    cfg["verify_cert"] = True

    mock_res = TunnelVerificationResult(
        tunnel_established=True,
        data_transfer_completed=True,
        handshake_ms=28.0,
        data_transfer_ms=42.0,
        http_status=204,
        error_message=None,
        tls_verified=True,
        tls_handshake_ms=16.0,
        tls_handshake_completed=True,
    )

    with patch.object(adapter, "check_executable", return_value=(True, fake_singbox_binary)), patch(
        "connscope.adapters.singbox.wait_for_proxy_ready", return_value=True
    ), patch(
        "connscope.adapters.singbox.verify_tunnel_and_data_transfer", return_value=mock_res
    ):
        result = await adapter.run(target, config=cfg)

    assert result.status == ProbeStatus.SUCCESS
    assert result.error is None
    assert result.details["failure_stage"] is None
    assert result.details["tunnel_established"] is True
    assert result.details["data_transfer_completed"] is True
    assert result.details["verified_data_transfer"] is True
    assert result.details["verify_cert"] is True
    assert result.details["tls_verification_mode"] == "enforced"
    assert result.details["tls_verified"] is True
    assert result.details["http_status"] == 204
