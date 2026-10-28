import asyncio
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any
import pytest

from connscope.adapters import (
    EngineType,
    FailureStage,
    ProtocolType,
    SecurityType,
    TransportType,
    XrayVlessTcpRealityAdapter,
    XrayVmessWebSocketTlsAdapter,
    generate_xray_vmess_ws_tls_client_config,
)
from connscope.adapters.security import resolve_safe_executable
from connscope.adapters.xray import generate_xray_client_config
from connscope.core import ProbeStatus, Target

TEST_REALITY_PUBKEY = "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk"
TEST_CLIENT_UUID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"

def load_real_xray_test_settings() -> tuple[Target | None, dict[str, Any] | None, str | None]:
    if os.environ.get("CONNSCOPE_TEST_REAL_XRAY") != "1":
        return None, None, "CONNSCOPE_TEST_REAL_XRAY=1 not set"

    raw_json = os.environ.get("CONNSCOPE_REAL_XRAY_CONFIG")
    if raw_json and raw_json.strip():
        try:
            cfg = json.loads(raw_json.strip())
            server_host = (
                cfg.get("server_host")
                or cfg.get("server_address")
                or cfg.get("server")
                or cfg.get("host")
            )
            server_port = int(cfg.get("server_port") or cfg.get("port", 443))
            if not server_host:
                return None, None, "CONNSCOPE_REAL_XRAY_CONFIG missing server_host/port"
            target = Target(host=server_host, port=server_port)
            return target, cfg, None
        except Exception as exc:
            return None, None, f"Failed to parse CONNSCOPE_REAL_XRAY_CONFIG: {exc}"

    server_host = os.environ.get("CONNSCOPE_REAL_XRAY_SERVER") or os.environ.get("CONNSCOPE_REAL_XRAY_HOST")
    raw_port = os.environ.get("CONNSCOPE_REAL_XRAY_PORT", "443")
    uuid_str = os.environ.get("CONNSCOPE_REAL_XRAY_UUID")
    pubkey = os.environ.get("CONNSCOPE_REAL_XRAY_PUBLIC_KEY") or os.environ.get("CONNSCOPE_REAL_XRAY_PASSWORD")
    short_id = os.environ.get("CONNSCOPE_REAL_XRAY_SHORT_ID", "")
    server_name = os.environ.get("CONNSCOPE_REAL_XRAY_SERVER_NAME")
    test_url = os.environ.get("CONNSCOPE_REAL_XRAY_TEST_URL", "http://cp.cloudflare.com/generate_204")

    missing = []
    if not server_host:
        missing.append("CONNSCOPE_REAL_XRAY_SERVER")
    if not uuid_str:
        missing.append("CONNSCOPE_REAL_XRAY_UUID")
    if not pubkey:
        missing.append("CONNSCOPE_REAL_XRAY_PUBLIC_KEY")
    if not server_name:
        missing.append("CONNSCOPE_REAL_XRAY_SERVER_NAME")

    if missing:
        return None, None, f"Missing required environment variables: {', '.join(missing)}"

    try:
        port = int(raw_port)
        target = Target(host=server_host, port=port)
    except Exception as exc:
        return None, None, f"Invalid target host/port ({server_host}:{raw_port}): {exc}"

    cfg = {
        "uuid": uuid_str,
        "public_key": pubkey,
        "short_id": short_id,
        "server_name": server_name,
        "test_url": test_url,
    }
    return target, cfg, None

def test_real_xray_binary_detection_and_allowlist():
    if os.environ.get("CONNSCOPE_TEST_REAL_XRAY") != "1":
        pytest.skip("Optional real Xray integration test skipped (set CONNSCOPE_TEST_REAL_XRAY=1 to enable)")

    adapter = XrayVlessTcpRealityAdapter()
    ok, exe_path = adapter.check_executable()
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted Xray executable found on host: {exe_path}")

    assert any(exe_path.startswith(d) for d in ("/usr/local/bin", "/usr/bin", "/bin"))

    res = subprocess.run([exe_path, "version"], capture_output=True, text=True, timeout=5.0)
    assert res.returncode == 0
    assert "Xray" in res.stdout

def test_real_xray_config_validation_and_schema_compatibility(tmp_path):
    if os.environ.get("CONNSCOPE_TEST_REAL_XRAY") != "1":
        pytest.skip("Optional real Xray integration test skipped (set CONNSCOPE_TEST_REAL_XRAY=1 to enable)")

    adapter = XrayVlessTcpRealityAdapter()
    ok, exe_path = adapter.check_executable()
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted Xray executable found on host: {exe_path}")

    target = Target(host="192.0.2.1", port=443)

    cfg_dual = {
        "uuid": TEST_CLIENT_UUID,
        "public_key": TEST_REALITY_PUBKEY,
        "short_id": "0123456789abcdef",
        "server_name": "www.apple.com",
    }
    xray_cfg_dual = generate_xray_client_config(target, cfg_dual, 10808, 10809)
    f_dual = tmp_path / "config_dual.json"
    f_dual.write_text(json.dumps(xray_cfg_dual), encoding="utf-8")

    ok_dual, msg_dual = adapter.test_configuration(f_dual, executable=exe_path)
    assert ok_dual is True, f"Dual-field config validation failed: {msg_dual}"
    assert "Configuration OK" in msg_dual

    cfg_pass_only = json.loads(json.dumps(xray_cfg_dual))
    reality_sec = cfg_pass_only["outbounds"][0]["streamSettings"]["realitySettings"]
    del reality_sec["publicKey"]
    assert "password" in reality_sec and "publicKey" not in reality_sec
    f_pass = tmp_path / "config_pass.json"
    f_pass.write_text(json.dumps(cfg_pass_only), encoding="utf-8")

    ok_pass, msg_pass = adapter.test_configuration(f_pass, executable=exe_path)
    assert ok_pass is True, f"Modern password schema validation failed: {msg_pass}"
    assert "Configuration OK" in msg_pass

    cfg_legacy = json.loads(json.dumps(xray_cfg_dual))
    reality_sec_legacy = cfg_legacy["outbounds"][0]["streamSettings"]["realitySettings"]
    del reality_sec_legacy["password"]
    assert "publicKey" in reality_sec_legacy and "password" not in reality_sec_legacy
    f_legacy = tmp_path / "config_legacy.json"
    f_legacy.write_text(json.dumps(cfg_legacy), encoding="utf-8")

    ok_legacy, msg_legacy = adapter.test_configuration(f_legacy, executable=exe_path)
    assert ok_legacy is True, f"Legacy publicKey schema validation failed: {msg_legacy}"
    assert "Configuration OK" in msg_legacy

    cfg_missing = json.loads(json.dumps(xray_cfg_dual))
    reality_sec_missing = cfg_missing["outbounds"][0]["streamSettings"]["realitySettings"]
    del reality_sec_missing["password"]
    del reality_sec_missing["publicKey"]
    f_missing = tmp_path / "config_missing.json"
    f_missing.write_text(json.dumps(cfg_missing), encoding="utf-8")

    ok_missing, msg_missing = adapter.test_configuration(f_missing, executable=exe_path)
    assert ok_missing is False
    assert "empty \"password\"" in msg_missing or "Failed to build REALITY config" in msg_missing

@pytest.mark.asyncio
async def test_real_xray_process_lifecycle_and_cleanup():
    if os.environ.get("CONNSCOPE_TEST_REAL_XRAY") != "1":
        pytest.skip("Optional real Xray integration test skipped (set CONNSCOPE_TEST_REAL_XRAY=1 to enable)")

    adapter = XrayVlessTcpRealityAdapter()
    ok, exe_path = adapter.check_executable()
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted Xray executable found on host: {exe_path}")

    target = Target(host="127.0.0.1", port=65534)
    cfg = {
        "uuid": TEST_CLIENT_UUID,
        "public_key": TEST_REALITY_PUBKEY,
        "short_id": "0123456789abcdef",
        "server_name": "www.apple.com",
        "timeout_s": 2.0,
        "startup_timeout_s": 1.5,
        "test_url": "http://127.0.0.1:65533/ping",
    }

    result = await adapter.run(target, config=cfg)

    assert result.status == ProbeStatus.FAILED
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.metrics["local_ready_ms"] > 0
    assert result.metrics["total_ms"] > 0

    assert TEST_CLIENT_UUID not in str(result.error)
    assert TEST_REALITY_PUBKEY not in str(result.error)
    assert result.details["redacted_config"]["uuid"] == "[REDACTED]"
    assert result.details["redacted_config"]["public_key"] == "[REDACTED]"

def test_real_xray_vmess_config_validation(tmp_path):
    if os.environ.get("CONNSCOPE_TEST_REAL_XRAY") != "1":
        pytest.skip("Optional real Xray integration test skipped (set CONNSCOPE_TEST_REAL_XRAY=1 to enable)")

    adapter = XrayVmessWebSocketTlsAdapter()
    ok, exe_path = adapter.check_executable()
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted Xray executable found on host: {exe_path}")

    target = Target(host="vmess.example.org", port=443)
    cfg = {
        "uuid": TEST_CLIENT_UUID,
        "server_name": "vmess.example.org",
        "path": "/ws",
        "alter_id": 0,
        "security": "auto",
        "host_header": "vmess.example.org",
        "verify_cert": True,
    }

    xray_cfg = generate_xray_vmess_ws_tls_client_config(target, cfg, 10810, 10811)
    cfg_file = tmp_path / "vmess_config.json"
    cfg_file.write_text(json.dumps(xray_cfg, indent=2), encoding="utf-8")

    ok_valid, msg = adapter.test_configuration(cfg_file, executable=exe_path)
    assert ok_valid is True, f"Real Xray VMess config validation failed: {msg}"
    assert "Configuration OK" in msg

    bad_cfg_file = tmp_path / "bad_vmess.json"
    bad_cfg_file.write_text('{"inbounds": "invalid"}', encoding="utf-8")
    ok_bad, _ = adapter.test_configuration(bad_cfg_file, executable=exe_path)
    assert ok_bad is False

@pytest.mark.asyncio
async def test_real_xray_vmess_process_lifecycle_and_cleanup():
    if os.environ.get("CONNSCOPE_TEST_REAL_XRAY") != "1":
        pytest.skip("Optional real Xray integration test skipped (set CONNSCOPE_TEST_REAL_XRAY=1 to enable)")

    adapter = XrayVmessWebSocketTlsAdapter()
    ok, exe_path = adapter.check_executable()
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted Xray executable found on host: {exe_path}")

    target = Target(host="127.0.0.1", port=65534)
    cfg = {
        "uuid": TEST_CLIENT_UUID,
        "server_name": "vmess.example.org",
        "path": "/ws",
        "timeout_s": 2.0,
        "startup_timeout_s": 1.5,
        "test_url": "http://127.0.0.1:65533/ping",
    }

    result = await adapter.run(target, config=cfg)

    assert result.status == ProbeStatus.FAILED
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.metrics["local_ready_ms"] > 0
    assert result.metrics["total_ms"] > 0
    assert TEST_CLIENT_UUID not in str(result.error)
    assert result.details["redacted_config"]["uuid"] == "[REDACTED]"

@pytest.mark.asyncio
async def test_real_xray_tunnel_and_data_transfer():
    target, cfg, reason = load_real_xray_test_settings()
    if target is None or cfg is None:
        pytest.skip(f"Real Xray live tunnel test skipped: {reason}")

    adapter = XrayVlessTcpRealityAdapter()
    ok, exe_path = adapter.check_executable()
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted Xray executable found on host: {exe_path}")

    result = await adapter.run(target, config=cfg)

    assert cfg["uuid"] not in str(result.error or "")
    if "public_key" in cfg:
        assert cfg["public_key"] not in str(result.error or "")
    if "password" in cfg:
        assert cfg["password"] not in str(result.error or "")

    assert result.status == ProbeStatus.SUCCESS
    assert result.details["tunnel_established"] is True
    assert result.details["data_transfer_completed"] is True
    assert result.details["failure_stage"] is None
    assert result.metrics["handshake_ms"] > 0
    assert result.metrics["data_transfer_ms"] > 0
