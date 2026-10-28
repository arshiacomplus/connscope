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
    SingBoxVlessTcpRealityAdapter,
    SingBoxVmessWebSocketTlsAdapter,
    TransportType,
    generate_singbox_client_config,
    generate_singbox_vmess_ws_tls_client_config,
)
from connscope.adapters.security import resolve_safe_executable
from connscope.core import ProbeStatus, Target

TEST_REALITY_PUBKEY = "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk"
TEST_CLIENT_UUID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"

def get_singbox_lookup_paths() -> tuple[str, ...]:
    paths = ["/usr/local/bin", "/usr/bin", "/bin"]
    extra_dir = os.environ.get("CONNSCOPE_SINGBOX_DIR")
    if extra_dir and os.path.isdir(extra_dir):
        paths.insert(0, extra_dir)
    user_v2rayn = Path.home() / ".local/share/v2rayN/bin/sing_box"
    if user_v2rayn.is_dir():
        paths.append(str(user_v2rayn))
    return tuple(paths)

def load_real_singbox_test_settings() -> tuple[Target | None, dict[str, Any] | None, str | None]:
    if os.environ.get("CONNSCOPE_TEST_REAL_SINGBOX") != "1":
        return None, None, "CONNSCOPE_TEST_REAL_SINGBOX=1 not set"

    raw_json = os.environ.get("CONNSCOPE_REAL_SINGBOX_CONFIG")
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
                return None, None, "CONNSCOPE_REAL_SINGBOX_CONFIG missing server_host/port"
            target = Target(host=server_host, port=server_port)
            return target, cfg, None
        except Exception as exc:
            return None, None, f"Failed to parse CONNSCOPE_REAL_SINGBOX_CONFIG: {exc}"

    server_host = os.environ.get("CONNSCOPE_REAL_SINGBOX_SERVER") or os.environ.get("CONNSCOPE_REAL_SINGBOX_HOST")
    raw_port = os.environ.get("CONNSCOPE_REAL_SINGBOX_PORT", "443")
    uuid_str = os.environ.get("CONNSCOPE_REAL_SINGBOX_UUID")
    pubkey = os.environ.get("CONNSCOPE_REAL_SINGBOX_PUBLIC_KEY") or os.environ.get("CONNSCOPE_REAL_SINGBOX_PASSWORD")
    short_id = os.environ.get("CONNSCOPE_REAL_SINGBOX_SHORT_ID", "")
    server_name = os.environ.get("CONNSCOPE_REAL_SINGBOX_SERVER_NAME")
    test_url = os.environ.get("CONNSCOPE_REAL_SINGBOX_TEST_URL", "http://cp.cloudflare.com/generate_204")

    missing = []
    if not server_host:
        missing.append("CONNSCOPE_REAL_SINGBOX_SERVER")
    if not uuid_str:
        missing.append("CONNSCOPE_REAL_SINGBOX_UUID")
    if not pubkey:
        missing.append("CONNSCOPE_REAL_SINGBOX_PUBLIC_KEY")
    if not server_name:
        missing.append("CONNSCOPE_REAL_SINGBOX_SERVER_NAME")

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

def test_real_singbox_binary_detection_and_allowlist():
    if os.environ.get("CONNSCOPE_TEST_REAL_SINGBOX") != "1":
        pytest.skip("Optional real sing-box integration test skipped (set CONNSCOPE_TEST_REAL_SINGBOX=1 to enable)")

    adapter = SingBoxVlessTcpRealityAdapter()
    ok, exe_path = adapter.check_executable(lookup_paths=get_singbox_lookup_paths())
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted sing-box executable found on host: {exe_path}")

    res = subprocess.run([exe_path, "version"], capture_output=True, text=True, timeout=5.0)
    assert res.returncode == 0
    assert "sing-box version" in res.stdout

def test_real_singbox_config_validation_and_schema_compatibility(tmp_path):
    if os.environ.get("CONNSCOPE_TEST_REAL_SINGBOX") != "1":
        pytest.skip("Optional real sing-box integration test skipped (set CONNSCOPE_TEST_REAL_SINGBOX=1 to enable)")

    adapter = SingBoxVlessTcpRealityAdapter()
    ok, exe_path = adapter.check_executable(lookup_paths=get_singbox_lookup_paths())
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted sing-box executable found on host: {exe_path}")

    target = Target(host="192.0.2.1", port=443)

    cfg_valid = {
        "uuid": TEST_CLIENT_UUID,
        "public_key": TEST_REALITY_PUBKEY,
        "short_id": "0123456789abcdef",
        "server_name": "www.apple.com",
    }
    sb_cfg = generate_singbox_client_config(target, cfg_valid, 20808, 20809)
    f_valid = tmp_path / "config_valid.json"
    f_valid.write_text(json.dumps(sb_cfg, indent=2), encoding="utf-8")

    ok_valid, msg_valid = adapter.test_configuration(f_valid, executable=exe_path)
    assert ok_valid is True, f"Valid sing-box configuration failed check: {msg_valid}"

    cfg_with_pass = json.loads(json.dumps(sb_cfg))
    cfg_with_pass["outbounds"][0]["tls"]["reality"]["password"] = TEST_REALITY_PUBKEY
    f_pass = tmp_path / "config_with_pass.json"
    f_pass.write_text(json.dumps(cfg_with_pass, indent=2), encoding="utf-8")

    ok_pass, msg_pass = adapter.test_configuration(f_pass, executable=exe_path)
    assert ok_pass is False, "sing-box unexpectedly accepted unknown field 'password' in reality block!"
    assert "unknown field \"password\"" in msg_pass

    cfg_with_pubkey = json.loads(json.dumps(sb_cfg))
    del cfg_with_pubkey["outbounds"][0]["tls"]["reality"]["public_key"]
    cfg_with_pubkey["outbounds"][0]["tls"]["reality"]["publicKey"] = TEST_REALITY_PUBKEY
    f_pub = tmp_path / "config_with_pubkey.json"
    f_pub.write_text(json.dumps(cfg_with_pubkey, indent=2), encoding="utf-8")

    ok_pub, msg_pub = adapter.test_configuration(f_pub, executable=exe_path)
    assert ok_pub is False, "sing-box unexpectedly accepted legacy camelCase 'publicKey'!"
    assert "unknown field \"publicKey\"" in msg_pub

    f_invalid = tmp_path / "config_invalid.json"
    f_invalid.write_text("{\"inbounds\": \"not-an-array\"}", encoding="utf-8")
    ok_invalid, msg_invalid = adapter.test_configuration(f_invalid, executable=exe_path)
    assert ok_invalid is False
    assert "cannot unmarshal" in msg_invalid or "FATAL" in msg_invalid

@pytest.mark.asyncio
async def test_real_singbox_process_lifecycle_and_cleanup():
    if os.environ.get("CONNSCOPE_TEST_REAL_SINGBOX") != "1":
        pytest.skip("Optional real sing-box integration test skipped (set CONNSCOPE_TEST_REAL_SINGBOX=1 to enable)")

    adapter = SingBoxVlessTcpRealityAdapter()
    ok, exe_path = adapter.check_executable(lookup_paths=get_singbox_lookup_paths())
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted sing-box executable found on host: {exe_path}")

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

    from unittest.mock import patch
    with patch.object(adapter, "check_executable", return_value=(True, exe_path)):
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

@pytest.mark.asyncio
async def test_real_singbox_tunnel_and_data_transfer():
    target, cfg, reason = load_real_singbox_test_settings()
    if target is None or cfg is None:
        pytest.skip(f"Real sing-box live tunnel test skipped: {reason}")

    adapter = SingBoxVlessTcpRealityAdapter()
    ok, exe_path = adapter.check_executable(lookup_paths=get_singbox_lookup_paths())
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted sing-box executable found on host: {exe_path}")

    from unittest.mock import patch
    with patch.object(adapter, "check_executable", return_value=(True, exe_path)):
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

def test_real_singbox_vmess_config_validation_and_schema_compatibility(tmp_path):
    if os.environ.get("CONNSCOPE_TEST_REAL_SINGBOX") != "1":
        pytest.skip("Optional real sing-box integration test skipped (set CONNSCOPE_TEST_REAL_SINGBOX=1 to enable)")

    adapter = SingBoxVmessWebSocketTlsAdapter()
    ok, exe_path = adapter.check_executable(lookup_paths=get_singbox_lookup_paths())
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted sing-box executable found on host: {exe_path}")

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

    sb_cfg = generate_singbox_vmess_ws_tls_client_config(target, cfg, 20810, 20811)
    f_valid = tmp_path / "vmess_valid.json"
    f_valid.write_text(json.dumps(sb_cfg, indent=2), encoding="utf-8")

    ok_valid, msg_valid = adapter.test_configuration(f_valid, executable=exe_path)
    assert ok_valid is True, f"Valid sing-box VMess configuration failed check: {msg_valid}"

    cfg_bad_tls = json.loads(json.dumps(sb_cfg))
    cfg_bad_tls["outbounds"][0]["tls"]["allowInsecure"] = True
    f_bad_tls = tmp_path / "vmess_bad_tls.json"
    f_bad_tls.write_text(json.dumps(cfg_bad_tls, indent=2), encoding="utf-8")

    ok_bad, msg_bad = adapter.test_configuration(f_bad_tls, executable=exe_path)
    assert ok_bad is False, "sing-box unexpectedly accepted unknown field 'allowInsecure' in tls block!"
    assert "unknown field \"allowInsecure\"" in msg_bad

    cfg_bad_sec = json.loads(json.dumps(sb_cfg))
    cfg_bad_sec["outbounds"][0]["security"] = "invalid_cipher_type"
    f_bad_sec = tmp_path / "vmess_bad_sec.json"
    f_bad_sec.write_text(json.dumps(cfg_bad_sec, indent=2), encoding="utf-8")

    ok_sec, msg_sec = adapter.test_configuration(f_bad_sec, executable=exe_path)
    assert ok_sec is False, "sing-box unexpectedly accepted unsupported security cipher!"
    assert "unsupported security type" in msg_sec

    f_malformed = tmp_path / "vmess_malformed.json"
    f_malformed.write_text("{\"outbounds\": \"invalid\"}", encoding="utf-8")
    ok_malformed, msg_malformed = adapter.test_configuration(f_malformed, executable=exe_path)
    assert ok_malformed is False
    assert "cannot unmarshal" in msg_malformed or "FATAL" in msg_malformed

@pytest.mark.asyncio
async def test_real_singbox_vmess_process_lifecycle_and_cleanup():
    if os.environ.get("CONNSCOPE_TEST_REAL_SINGBOX") != "1":
        pytest.skip("Optional real sing-box integration test skipped (set CONNSCOPE_TEST_REAL_SINGBOX=1 to enable)")

    adapter = SingBoxVmessWebSocketTlsAdapter()
    ok, exe_path = adapter.check_executable(lookup_paths=get_singbox_lookup_paths())
    if not ok or exe_path is None:
        pytest.skip(f"No allowlisted sing-box executable found on host: {exe_path}")

    target = Target(host="127.0.0.1", port=65534)
    cfg = {
        "uuid": TEST_CLIENT_UUID,
        "server_name": "vmess.example.org",
        "path": "/ws",
        "timeout_s": 2.0,
        "startup_timeout_s": 1.5,
        "test_url": "http://127.0.0.1:65533/ping",
    }

    from unittest.mock import patch
    with patch.object(adapter, "check_executable", return_value=(True, exe_path)):
        result = await adapter.run(target, config=cfg)

    assert result.status == ProbeStatus.FAILED
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.metrics["local_ready_ms"] > 0
    assert result.metrics["total_ms"] > 0
    assert TEST_CLIENT_UUID not in str(result.error)
    assert result.details["redacted_config"]["uuid"] == "[REDACTED]"

