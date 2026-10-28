from datetime import datetime, timezone
import ssl
from unittest.mock import patch
import pytest

from connscope.adapters import (
    AdapterCapability,
    AdapterStatus,
    EngineType,
    FailureStage,
    OperatingMode,
    ProtocolType,
    SecurityType,
    TransportType,
    XrayVmessWebSocketTlsAdapter,
    generate_xray_vmess_ws_tls_client_config,
)
from connscope.core import ProbeResult, ProbeStatus, Target
from connscope.serialization import result_from_dict, result_to_dict

def test_xray_vmess_metadata():
    adapter = XrayVmessWebSocketTlsAdapter()
    meta = adapter.metadata

    assert meta.adapter_id == "xray_vmess_ws_tls"
    assert meta.display_name == "Xray-core VMess WebSocket TLS"
    assert meta.engine == EngineType.XRAY
    assert meta.protocol == ProtocolType.VMESS
    assert meta.transport == TransportType.WEBSOCKET
    assert meta.security == SecurityType.TLS
    assert meta.operating_mode == OperatingMode.CLIENT_ONLY
    assert meta.status == AdapterStatus.MOCKED_LIFECYCLE_TESTED

    assert AdapterCapability.TCP_CONNECT in meta.capabilities
    assert AdapterCapability.HANDSHAKE in meta.capabilities
    assert AdapterCapability.TUNNEL_VERIFY in meta.capabilities
    assert AdapterCapability.DATA_TRANSFER in meta.capabilities
    assert AdapterCapability.LATENCY in meta.capabilities

    assert meta.executable is not None
    assert meta.executable.binary_name == "xray"
    assert meta.executable.min_version == "1.8.0"

def test_xray_vmess_validate_config_valid():
    adapter = XrayVmessWebSocketTlsAdapter()
    valid_cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "server_name": "target.domain.com",
        "path": "/my-ws-path",
        "host_header": "cdn.example.org",
        "alter_id": 16,
        "security": "aes-128-gcm",
        "fingerprint": "firefox",
        "timeout_s": 8.0,
        "startup_timeout_s": 2.5,
        "verify_cert": True,
    }

    validated = adapter.validate_config(valid_cfg)
    assert validated["uuid"] == "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    assert validated["server_name"] == "target.domain.com"
    assert validated["path"] == "/my-ws-path"
    assert validated["host_header"] == "cdn.example.org"
    assert validated["alter_id"] == 16
    assert validated["security"] == "aes-128-gcm"
    assert validated["fingerprint"] == "firefox"
    assert validated["timeout_s"] == 8.0
    assert validated["startup_timeout_s"] == 2.5
    assert validated["verify_cert"] is True

def test_xray_vmess_validate_config_defaults():
    adapter = XrayVmessWebSocketTlsAdapter()
    minimal_cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "server_name": "target.domain.com",
    }

    validated = adapter.validate_config(minimal_cfg)
    assert validated["uuid"] == "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    assert validated["server_name"] == "target.domain.com"
    assert validated["path"] == "/"
    assert validated["alter_id"] == 0
    assert validated["security"] == "auto"
    assert validated["fingerprint"] == "chrome"
    assert validated["timeout_s"] == 10.0
    assert validated["startup_timeout_s"] == 3.0
    assert validated["verify_cert"] is True
    assert "host_header" not in validated

def test_xray_vmess_path_normalization():
    adapter = XrayVmessWebSocketTlsAdapter()
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "server_name": "target.domain.com",
        "path": "custom-path",
    }
    validated = adapter.validate_config(cfg)
    assert validated["path"] == "/custom-path"

def test_xray_vmess_validate_config_invalid():
    adapter = XrayVmessWebSocketTlsAdapter()

    with pytest.raises(ValueError, match="Configuration dictionary is required"):
        adapter.validate_config({})

    with pytest.raises(ValueError, match="Configuration dictionary is required"):
        adapter.validate_config(None)

    with pytest.raises(ValueError, match="Missing or invalid 'uuid'"):
        adapter.validate_config({"server_name": "target.com"})

    with pytest.raises(ValueError, match="Invalid UUID"):
        adapter.validate_config({"uuid": "not-a-valid-uuid", "server_name": "target.com"})

    with pytest.raises(ValueError, match="Missing or invalid 'server_name'"):
        adapter.validate_config({"uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"})

    with pytest.raises(ValueError, match="Missing or invalid 'server_name'"):
        adapter.validate_config({"uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "server_name": "   "})

    with pytest.raises(ValueError, match="Invalid 'alter_id'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "alter_id": -1,
        })

    with pytest.raises(ValueError, match="Invalid 'alter_id'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "alter_id": 70000,
        })

    with pytest.raises(ValueError, match="Invalid 'alter_id'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "alter_id": True,
        })

    with pytest.raises(ValueError, match="Invalid 'security'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "security": "invalid-cipher-mode",
        })

    with pytest.raises(ValueError, match="Invalid 'security'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "security": "none",
        })

    with pytest.raises(ValueError, match="Invalid 'security'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "security": "zero",
        })

    with pytest.raises(ValueError, match="Invalid 'timeout_s'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "timeout_s": -5.0,
        })

    with pytest.raises(ValueError, match="Invalid 'startup_timeout_s'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "startup_timeout_s": 0,
        })

    with pytest.raises(TypeError, match="verify_cert must be a boolean"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "verify_cert": "yes",
        })

    with pytest.raises(TypeError, match="ssl_context must be an instance of ssl.SSLContext"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.com",
            "ssl_context": "invalid-context",
        })

def test_generate_xray_vmess_ws_tls_client_config():
    target = Target(host="vmess-server.example.net", port=443)
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "server_name": "my-sni.example.net",
        "path": "/ray-ws",
        "host_header": "my-host.example.net",
        "alter_id": 4,
        "security": "chacha20-poly1305",
        "fingerprint": "chrome",
        "verify_cert": True,
    }

    generated = generate_xray_vmess_ws_tls_client_config(
        target=target,
        config=cfg,
        local_socks_port=10808,
        local_http_port=10809,
    )

    assert generated["log"]["loglevel"] == "warning"

    inbounds = generated["inbounds"]
    assert len(inbounds) == 2
    assert inbounds[0]["protocol"] == "socks"
    assert inbounds[0]["port"] == 10808
    assert inbounds[0]["listen"] == "127.0.0.1"
    assert inbounds[0]["settings"]["udp"] is True
    assert inbounds[1]["protocol"] == "http"
    assert inbounds[1]["port"] == 10809

    outbounds = generated["outbounds"]
    assert len(outbounds) == 1
    vmess_out = outbounds[0]
    assert vmess_out["protocol"] == "vmess"

    vnext = vmess_out["settings"]["vnext"][0]
    assert vnext["address"] == "vmess-server.example.net"
    assert vnext["port"] == 443
    user = vnext["users"][0]
    assert user["id"] == "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    assert user["alterId"] == 4
    assert user["security"] == "chacha20-poly1305"

    stream = vmess_out["streamSettings"]
    assert stream["network"] == "ws"
    assert stream["security"] == "tls"

    tls = stream["tlsSettings"]
    assert tls["serverName"] == "my-sni.example.net"
    assert tls["allowInsecure"] is False
    assert tls["fingerprint"] == "chrome"

    ws = stream["wsSettings"]
    assert ws["path"] == "/ray-ws"
    assert ws["host"] == "my-host.example.net"
    assert ws["headers"]["Host"] == "my-host.example.net"

    assert "realitySettings" not in stream
    assert "password" not in tls
    assert "publicKey" not in tls
    assert "shortId" not in tls
    assert "spiderX" not in tls

def test_generate_xray_vmess_ws_tls_allow_insecure_flag():
    target = Target(host="vmess-server.example.net", port=443)
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "server_name": "self-signed.example.net",
        "verify_cert": False,
    }

    generated = generate_xray_vmess_ws_tls_client_config(
        target=target,
        config=cfg,
        local_socks_port=10808,
        local_http_port=10809,
    )
    tls = generated["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls["allowInsecure"] is True

def test_contract_representation_failed_handshake():
    adapter = XrayVmessWebSocketTlsAdapter()
    target = Target(host="example.com", port=443)
    started_at = datetime.now(timezone.utc)

    result = adapter.create_failure_result(
        target=target,
        started_at=started_at,
        duration_ms=180.0,
        failure_stage=FailureStage.HANDSHAKE,
        error="VMess WebSocket TLS handshake failed: HTTP 400 Bad Request",
        tunnel_established=False,
        data_transfer_completed=False,
    )

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False
    assert "VMess WebSocket TLS handshake failed" in result.error

def test_contract_representation_bounded_timeout():
    adapter = XrayVmessWebSocketTlsAdapter()
    target = Target(host="example.com", port=443)
    started_at = datetime.now(timezone.utc)

    result = adapter.create_result(
        target=target,
        status=ProbeStatus.TIMEOUT,
        started_at=started_at,
        duration_ms=10000.0,
        details={
            "adapter_id": adapter.metadata.adapter_id,
            "engine": adapter.metadata.engine.value,
            "protocol": adapter.metadata.protocol.value,
            "transport": adapter.metadata.transport.value,
            "security": adapter.metadata.security.value,
            "failure_stage": FailureStage.TIMEOUT.value,
            "tunnel_established": False,
            "data_transfer_completed": False,
        },
        error="Operation timed out after 10.0s during WebSocket upgrade",
    )

    assert result.status == ProbeStatus.TIMEOUT
    assert result.details["failure_stage"] == FailureStage.TIMEOUT.value
    assert result.details["tunnel_established"] is False

def test_contract_representation_successful_tunnel():
    adapter = XrayVmessWebSocketTlsAdapter()
    target = Target(host="example.com", port=443)
    started_at = datetime.now(timezone.utc)

    result = adapter.create_result(
        target=target,
        status=ProbeStatus.SUCCESS,
        started_at=started_at,
        duration_ms=310.0,
        metrics={
            "local_ready_ms": 28.0,
            "handshake_ms": 145.0,
            "data_transfer_ms": 82.0,
            "total_ms": 310.0,
        },
        details={
            "adapter_id": adapter.metadata.adapter_id,
            "engine": adapter.metadata.engine.value,
            "protocol": adapter.metadata.protocol.value,
            "transport": adapter.metadata.transport.value,
            "security": adapter.metadata.security.value,
            "tunnel_established": True,
            "data_transfer_completed": True,
            "test_url": "http://cp.cloudflare.com/generate_204",
            "http_status": 204,
        },
    )

    assert result.status == ProbeStatus.SUCCESS
    assert result.details["tunnel_established"] is True
    assert result.details["data_transfer_completed"] is True
    assert result.metrics["handshake_ms"] == 145.0
    assert result.error is None

def test_contract_representation_data_transfer_fails_after_tunnel():
    adapter = XrayVmessWebSocketTlsAdapter()
    target = Target(host="example.com", port=443)
    started_at = datetime.now(timezone.utc)

    result = adapter.create_failure_result(
        target=target,
        started_at=started_at,
        duration_ms=450.0,
        failure_stage=FailureStage.DATA_TRANSFER,
        error="Data transfer probe failed after tunnel establishment: remote connection reset",
        tunnel_established=True,
        data_transfer_completed=False,
        extra={"test_url": "http://cp.cloudflare.com/generate_204"},
    )

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.DATA_TRANSFER.value
    assert result.details["tunnel_established"] is True
    assert result.details["data_transfer_completed"] is False
    assert "remote connection reset" in result.error

def test_serialization_compatibility():
    adapter = XrayVmessWebSocketTlsAdapter()
    target = Target(host="example.com", port=443)
    started_at = datetime.now(timezone.utc)

    result = adapter.create_failure_result(
        target=target,
        started_at=started_at,
        duration_ms=140.0,
        failure_stage=FailureStage.HANDSHAKE,
        error="Handshake error",
        tunnel_established=False,
        extra={"uuid": "should-be-redacted", "safe_param": "ok"},
    )

    data = result_to_dict(result)
    assert data["probe"] == "xray_vmess_ws_tls"
    assert data["details"]["uuid"] == "[REDACTED]"
    assert data["details"]["safe_param"] == "ok"
    assert data["details"]["failure_stage"] == "handshake"

    restored = result_from_dict(data)
    assert isinstance(restored, ProbeResult)
    assert restored.probe == "xray_vmess_ws_tls"
    assert restored.target.host == "example.com"
    assert restored.details["failure_stage"] == "handshake"
    assert restored.details["uuid"] == "[REDACTED]"

def test_xray_vmess_test_configuration_mocked(tmp_path):
    adapter = XrayVmessWebSocketTlsAdapter()
    cfg_file = tmp_path / "xray_vmess_cfg.json"
    cfg_file.write_text("{}", encoding="utf-8")

    with patch.object(adapter, "check_executable", return_value=(False, "xray not found")):
        ok, msg = adapter.test_configuration(cfg_file)
        assert ok is False
        assert "Executable check failed" in msg

    import subprocess
    fake_completed = subprocess.CompletedProcess(
        args=["xray", "run", "-test", "-c", str(cfg_file)],
        returncode=0,
        stdout="Configuration OK.\n",
        stderr="",
    )
    with patch.object(adapter, "check_executable", return_value=(True, "/usr/bin/xray")), patch(
        "subprocess.run", return_value=fake_completed
    ):
        ok, msg = adapter.test_configuration(cfg_file)
        assert ok is True
        assert "Configuration OK" in msg

    secret_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    fake_failed = subprocess.CompletedProcess(
        args=["xray", "run", "-test", "-c", str(cfg_file)],
        returncode=23,
        stdout="",
        stderr=f"Error in config: invalid id={secret_uuid}",
    )
    with patch.object(adapter, "check_executable", return_value=(True, "/usr/bin/xray")), patch(
        "subprocess.run", return_value=fake_failed
    ):
        ok, msg = adapter.test_configuration(cfg_file, secrets=[secret_uuid])
        assert ok is False
        assert secret_uuid not in msg
        assert "[REDACTED]" in msg

def test_xray_vmess_security_enum_supported_and_rejected():
    adapter = XrayVmessWebSocketTlsAdapter()
    base_cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "server_name": "target.domain.com",
    }

    for sec in ["auto", "aes-128-gcm", "chacha20-poly1305", "AES-128-GCM", "CHACHA20-POLY1305"]:
        validated = adapter.validate_config({**base_cfg, "security": sec})
        assert validated["security"] == sec.lower()

    for bad_sec in ["none", "zero", "aes-256-gcm", "rc4", "invalid", ""]:
        with pytest.raises((ValueError, TypeError)):
            adapter.validate_config({**base_cfg, "security": bad_sec})

