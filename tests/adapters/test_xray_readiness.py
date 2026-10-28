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
    XrayVlessTcpRealityAdapter,
)
from connscope.adapters.xray import generate_xray_client_config
from connscope.core import ProbeResult, ProbeStatus, Target
from connscope.serialization import result_from_dict, result_to_dict

def test_xray_adapter_metadata():
    adapter = XrayVlessTcpRealityAdapter()
    meta = adapter.metadata

    assert meta.adapter_id == "xray_vless_tcp_reality"
    assert meta.display_name == "Xray-core VLESS TCP REALITY"
    assert meta.engine == EngineType.XRAY
    assert meta.protocol == ProtocolType.VLESS
    assert meta.transport == TransportType.TCP
    assert meta.security == SecurityType.REALITY
    assert meta.operating_mode == OperatingMode.CLIENT_ONLY
    assert meta.status == AdapterStatus.MOCKED_LIFECYCLE_TESTED

    assert AdapterCapability.HANDSHAKE in meta.capabilities
    assert AdapterCapability.TUNNEL_VERIFY in meta.capabilities
    assert AdapterCapability.DATA_TRANSFER in meta.capabilities

    assert meta.executable is not None
    assert meta.executable.binary_name == "xray"

def test_xray_adapter_validate_config_valid():
    adapter = XrayVlessTcpRealityAdapter()
    valid_cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "1234567890abcdef1234567890abcdef1234567890=",
        "short_id": "0123456789abcdef",
        "server_name": "target.domain.com",
        "timeout_s": 5.0,
        "fingerprint": "chrome",
    }

    validated = adapter.validate_config(valid_cfg)
    assert validated["uuid"] == "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    assert validated["public_key"] == "1234567890abcdef1234567890abcdef1234567890="
    assert validated["short_id"] == "0123456789abcdef"
    assert validated["server_name"] == "target.domain.com"
    assert validated["timeout_s"] == 5.0
    assert validated["fingerprint"] == "chrome"

def test_xray_adapter_validate_config_invalid():
    adapter = XrayVlessTcpRealityAdapter()

    with pytest.raises(ValueError, match="Configuration dictionary is required"):
        adapter.validate_config({})

    with pytest.raises(ValueError, match="Configuration dictionary is required"):
        adapter.validate_config(None)

    with pytest.raises(ValueError, match="Missing or invalid 'uuid'"):
        adapter.validate_config({"public_key": "k", "short_id": "01", "server_name": "s"})

    with pytest.raises(ValueError, match="Invalid UUID"):
        adapter.validate_config({"uuid": "not-a-uuid", "public_key": "k", "short_id": "01", "server_name": "s"})

    with pytest.raises(ValueError, match="Missing or invalid 'public_key'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "public_key": "   ",
            "short_id": "01",
            "server_name": "s",
        })

    with pytest.raises(ValueError, match="must be a hexadecimal string"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "public_key": "pubkey",
            "short_id": "not-hex-xyz!",
            "server_name": "s",
        })

    with pytest.raises(ValueError, match="Missing or invalid 'server_name'"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "public_key": "pubkey",
            "short_id": "01234567",
            "server_name": "",
        })

    with pytest.raises(ValueError, match="must be a positive number"):
        adapter.validate_config({
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "public_key": "pubkey",
            "short_id": "01234567",
            "server_name": "s",
            "timeout_s": -1.0,
        })

@pytest.mark.asyncio
async def test_xray_adapter_unsupported_config_stage():
    adapter = XrayVlessTcpRealityAdapter()
    target = Target(host="example.com", port=443)

    result = await adapter.run(target, config={"server_name": "example.com"})

    assert result.status == ProbeStatus.FAILED
    assert "Configuration error" in result.error
    assert result.details["failure_stage"] == FailureStage.CONFIG_GENERATION.value
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False

@pytest.mark.asyncio
async def test_xray_adapter_missing_executable_stage():
    adapter = XrayVlessTcpRealityAdapter()
    target = Target(host="example.com", port=443)
    valid_cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "pubkey123",
        "short_id": "01234567",
        "server_name": "example.com",
    }

    with patch.object(adapter, "check_executable", return_value=(False, "Executable 'xray' not found in allowlisted paths")):
        result = await adapter.run(target, config=valid_cfg)

    assert result.status == ProbeStatus.FAILED
    assert "Executable 'xray' not found" in result.error
    assert result.details["failure_stage"] == FailureStage.PRE_FLIGHT.value
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False

    redacted = result.details["redacted_config"]
    assert redacted["uuid"] == "[REDACTED]"
    assert redacted["public_key"] == "[REDACTED]"
    assert redacted["short_id"] == "[REDACTED]"
    assert redacted["server_name"] == "example.com"

def test_contract_representation_failed_handshake():
    adapter = XrayVlessTcpRealityAdapter()
    target = Target(host="example.com", port=443)
    started_at = datetime.now(timezone.utc)

    result = adapter.create_failure_result(
        target=target,
        started_at=started_at,
        duration_ms=150.0,
        failure_stage=FailureStage.HANDSHAKE,
        error="REALITY TLS handshake failed: invalid server identity response",
        tunnel_established=False,
        data_transfer_completed=False,
    )

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False
    assert "REALITY TLS handshake failed" in result.error

def test_contract_representation_bounded_timeout():
    adapter = XrayVlessTcpRealityAdapter()
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
        error="Operation timed out after 10.0s during handshake",
    )

    assert result.status == ProbeStatus.TIMEOUT
    assert result.details["failure_stage"] == FailureStage.TIMEOUT.value
    assert result.details["tunnel_established"] is False

def test_contract_representation_successful_tunnel():
    adapter = XrayVlessTcpRealityAdapter()
    target = Target(host="example.com", port=443)
    started_at = datetime.now(timezone.utc)

    result = adapter.create_result(
        target=target,
        status=ProbeStatus.SUCCESS,
        started_at=started_at,
        duration_ms=235.0,
        metrics={
            "tcp_connect_ms": 45.0,
            "handshake_ms": 110.0,
            "data_transfer_ms": 80.0,
            "total_ms": 235.0,
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
    assert result.metrics["handshake_ms"] == 110.0
    assert result.error is None

def test_contract_representation_data_transfer_fails_after_tunnel():
    adapter = XrayVlessTcpRealityAdapter()
    target = Target(host="example.com", port=443)
    started_at = datetime.now(timezone.utc)

    result = adapter.create_failure_result(
        target=target,
        started_at=started_at,
        duration_ms=500.0,
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
    adapter = XrayVlessTcpRealityAdapter()
    target = Target(host="example.com", port=443)
    started_at = datetime.now(timezone.utc)

    result = adapter.create_failure_result(
        target=target,
        started_at=started_at,
        duration_ms=120.0,
        failure_stage=FailureStage.HANDSHAKE,
        error="Handshake error",
        tunnel_established=False,
        extra={"password": "should-be-redacted", "safe_param": "ok"},
    )

    data = result_to_dict(result)
    assert data["probe"] == "xray_vless_tcp_reality"
    assert data["details"]["password"] == "[REDACTED]"
    assert data["details"]["safe_param"] == "ok"
    assert data["details"]["failure_stage"] == "handshake"

    restored = result_from_dict(data)
    assert isinstance(restored, ProbeResult)
    assert restored.probe == "xray_vless_tcp_reality"
    assert restored.target.host == "example.com"
    assert restored.details["failure_stage"] == "handshake"
    assert restored.details["password"] == "[REDACTED]"

def test_xray_short_id_validation_rules():
    adapter = XrayVlessTcpRealityAdapter()
    base_cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "pubkey1234567890abcdef1234567890abcdef123=",
        "server_name": "target.domain.com",
    }

    for sid in ["", "01", "0123", "01234567", "0123456789abcdef", "0123456789ABCDEF"]:
        cfg = {**base_cfg, "short_id": sid}
        validated = adapter.validate_config(cfg)
        assert validated["short_id"] == sid.lower()

    for odd_sid in ["1", "123", "01234", "0123456", "012345678", "0123456789a"]:
        with pytest.raises(ValueError, match="must be an even number of hex characters"):
            adapter.validate_config({**base_cfg, "short_id": odd_sid})

    with pytest.raises(ValueError, match="length exceeds maximum of 16 hexadecimal characters"):
        adapter.validate_config({**base_cfg, "short_id": "0123456789abcdef01"})

    for invalid_sid in ["0123g4", "xyz123", "01-23"]:
        with pytest.raises(ValueError, match="must be a hexadecimal string"):
            adapter.validate_config({**base_cfg, "short_id": invalid_sid})

    for non_str in [123, None, True, ["01"]]:
        with pytest.raises(ValueError, match="must be a string"):
            adapter.validate_config({**base_cfg, "short_id": non_str})

def test_generate_xray_client_config_reality_schema():
    target = Target(host="server.reality.net", port=443)
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "my-pubkey-32bytes-base64-encoded",
        "short_id": "0123456789abcdef",
        "server_name": "www.apple.com",
        "fingerprint": "chrome",
        "spider_x": "/downloads",
        "flow": "xtls-rprx-vision",
        "timeout_s": 15.0,
    }

    generated = generate_xray_client_config(
        target=target,
        config=cfg,
        local_socks_port=10808,
        local_http_port=10809,
    )

    inbounds = generated["inbounds"]
    assert len(inbounds) == 2
    assert inbounds[0]["protocol"] == "socks"
    assert inbounds[0]["port"] == 10808
    assert inbounds[0]["listen"] == "127.0.0.1"
    assert inbounds[1]["protocol"] == "http"
    assert inbounds[1]["port"] == 10809

    outbounds = generated["outbounds"]
    assert len(outbounds) == 1
    vless_out = outbounds[0]
    assert vless_out["protocol"] == "vless"

    vnext = vless_out["settings"]["vnext"][0]
    assert vnext["address"] == "server.reality.net"
    assert vnext["port"] == 443
    assert vnext["users"][0]["id"] == "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    assert vnext["users"][0]["encryption"] == "none"
    assert vnext["users"][0]["flow"] == "xtls-rprx-vision"

    stream = vless_out["streamSettings"]
    assert stream["network"] == "tcp"
    assert stream["security"] == "reality"

    reality = stream["realitySettings"]
    assert reality["serverName"] == "www.apple.com"
    assert reality["password"] == "my-pubkey-32bytes-base64-encoded"
    assert reality["publicKey"] == "my-pubkey-32bytes-base64-encoded"
    assert reality["shortId"] == "0123456789abcdef"
    assert reality["fingerprint"] == "chrome"
    assert reality["spiderX"] == "/downloads"
    assert reality["show"] is False

def test_generate_xray_client_config_with_password_input():
    target = Target(host="server.reality.net", port=443)
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "password": "modern-xray-password-key",
        "short_id": "0123",
        "server_name": "target.com",
    }
    generated = generate_xray_client_config(
        target=target,
        config=cfg,
        local_socks_port=10808,
        local_http_port=10809,
    )
    reality = generated["outbounds"][0]["streamSettings"]["realitySettings"]
    assert reality["password"] == "modern-xray-password-key"
    assert reality["publicKey"] == "modern-xray-password-key"

def test_xray_validate_config_accepts_password_or_public_key():
    adapter = XrayVlessTcpRealityAdapter()
    base = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "short_id": "01234567",
        "server_name": "target.domain.com",
    }

    v1 = adapter.validate_config({**base, "public_key": "pubkey-abc-123"})
    assert v1["public_key"] == "pubkey-abc-123"
    assert v1["password"] == "pubkey-abc-123"

    v2 = adapter.validate_config({**base, "password": "password-xyz-789"})
    assert v2["public_key"] == "password-xyz-789"
    assert v2["password"] == "password-xyz-789"

    with pytest.raises(ValueError, match="Missing or invalid 'public_key'"):
        adapter.validate_config(base)

def test_adapter_status_taxonomy_states():
    statuses = [
        AdapterStatus.CONFIG_VALIDATION_IMPLEMENTED,
        AdapterStatus.ADAPTER_LIFECYCLE_IMPLEMENTED,
        AdapterStatus.MOCKED_LIFECYCLE_TESTED,
        AdapterStatus.REAL_TUNNEL_VERIFIED,
        AdapterStatus.REAL_DATA_TRANSFER_TESTED,
        AdapterStatus.REAL_ENGINE_INTEGRATION_TESTED,
    ]
    str_values = [s.value for s in statuses]
    assert len(set(str_values)) == 6
    assert "mocked_lifecycle_tested" in str_values
    assert "real_engine_integration_tested" in str_values

    adapter = XrayVlessTcpRealityAdapter()
    assert adapter.metadata.status == AdapterStatus.MOCKED_LIFECYCLE_TESTED
    assert adapter.metadata.executable.min_version == "1.8.0"

def test_xray_validate_config_verify_cert_and_ssl_context():
    adapter = XrayVlessTcpRealityAdapter()
    base_cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "pubkey1234567890abcdef1234567890abcdef123=",
        "short_id": "0123456789abcdef",
        "server_name": "target.domain.com",
    }

    validated = adapter.validate_config(base_cfg)
    assert validated["verify_cert"] is True

    validated_no_verify = adapter.validate_config({**base_cfg, "verify_cert": False})
    assert validated_no_verify["verify_cert"] is False

    with pytest.raises(TypeError, match="verify_cert must be a boolean"):
        adapter.validate_config({**base_cfg, "verify_cert": "false"})

    ctx = ssl.create_default_context()
    validated_ctx = adapter.validate_config({**base_cfg, "ssl_context": ctx})
    assert validated_ctx["ssl_context"] is ctx

    with pytest.raises(TypeError, match="ssl_context must be an instance of ssl.SSLContext"):
        adapter.validate_config({**base_cfg, "ssl_context": "not-a-context"})

def test_xray_adapter_test_configuration_mocked(tmp_path):
    adapter = XrayVlessTcpRealityAdapter()
    cfg_file = tmp_path / "xray_cfg.json"
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
    secret_key = "sensitive-reality-key"
    fake_failed = subprocess.CompletedProcess(
        args=["xray", "run", "-test", "-c", str(cfg_file)],
        returncode=23,
        stdout="",
        stderr=f"Error in config: invalid key={secret_key} uuid={secret_uuid}",
    )
    with patch.object(adapter, "check_executable", return_value=(True, "/usr/bin/xray")), patch(
        "subprocess.run", return_value=fake_failed
    ):
        ok, msg = adapter.test_configuration(cfg_file, secrets=[secret_uuid, secret_key])
        assert ok is False
        assert secret_uuid not in msg
        assert secret_key not in msg
        assert "[REDACTED]" in msg

