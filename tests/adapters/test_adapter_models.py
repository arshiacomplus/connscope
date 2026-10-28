import pytest

from connscope.adapters.models import (
    AdapterCapability,
    AdapterMetadata,
    AdapterResultDetails,
    AdapterStatus,
    EngineType,
    ExecutableRequirement,
    FailureStage,
    OperatingMode,
    ProtocolType,
    SecurityType,
    TransportType,
)

def test_enum_members_and_string_values():
    assert EngineType.XRAY.value == "xray"
    assert EngineType.SING_BOX.value == "sing_box"
    assert EngineType.WIREGUARD.value == "wireguard"

    assert ProtocolType.VLESS.value == "vless"
    assert ProtocolType.VMESS.value == "vmess"
    assert ProtocolType.TROJAN.value == "trojan"
    assert ProtocolType.SHADOWSOCKS.value == "shadowsocks"

    assert TransportType.TCP.value == "tcp"
    assert TransportType.WEBSOCKET.value == "websocket"
    assert TransportType.GRPC.value == "grpc"
    assert TransportType.XHTTP.value == "xhttp"

    assert SecurityType.TLS.value == "tls"
    assert SecurityType.REALITY.value == "reality"
    assert SecurityType.NONE.value == "none"

    assert AdapterCapability.TUNNEL_VERIFY.value == "tunnel_verify"
    assert AdapterCapability.DATA_TRANSFER.value == "data_transfer"

    assert OperatingMode.CLIENT_ONLY.value == "client_only"
    assert AdapterStatus.IMPLEMENTED.value == "implemented"
    assert FailureStage.HANDSHAKE.value == "handshake"

def test_executable_requirement_validation():
    req = ExecutableRequirement(binary_name="xray", min_version="1.8.0")
    assert req.binary_name == "xray"
    assert req.min_version == "1.8.0"

    with pytest.raises(ValueError, match="binary_name must not be empty"):
        ExecutableRequirement(binary_name="")

    with pytest.raises(ValueError, match="Path separators are not allowed"):
        ExecutableRequirement(binary_name="/usr/bin/xray")

    with pytest.raises(ValueError, match="Path separators are not allowed"):
        ExecutableRequirement(binary_name="..\\xray")

def test_adapter_metadata_validation_and_serialization():
    meta = AdapterMetadata(
        adapter_id="xray_vless_tcp_reality",
        display_name="Xray VLESS TCP REALITY",
        engine=EngineType.XRAY,
        protocol=ProtocolType.VLESS,
        transport=TransportType.TCP,
        security=SecurityType.REALITY,
        operating_mode=OperatingMode.CLIENT_ONLY,
        capabilities=frozenset({
            AdapterCapability.HANDSHAKE,
            AdapterCapability.TUNNEL_VERIFY,
        }),
        status=AdapterStatus.PLANNED if hasattr(AdapterStatus, "PLANNED") else AdapterStatus.NOT_YET_SUPPORTED,
        executable=ExecutableRequirement(binary_name="xray", min_version="1.8.0"),
        description="Test metadata",
    )

    assert meta.adapter_id == "xray_vless_tcp_reality"
    d = meta.to_dict()
    assert d["adapter_id"] == "xray_vless_tcp_reality"
    assert d["engine"] == "xray"
    assert d["protocol"] == "vless"
    assert d["transport"] == "tcp"
    assert d["security"] == "reality"
    assert d["operating_mode"] == "client_only"
    assert d["capabilities"] == ["handshake", "tunnel_verify"]
    assert d["executable"] == {"binary_name": "xray", "min_version": "1.8.0"}

    with pytest.raises(ValueError, match="adapter_id must not be empty"):
        AdapterMetadata(
            adapter_id="",
            display_name="Test",
            engine=EngineType.XRAY,
            protocol=ProtocolType.VLESS,
            transport=TransportType.TCP,
            security=SecurityType.NONE,
            operating_mode=OperatingMode.CLIENT_ONLY,
            capabilities=frozenset({AdapterCapability.HANDSHAKE}),
            status=AdapterStatus.EXPERIMENTAL,
        )

    with pytest.raises(ValueError, match="capabilities must not be empty"):
        AdapterMetadata(
            adapter_id="test",
            display_name="Test",
            engine=EngineType.XRAY,
            protocol=ProtocolType.VLESS,
            transport=TransportType.TCP,
            security=SecurityType.NONE,
            operating_mode=OperatingMode.CLIENT_ONLY,
            capabilities=frozenset(),
            status=AdapterStatus.EXPERIMENTAL,
        )

def test_adapter_result_details():
    det = AdapterResultDetails(
        adapter_id="test_adapter",
        engine="xray",
        protocol="vless",
        transport="tcp",
        security="reality",
        failure_stage=FailureStage.HANDSHAKE,
        tunnel_established=False,
        data_transfer_completed=False,
        extra={"custom_key": 42},
    )

    data = det.to_dict()
    assert data["adapter_id"] == "test_adapter"
    assert data["failure_stage"] == "handshake"
    assert data["tunnel_established"] is False
    assert data["data_transfer_completed"] is False
    assert data["custom_key"] == 42
