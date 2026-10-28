from typing import Any
import pytest

from connscope.adapters import (
    AdapterCapability,
    AdapterMetadata,
    AdapterRegistry,
    AdapterStatus,
    EngineAdapter,
    EngineType,
    ExecutableRequirement,
    OperatingMode,
    ProtocolType,
    SecurityType,
    TransportType,
)
from connscope.core import ProbeEngine, ProbeRegistry, ProbeResult, ProbeStatus, Target

class DummyAdapter(EngineAdapter):
    def __init__(
        self,
        adapter_id: str,
        engine: EngineType = EngineType.XRAY,
        protocol: ProtocolType = ProtocolType.VLESS,
        transport: TransportType = TransportType.TCP,
        security: SecurityType = SecurityType.REALITY,
        status: AdapterStatus = AdapterStatus.EXPERIMENTAL,
        capabilities: frozenset[AdapterCapability] = frozenset({AdapterCapability.HANDSHAKE}),
    ) -> None:
        self.metadata = AdapterMetadata(
            adapter_id=adapter_id,
            display_name=f"Display {adapter_id}",
            engine=engine,
            protocol=protocol,
            transport=transport,
            security=security,
            operating_mode=OperatingMode.CLIENT_ONLY,
            capabilities=capabilities,
            status=status,
            executable=ExecutableRequirement(binary_name="xray"),
            description="Dummy description",
        )

    def validate_config(self, config: dict[str, Any] | None) -> dict[str, Any]:
        return config or {}

    def check_executable(self) -> tuple[bool, str | None]:
        return True, "/usr/bin/xray"

    async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
        from datetime import datetime, timezone
        return self.create_result(
            target=target,
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=10.0,
            details={"dummy": True},
        )

def test_registry_registration_and_duplicate_rejection():
    registry = AdapterRegistry()
    adapter1 = DummyAdapter("adapter_one")
    registry.register(adapter1)

    assert registry.get("adapter_one") is adapter1
    assert "adapter_one" in registry.adapter_ids()

    with pytest.raises(ValueError, match="already registered"):
        registry.register(DummyAdapter("adapter_one"))

    with pytest.raises(TypeError, match="Expected EngineAdapter"):
        registry.register("not_an_adapter")  # type: ignore

def test_registry_unknown_id_raises_key_error():
    registry = AdapterRegistry()
    with pytest.raises(KeyError, match="Unknown adapter ID"):
        registry.get("nonexistent")

def test_registry_deterministic_ordering():
    registry = AdapterRegistry()
    registry.register(DummyAdapter("z_adapter"))
    registry.register(DummyAdapter("a_adapter"))
    registry.register(DummyAdapter("m_adapter"))

    ids = registry.adapter_ids()
    assert ids == ("a_adapter", "m_adapter", "z_adapter")

    all_adapters = registry.list_all()
    assert [a.metadata.adapter_id for a in all_adapters] == ["a_adapter", "m_adapter", "z_adapter"]

def test_registry_filtering_find():
    registry = AdapterRegistry()

    a1 = DummyAdapter(
        "xray_vless_tcp_reality",
        engine=EngineType.XRAY,
        protocol=ProtocolType.VLESS,
        transport=TransportType.TCP,
        security=SecurityType.REALITY,
        status=AdapterStatus.PLANNED if hasattr(AdapterStatus, "PLANNED") else AdapterStatus.NOT_YET_SUPPORTED,
        capabilities=frozenset({AdapterCapability.HANDSHAKE, AdapterCapability.TUNNEL_VERIFY}),
    )
    a2 = DummyAdapter(
        "xray_vmess_ws_tls",
        engine=EngineType.XRAY,
        protocol=ProtocolType.VMESS,
        transport=TransportType.WEBSOCKET,
        security=SecurityType.TLS,
        status=AdapterStatus.EXPERIMENTAL,
        capabilities=frozenset({AdapterCapability.HANDSHAKE}),
    )
    a3 = DummyAdapter(
        "singbox_wireguard_udp",
        engine=EngineType.SING_BOX,
        protocol=ProtocolType.WIREGUARD,
        transport=TransportType.UDP,
        security=SecurityType.NONE,
        status=AdapterStatus.EXPERIMENTAL,
        capabilities=frozenset({AdapterCapability.TUNNEL_VERIFY, AdapterCapability.DATA_TRANSFER}),
    )

    registry.register(a1)
    registry.register(a2)
    registry.register(a3)

    assert registry.find(engine=EngineType.XRAY) == [a1, a2]
    assert registry.find(engine="sing_box") == [a3]
    assert registry.find(engine=EngineType.WIREGUARD) == []

    assert registry.find(protocol=ProtocolType.VLESS) == [a1]
    assert registry.find(protocol=ProtocolType.WIREGUARD) == [a3]

    assert registry.find(transport=TransportType.WEBSOCKET) == [a2]
    assert registry.find(transport=TransportType.UDP) == [a3]

    assert registry.find(security=SecurityType.REALITY) == [a1]
    assert registry.find(security=SecurityType.TLS) == [a2]

    assert registry.find(capability=AdapterCapability.TUNNEL_VERIFY) == [a3, a1]
    assert registry.find(capability=AdapterCapability.DATA_TRANSFER) == [a3]

    assert registry.find(engine=EngineType.XRAY, transport=TransportType.TCP) == [a1]
    assert registry.find(engine=EngineType.XRAY, security=SecurityType.TLS) == [a2]
    assert registry.find(engine=EngineType.XRAY, transport=TransportType.UDP) == []

def test_registry_catalog_metadata_export():
    registry = AdapterRegistry()
    adapter = DummyAdapter("test_id")
    registry.register(adapter)

    meta_list = registry.get_catalog_metadata()
    assert len(meta_list) == 1
    assert meta_list[0]["adapter_id"] == "test_id"
    assert meta_list[0]["engine"] == "xray"

@pytest.mark.asyncio
async def test_registry_probe_engine_compatibility():
    adapter = DummyAdapter("xray_test_probe")
    adapter_registry = AdapterRegistry()
    adapter_registry.register(adapter)

    core_probe_registry = ProbeRegistry()
    adapter_registry.populate_probe_registry(core_probe_registry)

    assert "xray_test_probe" in core_probe_registry.names()
    retrieved = core_probe_registry.get("xray_test_probe")
    assert retrieved is adapter

    engine = ProbeEngine(core_probe_registry)
    result = await engine.run("xray_test_probe", Target(host="example.com", port=443))

    assert isinstance(result, ProbeResult)
    assert result.probe == "xray_test_probe"
    assert result.status == ProbeStatus.SUCCESS
    assert result.details["dummy"] is True

def test_registry_with_concrete_adapters():
    from connscope.adapters import (
        SingBoxVlessTcpRealityAdapter,
        SingBoxVmessWebSocketTlsAdapter,
        XrayVlessTcpRealityAdapter,
        XrayVmessWebSocketTlsAdapter,
    )

    reg = AdapterRegistry()
    xray = XrayVlessTcpRealityAdapter()
    singbox = SingBoxVlessTcpRealityAdapter()
    vmess = XrayVmessWebSocketTlsAdapter()
    sb_vmess = SingBoxVmessWebSocketTlsAdapter()

    reg.register(xray)
    reg.register(singbox)
    reg.register(vmess)
    reg.register(sb_vmess)

    assert reg.adapter_ids() == (
        "singbox_vless_tcp_reality",
        "singbox_vmess_ws_tls",
        "xray_vless_tcp_reality",
        "xray_vmess_ws_tls",
    )
    assert reg.find(engine=EngineType.SING_BOX) == [singbox, sb_vmess]
    assert reg.find(engine=EngineType.XRAY) == [xray, vmess]
    assert reg.find(protocol=ProtocolType.VLESS) == [singbox, xray]
    assert reg.find(protocol=ProtocolType.VMESS) == [sb_vmess, vmess]
    assert reg.find(transport=TransportType.WEBSOCKET) == [sb_vmess, vmess]
    assert reg.find(security=SecurityType.TLS) == [sb_vmess, vmess]
    assert reg.find(security=SecurityType.REALITY) == [singbox, xray]
    assert reg.find(transport=TransportType.TCP) == [singbox, xray]

