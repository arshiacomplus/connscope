
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch
import pytest

from connscope.adapters import AdapterRegistry, EngineAdapter
from connscope.adapters.models import (
    AdapterCapability,
    AdapterMetadata,
    AdapterStatus,
    EngineType,
    OperatingMode,
    ProtocolType,
    SecurityType,
    TransportType,
)
from connscope.agent import (
    API_VERSION,
    AgentCapabilities,
    AgentServer,
    ClientConfigurationError,
    HttpError,
    PERMITTED_REMOTE_ADAPTERS,
    PROHIBITED_REMOTE_ADAPTERS,
    PROTOCOL_VERSION,
    RemoteAgentClient,
    RemoteAuthenticationError,
    RemoteHttpError,
    RemotePolicyError,
    RemoteProtocolError,
    RemoteUnavailableError,
)
from connscope.core import ProbeResult, ProbeStatus, Target

SAMPLE_TARGET = Target(host="127.0.0.1", port=8080)
AUTH_TOKEN = "secret-test-token-12345"

class MockProxyAdapter(EngineAdapter):

    def __init__(self, adapter_id: str = "xray_vless_tcp_reality", should_succeed: bool = True) -> None:
        self._name = adapter_id
        self._should_succeed = should_succeed
        self.metadata = AdapterMetadata(
            adapter_id=adapter_id,
            display_name=f"Mock {adapter_id}",
            engine=EngineType.XRAY,
            protocol=ProtocolType.VLESS,
            transport=TransportType.TCP,
            security=SecurityType.REALITY,
            operating_mode=OperatingMode.CLIENT_ONLY,
            capabilities=frozenset({AdapterCapability.TUNNEL_VERIFY}),
            status=AdapterStatus.IMPLEMENTED,
            description="Mock proxy adapter",
        )

    @property
    def name(self) -> str:
        return self._name

    def validate_config(self, config: dict[str, Any]) -> dict[str, Any]:
        if "invalid_key" in config:
            raise ValueError("Found invalid_key in config")
        return dict(config)

    def check_executable(self) -> tuple[bool, str]:
        return True, "/usr/bin/mock-binary"

    async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
        now = datetime.now(timezone.utc)
        if self._should_succeed:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=now,
                duration_ms=25.0,
                metrics={"handshake_ms": 10.0, "data_transfer_ms": 15.0},
                details={"tunnel_established": True, "data_transfer_completed": True},
            )
        return ProbeResult(
            probe=self.name,
            target=target,
            status=ProbeStatus.FAILED,
            started_at=now,
            duration_ms=50.0,
            metrics={"handshake_ms": 50.0},
            details={"failure_stage": "handshake", "tunnel_established": False},
            error="Connection refused by remote host",
        )

def test_agent_capabilities_model_validation():
    valid_data = {
        "protocol_version": PROTOCOL_VERSION,
        "api_version": "1.0",
        "supported_operations": ["measure_probe", "execute_adapter"],
        "allowlisted_adapters": ["xray_vless_tcp_reality"],
        "allowed_execution_modes": ["local_proxy"],
        "executable_versions": {"xray": "1.8.4"},
        "isolation_prerequisites": {},
    }

    caps = AgentCapabilities.from_dict(valid_data)
    assert caps.protocol_version == 1
    assert caps.api_version == "1.0"
    assert "execute_adapter" in caps.supported_operations
    assert "xray_vless_tcp_reality" in caps.allowlisted_adapters
    assert caps.executable_versions.get("xray") == "1.8.4"

    roundtrip = caps.to_dict()
    assert roundtrip["api_version"] == "1.0"
    assert roundtrip["allowlisted_adapters"] == ["xray_vless_tcp_reality"]

    invalid_pv = dict(valid_data, protocol_version=2)
    with pytest.raises(ValueError, match="Incompatible protocol_version"):
        AgentCapabilities.from_dict(invalid_pv)

    invalid_bool_pv = dict(valid_data, protocol_version=True)
    with pytest.raises(ValueError, match="Incompatible protocol_version"):
        AgentCapabilities.from_dict(invalid_bool_pv)

    invalid_api = dict(valid_data, api_version="2.0")
    with pytest.raises(ValueError, match="Incompatible agent api_version"):
        AgentCapabilities.from_dict(invalid_api)

    invalid_ops = dict(valid_data, supported_operations="invalid")
    with pytest.raises(ValueError, match="supported_operations must be a list"):
        AgentCapabilities.from_dict(invalid_ops)

@pytest.mark.asyncio
async def test_server_capability_discovery_unauthenticated():
    server = AgentServer(host="127.0.0.1", port=0, auth_token=AUTH_TOKEN)
    async with server:
        client_bad_token = RemoteAgentClient(
            node_url=f"http://127.0.0.1:{server.port}",
            token="invalid-token",
        )
        with pytest.raises(RemoteAuthenticationError):
            await asyncio.to_thread(client_bad_token.get_capabilities)

@pytest.mark.asyncio
async def test_server_capability_discovery_default_deny():
    server = AgentServer(host="127.0.0.1", port=0, auth_token=AUTH_TOKEN)
    async with server:
        client = RemoteAgentClient(
            node_url=f"http://127.0.0.1:{server.port}",
            token=AUTH_TOKEN,
        )
        caps = await asyncio.to_thread(client.get_capabilities)
        assert caps.protocol_version == PROTOCOL_VERSION
        assert caps.api_version == API_VERSION
        assert caps.allowlisted_adapters == ()
        assert "measure_probe" in caps.supported_operations
        assert "execute_adapter" not in caps.supported_operations

@pytest.mark.asyncio
async def test_server_capability_discovery_explicit_allowlist():
    server = AgentServer(
        host="127.0.0.1",
        port=0,
        auth_token=AUTH_TOKEN,
        allowlisted_adapters=["xray_vless_tcp_reality", "singbox_vmess_ws_tls"],
        executable_versions={"xray": "1.8.4", "sing-box": "1.12.12"},
    )
    async with server:
        client = RemoteAgentClient(
            node_url=f"http://127.0.0.1:{server.port}",
            token=AUTH_TOKEN,
        )
        caps = await asyncio.to_thread(client.get_capabilities)
        assert sorted(caps.allowlisted_adapters) == ["singbox_vmess_ws_tls", "xray_vless_tcp_reality"]
        assert "execute_adapter" in caps.supported_operations
        assert caps.executable_versions.get("xray") == "1.8.4"

def test_server_prohibits_layer3_adapters_in_allowlist():
    for l3 in ("wireguard_standard", "amnezia_wg_standard", "openvpn_standard"):
        with pytest.raises(ValueError, match="strictly prohibited from remote execution"):
            AgentServer(auth_token=AUTH_TOKEN, allowlisted_adapters=[l3])

    with pytest.raises(ValueError, match="not permitted for remote execution"):
        AgentServer(auth_token=AUTH_TOKEN, allowlisted_adapters=["arbitrary_backdoor_adapter"])

@pytest.mark.asyncio
async def test_server_adapter_execute_default_deny():
    server = AgentServer(host="127.0.0.1", port=0, auth_token=AUTH_TOKEN)
    async with server:
        client = RemoteAgentClient(node_url=f"http://127.0.0.1:{server.port}", token=AUTH_TOKEN)
        with pytest.raises(RemotePolicyError) as exc_info:
            await asyncio.to_thread(client.execute_adapter, "xray_vless_tcp_reality", SAMPLE_TARGET, {})
        assert exc_info.value.status_code == 403
        assert exc_info.value.error_code == "forbidden"

@pytest.mark.asyncio
async def test_client_execute_adapter_rejects_layer3_locally():
    client = RemoteAgentClient(node_url="http://127.0.0.1:8080", token=AUTH_TOKEN)
    for l3 in ("wireguard_standard", "amnezia_wg_standard", "openvpn_standard"):
        with pytest.raises(ClientConfigurationError, match="not supported for remote execution"):
            client.execute_adapter(l3, SAMPLE_TARGET, config={})

@pytest.mark.asyncio
async def test_server_adapter_execute_success():
    registry = AdapterRegistry()
    mock_adapter = MockProxyAdapter("xray_vless_tcp_reality", should_succeed=True)
    registry.register(mock_adapter)

    server = AgentServer(
        host="127.0.0.1",
        port=0,
        auth_token=AUTH_TOKEN,
        allowlisted_adapters=["xray_vless_tcp_reality"],
        adapter_registry=registry,
    )
    async with server:
        client = RemoteAgentClient(node_url=f"http://127.0.0.1:{server.port}", token=AUTH_TOKEN)
        result = await asyncio.to_thread(
            client.execute_adapter,
            "xray_vless_tcp_reality",
            SAMPLE_TARGET,
            {"server_name": "example.com"},
        )
        assert result.status == ProbeStatus.SUCCESS
        assert result.probe == "xray_vless_tcp_reality"
        assert result.duration_ms == 25.0
        assert result.details.get("tunnel_established") is True

@pytest.mark.asyncio
async def test_server_adapter_execute_failed_result():
    registry = AdapterRegistry()
    mock_adapter = MockProxyAdapter("xray_vless_tcp_reality", should_succeed=False)
    registry.register(mock_adapter)

    server = AgentServer(
        host="127.0.0.1",
        port=0,
        auth_token=AUTH_TOKEN,
        allowlisted_adapters=["xray_vless_tcp_reality"],
        adapter_registry=registry,
    )
    async with server:
        client = RemoteAgentClient(node_url=f"http://127.0.0.1:{server.port}", token=AUTH_TOKEN)
        result = await asyncio.to_thread(
            client.execute_adapter,
            "xray_vless_tcp_reality",
            SAMPLE_TARGET,
            {"server_name": "example.com"},
        )
        assert result.status == ProbeStatus.FAILED
        assert result.error == "Connection refused by remote host"
        assert result.details.get("failure_stage") == "handshake"

@pytest.mark.asyncio
async def test_server_adapter_execute_rejects_dangerous_keys():
    registry = AdapterRegistry()
    registry.register(MockProxyAdapter("xray_vless_tcp_reality"))

    server = AgentServer(
        host="127.0.0.1",
        port=0,
        auth_token=AUTH_TOKEN,
        allowlisted_adapters=["xray_vless_tcp_reality"],
        adapter_registry=registry,
    )
    async with server:
        client = RemoteAgentClient(node_url=f"http://127.0.0.1:{server.port}", token=AUTH_TOKEN)
        with pytest.raises(RemoteHttpError) as exc_info:
            await asyncio.to_thread(
                client.execute_adapter,
                "xray_vless_tcp_reality",
                SAMPLE_TARGET,
                {"command": "rm -rf /", "plugin": "malicious.so"},
            )
        assert exc_info.value.status_code == 400
        assert exc_info.value.error_code == "untrusted_config"
