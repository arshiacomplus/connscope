from __future__ import annotations

from typing import Any

from connscope.core import Target
from .models import (
    AdapterCapability,
    AdapterMetadata,
    AdapterStatus,
    EngineType,
    ExecutableRequirement,
    OperatingMode,
    ProtocolType,
    SecurityType,
    TransportType,
)
from .process import (
    TunnelVerificationResult,
    find_free_loopback_port,
    read_bounded_stream,
    scrub_sensitive_text,
    terminate_process_tree,
    verify_tunnel_and_data_transfer,
    wait_for_proxy_ready,
)
from .builders import VALID_VMESS_SECURITY, build_xray_config
from .profile_adapter import ProfileDrivenAdapter

__all__ = [
    "TunnelVerificationResult",
    "VALID_VMESS_SECURITY",
    "XrayVmessWebSocketTlsAdapter",
    "find_free_loopback_port",
    "generate_xray_vmess_ws_tls_client_config",
    "read_bounded_stream",
    "scrub_sensitive_text",
    "terminate_process_tree",
    "verify_tunnel_and_data_transfer",
    "wait_for_proxy_ready",
]

def generate_xray_vmess_ws_tls_client_config(
    target: Target,
    config: dict[str, Any],
    local_socks_port: int,
    local_http_port: int,
    local_host: str = "127.0.0.1",
) -> dict[str, Any]:
    return build_xray_config(
        target=target,
        protocol=ProtocolType.VMESS,
        transport=TransportType.WEBSOCKET,
        security=SecurityType.TLS,
        config=config,
        local_socks_port=local_socks_port,
        local_http_port=local_http_port,
        local_host=local_host,
    )

class XrayVmessWebSocketTlsAdapter(ProfileDrivenAdapter):
    metadata = AdapterMetadata(
        adapter_id="xray_vmess_ws_tls",
        display_name="Xray-core VMess WebSocket TLS",
        engine=EngineType.XRAY,
        protocol=ProtocolType.VMESS,
        transport=TransportType.WEBSOCKET,
        security=SecurityType.TLS,
        operating_mode=OperatingMode.CLIENT_ONLY,
        capabilities=frozenset({
            AdapterCapability.TCP_CONNECT,
            AdapterCapability.HANDSHAKE,
            AdapterCapability.TUNNEL_VERIFY,
            AdapterCapability.DATA_TRANSFER,
            AdapterCapability.LATENCY,
        }),
        status=AdapterStatus.MOCKED_LIFECYCLE_TESTED,
        executable=ExecutableRequirement(
            binary_name="xray",
            min_version="1.8.0",
        ),
        description="Measures VMess over WebSocket with TLS encryption using Xray-core client.",
    )

    def __init__(self) -> None:
        super().__init__(
            adapter_id="xray_vmess_ws_tls",
            engine=EngineType.XRAY,
            protocol=ProtocolType.VMESS,
            transport=TransportType.WEBSOCKET,
            security=SecurityType.TLS,
            display_name="Xray-core VMess WebSocket TLS",
            status=AdapterStatus.MOCKED_LIFECYCLE_TESTED,
            description="Measures VMess over WebSocket with TLS encryption using Xray-core client.",
        )
        self.metadata = XrayVmessWebSocketTlsAdapter.metadata
