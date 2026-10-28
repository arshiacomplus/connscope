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
from .builders import VALID_SINGBOX_VMESS_SECURITY, build_singbox_config
from .profile_adapter import ProfileDrivenAdapter

__all__ = [
    "SingBoxVmessWebSocketTlsAdapter",
    "TunnelVerificationResult",
    "VALID_SINGBOX_VMESS_SECURITY",
    "find_free_loopback_port",
    "generate_singbox_vmess_ws_tls_client_config",
    "read_bounded_stream",
    "scrub_sensitive_text",
    "terminate_process_tree",
    "verify_tunnel_and_data_transfer",
    "wait_for_proxy_ready",
]

def generate_singbox_vmess_ws_tls_client_config(
    target: Target,
    config: dict[str, Any],
    local_socks_port: int,
    local_http_port: int,
    local_host: str = "127.0.0.1",
) -> dict[str, Any]:
    return build_singbox_config(
        target=target,
        protocol=ProtocolType.VMESS,
        transport=TransportType.WEBSOCKET,
        security=SecurityType.TLS,
        config=config,
        local_socks_port=local_socks_port,
        local_http_port=local_http_port,
        local_host=local_host,
    )

class SingBoxVmessWebSocketTlsAdapter(ProfileDrivenAdapter):
    metadata = AdapterMetadata(
        adapter_id="singbox_vmess_ws_tls",
        display_name="sing-box VMess WebSocket TLS",
        engine=EngineType.SING_BOX,
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
            binary_name="sing-box",
            min_version="1.10.0",
        ),
        description="Measures VMess over WebSocket with TLS encryption using sing-box client.",
    )

    def __init__(self) -> None:
        super().__init__(
            adapter_id="singbox_vmess_ws_tls",
            engine=EngineType.SING_BOX,
            protocol=ProtocolType.VMESS,
            transport=TransportType.WEBSOCKET,
            security=SecurityType.TLS,
            display_name="sing-box VMess WebSocket TLS",
            status=AdapterStatus.MOCKED_LIFECYCLE_TESTED,
            description="Measures VMess over WebSocket with TLS encryption using sing-box client.",
        )
        self.metadata = SingBoxVmessWebSocketTlsAdapter.metadata
