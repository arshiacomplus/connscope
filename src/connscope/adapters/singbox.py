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
from .builders import build_singbox_config
from .profile_adapter import ProfileDrivenAdapter

__all__ = [
    "SingBoxVlessTcpRealityAdapter",
    "TunnelVerificationResult",
    "find_free_loopback_port",
    "generate_singbox_client_config",
    "read_bounded_stream",
    "scrub_sensitive_text",
    "terminate_process_tree",
    "verify_tunnel_and_data_transfer",
    "wait_for_proxy_ready",
]

def generate_singbox_client_config(
    target: Target,
    config: dict[str, Any],
    local_socks_port: int,
    local_http_port: int,
    local_host: str = "127.0.0.1",
) -> dict[str, Any]:
    return build_singbox_config(
        target=target,
        protocol=ProtocolType.VLESS,
        transport=TransportType.TCP,
        security=SecurityType.REALITY,
        config=config,
        local_socks_port=local_socks_port,
        local_http_port=local_http_port,
        local_host=local_host,
    )

class SingBoxVlessTcpRealityAdapter(ProfileDrivenAdapter):
    metadata = AdapterMetadata(
        adapter_id="singbox_vless_tcp_reality",
        display_name="sing-box VLESS TCP REALITY",
        engine=EngineType.SING_BOX,
        protocol=ProtocolType.VLESS,
        transport=TransportType.TCP,
        security=SecurityType.REALITY,
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
        description="Measures VLESS over TCP with REALITY camouflage using sing-box client (compatible with sing-box v1.10.0+).",
    )

    def __init__(self) -> None:
        super().__init__(
            adapter_id="singbox_vless_tcp_reality",
            engine=EngineType.SING_BOX,
            protocol=ProtocolType.VLESS,
            transport=TransportType.TCP,
            security=SecurityType.REALITY,
            display_name="sing-box VLESS TCP REALITY",
            status=AdapterStatus.MOCKED_LIFECYCLE_TESTED,
            description="Measures VLESS over TCP with REALITY camouflage using sing-box client (compatible with sing-box v1.10.0+).",
        )
        self.metadata = SingBoxVlessTcpRealityAdapter.metadata
