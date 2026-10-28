from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

class EngineType(StrEnum):
    XRAY = "xray"
    SING_BOX = "sing_box"
    V2RAY = "v2ray"
    EXCLAVE = "exclave"
    WIREGUARD = "wireguard"
    AMNEZIA_WG = "amnezia_wg"
    OPENVPN = "openvpn"
    IPSEC = "ipsec"
    SSH = "ssh"
    TRUST_TUNNEL = "trust_tunnel"
    DNSTT = "dnstt"
    SLIPSTREAM = "slipstream"
    NATIVE = "native"

class ProtocolType(StrEnum):
    VLESS = "vless"
    VMESS = "vmess"
    TROJAN = "trojan"
    SHADOWSOCKS = "shadowsocks"
    SHADOWSOCKS_2022 = "shadowsocks_2022"
    WIREGUARD = "wireguard"
    AMNEZIA_WG = "amnezia_wg"
    OPENVPN = "openvpn"
    IPSEC = "ipsec"
    SSH = "ssh"
    HYSTERIA2 = "hysteria2"
    TUIC = "tuic"
    TRUST_TUNNEL = "trust_tunnel"
    ANYTLS = "anytls"
    MIERU = "mieru"
    NAIVEPROXY = "naiveproxy"
    JUICITY = "juicity"
    MASQUE = "masque"
    SNELL = "snell"
    SHADOWQUIC = "shadowquic"
    SOCKS = "socks"
    HTTP_CONNECT = "http_connect"
    CONNECT_UDP = "connect_udp"
    MASTER_DNS_VPN = "master_dns_vpn"
    DNSTT = "dnstt"
    SLIPSTREAM = "slipstream"
    DNS = "dns"
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"

class TransportType(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    HTTP_UPGRADE = "httpupgrade"
    XHTTP = "xhttp"
    SPLIT_HTTP = "splithttp"
    MKCP = "mkcp"
    QUIC = "quic"
    HTTP2 = "http2"
    HTTP3 = "http3"

class SecurityType(StrEnum):
    NONE = "none"
    TLS = "tls"
    REALITY = "reality"
    SHADOW_TLS = "shadow_tls"
    NOISE = "noise"

class AdapterCapability(StrEnum):
    TCP_CONNECT = "tcp_connect"
    UDP_CONNECT = "udp_connect"
    HANDSHAKE = "handshake"
    TUNNEL_VERIFY = "tunnel_verify"
    DATA_TRANSFER = "data_transfer"
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    RECONNECT = "reconnect"

class OperatingMode(StrEnum):
    CLIENT_ONLY = "client_only"
    SERVER_ONLY = "server_only"
    CLIENT_SERVER = "client_server"

class TunnelExecutionMode(StrEnum):
    LOCAL_PROXY = "local_proxy"
    NETWORK_INTERFACE = "network_interface"

class AdapterStatus(StrEnum):
    CATALOGUED = "catalogued"
    CONFIG_VALIDATION_IMPLEMENTED = "config_validation_implemented"
    ADAPTER_LIFECYCLE_IMPLEMENTED = "adapter_lifecycle_implemented"
    MOCKED_LIFECYCLE_TESTED = "mocked_lifecycle_tested"
    LOCAL_DIAGNOSTIC_VERIFIED = "local_diagnostic_verified"
    REAL_TUNNEL_VERIFIED = "real_tunnel_verified"
    REAL_DATA_TRANSFER_TESTED = "real_data_transfer_tested"
    REAL_ENGINE_INTEGRATION_TESTED = "real_engine_integration_tested"
    CONFIG_VALIDATED = "config_validated"
    EXECUTION_IMPLEMENTED = "execution_implemented"
    TUNNEL_VERIFIED = "tunnel_verified"
    DATA_TRANSFER_VERIFIED = "data_transfer_verified"
    REAL_ENGINE_TESTED = "real_engine_tested"
    IMPLEMENTED = "implemented"
    EXPERIMENTAL = "experimental"
    UNAVAILABLE = "unavailable"
    NOT_YET_SUPPORTED = "not_yet_supported"

class FailureStage(StrEnum):
    PRE_FLIGHT = "pre_flight"
    CONFIG_GENERATION = "config_generation"
    PROCESS_SPAWN = "process_spawn"
    INTERFACE_SETUP = "interface_setup"
    HANDSHAKE = "handshake"
    TUNNEL_ESTABLISHMENT = "tunnel_establishment"
    TRAFFIC_TRAVERSAL = "traffic_traversal"
    DATA_TRANSFER = "data_transfer"
    CLEANUP = "cleanup"
    TIMEOUT = "timeout"

@dataclass(frozen=True, slots=True)
class ExecutableRequirement:
    binary_name: str
    min_version: str | None = None
    lookup_paths: tuple[str, ...] = (
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    )
    check_args: tuple[str, ...] = ("version",)

    def __post_init__(self) -> None:
        if not self.binary_name or not self.binary_name.strip():
            raise ValueError("binary_name must not be empty")
        if "/" in self.binary_name or "\\" in self.binary_name:
            raise ValueError(f"Path separators are not allowed in binary_name '{self.binary_name}'")

@dataclass(frozen=True, slots=True)
class AdapterMetadata:
    adapter_id: str
    display_name: str
    engine: EngineType
    protocol: ProtocolType
    transport: TransportType
    security: SecurityType
    operating_mode: OperatingMode
    capabilities: frozenset[AdapterCapability]
    status: AdapterStatus
    executable: ExecutableRequirement | None = None
    description: str = ""
    execution_mode: TunnelExecutionMode = TunnelExecutionMode.LOCAL_PROXY

    def __post_init__(self) -> None:
        if not self.adapter_id or not self.adapter_id.strip():
            raise ValueError("adapter_id must not be empty")
        if not self.display_name or not self.display_name.strip():
            raise ValueError("display_name must not be empty")
        if not self.capabilities:
            raise ValueError("capabilities must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "display_name": self.display_name,
            "engine": self.engine.value,
            "protocol": self.protocol.value,
            "transport": self.transport.value,
            "security": self.security.value,
            "operating_mode": self.operating_mode.value,
            "execution_mode": self.execution_mode.value,
            "capabilities": sorted(c.value for c in self.capabilities),
            "status": self.status.value,
            "executable": {
                "binary_name": self.executable.binary_name,
                "min_version": self.executable.min_version,
            }
            if self.executable
            else None,
            "description": self.description,
        }

@dataclass(slots=True)
class AdapterResultDetails:
    adapter_id: str
    engine: str
    protocol: str
    transport: str
    security: str
    failure_stage: FailureStage | None = None
    tunnel_established: bool = False
    data_transfer_completed: bool = False
    execution_mode: str = "local_proxy"
    interface_name: str | None = None
    interface_established: bool | None = None
    peer_handshake_completed: bool | None = None
    traffic_traversed: bool | None = None
    latest_handshake_timestamp: float | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    cleanup_completed: bool | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "adapter_id": self.adapter_id,
            "engine": self.engine,
            "protocol": self.protocol,
            "transport": self.transport,
            "security": self.security,
            "execution_mode": self.execution_mode,
            "tunnel_established": self.tunnel_established,
            "data_transfer_completed": self.data_transfer_completed,
        }
        d["failure_stage"] = self.failure_stage.value if self.failure_stage is not None else None
        if self.interface_name is not None:
            d["interface_name"] = self.interface_name
        if self.interface_established is not None:
            d["interface_established"] = self.interface_established
        if self.peer_handshake_completed is not None:
            d["peer_handshake_completed"] = self.peer_handshake_completed
        if self.traffic_traversed is not None:
            d["traffic_traversed"] = self.traffic_traversed
        if self.latest_handshake_timestamp is not None:
            d["latest_handshake_timestamp"] = self.latest_handshake_timestamp
        if self.rx_bytes is not None:
            d["rx_bytes"] = self.rx_bytes
        if self.tx_bytes is not None:
            d["tx_bytes"] = self.tx_bytes
        if self.cleanup_completed is not None:
            d["cleanup_completed"] = self.cleanup_completed
        d.update(self.extra)
        return d
