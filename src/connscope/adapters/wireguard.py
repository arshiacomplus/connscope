
from __future__ import annotations

import base64
import ipaddress
import os
from pathlib import Path
from typing import Any

from connscope.core import Target
from .base import EngineAdapter
from .layer3 import (
    Layer3IsolationBackend,
    Layer3TunnelAdapter,
    LinuxNetnsIsolationBackend,
    LinuxOriginNetnsIsolationBackend,
)
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
    TunnelExecutionMode,
)
from .security import resolve_safe_executable

ALLOWED_WIREGUARD_CONFIG_KEYS: frozenset[str] = frozenset({
    "private_key",
    "public_key",
    "preshared_key",
    "endpoint",
    "allowed_ips",
    "address",
    "listen_port",
    "mtu",
    "persistent_keepalive",
    "dns",
    "test_url",
    "timeout_s",
    "verify_cert",
})

def validate_wireguard_key(key: Any, name: str = "key") -> str:
    if not isinstance(key, str):
        raise TypeError(f"{name} must be a string, got {type(key).__name__}")
    key_str = key.strip()
    if not key_str:
        raise ValueError(f"{name} must not be empty")

    try:
        pad_len = (4 - len(key_str) % 4) % 4
        padded = key_str + ("=" * pad_len)
        decoded = base64.b64decode(padded)
        if len(decoded) != 32:
            raise ValueError(f"{name} must decode to exactly 32 bytes (got {len(decoded)})")
    except Exception as exc:
        if isinstance(exc, ValueError) and "32 bytes" in str(exc):
            raise
        raise ValueError(f"Invalid base64 encoding for {name}: {exc}") from exc

    return key_str

def validate_wireguard_config(
    config: dict[str, Any] | None,
    target: Target | None = None,
) -> dict[str, Any]:
    if config is None:
        raise ValueError("Configuration dictionary is required")
    if not isinstance(config, dict):
        raise TypeError(f"Configuration must be a dict, got {type(config).__name__}")

    for k in config:
        if k not in ALLOWED_WIREGUARD_CONFIG_KEYS:
            raise ValueError(
                f"Unknown parameter '{k}' in WireGuard configuration. "
                "Standard WireGuard does not accept obfuscation or non-standard parameters."
            )

    if "private_key" not in config:
        raise ValueError("Missing required parameter 'private_key'")
    if "public_key" not in config:
        raise ValueError("Missing required parameter 'public_key'")

    private_key = validate_wireguard_key(config["private_key"], "private_key")
    public_key = validate_wireguard_key(config["public_key"], "public_key")

    preshared_key = None
    if config.get("preshared_key") is not None:
        preshared_key = validate_wireguard_key(config["preshared_key"], "preshared_key")

    endpoint = config.get("endpoint")
    if endpoint is not None:
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError("endpoint must be a non-empty string in host:port format")
        endpoint = endpoint.strip()
        if ":" not in endpoint:
            raise ValueError(f"Invalid endpoint format '{endpoint}'; expected 'host:port'")
        parts = endpoint.rsplit(":", 1)
        try:
            port_num = int(parts[1])
            if not (1 <= port_num <= 65535):
                raise ValueError(f"Endpoint port {port_num} must be between 1 and 65535")
        except ValueError as exc:
            raise ValueError(f"Invalid port in endpoint '{endpoint}': {exc}") from exc
    elif target is not None:
        endpoint = f"{target.host}:{target.port}"
    else:
        raise ValueError("Either 'endpoint' in config or a valid Target must be provided")

    allowed_ips_raw = config.get("allowed_ips", "0.0.0.0/0, ::/0")
    if not isinstance(allowed_ips_raw, str) or not allowed_ips_raw.strip():
        raise ValueError("allowed_ips must be a non-empty comma-separated CIDR string")
    allowed_ips_list: list[str] = []
    for cidr_str in allowed_ips_raw.split(","):
        cidr = cidr_str.strip()
        if not cidr:
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
            allowed_ips_list.append(cidr)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR prefix in allowed_ips '{cidr}': {exc}") from exc
    if not allowed_ips_list:
        raise ValueError("allowed_ips must contain at least one valid CIDR prefix")
    allowed_ips = ", ".join(allowed_ips_list)

    address_raw = config.get("address", "10.0.0.2/32")
    if not isinstance(address_raw, str) or not address_raw.strip():
        raise ValueError("address must be a non-empty comma-separated CIDR string")
    address_list: list[str] = []
    for addr_str in address_raw.split(","):
        addr = addr_str.strip()
        if not addr:
            continue
        try:
            ipaddress.ip_interface(addr)
            address_list.append(addr)
        except ValueError as exc:
            raise ValueError(f"Invalid interface address '{addr}': {exc}") from exc
    if not address_list:
        raise ValueError("address must contain at least one valid interface IP")
    address = ", ".join(address_list)

    mtu = config.get("mtu", 1420)
    if not isinstance(mtu, int) or isinstance(mtu, bool):
        raise TypeError(f"mtu must be an integer, got {type(mtu).__name__}")
    if not (1280 <= mtu <= 1500):
        raise ValueError(f"mtu must be between 1280 and 1500 bytes (got {mtu})")

    persistent_keepalive = config.get("persistent_keepalive", 25)
    if not isinstance(persistent_keepalive, int) or isinstance(persistent_keepalive, bool):
        raise TypeError(f"persistent_keepalive must be an integer, got {type(persistent_keepalive).__name__}")
    if not (0 <= persistent_keepalive <= 3600):
        raise ValueError(f"persistent_keepalive must be between 0 and 3600 seconds (got {persistent_keepalive})")

    listen_port = config.get("listen_port")
    if listen_port is not None:
        if not isinstance(listen_port, int) or isinstance(listen_port, bool):
            raise TypeError(f"listen_port must be an integer, got {type(listen_port).__name__}")
        if not (1 <= listen_port <= 65535):
            raise ValueError(f"listen_port must be between 1 and 65535 (got {listen_port})")

    test_url = str(config.get("test_url", "http://cp.cloudflare.com/generate_204"))
    timeout_s = float(config.get("timeout_s", 10.0))
    if timeout_s <= 0.0:
        raise ValueError(f"timeout_s must be positive, got {timeout_s}")
    verify_cert = bool(config.get("verify_cert", True))

    validated: dict[str, Any] = {
        "private_key": private_key,
        "public_key": public_key,
        "endpoint": endpoint,
        "allowed_ips": allowed_ips,
        "address": address,
        "mtu": mtu,
        "persistent_keepalive": persistent_keepalive,
        "test_url": test_url,
        "timeout_s": timeout_s,
        "verify_cert": verify_cert,
    }
    if preshared_key is not None:
        validated["preshared_key"] = preshared_key
    if listen_port is not None:
        validated["listen_port"] = listen_port
    if config.get("dns"):
        validated["dns"] = str(config["dns"]).strip()

    return validated

def generate_wireguard_wg_setconf_config(
    config: dict[str, Any],
    target: Target | None = None,
) -> str:
    validated = validate_wireguard_config(config, target)

    lines: list[str] = [
        "[Interface]",
        f"PrivateKey = {validated['private_key']}",
    ]

    if validated.get("listen_port"):
        lines.append(f"ListenPort = {validated['listen_port']}")

    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {validated['public_key']}")

    if validated.get("preshared_key"):
        lines.append(f"PresharedKey = {validated['preshared_key']}")

    lines.append(f"Endpoint = {validated['endpoint']}")
    lines.append(f"AllowedIPs = {validated['allowed_ips']}")

    if validated.get("persistent_keepalive") is not None:
        lines.append(f"PersistentKeepalive = {validated['persistent_keepalive']}")

    lines.append("")
    return "\n".join(lines)

def generate_wireguard_client_config(
    config: dict[str, Any],
    target: Target | None = None,
) -> str:
    validated = validate_wireguard_config(config, target)

    lines: list[str] = [
        "[Interface]",
        f"PrivateKey = {validated['private_key']}",
        f"Address = {validated['address']}",
        f"MTU = {validated['mtu']}",
    ]

    if validated.get("listen_port"):
        lines.append(f"ListenPort = {validated['listen_port']}")
    if validated.get("dns"):
        lines.append(f"DNS = {validated['dns']}")

    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {validated['public_key']}")

    if validated.get("preshared_key"):
        lines.append(f"PresharedKey = {validated['preshared_key']}")

    lines.append(f"Endpoint = {validated['endpoint']}")
    lines.append(f"AllowedIPs = {validated['allowed_ips']}")

    if validated.get("persistent_keepalive") is not None:
        lines.append(f"PersistentKeepalive = {validated['persistent_keepalive']}")

    lines.append("")
    return "\n".join(lines)

class WireGuardStandardAdapter(Layer3TunnelAdapter):

    metadata = AdapterMetadata(
        adapter_id="wireguard_standard",
        display_name="Native WireGuard L3 Tunnel",
        engine=EngineType.WIREGUARD,
        protocol=ProtocolType.WIREGUARD,
        transport=TransportType.UDP,
        security=SecurityType.NONE,
        operating_mode=OperatingMode.CLIENT_ONLY,
        execution_mode=TunnelExecutionMode.NETWORK_INTERFACE,
        capabilities=frozenset({
            AdapterCapability.UDP_CONNECT,
            AdapterCapability.HANDSHAKE,
            AdapterCapability.TUNNEL_VERIFY,
            AdapterCapability.DATA_TRANSFER,
            AdapterCapability.LATENCY,
        }),
        status=AdapterStatus.CONFIG_VALIDATION_IMPLEMENTED,
        executable=ExecutableRequirement(
            binary_name="wg",
            lookup_paths=("/usr/local/bin", "/usr/bin", "/bin"),
            check_args=("--version",),
        ),
        description="Native WireGuard network-interface tunnel over UDP with peer handshake and transfer tracking",
    )

    default_interface_name: str = "wg0"

    def __init__(self, isolation_backend: Layer3IsolationBackend | None = None) -> None:
        super().__init__(isolation_backend=isolation_backend)

    def get_extra_result_details(self, config: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return {
            "driver": "wireguard",
            "implementation": "wireguard-linux-kernel-module",
        }

    def create_default_isolation_backend(self) -> Layer3IsolationBackend:
        if os.environ.get("CONNSCOPE_WIREGUARD_ORIGIN_NETNS", "0") == "1":
            return LinuxOriginNetnsIsolationBackend()
        return LinuxNetnsIsolationBackend()

    def validate_config(self, config: dict[str, Any] | None) -> dict[str, Any]:
        return validate_wireguard_config(config)

    def check_executable(self, lookup_paths: tuple[str, ...] | None = None) -> tuple[bool, str | None]:
        paths = lookup_paths or (self.metadata.executable.lookup_paths if self.metadata.executable else None)
        try:
            exe_path = resolve_safe_executable("wg", lookup_paths=paths)
            return True, str(exe_path)
        except (FileNotFoundError, PermissionError) as exc:
            return False, str(exc)

    def generate_config_file(self, config: dict[str, Any], target: Target, workspace_dir: Path) -> Path:
        config_text = generate_wireguard_wg_setconf_config(config, target)
        cfg_path = workspace_dir / "wg0.conf"

        fd = os.open(str(cfg_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(config_text)

        return cfg_path
