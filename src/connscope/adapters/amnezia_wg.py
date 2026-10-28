
from __future__ import annotations

import base64
import ipaddress
import os
from pathlib import Path
from typing import Any

from connscope.core import Target
from .layer3 import (
    AmneziaWGDeviceDriver,
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
from .wireguard import validate_wireguard_key

ALLOWED_AMNEZIAWG_CONFIG_KEYS: frozenset[str] = frozenset({
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
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "h1",
    "h2",
    "h3",
    "h4",
})

UNSUPPORTED_AMNEZIAWG_V2_KEYS: frozenset[str] = frozenset({
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "header_protection",
    "content_padding",
})

def validate_amneziawg_config(
    config: dict[str, Any] | None,
    target: Target | None = None,
) -> dict[str, Any]:
    if config is None:
        raise ValueError("Configuration dictionary is required")
    if not isinstance(config, dict):
        raise TypeError(f"Configuration must be a dict, got {type(config).__name__}")

    normalized_input: dict[str, Any] = {}
    for k, v in config.items():
        k_clean = k.strip().lower()
        normalized_input[k_clean] = v

    for k in normalized_input:
        if k in UNSUPPORTED_AMNEZIAWG_V2_KEYS:
            raise ValueError(
                f"Parameter '{k}' is part of the newer AmneziaWG v2 Header Protection / transport specification. "
                "The current v1.0 Linux kernel module backend does not support this parameter."
            )

    for k in normalized_input:
        if k not in ALLOWED_AMNEZIAWG_CONFIG_KEYS:
            raise ValueError(f"Unknown parameter '{k}' in AmneziaWG configuration.")

    if "private_key" not in normalized_input:
        raise ValueError("Missing required parameter 'private_key'")
    if "public_key" not in normalized_input:
        raise ValueError("Missing required parameter 'public_key'")

    private_key = validate_wireguard_key(normalized_input["private_key"], "private_key")
    public_key = validate_wireguard_key(normalized_input["public_key"], "public_key")

    preshared_key = None
    if normalized_input.get("preshared_key") is not None:
        preshared_key = validate_wireguard_key(normalized_input["preshared_key"], "preshared_key")

    endpoint = normalized_input.get("endpoint")
    if endpoint is not None:
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError("endpoint must be a non-empty string in host:port format")
        endpoint = endpoint.strip()
        if ":" not in endpoint:
            raise ValueError(f"endpoint must include a port separator ':' (got '{endpoint}')")
    elif target is not None:
        endpoint = f"{target.host}:{target.port}"
    else:
        raise ValueError("Missing endpoint and no Target provided")

    raw_mtu = normalized_input.get("mtu", 1420)
    try:
        mtu = int(raw_mtu)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"mtu must be an integer: {exc}") from exc
    if mtu < 1280 or mtu > 1500:
        raise ValueError(f"mtu must be between 1280 and 1500 (got {mtu})")

    raw_address = normalized_input.get("address", "10.0.0.2/32")
    if not isinstance(raw_address, str) or not raw_address.strip():
        raise ValueError("address must be a non-empty string")
    clean_addresses: list[str] = []
    for addr_str in raw_address.split(","):
        clean_addr = addr_str.strip()
        if not clean_addr:
            continue
        try:
            ipaddress.ip_interface(clean_addr)
            clean_addresses.append(clean_addr)
        except ValueError as exc:
            raise ValueError(f"Invalid IP interface for address '{clean_addr}': {exc}") from exc
    if not clean_addresses:
        raise ValueError("At least one valid IP address must be specified in address")

    raw_allowed = normalized_input.get("allowed_ips", "0.0.0.0/0, ::/0")
    if not isinstance(raw_allowed, str) or not raw_allowed.strip():
        raise ValueError("allowed_ips must be a non-empty string")
    clean_allowed: list[str] = []
    for cidr_str in raw_allowed.split(","):
        clean_cidr = cidr_str.strip()
        if not clean_cidr:
            continue
        try:
            ipaddress.ip_network(clean_cidr, strict=False)
            clean_allowed.append(clean_cidr)
        except ValueError as exc:
            raise ValueError(f"Invalid network CIDR in allowed_ips '{clean_cidr}': {exc}") from exc
    if not clean_allowed:
        raise ValueError("At least one valid network CIDR must be specified in allowed_ips")

    pka = normalized_input.get("persistent_keepalive")
    if pka is not None:
        try:
            pka_val = int(pka)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"persistent_keepalive must be an integer: {exc}") from exc
        if pka_val < 0 or pka_val > 3600:
            raise ValueError(f"persistent_keepalive must be between 0 and 3600 (got {pka_val})")
        pka = pka_val

    listen_port = normalized_input.get("listen_port")
    if listen_port is not None:
        try:
            lp_val = int(listen_port)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"listen_port must be an integer: {exc}") from exc
        if lp_val < 1 or lp_val > 65535:
            raise ValueError(f"listen_port must be between 1 and 65535 (got {lp_val})")
        listen_port = lp_val

    dns_val = normalized_input.get("dns")
    if dns_val is not None:
        if not isinstance(dns_val, str) or not dns_val.strip():
            raise ValueError("dns must be a non-empty string")
        dns_val = dns_val.strip()

    raw_jc = normalized_input.get("jc", 4)
    try:
        jc = int(raw_jc)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"jc must be an integer: {exc}") from exc
    if jc < 1 or jc > 128:
        raise ValueError(f"jc must be between 1 and 128 (got {jc})")

    raw_jmin = normalized_input.get("jmin", 40)
    try:
        jmin = int(raw_jmin)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"jmin must be an integer: {exc}") from exc
    if jmin < 0 or jmin > 1280:
        raise ValueError(f"jmin must be between 0 and 1280 (got {jmin})")

    raw_jmax = normalized_input.get("jmax", 70)
    try:
        jmax = int(raw_jmax)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"jmax must be an integer: {exc}") from exc
    if jmax < 0 or jmax > 1280:
        raise ValueError(f"jmax must be between 0 and 1280 (got {jmax})")

    if jmin >= jmax:
        raise ValueError(f"jmin ({jmin}) must be strictly less than jmax ({jmax})")

    raw_s1 = normalized_input.get("s1", 64)
    try:
        s1 = int(raw_s1)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"s1 must be an integer: {exc}") from exc
    if s1 < 0 or s1 > 1280:
        raise ValueError(f"s1 must be between 0 and 1280 (got {s1})")

    raw_s2 = normalized_input.get("s2", 64)
    try:
        s2 = int(raw_s2)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"s2 must be an integer: {exc}") from exc
    if s2 < 0 or s2 > 1280:
        raise ValueError(f"s2 must be between 0 and 1280 (got {s2})")

    if s1 + 56 == s2:
        raise ValueError(
            f"Invalid padding parameters: s1 + 56 must not equal s2 (got s1={s1}, s2={s2}). "
            "Handshake initiation (148 + s1) and response (92 + s2) must not result in identical packet sizes."
        )

    if 148 + s1 > mtu:
        raise ValueError(f"Init packet size with padding (148 + s1 = {148 + s1}) exceeds MTU ({mtu})")
    if 92 + s2 > mtu:
        raise ValueError(f"Response packet size with padding (92 + s2 = {92 + s2}) exceeds MTU ({mtu})")

    headers: list[int] = []
    for h_name, default_h in (("h1", 1), ("h2", 2), ("h3", 3), ("h4", 4)):
        raw_h = normalized_input.get(h_name, default_h)
        try:
            h_val = int(raw_h)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{h_name} must be an integer: {exc}") from exc
        if h_val < 1 or h_val > 4294967295:
            raise ValueError(f"{h_name} must be a 32-bit positive integer [1, 4294967295] (got {h_val})")
        headers.append(h_val)

    h1, h2, h3, h4 = headers
    if len({h1, h2, h3, h4}) != 4:
        raise ValueError(f"Header types H1, H2, H3, H4 must be distinct from each other (got {h1}, {h2}, {h3}, {h4})")

    test_url = normalized_input.get("test_url", "http://cp.cloudflare.com/generate_204")
    raw_timeout = normalized_input.get("timeout_s", 10.0)
    try:
        timeout_s = max(0.5, float(raw_timeout))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"timeout_s must be a number: {exc}") from exc
    verify_cert = bool(normalized_input.get("verify_cert", True))

    return {
        "private_key": private_key,
        "public_key": public_key,
        "preshared_key": preshared_key,
        "endpoint": endpoint,
        "address": ", ".join(clean_addresses),
        "allowed_ips": ", ".join(clean_allowed),
        "mtu": mtu,
        "listen_port": listen_port,
        "persistent_keepalive": pka,
        "dns": dns_val,
        "jc": jc,
        "jmin": jmin,
        "jmax": jmax,
        "s1": s1,
        "s2": s2,
        "h1": h1,
        "h2": h2,
        "h3": h3,
        "h4": h4,
        "test_url": test_url,
        "timeout_s": timeout_s,
        "verify_cert": verify_cert,
    }

def generate_amneziawg_awg_setconf_config(
    config: dict[str, Any],
    target: Target | None = None,
) -> str:
    validated = validate_amneziawg_config(config, target)

    lines: list[str] = [
        "[Interface]",
        f"PrivateKey = {validated['private_key']}",
        f"Jc = {validated['jc']}",
        f"Jmin = {validated['jmin']}",
        f"Jmax = {validated['jmax']}",
        f"S1 = {validated['s1']}",
        f"S2 = {validated['s2']}",
        f"H1 = {validated['h1']}",
        f"H2 = {validated['h2']}",
        f"H3 = {validated['h3']}",
        f"H4 = {validated['h4']}",
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

def generate_amneziawg_client_config(
    config: dict[str, Any],
    target: Target | None = None,
) -> str:
    validated = validate_amneziawg_config(config, target)

    lines: list[str] = [
        "[Interface]",
        f"PrivateKey = {validated['private_key']}",
        f"Address = {validated['address']}",
        f"MTU = {validated['mtu']}",
        f"Jc = {validated['jc']}",
        f"Jmin = {validated['jmin']}",
        f"Jmax = {validated['jmax']}",
        f"S1 = {validated['s1']}",
        f"S2 = {validated['s2']}",
        f"H1 = {validated['h1']}",
        f"H2 = {validated['h2']}",
        f"H3 = {validated['h3']}",
        f"H4 = {validated['h4']}",
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

class AmneziaWGStandardAdapter(Layer3TunnelAdapter):

    metadata = AdapterMetadata(
        adapter_id="amnezia_wg_standard",
        display_name="AmneziaWG Obfuscated L3 Tunnel",
        engine=EngineType.AMNEZIA_WG,
        protocol=ProtocolType.WIREGUARD,
        transport=TransportType.UDP,
        security=SecurityType.NOISE,
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
            binary_name="awg",
            lookup_paths=("/usr/local/bin", "/usr/bin", "/bin"),
            check_args=("--version",),
        ),
        description="AmneziaWG obfuscated network-interface tunnel over UDP with junk packet injection and custom magic headers",
    )

    default_interface_name: str = "awg0"

    def __init__(self, isolation_backend: Layer3IsolationBackend | None = None) -> None:
        super().__init__(isolation_backend=isolation_backend)

    def create_default_isolation_backend(self) -> Layer3IsolationBackend:
        driver = AmneziaWGDeviceDriver()
        if os.environ.get("CONNSCOPE_AMNEZIAWG_ORIGIN_NETNS", "0") == "1":
            return LinuxOriginNetnsIsolationBackend(driver=driver)
        return LinuxNetnsIsolationBackend(driver=driver)

    def validate_config(self, config: dict[str, Any] | None) -> dict[str, Any]:
        return validate_amneziawg_config(config)

    def check_executable(self, lookup_paths: tuple[str, ...] | None = None) -> tuple[bool, str | None]:
        paths = lookup_paths or (self.metadata.executable.lookup_paths if self.metadata.executable else None)
        try:
            exe_path = resolve_safe_executable("awg", lookup_paths=paths)
            return True, str(exe_path)
        except (FileNotFoundError, PermissionError) as exc:
            return False, str(exc)

    def generate_config_file(self, config: dict[str, Any], target: Target, workspace_dir: Path) -> Path:
        config_text = generate_amneziawg_awg_setconf_config(config, target)
        cfg_path = workspace_dir / "awg0.conf"

        fd = os.open(str(cfg_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(config_text)

        return cfg_path

    def get_extra_result_details(self, config: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return {
            "driver": "amneziawg",
            "implementation": "amneziawg-linux-kernel-module",
            "schema_version": "v1.0",
            "amnezia_parameters": {
                "jc": config.get("jc", 4),
                "jmin": config.get("jmin", 40),
                "jmax": config.get("jmax", 70),
                "s1": config.get("s1", 64),
                "s2": config.get("s2", 64),
                "h1": config.get("h1", 1),
                "h2": config.get("h2", 2),
                "h3": config.get("h3", 3),
                "h4": config.get("h4", 4),
            },
        }
