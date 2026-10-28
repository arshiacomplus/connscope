import ipaddress
from typing import Any, Callable, Sequence

from connscope.core import Target
from .security import (
    SecurityError,
    TargetPolicyViolation,
    TargetResolutionError,
    validate_target,
)

class UntrustedConfigError(SecurityError):
    pass

class UnsupportedProbeError(SecurityError):
    pass

CONNECTION_PROBE_NAMES: frozenset[str] = frozenset({
    "tcp_connect",
    "tls_handshake",
    "http_request",
})

SUPPORTED_PROBE_NAMES: frozenset[str] = CONNECTION_PROBE_NAMES | frozenset({"dns_resolve"})

def select_connection_ip(
    validated_ips: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...],
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not validated_ips:
        raise ValueError("No validated IP addresses available for selection")
    return validated_ips[0]

def prepare_probe_config(
    probe_name: str,
    target: Target,
    config: dict[str, Any] | None = None,
    *,
    allow_private: bool = False,
    resolver: Callable[[str], Sequence[str | ipaddress.IPv4Address | ipaddress.IPv6Address]] | None = None,
) -> dict[str, Any]:
    if not isinstance(probe_name, str):
        raise TypeError(f"Expected probe_name to be str, got {type(probe_name).__name__}")
    if not isinstance(target, Target):
        raise TypeError(f"Expected target to be Target, got {type(target).__name__}")
    if config is not None and not isinstance(config, dict):
        raise TypeError(f"Expected config to be dict or None, got {type(config).__name__}")

    if probe_name not in SUPPORTED_PROBE_NAMES:
        raise UnsupportedProbeError(f"Unsupported probe '{probe_name}' for agent execution")

    if config and "connect_ip" in config:
        raise UntrustedConfigError("Client-supplied 'connect_ip' is not allowed")

    prepared_config: dict[str, Any] = dict(config) if config else {}

    if probe_name == "dns_resolve":
        return prepared_config

    validated_ips = validate_target(target, allow_private=allow_private, resolver=resolver)
    selected_ip = select_connection_ip(validated_ips)

    prepared_config["connect_ip"] = str(selected_ip)
    return prepared_config
