import hmac
import ipaddress
import socket
from typing import Callable, Sequence

from connscope.core import Target

class SecurityError(Exception):
    pass

class TargetPolicyViolation(SecurityError):
    pass

class TargetResolutionError(SecurityError):
    pass

_CLOUD_METADATA_IPS: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset({
    ipaddress.IPv4Address("169.254.169.254"),
    ipaddress.IPv6Address("fd00:ec2::254"),
    ipaddress.IPv4Address("100.100.100.200"),
})

_RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_RFC4193_NETWORK: ipaddress.IPv6Network = ipaddress.IPv6Network("fc00::/7")

def is_rfc1918_or_rfc4193(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in _RFC1918_NETWORKS)
    if isinstance(ip, ipaddress.IPv6Address):
        return ip in _RFC4193_NETWORK
    return False

def verify_bearer_token(supplied_token: str | None, expected_token: str | None) -> bool:
    if not isinstance(expected_token, str) or not expected_token.strip():
        return False
    if not isinstance(supplied_token, str) or not supplied_token.strip():
        return False

    return hmac.compare_digest(
        supplied_token.encode("utf-8"),
        expected_token.encode("utf-8"),
    )

def extract_bearer_token(header_value: str | None) -> str | None:
    if not isinstance(header_value, str):
        return None
    s = header_value.strip()
    if not s:
        return None
    parts = s.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token else None

def normalize_ip_address(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip

def check_ip_address(
    ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool = False,
) -> str | None:
    if isinstance(ip, str):
        ip_obj = ipaddress.ip_address(ip.strip("[]"))
    else:
        ip_obj = ip

    norm_ip = normalize_ip_address(ip_obj)

    if norm_ip.is_loopback:
        return "loopback address is not allowed"
    if norm_ip.is_unspecified:
        return "unspecified address is not allowed"
    if norm_ip.is_multicast:
        return "multicast address is not allowed"
    if norm_ip.is_reserved:
        return "reserved address is not allowed"
    if norm_ip in _CLOUD_METADATA_IPS:
        return "cloud metadata address is not allowed"
    if norm_ip.is_link_local:
        return "link-local address is not allowed"

    if allow_private and is_rfc1918_or_rfc4193(norm_ip):
        return None

    if norm_ip.is_private:
        return "private address is not allowed"
    if not norm_ip.is_global:
        return "non-global address is not allowed"

    return None

def is_ip_allowed(
    ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool = False,
) -> bool:
    return check_ip_address(ip, allow_private=allow_private) is None

def validate_ip_address(
    ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool = False,
) -> None:
    reason = check_ip_address(ip, allow_private=allow_private)
    if reason:
        raise TargetPolicyViolation(f"Destination IP '{ip}' violates policy: {reason}")

def default_resolve_host(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        addr_info = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetResolutionError(f"DNS resolution failed for hostname '{host}': {exc}") from exc
    except Exception as exc:
        raise TargetResolutionError(f"Unexpected error resolving hostname '{host}': {exc}") from exc

    results: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj not in seen:
                seen.add(ip_obj)
                results.append(ip_obj)
        except ValueError:
            continue
    return results

def validate_target(
    target: Target,
    *,
    allow_private: bool = False,
    resolver: Callable[[str], Sequence[str | ipaddress.IPv4Address | ipaddress.IPv6Address]] | None = None,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    if not isinstance(target, Target):
        raise TypeError(f"Expected Target instance, got {type(target).__name__}")

    raw_host = target.host.strip("[]")

    try:
        ip_literal = ipaddress.ip_address(raw_host)
        norm_literal = normalize_ip_address(ip_literal)
        validate_ip_address(norm_literal, allow_private=allow_private)
        return (norm_literal,)
    except ValueError:
        pass

    resolve_fn = resolver if resolver is not None else default_resolve_host
    try:
        resolved = resolve_fn(target.host)
    except TargetResolutionError:
        raise
    except Exception as exc:
        raise TargetResolutionError(f"DNS resolution failed for hostname '{target.host}': {exc}") from exc

    if not resolved:
        raise TargetResolutionError(f"Hostname '{target.host}' resolved to no usable IP addresses")

    validated_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for item in resolved:
        try:
            if isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                ip_obj = item
            elif isinstance(item, str):
                ip_obj = ipaddress.ip_address(item.strip("[]"))
            else:
                raise TypeError(f"Unsupported resolved address type: {type(item).__name__}")
        except ValueError as exc:
            raise TargetResolutionError(f"Hostname '{target.host}' yielded invalid address '{item}': {exc}") from exc

        norm_ip = normalize_ip_address(ip_obj)
        reason = check_ip_address(norm_ip, allow_private=allow_private)
        if reason:
            raise TargetPolicyViolation(
                f"Target hostname '{target.host}' resolves to prohibited address '{ip_obj}': {reason}"
            )
        validated_ips.append(norm_ip)

    return tuple(validated_ips)
