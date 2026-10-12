import ipaddress
import math
import urllib.parse
from typing import Any

from connscope.core import ProbeRegistry, Target

PROBE_ALIASES: dict[str, str] = {
    "tcp": "tcp_connect",
    "dns": "dns_resolve",
    "tls": "tls_handshake",
    "http": "http_request",
}


def _parse_port(port_str: str) -> int:
    if not port_str:
        raise ValueError("Port cannot be empty")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"Invalid port '{port_str}': must be an integer") from None
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} out of valid range (1-65535)")
    return port


def parse_target(raw: str) -> Target:
    if not raw or not raw.strip():
        raise ValueError("Target host cannot be empty")
    s = raw.strip()

    if "://" in s:
        raise ValueError(f"Generic target must not contain URL scheme: '{raw}'")

    for ch in ("/", "\\", " ", "?", "#", "@"):
        if ch in s:
            raise ValueError(f"Invalid character '{ch}' in target: '{raw}'")

    if s.startswith("["):
        closing = s.find("]")
        if closing == -1:
            raise ValueError(f"Malformed bracketed IPv6 target (missing ']'): '{raw}'")
        host_inner = s[1:closing]
        if not host_inner:
            raise ValueError(f"Empty IPv6 address inside brackets: '{raw}'")
        try:
            ipaddress.IPv6Address(host_inner)
        except ValueError:
            raise ValueError(f"Invalid IPv6 address inside brackets '{host_inner}': '{raw}'") from None

        remainder = s[closing + 1:]
        port = None
        if remainder:
            if not remainder.startswith(":"):
                raise ValueError(f"Malformed bracketed target syntax '{raw}': expected ':' before port")
            port = _parse_port(remainder[1:])
        return Target(host=host_inner, port=port)

    if "]" in s or "[" in s:
        raise ValueError(f"Malformed bracket syntax in target: '{raw}'")

    try:
        ipaddress.IPv6Address(s)
        return Target(host=s, port=None)
    except ValueError:
        pass

    if ":" in s:
        if s.count(":") > 1:
            raise ValueError(f"Invalid target format: multiple colons in non-IPv6 address: '{raw}'")
        host_part, port_part = s.split(":", 1)
        if not host_part:
            raise ValueError(f"Host cannot be empty in '{raw}'")
        port = _parse_port(port_part)
        return Target(host=host_part, port=port)

    return Target(host=s, port=None)


def parse_http_target(raw: str) -> tuple[Target, dict[str, Any]]:
    if not raw or not raw.strip():
        raise ValueError("HTTP target cannot be empty")
    s = raw.strip()

    if "://" in s:
        parsed = urllib.parse.urlsplit(s)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme '{parsed.scheme}'. Only 'http' and 'https' are supported.")

        if not parsed.hostname:
            raise ValueError(f"URL missing valid hostname: '{raw}'")

        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"Invalid port in URL '{raw}': {exc}") from None

        use_tls = (scheme == "https")
        if port is None:
            port = 443 if use_tls else 80
        elif not (1 <= port <= 65535):
            raise ValueError(f"Port {port} out of valid range (1-65535)")

        path = parsed.path if parsed.path else "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        config = {
            "use_tls": use_tls,
            "path": path,
        }
        return Target(host=parsed.hostname, port=port), config

    if "/" in s:
        raise ValueError(
            f"Target contains a path but no scheme: '{raw}'. "
            "Please specify a full URL like 'https://example.com/path' or 'http://example.com/path'."
        )

    target = parse_target(s)
    if target.port is None:
        target = Target(host=target.host, port=443)
        use_tls = True
    else:
        use_tls = False if target.port == 80 else True

    config = {
        "use_tls": use_tls,
        "path": "/",
    }
    return target, config


def resolve_probe_name(name: str, registry: ProbeRegistry) -> str:
    cleaned = name.strip().lower()
    canonical = PROBE_ALIASES.get(cleaned, cleaned)
    available = registry.names()
    if canonical not in available:
        valid = ", ".join(sorted(set(list(PROBE_ALIASES.keys()) + list(available))))
        raise KeyError(f"Unknown probe '{name}'. Available probes: {valid}")
    return canonical


def validate_timeout(timeout_val: float | str | None) -> float | None:
    if timeout_val is None:
        return None
    try:
        val = float(timeout_val)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid timeout '{timeout_val}': must be a positive number") from None
    if not math.isfinite(val) or val <= 0:
        raise ValueError(f"Invalid timeout '{timeout_val}': must be a positive finite number")
    return val
