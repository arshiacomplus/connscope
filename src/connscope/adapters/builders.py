from __future__ import annotations

import base64
import ipaddress
import re
import ssl
from typing import Any
import urllib.parse
import uuid

from connscope.core import Target
from .models import EngineType, ProtocolType, SecurityType, TransportType

DANGEROUS_CONFIG_KEYS = frozenset({
    "command",
    "plugin",
    "executable",
    "executable_path",
    "exec",
    "shell",
    "system",
    "sh",
    "bash",
    "script",
})

SUPPORTED_SHADOWSOCKS_METHODS = frozenset({
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
})

SHADOWSOCKS_2022_KEY_SIZES = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}

VALID_VMESS_SECURITY = frozenset({
    "auto",
    "aes-128-gcm",
    "chacha20-poly1305",
})

VALID_SINGBOX_VMESS_SECURITY = frozenset({
    "auto",
    "aes-128-gcm",
    "chacha20-poly1305",
    "none",
    "zero",
})

SUPPORTED_VMESS_SECURITIES = VALID_VMESS_SECURITY

COMMON_ALLOWED_KEYS = frozenset({
    "timeout_s",
    "startup_timeout_s",
    "test_url",
    "local_port",
    "verify_cert",
    "ssl_context",
    "endpoint",
    "mux_enabled",
    "mux_concurrency",
    "tcp_fast_open",
})

TLS_ALLOWED_KEYS = frozenset({
    "server_name",
    "fingerprint",
    "alpn",
    "min_version",
    "max_version",
})

WS_ALLOWED_KEYS = frozenset({
    "path",
    "host_header",
    "host",
    "headers",
    "max_early_data",
    "early_data_header_name",
})

GRPC_ALLOWED_KEYS = frozenset({
    "service_name",
    "multi_mode",
    "idle_timeout_s",
    "ping_timeout_s",
})

PROFILE_ALLOWED_KEYS = {
    ("vless", "tcp", "reality"): COMMON_ALLOWED_KEYS | TLS_ALLOWED_KEYS | {
        "uuid",
        "public_key",
        "password",
        "short_id",
        "flow",
        "spiderX",
        "spider_x",
    },
    ("vless", "tcp", "tls"): COMMON_ALLOWED_KEYS | TLS_ALLOWED_KEYS | {
        "uuid",
        "flow",
    },
    ("vless", "tcp", "none"): COMMON_ALLOWED_KEYS | {
        "uuid",
        "flow",
        "allow_insecure_transport",
    },
    ("vless", "websocket", "tls"): COMMON_ALLOWED_KEYS | TLS_ALLOWED_KEYS | WS_ALLOWED_KEYS | {
        "uuid",
        "flow",
    },
    ("vless", "grpc", "tls"): COMMON_ALLOWED_KEYS | TLS_ALLOWED_KEYS | GRPC_ALLOWED_KEYS | {
        "uuid",
        "flow",
    },
    ("vmess", "websocket", "tls"): COMMON_ALLOWED_KEYS | TLS_ALLOWED_KEYS | WS_ALLOWED_KEYS | {
        "uuid",
        "alter_id",
        "security",
        "packet_encoding",
    },
    ("trojan", "tcp", "tls"): COMMON_ALLOWED_KEYS | TLS_ALLOWED_KEYS | {
        "password",
    },
    ("shadowsocks", "tcp", "none"): COMMON_ALLOWED_KEYS | {
        "method",
        "password",
        "uot",
    },
}

def normalize_profile_keys(
    protocol: ProtocolType | str,
    transport: TransportType | str,
    security: SecurityType | str,
) -> tuple[str, str, str]:
    p = protocol.value if isinstance(protocol, ProtocolType) else str(protocol).lower()
    t = transport.value if isinstance(transport, TransportType) else str(transport).lower()
    s = security.value if isinstance(security, SecurityType) else str(security).lower()
    return p, t, s

def validate_profile_config(
    protocol: ProtocolType | str,
    transport: TransportType | str,
    security: SecurityType | str,
    config: dict[str, Any] | None,
    engine: EngineType | str | None = None,
) -> dict[str, Any]:
    if not isinstance(config, dict) or not config:
        raise ValueError("Configuration dictionary is required")

    p, t, s = normalize_profile_keys(protocol, transport, security)
    profile_key = (p, t, s)
    if profile_key not in PROFILE_ALLOWED_KEYS:
        raise ValueError(f"Unsupported protocol profile combination: {p}/{t}/{s}")

    for k in config:
        if k in DANGEROUS_CONFIG_KEYS or any(bad in k.lower() for bad in ("command", "exec", "shell", "plugin")):
            raise ValueError(f"Dangerous configuration key rejected: {k}")

    allowed_keys = PROFILE_ALLOWED_KEYS[profile_key]
    unknown_keys = set(config.keys()) - allowed_keys
    if unknown_keys:
        raise ValueError(f"Unknown configuration keys for profile {p}/{t}/{s}: {sorted(unknown_keys)}")

    validated: dict[str, Any] = {}

    eng_str = engine.value if isinstance(engine, EngineType) else str(engine or "").lower()

    timeout_s = config.get("timeout_s", 10.0)
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
        raise ValueError(f"Invalid 'timeout_s': must be a positive number, got {timeout_s!r}")
    validated["timeout_s"] = float(timeout_s)

    startup_timeout_s = config.get("startup_timeout_s", 3.0)
    if (
        isinstance(startup_timeout_s, bool)
        or not isinstance(startup_timeout_s, (int, float))
        or startup_timeout_s <= 0
    ):
        raise ValueError(f"Invalid 'startup_timeout_s': must be a positive number, got {startup_timeout_s!r}")
    validated["startup_timeout_s"] = float(startup_timeout_s)

    test_url = config.get("test_url", "http://cp.cloudflare.com/generate_204")
    if not isinstance(test_url, str) or not test_url.strip():
        raise ValueError("Invalid 'test_url': must be a non-empty string")
    clean_url = test_url.strip()
    parsed_url = urllib.parse.urlparse(clean_url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        raise ValueError(f"Invalid 'test_url' '{test_url}': must be a valid absolute HTTP/HTTPS URL")
    validated["test_url"] = clean_url

    if "local_port" in config and config["local_port"] is not None:
        lp = config["local_port"]
        if isinstance(lp, bool) or not isinstance(lp, int) or not (0 <= lp <= 65535):
            raise ValueError(f"Invalid 'local_port' {lp!r}: must be an integer between 0 and 65535")
        validated["local_port"] = lp

    vc = config.get("verify_cert", True)
    if not isinstance(vc, bool):
        raise TypeError("verify_cert must be a boolean")
    validated["verify_cert"] = vc

    if "ssl_context" in config and config["ssl_context"] is not None:
        ctx = config["ssl_context"]
        if not isinstance(ctx, ssl.SSLContext):
            raise TypeError("ssl_context must be an instance of ssl.SSLContext")
        validated["ssl_context"] = ctx

    if "mux_enabled" in config:
        me = config["mux_enabled"]
        if not isinstance(me, bool):
            raise TypeError("mux_enabled must be a boolean")
        validated["mux_enabled"] = me

    if "mux_concurrency" in config:
        mc = config["mux_concurrency"]
        if isinstance(mc, bool) or not isinstance(mc, int) or not (1 <= mc <= 1024):
            raise ValueError(f"Invalid 'mux_concurrency' {mc!r}: must be an integer between 1 and 1024")
        validated["mux_concurrency"] = mc

    if "tcp_fast_open" in config:
        tfo = config["tcp_fast_open"]
        if not isinstance(tfo, bool):
            raise TypeError("tcp_fast_open must be a boolean")
        validated["tcp_fast_open"] = tfo

    if p in ("vless", "vmess"):
        raw_uuid = config.get("uuid")
        if not isinstance(raw_uuid, str) or not raw_uuid.strip():
            raise ValueError("Missing or invalid 'uuid': must be a non-empty string")
        try:
            uuid.UUID(raw_uuid.strip())
            validated["uuid"] = raw_uuid.strip()
        except ValueError as exc:
            raise ValueError(f"Invalid UUID '{raw_uuid}': must be valid RFC 4122 format") from exc

    if s in ("reality", "tls"):
        server_name = config.get("server_name")
        if not isinstance(server_name, str) or not server_name.strip():
            raise ValueError("Missing or invalid 'server_name': must be a non-empty string")
        validated["server_name"] = server_name.strip()
        validated["fingerprint"] = str(config.get("fingerprint", "chrome")).strip()

        if "alpn" in config and config["alpn"] is not None:
            alpn_val = config["alpn"]
            if isinstance(alpn_val, str):
                alpn_list = [x.strip() for x in alpn_val.split(",") if x.strip()]
            elif isinstance(alpn_val, (list, tuple)):
                if any(not isinstance(x, str) or not x.strip() for x in alpn_val):
                    raise ValueError("Invalid 'alpn': elements must be non-empty strings")
                alpn_list = [x.strip() for x in alpn_val]
            else:
                raise TypeError("alpn must be a list of strings or comma-separated string")
            validated["alpn"] = alpn_list

        if "min_version" in config and config["min_version"] is not None:
            mv = str(config["min_version"]).strip()
            if mv not in ("1.2", "1.3"):
                raise ValueError(f"Invalid 'min_version' '{mv}': must be '1.2' or '1.3'")
            validated["min_version"] = mv

        if "max_version" in config and config["max_version"] is not None:
            xv = str(config["max_version"]).strip()
            if xv not in ("1.2", "1.3"):
                raise ValueError(f"Invalid 'max_version' '{xv}': must be '1.2' or '1.3'")
            validated["max_version"] = xv

        if "min_version" in validated and "max_version" in validated:
            if float(validated["min_version"]) > float(validated["max_version"]):
                raise ValueError(f"min_version ({validated['min_version']}) cannot exceed max_version ({validated['max_version']})")

    if s == "reality":
        raw_key = config.get("public_key") if config.get("public_key") is not None else config.get("password")
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise ValueError("Missing or invalid 'public_key': must be a non-empty string")
        clean_key = raw_key.strip()
        validated["public_key"] = clean_key
        validated["password"] = clean_key

        short_id = config.get("short_id")
        if not isinstance(short_id, str):
            raise ValueError("Missing or invalid 'short_id': must be a string")
        clean_sid = short_id.strip()
        if clean_sid:
            if not all(c in "0123456789abcdefABCDEF" for c in clean_sid):
                raise ValueError(f"Invalid 'short_id' '{short_id}': must be a hexadecimal string")
            if len(clean_sid) > 16:
                raise ValueError(f"Invalid 'short_id' '{short_id}': length exceeds maximum of 16 hexadecimal characters")
            if len(clean_sid) % 2 != 0:
                raise ValueError(f"Invalid 'short_id' '{short_id}': length must be an even number of hex characters")
        validated["short_id"] = clean_sid.lower()

        sp = config.get("spiderX") or config.get("spider_x")
        if sp is not None:
            if not isinstance(sp, str):
                raise ValueError("Invalid 'spiderX': must be a string")
            if eng_str in ("sing_box", "singbox") and sp not in ("", "/"):
                raise ValueError("REALITY 'spiderX' crawler path is not supported by sing-box outbound")
            validated["spiderX"] = sp

    if p == "vless":
        flow = config.get("flow", "")
        if flow is not None and not isinstance(flow, str):
            raise ValueError("Invalid 'flow': must be a string")
        clean_flow = (flow or "").strip()
        if s == "none" and clean_flow:
            raise ValueError("VLESS over unencrypted transport (security=none) cannot use flow (vision requires TLS/REALITY)")
        if t in ("websocket", "grpc") and clean_flow:
            raise ValueError(f"VLESS over {t} cannot use flow (flow is restricted to direct TCP transport)")
        validated["flow"] = clean_flow

    if t == "websocket":
        path = config.get("path", "/")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Invalid 'path': must be a non-empty string")
        clean_path = path.strip()
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path
        validated["path"] = clean_path

        host_hdr = config.get("host_header") or config.get("host")
        if host_hdr is not None:
            if not isinstance(host_hdr, str) or not host_hdr.strip():
                raise ValueError("Invalid 'host_header': must be a non-empty string")
            validated["host_header"] = host_hdr.strip()

        if "headers" in config and config["headers"] is not None:
            if not isinstance(config["headers"], dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in config["headers"].items()
            ):
                raise ValueError("Invalid 'headers': must be a dictionary of strings")
            validated["headers"] = dict(config["headers"])

        if "max_early_data" in config and config["max_early_data"] is not None:
            med = config["max_early_data"]
            if isinstance(med, bool) or not isinstance(med, int) or med < 0:
                raise ValueError(f"Invalid 'max_early_data': must be a non-negative integer, got {med!r}")
            validated["max_early_data"] = med

        if "early_data_header_name" in config and config["early_data_header_name"] is not None:
            edhn = config["early_data_header_name"]
            if not isinstance(edhn, str) or not edhn.strip():
                raise ValueError("Invalid 'early_data_header_name': must be a non-empty string")
            validated["early_data_header_name"] = edhn.strip()

    if t == "grpc":
        service_name = config.get("service_name", "grpc")
        if not isinstance(service_name, str) or not service_name.strip():
            raise ValueError("Invalid 'service_name': must be a non-empty string")
        validated["service_name"] = service_name.strip()

        if "multi_mode" in config and config["multi_mode"] is not None:
            mm = config["multi_mode"]
            if not isinstance(mm, bool):
                raise TypeError("multi_mode must be a boolean")
            if eng_str in ("sing_box", "singbox") and mm:
                raise ValueError("gRPC multi_mode is not supported by sing-box client configuration")
            validated["multi_mode"] = mm

        if "idle_timeout_s" in config and config["idle_timeout_s"] is not None:
            ito = config["idle_timeout_s"]
            if isinstance(ito, bool) or not isinstance(ito, (int, float)) or ito < 1:
                raise ValueError(f"Invalid 'idle_timeout_s': must be >= 1, got {ito!r}")
            validated["idle_timeout_s"] = int(ito)

        if "ping_timeout_s" in config and config["ping_timeout_s"] is not None:
            pto = config["ping_timeout_s"]
            if isinstance(pto, bool) or not isinstance(pto, (int, float)) or pto < 1:
                raise ValueError(f"Invalid 'ping_timeout_s': must be >= 1, got {pto!r}")
            validated["ping_timeout_s"] = int(pto)

    if p == "vmess":
        alter_id = config.get("alter_id", 0)
        if isinstance(alter_id, bool) or not isinstance(alter_id, int) or not (0 <= alter_id <= 65535):
            raise ValueError(f"Invalid 'alter_id': must be between 0 and 65535, got {alter_id!r}")
        validated["alter_id"] = alter_id

        sec = str(config.get("security", "auto")).lower()
        allowed_vmess_sec = VALID_VMESS_SECURITY if eng_str == "xray" else VALID_SINGBOX_VMESS_SECURITY
        if sec not in allowed_vmess_sec:
            raise ValueError(f"Invalid 'security' for VMess '{sec}'. Supported: {sorted(allowed_vmess_sec)}")
        validated["security"] = sec

        if "packet_encoding" in config and config["packet_encoding"] is not None:
            pe = str(config["packet_encoding"]).strip().lower()
            if pe not in ("packetaddr", "xudp", "none", ""):
                raise ValueError(f"Invalid 'packet_encoding' '{pe}': must be 'packetaddr', 'xudp', or 'none'")
            if eng_str in ("sing_box", "singbox") and pe == "none":
                raise ValueError("Engine 'sing_box' does not support packet_encoding='none' (supported values: '', 'packetaddr', 'xudp')")
            validated["packet_encoding"] = pe

    if p == "trojan":
        password = config.get("password")
        if not isinstance(password, str) or not password.strip():
            raise ValueError("Missing or invalid 'password': must be a non-empty string")
        validated["password"] = password.strip()

    if p == "shadowsocks":
        if "uot" in config and config["uot"] is not None:
            uot_val = config["uot"]
            if not isinstance(uot_val, bool):
                raise TypeError("uot must be a boolean")
            if eng_str in ("sing_box", "singbox") and uot_val:
                raise ValueError("Shadowsocks UOT (UDP over TCP) is not supported by sing-box outbound")
            validated["uot"] = uot_val

        method = config.get("method")
        if not isinstance(method, str) or method.strip() not in SUPPORTED_SHADOWSOCKS_METHODS:
            raise ValueError(f"Invalid Shadowsocks method '{method}'. Supported: {sorted(SUPPORTED_SHADOWSOCKS_METHODS)}")
        clean_method = method.strip()
        validated["method"] = clean_method

        pwd = config.get("password")
        if not isinstance(pwd, str) or not pwd.strip():
            raise ValueError("Missing or invalid Shadowsocks 'password': must be a non-empty string")
        clean_pwd = pwd.strip()

        if clean_method in SHADOWSOCKS_2022_KEY_SIZES:
            expected_len = SHADOWSOCKS_2022_KEY_SIZES[clean_method]
            try:
                decoded = base64.b64decode(clean_pwd, validate=True)
                if len(decoded) != expected_len:
                    raise ValueError(
                        f"Shadowsocks 2022 key for '{clean_method}' must decode to exactly {expected_len} bytes, got {len(decoded)}"
                    )
            except Exception as exc:
                raise ValueError(
                    f"Shadowsocks 2022 key for '{clean_method}' must be valid Base64 encoding {expected_len} bytes: {exc}"
                ) from exc

        validated["password"] = clean_pwd

    return validated

def get_profile_secrets(config: dict[str, Any]) -> list[str]:
    secrets: list[str] = []
    for key in ("uuid", "password", "public_key", "short_id"):
        val = config.get(key)
        if isinstance(val, str) and val.strip():
            secrets.append(val.strip())
    return secrets

def build_xray_config(
    target: Target,
    protocol: ProtocolType | str,
    transport: TransportType | str,
    security: SecurityType | str,
    config: dict[str, Any],
    local_socks_port: int,
    local_http_port: int,
    local_host: str = "127.0.0.1",
) -> dict[str, Any]:
    p, t, s = normalize_profile_keys(protocol, transport, security)

    outbound: dict[str, Any] = {
        "protocol": p,
    }

    if p == "vless":
        user_entry: dict[str, Any] = {
            "id": config["uuid"],
            "encryption": "none",
            "flow": config.get("flow", ""),
        }
        outbound["settings"] = {
            "vnext": [
                {
                    "address": target.host,
                    "port": target.port,
                    "users": [user_entry],
                }
            ]
        }
    elif p == "vmess":
        outbound["settings"] = {
            "vnext": [
                {
                    "address": target.host,
                    "port": target.port,
                    "users": [
                        {
                            "id": config["uuid"],
                            "alterId": int(config.get("alter_id", 0)),
                            "security": config.get("security", "auto"),
                        }
                    ],
                }
            ]
        }
        if "packet_encoding" in config and config["packet_encoding"]:
            outbound["settings"]["packetEncoding"] = config["packet_encoding"]
    elif p == "trojan":
        outbound["settings"] = {
            "servers": [
                {
                    "address": target.host,
                    "port": target.port,
                    "password": config["password"],
                }
            ]
        }
    elif p == "shadowsocks":
        ss_srv: dict[str, Any] = {
            "address": target.host,
            "port": target.port,
            "method": config["method"],
            "password": config["password"],
            "uot": bool(config.get("uot", False)),
        }
        if "packet_encoding" in config and config["packet_encoding"]:
            ss_srv["packetEncoding"] = config["packet_encoding"]
        outbound["settings"] = {
            "servers": [ss_srv]
        }

    stream_settings: dict[str, Any] = {
        "network": "ws" if t == "websocket" else t,
        "security": s,
    }

    if config.get("tcp_fast_open"):
        stream_settings["sockopt"] = {"tcpFastOpen": True}

    if s == "reality":
        pubkey = config.get("public_key") or config.get("password") or config.get("publicKey", "")
        reality_settings: dict[str, Any] = {
            "show": False,
            "fingerprint": config.get("fingerprint", "chrome"),
            "serverName": config["server_name"],
            "password": pubkey,
            "publicKey": pubkey,
            "shortId": config.get("short_id", ""),
            "spiderX": config.get("spider_x") or config.get("spiderX") or "/",
        }
        if "alpn" in config:
            reality_settings["alpn"] = list(config["alpn"])
        stream_settings["realitySettings"] = reality_settings
    elif s == "tls":
        tls_settings: dict[str, Any] = {
            "serverName": config["server_name"],
            "allowInsecure": not config.get("verify_cert", True),
            "fingerprint": config.get("fingerprint", "chrome"),
        }
        if "alpn" in config:
            tls_settings["alpn"] = list(config["alpn"])
        if "min_version" in config:
            tls_settings["minVersion"] = config["min_version"]
        if "max_version" in config:
            tls_settings["maxVersion"] = config["max_version"]
        stream_settings["tlsSettings"] = tls_settings

    if t == "websocket":
        ws_settings: dict[str, Any] = {
            "path": config.get("path", "/"),
        }
        host_header = config.get("host_header") or config.get("host")
        if host_header:
            ws_settings["host"] = host_header
            ws_settings["headers"] = {"Host": host_header}
        if "headers" in config and isinstance(config["headers"], dict):
            existing_headers = ws_settings.get("headers", {})
            existing_headers.update(config["headers"])
            ws_settings["headers"] = existing_headers
        if "max_early_data" in config:
            ws_settings["maxEarlyData"] = int(config["max_early_data"])
        if "early_data_header_name" in config:
            ws_settings["earlyDataHeaderName"] = str(config["early_data_header_name"])
        stream_settings["wsSettings"] = ws_settings
    elif t == "grpc":
        grpc_settings: dict[str, Any] = {
            "serviceName": config.get("service_name", "grpc"),
            "multiMode": bool(config.get("multi_mode", False)),
        }
        if "idle_timeout_s" in config:
            grpc_settings["idle_timeout"] = int(config["idle_timeout_s"])
        if "ping_timeout_s" in config:
            grpc_settings["health_check_timeout"] = int(config["ping_timeout_s"])
        stream_settings["grpcSettings"] = grpc_settings

    outbound["streamSettings"] = stream_settings

    if config.get("mux_enabled"):
        outbound["mux"] = {
            "enabled": True,
            "concurrency": int(config.get("mux_concurrency", 8)),
        }

    return {
        "log": {
            "loglevel": "warning",
        },
        "inbounds": [
            {
                "listen": local_host,
                "port": local_socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
            },
            {
                "listen": local_host,
                "port": local_http_port,
                "protocol": "http",
                "settings": {
                    "timeout": int(config.get("timeout_s", 10.0)),
                },
            },
        ],
        "outbounds": [outbound],
    }

def build_singbox_config(
    target: Target,
    protocol: ProtocolType | str,
    transport: TransportType | str,
    security: SecurityType | str,
    config: dict[str, Any],
    local_socks_port: int,
    local_http_port: int,
    local_host: str = "127.0.0.1",
) -> dict[str, Any]:
    p, t, s = normalize_profile_keys(protocol, transport, security)

    outbound: dict[str, Any] = {
        "type": p,
        "tag": f"{p}-out",
        "server": target.host,
        "server_port": target.port,
    }

    if p == "vless":
        outbound["uuid"] = config["uuid"]
        outbound["flow"] = config.get("flow", "")
        outbound["network"] = "tcp"
    elif p == "vmess":
        outbound["uuid"] = config["uuid"]
        outbound["security"] = config.get("security", "auto")
        outbound["alter_id"] = int(config.get("alter_id", 0))
        if "packet_encoding" in config and config["packet_encoding"]:
            outbound["packet_encoding"] = config["packet_encoding"]
    elif p == "trojan":
        outbound["password"] = config["password"]
        outbound["network"] = "tcp"
    elif p == "shadowsocks":
        outbound["method"] = config["method"]
        outbound["password"] = config["password"]
        outbound["network"] = "tcp"

    if config.get("mux_enabled"):
        outbound["multiplex"] = {
            "enabled": True,
            "max_connections": int(config.get("mux_concurrency", 8)),
        }
    if config.get("tcp_fast_open"):
        outbound["tcp_fast_open"] = True

    if s == "reality":
        pubkey = config.get("public_key") or config.get("password") or ""
        tls_block = {
            "enabled": True,
            "server_name": config["server_name"],
            "utls": {
                "enabled": True,
                "fingerprint": config.get("fingerprint", "chrome"),
            },
            "reality": {
                "enabled": True,
                "public_key": pubkey,
                "short_id": config.get("short_id", ""),
            },
            "insecure": not config.get("verify_cert", True),
        }
        if "alpn" in config:
            tls_block["alpn"] = list(config["alpn"])
        if "min_version" in config:
            tls_block["min_version"] = config["min_version"]
        if "max_version" in config:
            tls_block["max_version"] = config["max_version"]
        outbound["tls"] = tls_block
    elif s == "tls":
        tls_block: dict[str, Any] = {
            "enabled": True,
            "server_name": config["server_name"],
            "insecure": not config.get("verify_cert", True),
        }
        fp = config.get("fingerprint", "chrome")
        if fp:
            tls_block["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }
        if "alpn" in config:
            tls_block["alpn"] = list(config["alpn"])
        if "min_version" in config:
            tls_block["min_version"] = config["min_version"]
        if "max_version" in config:
            tls_block["max_version"] = config["max_version"]
        outbound["tls"] = tls_block

    if t == "websocket":
        tr_block: dict[str, Any] = {
            "type": "ws",
            "path": config.get("path", "/"),
        }
        headers: dict[str, str] = {}
        if "headers" in config and isinstance(config["headers"], dict):
            headers.update(config["headers"])
        host_hdr = config.get("host_header") or config.get("host")
        if host_hdr:
            headers["Host"] = host_hdr
        if headers:
            tr_block["headers"] = headers
        if "max_early_data" in config:
            tr_block["max_early_data"] = int(config["max_early_data"])
        if "early_data_header_name" in config:
            tr_block["early_data_header_name"] = str(config["early_data_header_name"])
        outbound["transport"] = tr_block
    elif t == "grpc":
        grpc_tr: dict[str, Any] = {
            "type": "grpc",
            "service_name": config.get("service_name", "grpc"),
        }
        if "idle_timeout_s" in config:
            grpc_tr["idle_timeout"] = f"{int(config['idle_timeout_s'])}s"
        if "ping_timeout_s" in config:
            grpc_tr["ping_timeout"] = f"{int(config['ping_timeout_s'])}s"
        outbound["transport"] = grpc_tr

    return {
        "log": {
            "level": "warn",
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": local_host,
                "listen_port": local_socks_port,
            },
            {
                "type": "http",
                "tag": "http-in",
                "listen": local_host,
                "listen_port": local_http_port,
            },
        ],
        "outbounds": [outbound],
    }
