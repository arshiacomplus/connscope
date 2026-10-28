
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from connscope.core import Target

from .layer3 import (
    Layer3IsolationBackend,
    Layer3TunnelAdapter,
    LinuxNetnsIsolationBackend,
    OpenVPNDeviceDriver,
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

ALLOWED_OPENVPN_CONFIG_KEYS: frozenset[str] = frozenset({
    "endpoint",
    "remote_host",
    "remote_port",
    "proto",
    "dev_type",
    "interface_name",
    "ca_cert",
    "remote_cert_tls",
    "verify_x509_name",
    "client_cert",
    "client_key",
    "auth_user",
    "auth_password",
    "tls_auth_key",
    "tls_auth_direction",
    "tls_crypt_key",
    "cipher",
    "data_ciphers",
    "tun_mtu",
    "route_nopull",
    "nobind",
    "persist_key",
    "persist_tun",
    "connect_timeout_s",
    "test_url",
    "timeout_s",
    "verify_cert",
})

UNSUPPORTED_OPENVPN_DIRECTIVES: frozenset[str] = frozenset({
    "up",
    "down",
    "route-up",
    "route-pre-down",
    "client-connect",
    "client-disconnect",
    "tls-verify",
    "ipchange",
    "auth-user-pass-verify",
    "script-security",
    "plugin",
    "config",
    "management",
    "management-query-remote",
    "socks-proxy",
    "http-proxy",
    "redirect-gateway",
    "dhcp-option",
})

ALLOWED_CIPHERS: frozenset[str] = frozenset({
    "AES-256-GCM",
    "AES-128-GCM",
    "CHACHA20-POLY1305",
})

VALID_PROTOCOLS: dict[str, str] = {
    "udp": "udp",
    "udp4": "udp",
    "tcp": "tcp-client",
    "tcp-client": "tcp-client",
    "tcp4-client": "tcp-client",
}

def validate_openvpn_config(
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
        if k in UNSUPPORTED_OPENVPN_DIRECTIVES:
            raise ValueError(
                f"Directive '{k}' is unsafe and rejected by ConnScope. "
                "OpenVPN configurations must not execute scripts, load plugins, include nested files, or modify host routes."
            )

    for k in normalized_input:
        if k not in ALLOWED_OPENVPN_CONFIG_KEYS:
            raise ValueError(f"Unknown parameter '{k}' in OpenVPN configuration.")

    for k, v in normalized_input.items():
        if isinstance(v, str):
            is_pem_block = k in {"ca_cert", "client_cert", "client_key", "tls_auth_key", "tls_crypt_key"}
            if not is_pem_block and ("\n" in v or "\r" in v):
                raise ValueError(f"Newline characters are not permitted in parameter '{k}'")
            if "`" in v or "$(" in v:
                raise ValueError(f"Command substitution characters are not permitted in parameter '{k}'")
            if k in {"remote_host", "interface_name", "proto", "cipher"} and any(c in v for c in (";", "&", "|", ">", "<")):
                raise ValueError(f"Shell control characters are not permitted in parameter '{k}'")

    remote_host = normalized_input.get("remote_host")
    remote_port = normalized_input.get("remote_port")

    endpoint = normalized_input.get("endpoint")
    if endpoint:
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError("endpoint must be a non-empty string in host:port format")
        endpoint = endpoint.strip()
        if ":" not in endpoint:
            raise ValueError(f"endpoint must include a port separator ':' (got '{endpoint}')")
        host_part, port_str = endpoint.rsplit(":", 1)
        remote_host = host_part.strip("[]")
        try:
            remote_port = int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port in endpoint '{endpoint}'")
    elif not remote_host and target is not None:
        remote_host = target.host
        remote_port = target.port

    if not remote_host or not isinstance(remote_host, str):
        raise ValueError("Missing required remote host (endpoint or remote_host)")

    if remote_port is None:
        raise ValueError("Missing required remote port (endpoint or remote_port)")

    try:
        port_num = int(remote_port)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"remote_port must be an integer: {exc}") from exc
    if port_num < 1 or port_num > 65535:
        raise ValueError(f"remote_port must be between 1 and 65535 (got {port_num})")

    raw_proto = normalized_input.get("proto", "udp")
    if not isinstance(raw_proto, str):
        raise TypeError(f"proto must be a string, got {type(raw_proto).__name__}")
    proto_clean = raw_proto.strip().lower()
    if proto_clean not in VALID_PROTOCOLS:
        raise ValueError(
            f"Unsupported OpenVPN protocol '{raw_proto}'. Supported protocols: {sorted(VALID_PROTOCOLS.keys())}"
        )
    proto = VALID_PROTOCOLS[proto_clean]

    dev_type = normalized_input.get("dev_type", "tun")
    if dev_type != "tun":
        raise ValueError(f"Unsupported dev_type '{dev_type}'. ConnScope only supports Layer-3 'tun' interfaces.")

    interface_name = normalized_input.get("interface_name", "tun0")
    if not isinstance(interface_name, str) or not interface_name.strip():
        raise ValueError("interface_name must be a non-empty string")
    clean_iface = interface_name.strip()
    if not re.match(r"^[a-zA-Z0-9_-]{1,15}$", clean_iface):
        raise ValueError(f"Invalid interface_name '{clean_iface}': must be 1-15 alphanumeric characters or dashes")

    ca_cert = normalized_input.get("ca_cert")
    if not ca_cert or not isinstance(ca_cert, str) or not ca_cert.strip():
        raise ValueError("Missing required trusted CA certificate 'ca_cert'")
    ca_cert = ca_cert.strip()

    remote_cert_tls = normalized_input.get("remote_cert_tls", True)
    if not isinstance(remote_cert_tls, bool):
        raise TypeError(f"remote_cert_tls must be a boolean, got {type(remote_cert_tls).__name__}")
    if not remote_cert_tls:
        raise ValueError("remote_cert_tls=False is unsafe: ConnScope requires verifying that remote cert is a server cert")

    verify_x509_name = normalized_input.get("verify_x509_name")
    if verify_x509_name is not None:
        if not isinstance(verify_x509_name, str) or not verify_x509_name.strip():
            raise ValueError("verify_x509_name must be a non-empty string if provided")
        verify_x509_name = verify_x509_name.strip()

    client_cert = normalized_input.get("client_cert")
    client_key = normalized_input.get("client_key")
    if (client_cert and not client_key) or (client_key and not client_cert):
        raise ValueError("Both client_cert and client_key must be provided for mutual TLS authentication")

    auth_user = normalized_input.get("auth_user")
    auth_password = normalized_input.get("auth_password")

    tls_auth_key = normalized_input.get("tls_auth_key")
    tls_auth_direction = normalized_input.get("tls_auth_direction")
    tls_crypt_key = normalized_input.get("tls_crypt_key")

    if tls_auth_key and tls_crypt_key:
        raise ValueError("Cannot specify both tls_auth_key and tls_crypt_key simultaneously")

    if tls_auth_direction is not None:
        tls_auth_direction = str(tls_auth_direction).strip()
        if tls_auth_direction not in {"0", "1"}:
            raise ValueError(f"tls_auth_direction must be '0' or '1' (got '{tls_auth_direction}')")

    cipher = normalized_input.get("cipher", "AES-256-GCM")
    if not isinstance(cipher, str) or cipher.strip().upper() not in ALLOWED_CIPHERS:
        raise ValueError(
            f"Unsupported cipher '{cipher}'. Allowed ciphers: {sorted(ALLOWED_CIPHERS)}"
        )
    cipher = cipher.strip().upper()

    data_ciphers = normalized_input.get("data_ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305")

    raw_mtu = normalized_input.get("tun_mtu", 1500)
    try:
        tun_mtu = int(raw_mtu)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"tun_mtu must be an integer: {exc}") from exc
    if tun_mtu < 1280 or tun_mtu > 1500:
        raise ValueError(f"tun_mtu must be between 1280 and 1500 (got {tun_mtu})")

    route_nopull = normalized_input.get("route_nopull", True)
    if not isinstance(route_nopull, bool) or not route_nopull:
        raise ValueError("route_nopull must be True to prevent server routes overriding host routes")

    test_url = normalized_input.get("test_url", "http://cp.cloudflare.com/generate_204")
    raw_timeout = normalized_input.get("timeout_s", 10.0)
    try:
        timeout_s = max(0.5, float(raw_timeout))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"timeout_s must be a number: {exc}") from exc
    verify_cert = bool(normalized_input.get("verify_cert", True))

    return {
        "remote_host": remote_host,
        "remote_port": port_num,
        "endpoint": f"{remote_host}:{port_num}",
        "proto": proto,
        "dev_type": dev_type,
        "interface_name": clean_iface,
        "ca_cert": ca_cert,
        "remote_cert_tls": True,
        "verify_x509_name": verify_x509_name,
        "client_cert": client_cert.strip() if client_cert else None,
        "client_key": client_key.strip() if client_key else None,
        "auth_user": auth_user,
        "auth_password": auth_password,
        "tls_auth_key": tls_auth_key.strip() if tls_auth_key else None,
        "tls_auth_direction": tls_auth_direction,
        "tls_crypt_key": tls_crypt_key.strip() if tls_crypt_key else None,
        "cipher": cipher,
        "data_ciphers": data_ciphers,
        "tun_mtu": tun_mtu,
        "route_nopull": True,
        "nobind": bool(normalized_input.get("nobind", True)),
        "persist_key": bool(normalized_input.get("persist_key", True)),
        "persist_tun": bool(normalized_input.get("persist_tun", True)),
        "connect_timeout_s": float(normalized_input.get("connect_timeout_s", 10.0)),
        "test_url": test_url,
        "timeout_s": timeout_s,
        "verify_cert": verify_cert,
    }

def generate_openvpn_client_config(
    config: dict[str, Any],
    target: Target | None = None,
) -> str:
    validated = validate_openvpn_config(config, target)

    lines: list[str] = [
        "# ConnScope OpenVPN Client Configuration",
        "client",
        f"dev {validated['interface_name']}",
        "dev-type tun",
        f"proto {validated['proto']}",
        f"remote {validated['remote_host']} {validated['remote_port']}",
        "resolv-retry 30",
        "nobind",
        "persist-key",
        "persist-tun",
        "remote-cert-tls server",
        f"cipher {validated['cipher']}",
        f"data-ciphers {validated['data_ciphers']}",
        f"tun-mtu {validated['tun_mtu']}",
        "route-nopull",
        "verb 3",
        "status status.log 1",
    ]

    if validated.get("verify_x509_name"):
        lines.append(f"verify-x509-name {validated['verify_x509_name']} name")

    if validated.get("tls_auth_direction") is not None:
        lines.append(f"key-direction {validated['tls_auth_direction']}")

    lines.append("")

    ca_content = validated["ca_cert"]
    if Path(ca_content).is_file():
        ca_content = Path(ca_content).read_text(encoding="utf-8").strip()

    lines.extend([
        "<ca>",
        ca_content,
        "</ca>",
    ])

    if validated.get("client_cert") and validated.get("client_key"):
        cert_content = validated["client_cert"]
        if Path(cert_content).is_file():
            cert_content = Path(cert_content).read_text(encoding="utf-8").strip()

        key_content = validated["client_key"]
        if Path(key_content).is_file():
            key_content = Path(key_content).read_text(encoding="utf-8").strip()

        lines.extend([
            "",
            "<cert>",
            cert_content,
            "</cert>",
            "",
            "<key>",
            key_content,
            "</key>",
        ])

    if validated.get("tls_auth_key"):
        ta_content = validated["tls_auth_key"]
        if Path(ta_content).is_file():
            ta_content = Path(ta_content).read_text(encoding="utf-8").strip()
        lines.extend([
            "",
            "<tls-auth>",
            ta_content,
            "</tls-auth>",
        ])

    if validated.get("tls_crypt_key"):
        tc_content = validated["tls_crypt_key"]
        if Path(tc_content).is_file():
            tc_content = Path(tc_content).read_text(encoding="utf-8").strip()
        lines.extend([
            "",
            "<tls-crypt>",
            tc_content,
            "</tls-crypt>",
        ])

    lines.append("")
    return "\n".join(lines)

class OpenVPNStandardAdapter(Layer3TunnelAdapter):

    default_interface_name = "tun0"

    def __init__(self, isolation_backend: Layer3IsolationBackend | None = None) -> None:
        super().__init__(isolation_backend=isolation_backend)
        self.metadata = AdapterMetadata(
            adapter_id="openvpn_standard",
            display_name="OpenVPN TLS Client L3 Tunnel",
            engine=EngineType.OPENVPN,
            protocol=ProtocolType.OPENVPN,
            transport=TransportType.UDP,
            security=SecurityType.TLS,
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
                binary_name="openvpn",
                min_version="2.5.0",
                lookup_paths=(
                    "/usr/local/bin",
                    "/usr/bin",
                    "/bin",
                    "/usr/sbin",
                    "/sbin",
                ),
                check_args=("--version",),
            ),
            description="OpenVPN TLS client adapter using Layer-3 network interface lifecycle",
        )

    def create_default_isolation_backend(self) -> Layer3IsolationBackend:
        return LinuxNetnsIsolationBackend(driver=OpenVPNDeviceDriver())

    def validate_config(self, config: dict[str, Any] | None, target: Target | None = None) -> dict[str, Any]:
        return validate_openvpn_config(config, target)

    def check_executable(self, lookup_paths: tuple[str, ...] | None = None) -> tuple[bool, str | None]:
        paths = lookup_paths or (self.metadata.executable.lookup_paths if self.metadata.executable else None)
        try:
            exe_path = resolve_safe_executable("openvpn", lookup_paths=paths)
            if not exe_path:
                return False, "Executable 'openvpn' not found in lookup paths"
            return True, str(exe_path)
        except (FileNotFoundError, PermissionError) as exc:
            return False, str(exc)

    def generate_config_file(self, config: dict[str, Any], target: Target, workspace_dir: Path) -> Path:
        config_text = generate_openvpn_client_config(config, target)
        cfg_path = workspace_dir / "openvpn.ovpn"

        fd = os.open(str(cfg_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(config_text)

        return cfg_path

    def get_extra_result_details(self, config: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return {
            "proto": config.get("proto", "udp"),
            "tun_mtu": config.get("tun_mtu", 1500),
            "cipher": config.get("cipher", "AES-256-GCM"),
            "remote_cert_tls": config.get("remote_cert_tls", True),
            "route_nopull": config.get("route_nopull", True),
            "dev_type": "tun",
        }
