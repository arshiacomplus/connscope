from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import time
from unittest.mock import patch

import pytest

from connscope.adapters import (
    EngineType,
    ExecutableRequirement,
    FailureStage,
    ProfileDrivenAdapter,
    ProtocolType,
    SecurityType,
    SingBoxVlessTcpRealityAdapter,
    SingBoxVmessWebSocketTlsAdapter,
    TransportType,
    XrayVlessTcpRealityAdapter,
    XrayVmessWebSocketTlsAdapter,
    build_singbox_config,
    build_xray_config,
    find_free_loopback_port,
    get_profile_secrets,
    normalize_profile_keys,
    resolve_safe_executable,
    safe_temporary_workspace,
    validate_profile_config,
)
from connscope.core import ProbeResult, ProbeStatus, Target

def test_normalize_profile_keys():
    assert normalize_profile_keys(ProtocolType.VLESS, TransportType.TCP, SecurityType.REALITY) == ("vless", "tcp", "reality")
    assert normalize_profile_keys("VMESS", "WEBSOCKET", "TLS") == ("vmess", "websocket", "tls")
    assert normalize_profile_keys("trojan", "tcp", "tls") == ("trojan", "tcp", "tls")
    assert normalize_profile_keys("shadowsocks", "tcp", "none") == ("shadowsocks", "tcp", "none")

def test_get_profile_secrets():
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "my-public-key",
        "password": "my-password",
        "short_id": "0123456789abcdef",
    }
    secrets = get_profile_secrets(cfg)
    assert "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d" in secrets
    assert "my-public-key" in secrets
    assert "my-password" in secrets
    assert "0123456789abcdef" in secrets

def test_validation_rejects_dangerous_keys():
    bad_keys = ["command", "exec", "plugin", "shell", "system", "custom_command_inject"]
    for bad in bad_keys:
        with pytest.raises(ValueError, match="Dangerous configuration key rejected"):
            validate_profile_config(
                ProtocolType.VLESS,
                TransportType.TCP,
                SecurityType.TLS,
                {
                    "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                    "server_name": "example.com",
                    bad: "rm -rf /",
                },
            )

def test_validation_rejects_unknown_keys():
    with pytest.raises(ValueError, match="Unknown configuration keys"):
        validate_profile_config(
            ProtocolType.VLESS,
            TransportType.TCP,
            SecurityType.TLS,
            {
                "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "server_name": "example.com",
                "unsupported_extra_field": "val",
            },
        )

def test_validation_flow_constraints():
    with pytest.raises(ValueError, match="cannot use flow"):
        validate_profile_config(
            ProtocolType.VLESS,
            TransportType.TCP,
            SecurityType.NONE,
            {
                "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "flow": "xtls-rprx-vision",
            },
        )

    with pytest.raises(ValueError, match="flow is restricted to direct TCP transport"):
        validate_profile_config(
            ProtocolType.VLESS,
            TransportType.WEBSOCKET,
            SecurityType.TLS,
            {
                "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "server_name": "example.com",
                "flow": "xtls-rprx-vision",
            },
        )

    with pytest.raises(ValueError, match="flow is restricted to direct TCP transport"):
        validate_profile_config(
            ProtocolType.VLESS,
            TransportType.GRPC,
            SecurityType.TLS,
            {
                "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "server_name": "example.com",
                "flow": "xtls-rprx-vision",
            },
        )

def test_validation_shadowsocks_2022_key_sizes():
    key_16 = base64.b64encode(b"0" * 16).decode("ascii")
    val_16 = validate_profile_config(
        ProtocolType.SHADOWSOCKS,
        TransportType.TCP,
        SecurityType.NONE,
        {
            "method": "2022-blake3-aes-128-gcm",
            "password": key_16,
        },
    )
    assert val_16["method"] == "2022-blake3-aes-128-gcm"
    assert val_16["password"] == key_16

    key_32 = base64.b64encode(b"0" * 32).decode("ascii")
    val_32 = validate_profile_config(
        ProtocolType.SHADOWSOCKS,
        TransportType.TCP,
        SecurityType.NONE,
        {
            "method": "2022-blake3-aes-256-gcm",
            "password": key_32,
        },
    )
    assert val_32["method"] == "2022-blake3-aes-256-gcm"

    with pytest.raises(ValueError, match="must decode to exactly 32 bytes"):
        validate_profile_config(
            ProtocolType.SHADOWSOCKS,
            TransportType.TCP,
            SecurityType.NONE,
            {
                "method": "2022-blake3-aes-256-gcm",
                "password": key_16,
            },
        )

    with pytest.raises(ValueError, match="must be valid Base64"):
        validate_profile_config(
            ProtocolType.SHADOWSOCKS,
            TransportType.TCP,
            SecurityType.NONE,
            {
                "method": "2022-blake3-aes-128-gcm",
                "password": "not-valid-base64!!!",
            },
        )

def test_validation_all_eight_profiles_success():
    profiles = [
        (ProtocolType.VLESS, TransportType.TCP, SecurityType.REALITY, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "public_key": "CZiUCXOaBUHWUwK4x5PW8UmsqmETL2liYUe6xHbzGDk",
            "short_id": "0123456789abcdef",
            "server_name": "target.domain.com",
            "flow": "xtls-rprx-vision",
        }),
        (ProtocolType.VLESS, TransportType.TCP, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "flow": "xtls-rprx-vision",
        }),
        (ProtocolType.VLESS, TransportType.TCP, SecurityType.NONE, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        }),
        (ProtocolType.VLESS, TransportType.WEBSOCKET, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "path": "/ws",
            "host_header": "target.domain.com",
        }),
        (ProtocolType.VLESS, TransportType.GRPC, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "service_name": "my-grpc",
        }),
        (ProtocolType.VMESS, TransportType.WEBSOCKET, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "path": "/vmess-ws",
            "security": "auto",
        }),
        (ProtocolType.TROJAN, TransportType.TCP, SecurityType.TLS, {
            "password": "trojan-password-123",
            "server_name": "target.domain.com",
        }),
        (ProtocolType.SHADOWSOCKS, TransportType.TCP, SecurityType.NONE, {
            "method": "2022-blake3-aes-128-gcm",
            "password": base64.b64encode(b"k" * 16).decode("ascii"),
        }),
    ]

    target = Target(host="target.domain.com", port=443)
    p_socks = find_free_loopback_port()
    p_http = find_free_loopback_port()

    for proto, trans, sec, cfg in profiles:
        validated = validate_profile_config(proto, trans, sec, cfg)
        assert isinstance(validated, dict)

        xray_cfg = build_xray_config(
            target=target,
            protocol=proto,
            transport=trans,
            security=sec,
            config=validated,
            local_socks_port=p_socks,
            local_http_port=p_http,
        )
        assert "inbounds" in xray_cfg
        assert "outbounds" in xray_cfg
        assert len(xray_cfg["outbounds"]) >= 1

        sb_cfg = build_singbox_config(
            target=target,
            protocol=proto,
            transport=trans,
            security=sec,
            config=validated,
            local_socks_port=p_socks,
            local_http_port=p_http,
        )
        assert "inbounds" in sb_cfg
        assert "outbounds" in sb_cfg
        assert len(sb_cfg["outbounds"]) >= 1

def test_real_xray_binary_check_all_profiles():
    xray_path = resolve_safe_executable("xray")
    if not xray_path:
        pytest.skip("xray binary not available on host")

    configs = [
        (ProtocolType.VLESS, TransportType.TCP, SecurityType.REALITY, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "public_key": "CZiUCXOaBUHWUwK4x5PW8UmsqmETL2liYUe6xHbzGDk",
            "short_id": "0123456789abcdef",
            "server_name": "target.domain.com",
            "flow": "xtls-rprx-vision",
        }),
        (ProtocolType.VLESS, TransportType.TCP, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "flow": "xtls-rprx-vision",
        }),
        (ProtocolType.VLESS, TransportType.TCP, SecurityType.NONE, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        }),
        (ProtocolType.VLESS, TransportType.WEBSOCKET, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "path": "/ws",
        }),
        (ProtocolType.VLESS, TransportType.GRPC, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "service_name": "my-grpc",
        }),
        (ProtocolType.VMESS, TransportType.WEBSOCKET, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "path": "/vmess-ws",
            "security": "auto",
        }),
        (ProtocolType.TROJAN, TransportType.TCP, SecurityType.TLS, {
            "password": "trojan-password-123",
            "server_name": "target.domain.com",
        }),
        (ProtocolType.SHADOWSOCKS, TransportType.TCP, SecurityType.NONE, {
            "method": "2022-blake3-aes-128-gcm",
            "password": base64.b64encode(b"k" * 16).decode("ascii"),
        }),
    ]

    target = Target(host="target.domain.com", port=443)

    for proto, trans, sec, raw_cfg in configs:
        adapter = ProfileDrivenAdapter(
            adapter_id=f"test_xray_{proto}_{trans}_{sec}",
            engine=EngineType.XRAY,
            protocol=proto,
            transport=trans,
            security=sec,
        )
        ok, msg = adapter.test_configuration(raw_cfg, target=target)
        assert ok is True, f"Xray failed on profile {proto}/{trans}/{sec}: {msg}"
        assert "Configuration OK" in msg

def test_real_singbox_binary_check_all_profiles():
    sb_path = resolve_safe_executable(
        "sing-box",
        lookup_paths=(
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            str(Path.home() / ".local/share/v2rayN/bin/sing_box"),
            str(Path.home() / "ACP-Portable/tools/proxy/bin"),
        ),
    )
    if not sb_path:
        pytest.skip("sing-box binary not available on host")

    configs = [
        (ProtocolType.VLESS, TransportType.TCP, SecurityType.REALITY, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "public_key": "CZiUCXOaBUHWUwK4x5PW8UmsqmETL2liYUe6xHbzGDk",
            "short_id": "0123456789abcdef",
            "server_name": "target.domain.com",
            "flow": "xtls-rprx-vision",
        }),
        (ProtocolType.VLESS, TransportType.TCP, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "flow": "xtls-rprx-vision",
        }),
        (ProtocolType.VLESS, TransportType.TCP, SecurityType.NONE, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        }),
        (ProtocolType.VLESS, TransportType.WEBSOCKET, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "path": "/ws",
        }),
        (ProtocolType.VLESS, TransportType.GRPC, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "service_name": "my-grpc",
        }),
        (ProtocolType.VMESS, TransportType.WEBSOCKET, SecurityType.TLS, {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "path": "/vmess-ws",
            "security": "auto",
        }),
        (ProtocolType.TROJAN, TransportType.TCP, SecurityType.TLS, {
            "password": "trojan-password-123",
            "server_name": "target.domain.com",
        }),
        (ProtocolType.SHADOWSOCKS, TransportType.TCP, SecurityType.NONE, {
            "method": "2022-blake3-aes-128-gcm",
            "password": base64.b64encode(b"k" * 16).decode("ascii"),
        }),
    ]

    target = Target(host="target.domain.com", port=443)

    for proto, trans, sec, raw_cfg in configs:
        adapter = ProfileDrivenAdapter(
            adapter_id=f"test_singbox_{proto}_{trans}_{sec}",
            engine=EngineType.SING_BOX,
            protocol=proto,
            transport=trans,
            security=sec,
        )
        ok, msg = adapter.test_configuration(raw_cfg, target=target)
        assert ok is True, f"sing-box check failed on profile {proto}/{trans}/{sec}: {msg}"

def test_profile_adapter_backward_compatibility():
    xray_reality = XrayVlessTcpRealityAdapter()
    assert isinstance(xray_reality, ProfileDrivenAdapter)
    assert xray_reality.metadata.adapter_id == "xray_vless_tcp_reality"

    singbox_reality = SingBoxVlessTcpRealityAdapter()
    assert isinstance(singbox_reality, ProfileDrivenAdapter)
    assert singbox_reality.metadata.adapter_id == "singbox_vless_tcp_reality"

    xray_vmess = XrayVmessWebSocketTlsAdapter()
    assert isinstance(xray_vmess, ProfileDrivenAdapter)
    assert xray_vmess.metadata.adapter_id == "xray_vmess_ws_tls"

    singbox_vmess = SingBoxVmessWebSocketTlsAdapter()
    assert isinstance(singbox_vmess, ProfileDrivenAdapter)
    assert singbox_vmess.metadata.adapter_id == "singbox_vmess_ws_tls"

@pytest.mark.asyncio
async def test_profile_adapter_mocked_lifecycle(tmp_path):
    fake_script = """#!/usr/bin/env python3
import sys, json, socket, signal, os

cfg_path = None
for i, arg in enumerate(sys.argv):
    if arg == "-c" and i + 1 < len(sys.argv):
        cfg_path = sys.argv[i + 1]
        break

with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

socks_port = cfg["inbounds"][0]["port"]
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", socks_port))
srv.listen(5)

def on_term(s, f):
    srv.close()
    sys.exit(0)
signal.signal(signal.SIGTERM, on_term)

while True:
    try:
        conn, _ = srv.accept()
        g = conn.recv(3)
        if not g:
            conn.close()
            continue
        conn.sendall(bytes([5, 0]))
        cmd = conn.recv(256)
        if not cmd:
            conn.close()
            continue
        conn.sendall(bytes([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]))
        req = conn.recv(1024)
        conn.sendall(b"HTTP/1.1 204 No Content\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n")
        conn.close()
    except Exception:
        break
"""
    bin_file = tmp_path / "xray"
    bin_file.write_text(fake_script, encoding="utf-8")
    os.chmod(bin_file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    adapter = ProfileDrivenAdapter(
        adapter_id="xray_trojan_tcp_tls",
        engine=EngineType.XRAY,
        protocol=ProtocolType.TROJAN,
        transport=TransportType.TCP,
        security=SecurityType.TLS,
    )
    target = Target(host="target.domain.com", port=443)
    cfg = {
        "password": "secret-trojan-password",
        "server_name": "target.domain.com",
        "timeout_s": 5.0,
        "startup_timeout_s": 2.0,
    }

    with patch.object(adapter, "check_executable", return_value=(True, str(bin_file))):
        result = await adapter.run(target, config=cfg)

    assert result.status == ProbeStatus.SUCCESS
    assert result.error is None
    assert result.details["tunnel_established"] is True
    assert result.details["data_transfer_completed"] is True
    assert result.details["http_status"] == 204
    assert result.details["redacted_config"]["password"] == "[REDACTED]"
