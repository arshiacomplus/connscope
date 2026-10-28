from __future__ import annotations

import pytest

from connscope.adapters import (
    build_singbox_config,
    build_xray_config,
    resolve_safe_executable,
)
from connscope.core import Target
from connscope.scenarios import (
    create_default_protocol_catalog,
)
from connscope.scenarios.parameter_coverage import (
    BASELINE_PROFILE_CONFIGS,
    detect_local_engine_versions,
    validate_binary_configuration,
)

def test_detect_local_engine_versions():
    versions = detect_local_engine_versions()
    assert "xray" in versions
    assert "sing_box" in versions
    assert versions["xray"] == "26.3.27"
    assert versions["sing_box"] == "1.12.12"

@pytest.mark.parametrize(
    "profile_id",
    [
        "vless_tcp_reality",
        "vless_tcp_tls",
        "vless_tcp_none",
        "vless_ws_tls",
        "vless_grpc_tls",
        "vmess_ws_tls",
        "trojan_tcp_tls",
        "shadowsocks_tcp",
    ],
)
def test_xray_baseline_binary_validation(profile_id: str):
    xray_bin = resolve_safe_executable("xray")
    if not xray_bin:
        pytest.skip("xray binary not available")

    catalog = create_default_protocol_catalog()
    prof = catalog.get_profile(profile_id)
    assert prof is not None

    target = Target(host="127.0.0.1", port=443)
    params = BASELINE_PROFILE_CONFIGS[profile_id]

    config = build_xray_config(target, prof.protocol, prof.transport, prof.security, params, 10811, 10812)
    is_valid, error = validate_binary_configuration("xray", config)

    assert is_valid is True, f"Xray binary validation failed for {profile_id}: {error}"
    assert error is None

@pytest.mark.parametrize(
    "profile_id",
    [
        "vless_tcp_reality",
        "vless_tcp_tls",
        "vless_tcp_none",
        "vless_ws_tls",
        "vless_grpc_tls",
        "vmess_ws_tls",
        "trojan_tcp_tls",
        "shadowsocks_tcp",
    ],
)
def test_singbox_baseline_binary_validation(profile_id: str):
    sb_bin = resolve_safe_executable("sing-box")
    if not sb_bin:
        pytest.skip("sing-box binary not available")

    catalog = create_default_protocol_catalog()
    prof = catalog.get_profile(profile_id)
    assert prof is not None

    target = Target(host="127.0.0.1", port=443)
    params = BASELINE_PROFILE_CONFIGS[profile_id]

    config = build_singbox_config(target, prof.protocol, prof.transport, prof.security, params, 10811, 10812)
    is_valid, error = validate_binary_configuration("sing_box", config)

    assert is_valid is True, f"sing-box binary validation failed for {profile_id}: {error}"
    assert error is None

def test_xray_invalid_binary_validation():
    xray_bin = resolve_safe_executable("xray")
    if not xray_bin:
        pytest.skip("xray binary not available")

    catalog = create_default_protocol_catalog()
    prof = catalog.get_profile("vless_tcp_tls")
    assert prof is not None

    target = Target(host="127.0.0.1", port=443)
    params = dict(BASELINE_PROFILE_CONFIGS["vless_tcp_tls"])
    params["verify_cert"] = False

    config = build_xray_config(target, prof.protocol, prof.transport, prof.security, params, 10811, 10812)
    is_valid, error = validate_binary_configuration("xray", config)
    assert is_valid is False
    assert error is not None
    assert "allowinsecure" in error.lower() or "failed" in error.lower()

    bad_config = {
        "inbounds": [],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [{"id": "not-a-valid-uuid-format"}],
                }]
            },
        }],
    }
    is_valid, error = validate_binary_configuration("xray", bad_config)
    assert is_valid is False
    assert error is not None
    assert "uuid" in error.lower() or "failed" in error.lower()

def test_singbox_invalid_binary_validation():
    sb_bin = resolve_safe_executable("sing-box")
    if not sb_bin:
        pytest.skip("sing-box binary not available")

    catalog = create_default_protocol_catalog()
    prof = catalog.get_profile("vmess_ws_tls")
    assert prof is not None

    target = Target(host="127.0.0.1", port=443)
    params = dict(BASELINE_PROFILE_CONFIGS["vmess_ws_tls"])
    params["packet_encoding"] = "none"

    bad_config = {
        "inbounds": [],
        "outbounds": [{
            "type": "vmess",
            "server": "127.0.0.1",
            "server_port": 443,
            "packet_encoding": "none",
        }],
    }
    is_valid, error = validate_binary_configuration("sing_box", bad_config)
    assert is_valid is False
    assert error is not None
    assert "packet encoding" in error.lower()
