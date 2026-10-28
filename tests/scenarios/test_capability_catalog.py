from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import pytest

from connscope.adapters import (
    build_singbox_config,
    build_xray_config,
    resolve_safe_executable,
    validate_profile_config,
)
from connscope.adapters.models import (
    EngineType,
    ProtocolType,
    SecurityType,
    TransportType,
)
from connscope.cli.main import ExitCode, cli_entry
from connscope.core import Target
from connscope.scenarios import (
    CapabilityDefinition,
    CoverageReport,
    CoverageTier,
    EngineDefinition,
    ProtocolCatalog,
    SourceReference,
    VerificationStatus,
    create_default_protocol_catalog,
    generate_coverage_report,
    render_coverage_json,
    render_coverage_table,
)

def test_coverage_tier_enum():
    assert CoverageTier.CATALOGUED == "catalogued"
    assert CoverageTier.SCHEMA_VALIDATED == "schema_validated"
    assert CoverageTier.CONFIG_GENERATED == "config_generated"
    assert CoverageTier.BINARY_VALIDATED == "binary_validated"
    assert CoverageTier.LIVE_CONNECTED == "live_connected"
    assert CoverageTier.DATA_TRANSFERRED == "data_transferred"
    assert len(CoverageTier) == 6

def test_capability_definition_model():
    cap = CapabilityDefinition(
        capability_id="test_cap",
        display_name="Test Capability",
        engine_id="xray",
        category="protocol",
        protocol=ProtocolType.VLESS,
        transport=TransportType.TCP,
        security=SecurityType.REALITY,
        supported_versions=">=26.0.0",
        status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
        is_executable=True,
        source_reference=SourceReference(repository_url="https://example.com/docs"),
        config_mapping="test_mapping",
        dependencies=("dep_a",),
        exclusions=("excl_a",),
        description="Test description",
    )
    d = cap.to_dict()
    assert d["capability_id"] == "test_cap"
    assert d["engine_id"] == "xray"
    assert d["status"] == "config_validation_implemented"
    assert d["is_executable"] is True

    restored = CapabilityDefinition.from_dict(d)
    assert restored.capability_id == cap.capability_id
    assert restored.engine_id == cap.engine_id
    assert restored.status == VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED
    assert restored.dependencies == ("dep_a",)
    assert restored.exclusions == ("excl_a",)

def test_default_catalog_capabilities():
    catalog = create_default_protocol_catalog()
    caps = catalog.list_capabilities()
    assert len(caps) >= 40

    cap_map = {c.capability_id: c for c in caps}
    assert "xray_vless" in cap_map
    assert "xray_vmess" in cap_map
    assert "xray_trojan" in cap_map
    assert "xray_shadowsocks" in cap_map
    assert "xray_splithttp" in cap_map
    assert "xray_mkcp" in cap_map
    assert "xray_quic" in cap_map
    assert "xray_mux" in cap_map
    assert "xray_tcp_fast_open" in cap_map

    assert "singbox_vless" in cap_map
    assert "singbox_vmess" in cap_map
    assert "singbox_trojan" in cap_map
    assert "singbox_shadowsocks" in cap_map
    assert "singbox_multiplex" in cap_map
    assert "singbox_httpupgrade" in cap_map

    assert "exclave_vless" in cap_map
    assert "exclave_vmess" in cap_map
    assert "exclave_trojan" in cap_map
    assert "exclave_shadowsocks" in cap_map
    assert "exclave_tun" in cap_map

    assert "wireguard_standard" in cap_map
    assert "amneziawg_obfs" in cap_map
    assert "openvpn_udp" in cap_map
    assert "openvpn_tcp" in cap_map
    assert "aether_tun" in cap_map

def test_capability_filtering():
    catalog = create_default_protocol_catalog()

    xray_caps = catalog.list_capabilities(engine_id="xray")
    assert len(xray_caps) >= 15
    assert all(c.engine_id == "xray" for c in xray_caps)

    sb_caps = catalog.list_capabilities(engine_id="sing_box")
    assert len(sb_caps) >= 15
    assert all(c.engine_id == "sing_box" for c in sb_caps)

    exclave_caps = catalog.list_capabilities(engine_id="exclave")
    assert len(exclave_caps) == 30
    assert all(c.engine_id == "exclave" for c in exclave_caps)

    transport_caps = catalog.list_capabilities(category="transport")
    assert len(transport_caps) >= 8
    assert all(c.category == "transport" for c in transport_caps)

def test_capability_registration_duplicate_error():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("xray_vless")
    assert cap is not None
    with pytest.raises(ValueError, match="already registered"):
        catalog.register_capability(cap)

def test_catalog_validation_detects_unknown_capability_engine():
    catalog = create_default_protocol_catalog()
    ghost_cap = CapabilityDefinition(
        capability_id="ghost_cap",
        display_name="Ghost Cap",
        engine_id="nonexistent_engine",
        category="protocol",
    )
    catalog.register_capability(ghost_cap)
    errors = catalog.validate_catalog()
    assert any("references unknown engine 'nonexistent_engine'" in e for e in errors)

def test_catalog_validation_detects_broken_capability_dependency():
    catalog = create_default_protocol_catalog()
    broken_cap = CapabilityDefinition(
        capability_id="broken_dep_cap",
        display_name="Broken Dep Cap",
        engine_id="xray",
        category="protocol",
        dependencies=("nonexistent_capability_12345",),
    )
    catalog.register_capability(broken_cap)
    errors = catalog.validate_catalog()
    assert any("references unknown dependency 'nonexistent_capability_12345'" in e for e in errors)

def test_catalog_capabilities_serialization_roundtrip(tmp_path: Path):
    catalog = create_default_protocol_catalog()
    data = catalog.to_dict()
    assert "capabilities" in data
    assert len(data["capabilities"]) >= 40

    json_path = tmp_path / "catalog_with_caps.json"
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    restored = ProtocolCatalog.from_json_file(json_path)
    errors = restored.validate_catalog()
    assert errors == []
    assert len(restored.list_capabilities()) == len(catalog.list_capabilities())
    assert restored.get_capability("xray_mux") is not None
    assert restored.get_capability("singbox_multiplex") is not None

def test_parameter_schema_extended_coverage():
    catalog = create_default_protocol_catalog()
    vless_p = catalog.get_profile("vless_tcp_reality")
    assert vless_p is not None
    vless_param_names = {p.param_id for p in vless_p.parameters}
    assert "alpn" in vless_param_names
    assert "min_version" in vless_param_names
    assert "max_version" in vless_param_names
    assert "mux_enabled" in vless_param_names
    assert "mux_concurrency" in vless_param_names
    assert "tcp_fast_open" in vless_param_names

    vmess_p = catalog.get_profile("vmess_ws_tls")
    assert vmess_p is not None
    vmess_param_names = {p.param_id for p in vmess_p.parameters}
    assert "max_early_data" in vmess_param_names
    assert "early_data_header_name" in vmess_param_names

    ss_p = catalog.get_profile("shadowsocks_tcp")
    assert ss_p is not None
    ss_param_names = {p.param_id for p in ss_p.parameters}
    assert "uot" in ss_param_names
    assert "tcp_fast_open" in ss_param_names

def test_extended_parameter_validation_logic():
    base_valid = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
        "short_id": "0123456789abcdef",
        "server_name": "example.com",
    }

    validate_profile_config("vless", "tcp", "reality", base_valid, EngineType.XRAY)

    with pytest.raises(ValueError, match="Invalid 'mux_concurrency'"):
        validate_profile_config("vless", "tcp", "reality", {**base_valid, "mux_concurrency": 0}, EngineType.XRAY)

    with pytest.raises(ValueError, match="Invalid 'mux_concurrency'"):
        validate_profile_config("vless", "tcp", "reality", {**base_valid, "mux_concurrency": 2048}, EngineType.XRAY)

    with pytest.raises(ValueError, match="min_version.*cannot exceed max_version"):
        validate_profile_config("vless", "tcp", "reality", {**base_valid, "min_version": "1.3", "max_version": "1.2"}, EngineType.XRAY)

    with pytest.raises(ValueError, match="Invalid 'min_version'"):
        validate_profile_config("vless", "tcp", "reality", {**base_valid, "min_version": "1.0"}, EngineType.XRAY)

    with pytest.raises(ValueError, match="Invalid 'max_early_data'"):
        validate_profile_config("vmess", "websocket", "tls", {"uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "server_name": "example.com", "path": "/", "max_early_data": -5}, EngineType.XRAY)

    with pytest.raises(ValueError, match="Shadowsocks UOT"):
        validate_profile_config("shadowsocks", "tcp", "none", {"method": "aes-128-gcm", "password": "pass", "uot": True}, EngineType.SING_BOX)

    with pytest.raises(ValueError, match="gRPC multi_mode is not supported by sing-box"):
        validate_profile_config("vless", "grpc", "tls", {"uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "server_name": "example.com", "multi_mode": True}, EngineType.SING_BOX)

def test_engine_builder_extended_parameters_xray():
    target = Target("203.0.113.10", 443)
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
        "short_id": "0123456789abcdef",
        "server_name": "example.com",
        "alpn": ["h2", "http/1.1"],
        "min_version": "1.2",
        "max_version": "1.3",
        "mux_enabled": True,
        "mux_concurrency": 16,
        "tcp_fast_open": True,
    }
    xray_conf = build_xray_config(
        target,
        "vless", "tcp", "reality",
        cfg,
        10809,
        10810,
    )
    outbound = xray_conf["outbounds"][0]
    stream = outbound["streamSettings"]
    reality = stream["realitySettings"]
    assert reality["serverName"] == "example.com"
    assert stream["sockopt"]["tcpFastOpen"] is True
    assert outbound["mux"]["enabled"] is True
    assert outbound["mux"]["concurrency"] == 16

    ws_cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "path": "/ws",
        "server_name": "example.com",
        "alpn": ["http/1.1"],
        "max_early_data": 2048,
        "early_data_header_name": "Sec-WebSocket-Protocol",
    }
    xray_ws_conf = build_xray_config(
        target,
        "vmess", "websocket", "tls",
        ws_cfg,
        10809,
        10810,
    )
    ws_stream = xray_ws_conf["outbounds"][0]["streamSettings"]
    assert ws_stream["tlsSettings"]["alpn"] == ["http/1.1"]
    assert ws_stream["wsSettings"]["maxEarlyData"] == 2048
    assert ws_stream["wsSettings"]["earlyDataHeaderName"] == "Sec-WebSocket-Protocol"

    grpc_cfg = {
        "password": "secretpassword",
        "server_name": "example.com",
        "service_name": "grpc-svc",
        "multi_mode": True,
        "idle_timeout_s": 30,
        "ping_timeout_s": 10,
    }
    xray_grpc_conf = build_xray_config(
        target,
        "trojan", "grpc", "tls",
        grpc_cfg,
        10809,
        10810,
    )
    grpc_stream = xray_grpc_conf["outbounds"][0]["streamSettings"]
    assert grpc_stream["grpcSettings"]["multiMode"] is True
    assert grpc_stream["grpcSettings"]["idle_timeout"] == 30
    assert grpc_stream["grpcSettings"]["health_check_timeout"] == 10

    ss_cfg = {
        "method": "aes-128-gcm",
        "password": "secretpassword",
        "uot": True,
        "packet_encoding": "packetaddr",
    }
    ss_target = Target("203.0.113.10", 8388)
    xray_ss_conf = build_xray_config(
        ss_target,
        "shadowsocks", "tcp", "none",
        ss_cfg,
        10809,
        10810,
    )
    ss_server = xray_ss_conf["outbounds"][0]["settings"]["servers"][0]
    assert ss_server["uot"] is True
    assert ss_server["packetEncoding"] == "packetaddr"

def test_engine_builder_extended_parameters_singbox():
    target = Target("203.0.113.10", 443)
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
        "short_id": "0123456789abcdef",
        "server_name": "example.com",
        "alpn": ["h2", "http/1.1"],
        "min_version": "1.2",
        "max_version": "1.3",
        "mux_enabled": True,
        "mux_concurrency": 8,
        "tcp_fast_open": True,
    }
    sb_conf = build_singbox_config(
        target,
        "vless", "tcp", "reality",
        cfg,
        10809,
        10810,
    )
    outbound = sb_conf["outbounds"][0]
    assert outbound["tls"]["alpn"] == ["h2", "http/1.1"]
    assert outbound["tls"]["min_version"] == "1.2"
    assert outbound["tls"]["max_version"] == "1.3"
    assert outbound["tcp_fast_open"] is True
    assert outbound["multiplex"]["enabled"] is True
    assert outbound["multiplex"]["max_connections"] == 8

    ws_cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "path": "/ws",
        "server_name": "example.com",
        "max_early_data": 4096,
        "early_data_header_name": "Sec-WebSocket-Protocol",
        "packet_encoding": "packetaddr",
    }
    sb_ws_conf = build_singbox_config(
        target,
        "vmess", "websocket", "tls",
        ws_cfg,
        10809,
        10810,
    )
    ws_out = sb_ws_conf["outbounds"][0]
    assert ws_out["transport"]["max_early_data"] == 4096
    assert ws_out["transport"]["early_data_header_name"] == "Sec-WebSocket-Protocol"
    assert ws_out["packet_encoding"] == "packetaddr"

    grpc_cfg = {
        "password": "secretpassword",
        "server_name": "example.com",
        "service_name": "grpc-svc",
        "idle_timeout_s": 25,
        "ping_timeout_s": 15,
    }
    sb_grpc_conf = build_singbox_config(
        target,
        "trojan", "grpc", "tls",
        grpc_cfg,
        10809,
        10810,
    )
    grpc_out = sb_grpc_conf["outbounds"][0]
    assert grpc_out["transport"]["idle_timeout"] == "25s"
    assert grpc_out["transport"]["ping_timeout"] == "15s"

    ss_cfg = {
        "method": "aes-128-gcm",
        "password": "secretpassword",
    }
    ss_target = Target("203.0.113.10", 8388)
    sb_ss_conf = build_singbox_config(
        ss_target,
        "shadowsocks", "tcp", "none",
        ss_cfg,
        10809,
        10810,
    )
    ss_out = sb_ss_conf["outbounds"][0]
    assert ss_out["method"] == "aes-128-gcm"

def test_coverage_report_generation():
    catalog = create_default_protocol_catalog()
    report = generate_coverage_report(catalog)

    assert isinstance(report, CoverageReport)
    assert len(report.entries) >= 40
    assert report.tier_totals[CoverageTier.CATALOGUED] >= 40
    assert report.tier_totals[CoverageTier.SCHEMA_VALIDATED] >= 20
    assert report.tier_totals[CoverageTier.CONFIG_GENERATED] >= 15
    assert report.tier_totals[CoverageTier.BINARY_VALIDATED] >= 10
    assert report.tier_totals[CoverageTier.LIVE_CONNECTED] == 0
    assert report.tier_totals[CoverageTier.DATA_TRANSFERRED] == 0

    assert "xray" in report.engine_statistics
    assert "sing_box" in report.engine_statistics
    assert "exclave" in report.engine_statistics
    assert "wireguard" in report.engine_statistics
    assert "amnezia_wg" in report.engine_statistics
    assert "openvpn" in report.engine_statistics
    assert "aether" in report.engine_statistics

    xray_stats = report.engine_statistics["xray"]
    assert xray_stats["total_items"] >= 15
    assert xray_stats[CoverageTier.BINARY_VALIDATED.value] > 0

    d = report.to_dict()
    assert "tier_totals" in d
    assert "engine_statistics" in d
    assert "entries" in d
    assert len(d["entries"]) == len(report.entries)

def test_coverage_report_engine_filter():
    catalog = create_default_protocol_catalog()
    xray_report = generate_coverage_report(catalog, engine_filter="xray")
    assert len(xray_report.entries) >= 15
    assert all(e.engine_id == "xray" for e in xray_report.entries)
    assert list(xray_report.engine_statistics.keys()) == ["xray"]

def test_coverage_render_table_and_json():
    catalog = create_default_protocol_catalog()
    report = generate_coverage_report(catalog)

    table_out = render_coverage_table(report)
    assert "ConnScope Capability & Parameter Coverage Report" in table_out
    assert "Coverage Statistics by Engine:" in table_out
    assert "xray" in table_out
    assert "sing_box" in table_out

    json_out = render_coverage_json(report)
    parsed = json.loads(json_out)
    assert len(parsed["entries"]) == len(report.entries)
    assert "tier_totals" in parsed
    assert "entries" in parsed

def test_cli_catalog_coverage_table():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "coverage"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    val = out.getvalue()
    assert "ConnScope Capability & Parameter Coverage Report" in val
    assert "xray" in val
    assert "sing_box" in val

def test_cli_catalog_coverage_json():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "coverage", "--json"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    data = json.loads(out.getvalue())
    assert "tier_totals" in data
    assert "entries" in data
    assert data["tier_totals"]["catalogued"] >= 40

def test_cli_catalog_coverage_engine_filter():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "coverage", "--engine", "xray", "--json"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    data = json.loads(out.getvalue())
    assert all(e["engine_id"] == "xray" for e in data["entries"])

def test_cli_matrix_coverage():
    out_table = io.StringIO()
    err_table = io.StringIO()
    code_t = cli_entry(["matrix", "coverage"], stdout=out_table, stderr=err_table)
    assert code_t == ExitCode.OK
    assert "ConnScope Capability & Parameter Coverage Report" in out_table.getvalue()

    out_json = io.StringIO()
    err_json = io.StringIO()
    code_j = cli_entry(["matrix", "coverage", "--json"], stdout=out_json, stderr=err_json)
    assert code_j == ExitCode.OK
    data = json.loads(out_json.getvalue())
    assert "tier_totals" in data

def test_real_binary_xray_extended_config_validation(tmp_path: Path):
    xray_bin = resolve_safe_executable("xray")
    if not xray_bin:
        pytest.skip("xray binary not available")

    target = Target("127.0.0.1", 23456)
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
        "short_id": "0123456789abcdef",
        "server_name": "example.com",
        "alpn": ["h2", "http/1.1"],
        "min_version": "1.2",
        "max_version": "1.3",
        "mux_enabled": True,
        "mux_concurrency": 16,
        "tcp_fast_open": True,
    }
    xray_conf = build_xray_config(
        target,
        "vless", "tcp", "reality",
        cfg,
        23457,
        23458,
    )
    conf_file = tmp_path / "xray_ext_test.json"
    conf_file.write_text(json.dumps(xray_conf), encoding="utf-8")

    result = subprocess.run(
        [xray_bin, "run", "-test", "-c", str(conf_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Xray test failed: {result.stderr}"

def test_real_binary_singbox_extended_config_validation(tmp_path: Path):
    sb_lookup = (
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        str(Path.home() / ".local/share/v2rayN/bin/sing_box"),
    )
    sb_bin = resolve_safe_executable("sing-box", lookup_paths=sb_lookup)
    if not sb_bin:
        pytest.skip("sing-box binary not available")

    target = Target("127.0.0.1", 23456)
    cfg = {
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
        "short_id": "0123456789abcdef",
        "server_name": "example.com",
        "alpn": ["h2", "http/1.1"],
        "min_version": "1.2",
        "max_version": "1.3",
        "mux_enabled": True,
        "mux_concurrency": 8,
        "tcp_fast_open": True,
    }
    sb_conf = build_singbox_config(
        target,
        "vless", "tcp", "reality",
        cfg,
        23457,
        23458,
    )
    conf_file = tmp_path / "singbox_ext_test.json"
    conf_file.write_text(json.dumps(sb_conf), encoding="utf-8")

    result = subprocess.run(
        [sb_bin, "check", "-c", str(conf_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"sing-box check failed: {result.stderr}"
