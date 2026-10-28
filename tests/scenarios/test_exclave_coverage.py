from __future__ import annotations

import base64
import json
import uuid

import pytest

from connscope.adapters.models import ProtocolType
from connscope.cli.main import cli_entry
from connscope.scenarios.catalog import (
    create_default_protocol_catalog,
    validate_exclave_config,
)
from connscope.scenarios.coverage import (
    CoverageReport,
    CoverageTier,
    generate_coverage_report,
)
from connscope.scenarios.models import (
    CapabilityCategory,
    ParameterType,
    VerificationStatus,
)

def test_exclave_capabilities_inventory_count():
    catalog = create_default_protocol_catalog()
    exclave_caps = catalog.list_capabilities(engine_id="exclave")
    assert len(exclave_caps) == 30
    cap_ids = {c.capability_id for c in exclave_caps}

    expected_ids = {
        "exclave_shadowsocks",
        "exclave_shadowsocks_2022",
        "exclave_shadowsocks_legacy",
        "exclave_shadowsocks_plugin",
        "exclave_trojan",
        "exclave_hysteria2",
        "exclave_anytls",
        "exclave_mieru",
        "exclave_naiveproxy",
        "exclave_tuic_v5",
        "exclave_juicity",
        "exclave_vless",
        "exclave_vmess",
        "exclave_wireguard",
        "exclave_masque_connect_ip",
        "exclave_trusttunnel",
        "exclave_snell_v4",
        "exclave_snell_v6",
        "exclave_shadowquic",
        "exclave_ssh",
        "exclave_http_connect",
        "exclave_connect_udp",
        "exclave_socks4",
        "exclave_socks5",
        "exclave_tun",
        "exclave_netstack_gvisor",
        "exclave_tun_system",
        "exclave_traffic_sniffing",
        "exclave_happy_eyeballs",
        "exclave_icmp_policy",
    }
    assert cap_ids == expected_ids

def test_exclave_upstream_source_references():
    catalog = create_default_protocol_catalog()
    engine_def = catalog.get_engine("exclave")
    assert engine_def is not None
    assert engine_def.source_reference is not None
    assert engine_def.source_reference.repository_url == "https://github.com/ExclaveNetwork/Exclave"
    assert engine_def.source_reference.pinned_version == "0.17.66"
    assert engine_def.source_reference.pinned_commit == "71ae3bca4217f78d704713dbb6328aad067404a1"

    for cap in catalog.list_capabilities(engine_id="exclave"):
        assert cap.source_reference is not None
        assert cap.source_reference.repository_url == "https://github.com/ExclaveNetwork/Exclave"
        assert cap.source_reference.pinned_version == "0.17.66"
        assert cap.source_reference.pinned_commit == "71ae3bca4217f78d704713dbb6328aad067404a1"
        assert cap.source_reference.source_file
        assert cap.source_reference.reference_type
        assert cap.source_reference.verification_status

def test_exclave_execution_feasibility_status():
    catalog = create_default_protocol_catalog()
    for cap in catalog.list_capabilities(engine_id="exclave"):
        assert cap.is_executable is False
        assert cap.status == VerificationStatus.CATALOGUED
        assert cap.unsupported_reason is not None
        assert len(cap.unsupported_reason) > 10

def test_exclave_parameter_definitions_present():
    catalog = create_default_protocol_catalog()
    for cap in catalog.list_capabilities(engine_id="exclave"):
        assert len(cap.parameters) > 0
        for param in cap.parameters:
            assert param.param_id
            assert param.display_name
            assert isinstance(param.param_type, ParameterType)

def test_validate_exclave_config_valid_shadowsocks_aead():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("exclave_shadowsocks")
    assert cap is not None
    valid_cfg = {
        "method": "chacha20-ietf-poly1305",
        "password": "secret_password_123",
        "udp_relay": True,
    }
    errors = validate_exclave_config(cap, valid_cfg, catalog)
    assert errors == []

def test_validate_exclave_config_shadowsocks_2022():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("exclave_shadowsocks_2022")
    assert cap is not None

    key_16 = base64.b64encode(b"0123456789abcdef").decode("utf-8")
    valid_cfg = {
        "method": "2022-blake3-aes-128-gcm",
        "password": key_16,
        "udp_relay": True,
    }
    assert validate_exclave_config(cap, valid_cfg, catalog) == []

    key_32 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("utf-8")
    valid_cfg_32 = {
        "method": "2022-blake3-aes-256-gcm",
        "password": key_32,
        "udp_relay": True,
    }
    assert validate_exclave_config(cap, valid_cfg_32, catalog) == []

    invalid_key_cfg = {
        "method": "2022-blake3-aes-128-gcm",
        "password": key_32,
        "udp_relay": True,
    }
    errs = validate_exclave_config(cap, invalid_key_cfg, catalog)
    assert any("requires 16-byte base64 key" in e for e in errs)

    corrupt_cfg = {
        "method": "2022-blake3-aes-128-gcm",
        "password": "not_a_valid_base64!!!",
        "udp_relay": True,
    }
    errs = validate_exclave_config(cap, corrupt_cfg, catalog)
    assert any("valid base64 string" in e for e in errs)

def test_validate_exclave_config_hysteria2():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("exclave_hysteria2")
    assert cap is not None

    valid_hy2 = {
        "password": "hy2_password",
        "up_mbps": 100,
        "down_mbps": 200,
        "obfs_type": "salamander",
        "obfs_password": "obfs_secret",
    }
    assert validate_exclave_config(cap, valid_hy2, catalog) == []

    missing_obfs_pwd = {
        "password": "hy2_password",
        "obfs_type": "salamander",
        "obfs_password": "",
    }
    errs = validate_exclave_config(cap, missing_obfs_pwd, catalog)
    assert any("requires non-empty 'obfs_password'" in e for e in errs)

def test_validate_exclave_config_ssh():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("exclave_ssh")
    assert cap is not None

    valid_pwd = {"username": "root", "password": "secure_ssh_password"}
    assert validate_exclave_config(cap, valid_pwd, catalog) == []

    valid_key = {"username": "root", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----..."}
    assert validate_exclave_config(cap, valid_key, catalog) == []

    no_auth = {"username": "root"}
    errs = validate_exclave_config(cap, no_auth, catalog)
    assert any("at least one authentication method" in e for e in errs)

def test_validate_exclave_config_wireguard():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("exclave_wireguard")
    assert cap is not None

    k32_1 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("utf-8")
    k32_2 = base64.b64encode(b"fedcba9876543210fedcba9876543210").decode("utf-8")
    valid_wg = {
        "private_key": k32_1,
        "peer_public_key": k32_2,
        "local_address": "10.0.0.2/32",
        "mtu": 1420,
    }
    assert validate_exclave_config(cap, valid_wg, catalog) == []

    bad_key_wg = {
        "private_key": "short_key",
        "peer_public_key": k32_2,
    }
    errs = validate_exclave_config(cap, bad_key_wg, catalog)
    assert any("must decode to 32 bytes" in e or "valid 32-byte base64" in e for e in errs)

def test_validate_exclave_config_naiveproxy_plugin_path_safety():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("exclave_naiveproxy")
    assert cap is not None

    valid_naive = {
        "username": "user1",
        "password": "pass1",
        "server_name": "proxy.example.com",
        "plugin_path": "/data/app/libnaive.so",
    }
    assert validate_exclave_config(cap, valid_naive, catalog) == []

    dangerous_naive = {
        "username": "user1",
        "password": "pass1",
        "server_name": "proxy.example.com",
        "plugin_path": "/data/app/libnaive.so; rm -rf /",
    }
    errs = validate_exclave_config(cap, dangerous_naive, catalog)
    assert any("dangerous character" in e for e in errs)

def test_validate_exclave_config_forbidden_keys():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("exclave_vless")
    assert cap is not None

    bad_cfg = {
        "uuid": str(uuid.uuid4()),
        "command": "/bin/sh -c evil",
    }
    errs = validate_exclave_config(cap, bad_cfg, catalog)
    assert any("Forbidden/dangerous configuration key detected: 'command'" in e for e in errs)

def test_validate_exclave_config_unknown_fields():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("exclave_trojan")
    assert cap is not None

    cfg = {
        "password": "trojan_secret",
        "server_name": "trojan.example.com",
        "unrecognized_param": 1234,
    }
    errs = validate_exclave_config(cap, cfg, catalog)
    assert any("Unknown field 'unrecognized_param'" in e for e in errs)

def test_validate_exclave_config_socks4():
    catalog = create_default_protocol_catalog()
    cap = catalog.get_capability("exclave_socks4")
    assert cap is not None

    valid_s4 = {"version": "4a", "user_id": "test_user"}
    assert validate_exclave_config(cap, valid_s4, catalog) == []

    long_user_s4 = {"version": "4a", "user_id": "a" * 256}
    errs = validate_exclave_config(cap, long_user_s4, catalog)
    assert any("user_id cannot exceed 255 characters" in e for e in errs)

def test_validate_exclave_config_tuic_and_juicity():
    catalog = create_default_protocol_catalog()
    tuic_cap = catalog.get_capability("exclave_tuic_v5")
    assert tuic_cap is not None
    valid_uuid = str(uuid.uuid4())

    valid_tuic = {
        "uuid": valid_uuid,
        "password": "tuic_secret_pwd",
        "congestion_control": "bbr",
    }
    assert validate_exclave_config(tuic_cap, valid_tuic, catalog) == []

    invalid_uuid_tuic = {
        "uuid": "invalid-uuid-format",
        "password": "tuic_secret_pwd",
    }
    errs = validate_exclave_config(tuic_cap, invalid_uuid_tuic, catalog)
    assert any("must be a valid RFC 4122 UUID" in e for e in errs)

    juicity_cap = catalog.get_capability("exclave_juicity")
    assert juicity_cap is not None
    valid_jui = {
        "uuid": valid_uuid,
        "password": "jui_secret_pwd",
        "server_name": "jui.example.com",
    }
    assert validate_exclave_config(juicity_cap, valid_jui, catalog) == []

def test_validate_exclave_config_non_exclave_engine_rejected():
    catalog = create_default_protocol_catalog()
    xray_cap = catalog.get_capability("xray_vless")
    assert xray_cap is not None
    errs = validate_exclave_config(xray_cap, {"uuid": str(uuid.uuid4())}, catalog)
    assert any("not 'exclave'" in e for e in errs)

def test_coverage_report_counting_reconciliation():
    catalog = create_default_protocol_catalog()
    report = generate_coverage_report(catalog)

    assert report.canonical_capabilities_count == 48
    assert report.engine_capabilities_count == 65
    assert report.profile_compatibilities_count == 21
    assert len(report.entries) == 86
    assert report.parameter_definitions_count > 200
    assert report.variants_count > 30
    assert report.compatibility_rules_count > 40

    d = report.to_dict()
    assert d["canonical_capabilities_count"] == 48
    assert d["engine_capabilities_count"] == 65
    assert d["profile_compatibilities_count"] == 21
    assert d["parameter_definitions_count"] > 200
    assert d["variants_count"] > 30
    assert d["compatibility_rules_count"] > 40
    assert "category_statistics" in d
    assert "protocol" in d["category_statistics"]
    assert "runtime_mode" in d["category_statistics"]
    assert "network_stack" in d["category_statistics"]
    assert "inbound_processing" in d["category_statistics"]
    assert "global_setting" in d["category_statistics"]

def test_coverage_report_protocol_filtering():
    catalog = create_default_protocol_catalog()
    report_vless = generate_coverage_report(catalog, protocol_filter="vless")

    assert all(
        "vless" in e.item_id.lower() or "vless" in e.display_name.lower()
        for e in report_vless.entries
    )
    assert report_vless.canonical_capabilities_count == 1
    assert report_vless.engine_capabilities_count == 3
    assert report_vless.profile_compatibilities_count == 10

def test_coverage_report_category_filtering():
    catalog = create_default_protocol_catalog()
    report_runtime = generate_coverage_report(catalog, category_filter="runtime_mode")
    assert len(report_runtime.entries) == 1
    assert report_runtime.entries[0].item_id == "exclave_tun"
    assert report_runtime.entries[0].category == "runtime_mode"

    report_netstack = generate_coverage_report(catalog, category_filter="network_stack")
    assert len(report_netstack.entries) == 2
    ids = {e.item_id for e in report_netstack.entries}
    assert ids == {"exclave_netstack_gvisor", "exclave_tun_system"}

def test_exclave_capability_taxonomy_categories():
    catalog = create_default_protocol_catalog()
    tun_cap = catalog.get_capability("exclave_tun")
    assert tun_cap is not None
    assert tun_cap.category == CapabilityCategory.RUNTIME_MODE

    gvisor_cap = catalog.get_capability("exclave_netstack_gvisor")
    assert gvisor_cap is not None
    assert gvisor_cap.category == CapabilityCategory.NETWORK_STACK

    system_cap = catalog.get_capability("exclave_tun_system")
    assert system_cap is not None
    assert system_cap.category == CapabilityCategory.NETWORK_STACK

    sniff_cap = catalog.get_capability("exclave_traffic_sniffing")
    assert sniff_cap is not None
    assert sniff_cap.category == CapabilityCategory.INBOUND_PROCESSING

    eyeballs_cap = catalog.get_capability("exclave_happy_eyeballs")
    assert eyeballs_cap is not None
    assert eyeballs_cap.category == CapabilityCategory.GLOBAL_SETTING

    icmp_cap = catalog.get_capability("exclave_icmp_policy")
    assert icmp_cap is not None
    assert icmp_cap.category == CapabilityCategory.GLOBAL_SETTING

def test_exclave_parameter_traceability_evidence():
    catalog = create_default_protocol_catalog()
    for cap in catalog.list_capabilities(engine_id="exclave"):
        for param in cap.parameters:
            assert param.evidence_status
            assert param.impact_scope
            assert isinstance(param.is_source_confirmed, bool)

def test_cli_catalog_coverage_exclave(capsys):
    ret = cli_entry(["catalog", "coverage", "--engine", "exclave", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["engine_capabilities_count"] == 30
    assert data["profile_compatibilities_count"] == 0
    assert "exclave" in data["engine_statistics"]
    assert data["engine_statistics"]["exclave"]["total_items"] == 30
    assert data["engine_statistics"]["exclave"]["executable_items"] == 0

def test_cli_catalog_coverage_category_filter(capsys):
    ret = cli_entry(["catalog", "coverage", "--category", "runtime_mode", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data["entries"]) == 1
    assert data["entries"][0]["item_id"] == "exclave_tun"

def test_cli_matrix_coverage_protocol(capsys):
    ret = cli_entry(["matrix", "coverage", "--protocol", "vless"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "ConnScope Capability & Parameter Coverage Report" in captured.out
    assert "sing_box:vless_tcp_reality" in captured.out
    assert "xray:vless_tcp_reality" in captured.out
    assert "exclave_vless" in captured.out
