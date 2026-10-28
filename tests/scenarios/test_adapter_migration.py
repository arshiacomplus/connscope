
import pytest

from connscope.adapters import (
    AdapterRegistry,
    SingBoxVlessTcpRealityAdapter,
    SingBoxVmessWebSocketTlsAdapter,
    XrayVlessTcpRealityAdapter,
    XrayVmessWebSocketTlsAdapter,
)
from connscope.core import Target
from connscope.scenarios import (
    AdapterMigrationBridge,
    ScenarioGenerator,
    create_default_protocol_catalog,
)

SAMPLE_TARGET = Target(host="192.0.2.1", port=443)
VLESS_CONFIG = {
    "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
    "server_name": "example.com",
    "short_id": "0123456789abcdef",
}
VMESS_CONFIG = {
    "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "server_name": "example.com",
    "path": "/ws",
    "alter_id": 0,
    "security": "auto",
}

def test_migration_bridge_registers_all_four_adapters():
    bridge = AdapterMigrationBridge()
    adapter_ids = bridge.registry.adapter_ids()

    assert "xray_vless_tcp_reality" in adapter_ids
    assert "singbox_vless_tcp_reality" in adapter_ids
    assert "xray_vmess_ws_tls" in adapter_ids
    assert "singbox_vmess_ws_tls" in adapter_ids

def test_migration_xray_vless_adapter_validation():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()

    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=VLESS_CONFIG,
    )
    scn = plan.scenarios[0]
    assert scn.adapter_id == "xray_vless_tcp_reality"

    adapter = bridge.get_adapter_for_scenario(scn)
    assert isinstance(adapter, XrayVlessTcpRealityAdapter)

    is_valid, err, norm_cfg = bridge.validate_scenario(scn)
    assert is_valid is True
    assert err is None
    assert norm_cfg["uuid"] == VLESS_CONFIG["uuid"]

    dry = bridge.dry_run_scenario(scn)
    assert dry["supported"] is True
    assert dry["config_valid"] is True
    assert dry["adapter_id"] == "xray_vless_tcp_reality"
    assert dry["redacted_config"]["uuid"] == "[REDACTED]"

def test_migration_singbox_vless_adapter_validation():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()

    plan = generator.generate_explicit(
        engine_ids=["sing_box"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=VLESS_CONFIG,
    )
    scn = plan.scenarios[0]
    assert scn.adapter_id == "singbox_vless_tcp_reality"

    adapter = bridge.get_adapter_for_scenario(scn)
    assert isinstance(adapter, SingBoxVlessTcpRealityAdapter)

    is_valid, err, norm_cfg = bridge.validate_scenario(scn)
    assert is_valid is True
    assert err is None
    assert norm_cfg["uuid"] == VLESS_CONFIG["uuid"]

    dry = bridge.dry_run_scenario(scn)
    assert dry["supported"] is True
    assert dry["config_valid"] is True
    assert dry["adapter_id"] == "singbox_vless_tcp_reality"

def test_migration_xray_vmess_adapter_validation():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()

    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vmess_ws_tls"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=VMESS_CONFIG,
    )
    scn = plan.scenarios[0]
    assert scn.adapter_id == "xray_vmess_ws_tls"

    adapter = bridge.get_adapter_for_scenario(scn)
    assert isinstance(adapter, XrayVmessWebSocketTlsAdapter)

    is_valid, err, norm_cfg = bridge.validate_scenario(scn)
    assert is_valid is True
    assert err is None

    dry = bridge.dry_run_scenario(scn)
    assert dry["supported"] is True
    assert dry["config_valid"] is True
    assert dry["adapter_id"] == "xray_vmess_ws_tls"

def test_migration_singbox_vmess_adapter_validation():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()

    plan = generator.generate_explicit(
        engine_ids=["sing_box"],
        profile_ids=["vmess_ws_tls"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=VMESS_CONFIG,
    )
    scn = plan.scenarios[0]
    assert scn.adapter_id == "singbox_vmess_ws_tls"

    adapter = bridge.get_adapter_for_scenario(scn)
    assert isinstance(adapter, SingBoxVmessWebSocketTlsAdapter)

    is_valid, err, norm_cfg = bridge.validate_scenario(scn)
    assert is_valid is True
    assert err is None

    dry = bridge.dry_run_scenario(scn)
    assert dry["supported"] is True
    assert dry["config_valid"] is True
    assert dry["adapter_id"] == "singbox_vmess_ws_tls"

def test_migration_unsupported_future_scenario():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()

    plan = generator.generate_explicit(
        engine_ids=["aether"],
        profile_ids=["aether_tun"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides={"auth_token": "test-token-123"},
    )
    scn = plan.scenarios[0]
    assert scn.adapter_id is None

    adapter = bridge.get_adapter_for_scenario(scn)
    assert adapter is None

    dry = bridge.dry_run_scenario(scn)
    assert dry["supported"] is False
    assert "No concrete adapter mapped" in dry["reason"]

def test_remote_agent_isolation_remains_intact():
    from connscope.agent.execution import UnsupportedProbeError, prepare_probe_config
    from connscope.core import ProbeRegistry
    from connscope.probes import register_builtin_probes

    reg = ProbeRegistry()
    register_builtin_probes(reg)
    assert "xray_vless_tcp_reality" not in reg.names()
    assert "singbox_vless_tcp_reality" not in reg.names()
    assert "xray_vmess_ws_tls" not in reg.names()
    assert "singbox_vmess_ws_tls" not in reg.names()

    target = Target(host="example.com", port=443)
    with pytest.raises(UnsupportedProbeError, match="Unsupported probe 'xray_vless_tcp_reality'"):
        prepare_probe_config("xray_vless_tcp_reality", target, config={})

    with pytest.raises(UnsupportedProbeError, match="Unsupported probe 'singbox_vmess_ws_tls'"):
        prepare_probe_config("singbox_vmess_ws_tls", target, config={})
