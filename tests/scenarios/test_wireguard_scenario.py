
import json
from pathlib import Path
import pytest

from connscope.adapters import (
    AdapterRegistry,
    MockLayer3IsolationBackend,
    SingBoxVlessTcpRealityAdapter,
    SingBoxVmessWebSocketTlsAdapter,
    TunnelExecutionMode,
    WireGuardStandardAdapter,
    XrayVlessTcpRealityAdapter,
    XrayVmessWebSocketTlsAdapter,
)
from connscope.agent.execution import UnsupportedProbeError, prepare_probe_config
from connscope.core import ProbeRegistry, Target
from connscope.probes import register_builtin_probes
from connscope.scenarios import (
    AdapterMigrationBridge,
    GenerationMode,
    MatrixPlan,
    MeasurementRecord,
    ScenarioCoordinator,
    ScenarioGenerator,
    create_default_protocol_catalog,
    read_jsonl,
    write_jsonl,
)

SAMPLE_TARGET = Target(host="198.51.100.1", port=51820)
CLIENT_PRIVKEY = "YAmZ1y5v+7vX+Z/Qf6s5k1y5v+7vX+Z/Qf6s5k1y5v8="
PEER_PUBKEY = "8n5WzXghUgGfcEzTt+vGU5ZXAij+pc5rVni0dyJ0xhk="
WG_CONFIG = {
    "private_key": CLIENT_PRIVKEY,
    "public_key": PEER_PUBKEY,
    "endpoint": "198.51.100.1:51820",
}

def test_wireguard_declarative_variants_without_adapter_duplication():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["wireguard"],
        profile_ids=["wireguard_standard"],
        variant_ids=["baseline", "low_mtu", "keepalive_disabled"],
        target=SAMPLE_TARGET,
        parameter_overrides=WG_CONFIG,
    )

    assert len(plan.scenarios) == 3
    for scn in plan.scenarios:
        assert scn.adapter_id == "wireguard_standard"
        assert scn.is_valid is True

    scenarios_by_variant = {s.variant_id: s for s in plan.scenarios}

    baseline_cfg = scenarios_by_variant["baseline"].resolved_config
    assert baseline_cfg["mtu"] == 1420
    assert baseline_cfg["persistent_keepalive"] == 25

    low_mtu_cfg = scenarios_by_variant["low_mtu"].resolved_config
    assert low_mtu_cfg["mtu"] == 1280
    assert low_mtu_cfg["persistent_keepalive"] == 25

    no_ka_cfg = scenarios_by_variant["keepalive_disabled"].resolved_config
    assert no_ka_cfg["mtu"] == 1420
    assert no_ka_cfg["persistent_keepalive"] == 0

def test_wireguard_migration_bridge_resolution_and_validation():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()

    plan = generator.generate_explicit(
        engine_ids=["wireguard"],
        profile_ids=["wireguard_standard"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=WG_CONFIG,
    )
    scn = plan.scenarios[0]

    adapter = bridge.get_adapter_for_scenario(scn)
    assert adapter is not None
    assert isinstance(adapter, WireGuardStandardAdapter)
    assert adapter.metadata.execution_mode == TunnelExecutionMode.NETWORK_INTERFACE

    is_valid, err, norm_cfg = bridge.validate_scenario(scn)
    assert is_valid is True
    assert err is None
    assert norm_cfg["private_key"] == CLIENT_PRIVKEY
    assert norm_cfg["public_key"] == PEER_PUBKEY

@pytest.mark.asyncio
async def test_wireguard_coordinator_dry_run_planning(monkeypatch):
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["wireguard"],
        profile_ids=["wireguard_standard"],
        variant_ids=["baseline", "low_mtu"],
        target=SAMPLE_TARGET,
        parameter_overrides=WG_CONFIG,
    )

    bridge = AdapterMigrationBridge()
    adapter = bridge.registry.get("wireguard_standard")
    assert adapter is not None
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    coordinator = ScenarioCoordinator(catalog=catalog, migration_bridge=bridge)
    result = await coordinator.execute_plan(plan, execute=False)

    assert result.is_dry_run is True
    assert len(result.records) == 0
    assert result.summary.planned_scenarios == 2
    assert result.summary.executed_scenarios == 0
    assert result.summary.excluded_scenarios == 0

@pytest.mark.asyncio
async def test_wireguard_coordinator_execution_and_measurement_records(monkeypatch, tmp_path: Path):
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["wireguard"],
        profile_ids=["wireguard_standard"],
        variant_ids=["baseline", "low_mtu"],
        target=SAMPLE_TARGET,
        parameter_overrides=WG_CONFIG,
    )

    mock_backend = MockLayer3IsolationBackend(
        should_pass_capabilities=True,
        should_pass_setup=True,
        should_handshake=True,
        should_traverse_traffic=True,
        should_complete_data_transfer=True,
        http_status=204,
    )
    wg_adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(wg_adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    reg = AdapterRegistry()
    reg.register(wg_adapter)
    bridge = AdapterMigrationBridge(registry=reg)

    coordinator = ScenarioCoordinator(catalog=catalog, migration_bridge=bridge)
    result = await coordinator.execute_plan(plan, execute=True, repetitions_override=2)

    assert result.is_dry_run is False
    assert len(result.records) == 4
    assert result.summary.executed_scenarios == 2
    assert result.summary.succeeded_scenarios == 2
    assert result.summary.success_rate == 1.0

    for rec in result.records:
        assert rec.engine_id == "wireguard"
        assert rec.profile_id == "wireguard_standard"
        assert rec.adapter_id == "wireguard_standard"
        assert rec.status == "success"
        assert rec.execution_mode == "network_interface"
        assert rec.interface_established is True
        assert rec.peer_handshake_completed is True
        assert rec.tunnel_established is True
        assert rec.traffic_traversed is True
        assert rec.data_transfer_completed is True
        assert rec.resolved_config["private_key"] == "[REDACTED]"
        assert rec.resolved_config["public_key"] == "[REDACTED]"

    jsonl_file = tmp_path / "wg_measurements.jsonl"
    write_jsonl(result.records, jsonl_file)

    loaded_records = read_jsonl(jsonl_file)
    assert len(loaded_records) == 4
    for orig, loaded in zip(result.records, loaded_records):
        assert loaded.scenario_id == orig.scenario_id
        assert loaded.repetition_index == orig.repetition_index
        assert loaded.execution_mode == "network_interface"
        assert loaded.traffic_traversed is True
        assert loaded.resolved_config["private_key"] == "[REDACTED]"

def test_remote_agent_isolation_strictly_rejects_wireguard():
    target = Target(host="example.com", port=51820)
    with pytest.raises(UnsupportedProbeError, match="Unsupported probe 'wireguard_standard'"):
        prepare_probe_config("wireguard_standard", target, config={})

def test_backward_compatibility_with_all_existing_proxy_adapters():
    bridge = AdapterMigrationBridge()
    adapter_ids = bridge.registry.adapter_ids()

    assert "xray_vless_tcp_reality" in adapter_ids
    assert "singbox_vless_tcp_reality" in adapter_ids
    assert "xray_vmess_ws_tls" in adapter_ids
    assert "singbox_vmess_ws_tls" in adapter_ids
    assert "wireguard_standard" in adapter_ids

    xray_adapter = bridge.registry.get("xray_vless_tcp_reality")
    assert xray_adapter.metadata.execution_mode == TunnelExecutionMode.LOCAL_PROXY

    wg_adapter = bridge.registry.get("wireguard_standard")
    assert wg_adapter.metadata.execution_mode == TunnelExecutionMode.NETWORK_INTERFACE
