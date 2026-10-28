
import asyncio
import os
from pathlib import Path
import pytest

from connscope.adapters import (
    ALLOWED_AMNEZIAWG_CONFIG_KEYS,
    AdapterRegistry,
    AmneziaWGDeviceDriver,
    AmneziaWGStandardAdapter,
    EngineType,
    FailureStage,
    HostNetworkSnapshot,
    LinuxNetnsIsolationBackend,
    LinuxOriginNetnsIsolationBackend,
    MockLayer3IsolationBackend,
    ProtocolType,
    SecurityType,
    TransportType,
    TunnelExecutionMode,
    UNSUPPORTED_AMNEZIAWG_V2_KEYS,
    WireGuardDeviceDriver,
    WireGuardStandardAdapter,
    generate_amneziawg_awg_setconf_config,
    generate_amneziawg_client_config,
    validate_amneziawg_config,
)
from connscope.agent.execution import SUPPORTED_PROBE_NAMES, select_connection_ip
from connscope.core import ProbeStatus, Target
from connscope.scenarios import (
    AdapterMigrationBridge,
    MatrixPlan,
    MeasurementNode,
    MeasurementWorkload,
    MeasurementRecord,
    Scenario,
    ScenarioCoordinator,
    ScenarioGenerator,
    VerificationStatus,
    create_default_protocol_catalog,
)

SAMPLE_TARGET = Target(host="198.51.100.1", port=51820)
CLIENT_PRIVKEY = "YAmZ1y5v+7vX+Z/Qf6s5k1y5v+7vX+Z/Qf6s5k1y5v8="
PEER_PUBKEY = "8n5WzXghUgGfcEzTt+vGU5ZXAij+pc5rVni0dyJ0xhk="
SAMPLE_CONFIG = {
    "private_key": CLIENT_PRIVKEY,
    "public_key": PEER_PUBKEY,
    "endpoint": "198.51.100.1:51820",
    "mtu": 1420,
    "persistent_keepalive": 25,
    "jc": 4,
    "jmin": 40,
    "jmax": 70,
    "s1": 64,
    "s2": 64,
    "h1": 1,
    "h2": 2,
    "h3": 3,
    "h4": 4,
}

def test_amneziawg_adapter_metadata_and_execution_mode():
    adapter = AmneziaWGStandardAdapter()
    meta = adapter.metadata

    assert meta.adapter_id == "amnezia_wg_standard"
    assert meta.engine == EngineType.AMNEZIA_WG
    assert meta.protocol == ProtocolType.WIREGUARD
    assert meta.transport == TransportType.UDP
    assert meta.security == SecurityType.NOISE
    assert meta.execution_mode == TunnelExecutionMode.NETWORK_INTERFACE
    assert meta.executable.binary_name == "awg"

    d = meta.to_dict()
    assert d["execution_mode"] == "network_interface"
    assert d["engine"] == "amnezia_wg"
    assert d["executable"]["binary_name"] == "awg"

def test_amneziawg_adapter_executable_and_capability_check(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="amneziawg",
        should_pass_capabilities=False,
        capability_error="Missing CAP_NET_ADMIN privilege",
    )
    adapter = AmneziaWGStandardAdapter(isolation_backend=mock_backend)

    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (False, "Executable 'awg' not found"))
    cap_ok, cap_err = adapter.check_capabilities()
    assert cap_ok is False
    assert "CAP_NET_ADMIN" in cap_err

def test_validate_amneziawg_config_valid_defaults():
    minimal_cfg = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY,
        "endpoint": "198.51.100.1:51820",
    }
    validated = validate_amneziawg_config(minimal_cfg)

    assert validated["private_key"] == CLIENT_PRIVKEY
    assert validated["public_key"] == PEER_PUBKEY
    assert validated["endpoint"] == "198.51.100.1:51820"
    assert validated["mtu"] == 1420
    assert validated["address"] == "10.0.0.2/32"
    assert validated["allowed_ips"] == "0.0.0.0/0, ::/0"
    assert validated["jc"] == 4
    assert validated["jmin"] == 40
    assert validated["jmax"] == 70
    assert validated["s1"] == 64
    assert validated["s2"] == 64
    assert validated["h1"] == 1
    assert validated["h2"] == 2
    assert validated["h3"] == 3
    assert validated["h4"] == 4

def test_validate_amneziawg_config_case_insensitivity():
    cfg = {
        "private_key": CLIENT_PRIVKEY,
        "public_key": PEER_PUBKEY,
        "endpoint": "198.51.100.1:51820",
        "Jc": 8,
        "Jmin": 50,
        "Jmax": 100,
        "S1": 32,
        "S2": 32,
        "H1": 10,
        "H2": 20,
        "H3": 30,
        "H4": 40,
    }
    validated = validate_amneziawg_config(cfg)
    assert validated["jc"] == 8
    assert validated["jmin"] == 50
    assert validated["jmax"] == 100
    assert validated["s1"] == 32
    assert validated["s2"] == 32
    assert validated["h1"] == 10
    assert validated["h2"] == 20
    assert validated["h3"] == 30
    assert validated["h4"] == 40

def test_validate_amneziawg_config_rejection_of_v2_parameters():
    cfg = {
        **SAMPLE_CONFIG,
        "i1": 12345,
    }
    with pytest.raises(ValueError, match="newer AmneziaWG v2 Header Protection / transport"):
        validate_amneziawg_config(cfg)

    cfg2 = {
        **SAMPLE_CONFIG,
        "header_protection": True,
    }
    with pytest.raises(ValueError, match="newer AmneziaWG v2 Header Protection / transport"):
        validate_amneziawg_config(cfg2)

def test_validate_amneziawg_config_rejection_of_unknown_keys():
    cfg = {
        **SAMPLE_CONFIG,
        "unknown_flag": "test",
    }
    with pytest.raises(ValueError, match="Unknown parameter 'unknown_flag'"):
        validate_amneziawg_config(cfg)

def test_validate_amneziawg_config_bounds():
    with pytest.raises(ValueError, match="jc must be between 1 and 128"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "jc": 0})
    with pytest.raises(ValueError, match="jc must be between 1 and 128"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "jc": 129})

    with pytest.raises(ValueError, match="jmin must be between 0 and 1280"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "jmin": -1})

    with pytest.raises(ValueError, match="jmax must be between 0 and 1280"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "jmax": 1281})

    with pytest.raises(ValueError, match="s1 must be between 0 and 1280"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "s1": -1})
    with pytest.raises(ValueError, match="s2 must be between 0 and 1280"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "s2": 1500})

    with pytest.raises(ValueError, match="h1 must be a 32-bit positive integer"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "h1": 0})
    with pytest.raises(ValueError, match="h4 must be a 32-bit positive integer"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "h4": 4294967296})

def test_validate_amneziawg_config_cross_field_constraints():
    cfg_j_valid = validate_amneziawg_config({**SAMPLE_CONFIG, "jmin": 40, "jmax": 70})
    assert cfg_j_valid["jmin"] == 40
    assert cfg_j_valid["jmax"] == 70

    with pytest.raises(ValueError, match="jmin .* must be strictly less than jmax"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "jmin": 50, "jmax": 50})

    with pytest.raises(ValueError, match="jmin .* must be strictly less than jmax"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "jmin": 100, "jmax": 50})

    with pytest.raises(ValueError, match=r"s1 \+ 56 must not equal s2"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "s1": 0, "s2": 56})

    with pytest.raises(ValueError, match=r"s1 \+ 56 must not equal s2"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "s1": 10, "s2": 66})

    with pytest.raises(ValueError, match=r"s1 \+ 56 must not equal s2"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "s1": 64, "s2": 120})

    cfg_s_valid1 = validate_amneziawg_config({**SAMPLE_CONFIG, "s1": 0, "s2": 0})
    assert cfg_s_valid1["s1"] == 0
    assert cfg_s_valid1["s2"] == 0

    cfg_s_valid2 = validate_amneziawg_config({**SAMPLE_CONFIG, "s1": 56, "s2": 56})
    assert cfg_s_valid2["s1"] == 56
    assert cfg_s_valid2["s2"] == 56

    cfg_s_valid3 = validate_amneziawg_config({**SAMPLE_CONFIG, "s1": 64, "s2": 64})
    assert cfg_s_valid3["s1"] == 64
    assert cfg_s_valid3["s2"] == 64

    with pytest.raises(ValueError, match="Init packet size with padding .* exceeds MTU"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "mtu": 1280, "s1": 1200})

    with pytest.raises(ValueError, match="Response packet size with padding .* exceeds MTU"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "mtu": 1280, "s2": 1200})

    cfg_exact_mtu = validate_amneziawg_config({
        **SAMPLE_CONFIG,
        "mtu": 1280,
        "s1": 1280 - 148,
        "s2": 50,
    })
    assert cfg_exact_mtu["s1"] == 1132

    cfg_default_headers = validate_amneziawg_config({**SAMPLE_CONFIG, "h1": 1, "h2": 2, "h3": 3, "h4": 4})
    assert cfg_default_headers["h1"] == 1

    cfg_distinct = validate_amneziawg_config({
        **SAMPLE_CONFIG,
        "h1": 1001,
        "h2": 1002,
        "h3": 1003,
        "h4": 1004,
    })
    assert cfg_distinct["h1"] == 1001

    with pytest.raises(ValueError, match="Header types H1, H2, H3, H4 must be distinct"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "h1": 100, "h2": 100, "h3": 200, "h4": 300})

    with pytest.raises(ValueError, match="Header types H1, H2, H3, H4 must be distinct"):
        validate_amneziawg_config({**SAMPLE_CONFIG, "h1": 1, "h2": 1, "h3": 3, "h4": 4})

def test_generate_amneziawg_awg_setconf_config_strictly_excludes_address_and_mtu():
    config_text = generate_amneziawg_awg_setconf_config(SAMPLE_CONFIG)

    assert "[Interface]" in config_text
    assert f"PrivateKey = {CLIENT_PRIVKEY}" in config_text
    assert "Jc = 4" in config_text
    assert "Jmin = 40" in config_text
    assert "Jmax = 70" in config_text
    assert "S1 = 64" in config_text
    assert "S2 = 64" in config_text
    assert "H1 = 1" in config_text
    assert "H2 = 2" in config_text
    assert "H3 = 3" in config_text
    assert "H4 = 4" in config_text
    assert "[Peer]" in config_text
    assert f"PublicKey = {PEER_PUBKEY}" in config_text
    assert "Endpoint = 198.51.100.1:51820" in config_text
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in config_text

    assert "Address =" not in config_text
    assert "MTU =" not in config_text
    assert "DNS =" not in config_text

def test_generate_amneziawg_client_config_includes_address_and_mtu():
    cfg = {
        **SAMPLE_CONFIG,
        "address": "10.0.0.5/24",
        "mtu": 1360,
        "dns": "1.1.1.1, 8.8.8.8",
    }
    client_text = generate_amneziawg_client_config(cfg)

    assert "Address = 10.0.0.5/24" in client_text
    assert "MTU = 1360" in client_text
    assert "DNS = 1.1.1.1, 8.8.8.8" in client_text
    assert "Jc = 4" in client_text
    assert "H1 = 1" in client_text

def test_device_driver_properties_and_separation():
    awg_driver = AmneziaWGDeviceDriver()
    wg_driver = WireGuardDeviceDriver()

    assert awg_driver.driver_name == "amneziawg"
    assert awg_driver.link_type == "amneziawg"
    assert awg_driver.tool_binary == "awg"
    assert awg_driver.default_interface_prefix == "awg-cs-"
    assert awg_driver.opt_in_env_var == "CONNSCOPE_ENABLE_REAL_AMNEZIAWG"
    assert awg_driver.origin_netns_env_var == "CONNSCOPE_AMNEZIAWG_ORIGIN_NETNS"
    assert awg_driver.supports_origin_netns is True

    assert wg_driver.driver_name == "wireguard"
    assert wg_driver.link_type == "wireguard"
    assert wg_driver.tool_binary == "wg"
    assert wg_driver.default_interface_prefix == "wg-cs-"

def test_amneziawg_driver_check_capabilities_opt_in(monkeypatch):
    driver = AmneziaWGDeviceDriver()

    monkeypatch.delenv("CONNSCOPE_ENABLE_REAL_AMNEZIAWG", raising=False)
    monkeypatch.delenv("CONNSCOPE_TEST_REAL_AMNEZIAWG", raising=False)
    ok, err = driver.check_capabilities()
    assert ok is False
    assert "CONNSCOPE_ENABLE_REAL_AMNEZIAWG=1" in err

    monkeypatch.setenv("CONNSCOPE_ENABLE_REAL_AMNEZIAWG", "1")
    monkeypatch.delenv("CONNSCOPE_AMNEZIAWG_ORIGIN_NETNS", raising=False)
    ok_orig, err_orig = driver.check_capabilities(require_origin_netns=True)
    assert ok_orig is False
    assert "CONNSCOPE_AMNEZIAWG_ORIGIN_NETNS=1" in err_orig

    monkeypatch.setenv("CONNSCOPE_AMNEZIAWG_ORIGIN_NETNS", "1")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    ok_root, err_root = driver.check_capabilities()
    assert ok_root is False
    assert "root / CAP_NET_ADMIN" in err_root

@pytest.mark.asyncio
async def test_amneziawg_mock_full_successful_lifecycle(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="amneziawg",
        should_pass_capabilities=True,
        should_pass_setup=True,
        should_handshake=True,
        should_traverse_traffic=True,
        should_complete_data_transfer=True,
        http_status=204,
    )
    adapter = AmneziaWGStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/awg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.SUCCESS
    assert result.error is None
    assert result.duration_ms > 0.0

    details = result.details
    assert details["execution_mode"] == "network_interface"
    assert details["interface_name"] == "awg-mock0"
    assert details["interface_established"] is True
    assert details["peer_handshake_completed"] is True
    assert details["tunnel_established"] is True
    assert details["traffic_traversed"] is True
    assert details["data_transfer_completed"] is True
    assert details["cleanup_completed"] is True

    assert details["driver"] == "amneziawg"
    assert details["implementation"] == "amneziawg-linux-kernel-module"
    assert details["amnezia_parameters"]["jc"] == 4
    assert details["amnezia_parameters"]["h1"] == 1

    assert mock_backend.prepare_called is True
    assert mock_backend.setup_called is True
    assert mock_backend.workload_called is True
    assert mock_backend.teardown_called is True
    assert mock_backend.amnezia_parameters["jc"] == 4

@pytest.mark.asyncio
async def test_amneziawg_mock_origin_namespace_lifecycle(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="amneziawg",
        origin_namespace_mode=True,
    )
    adapter = AmneziaWGStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/awg"))

    snap_before = HostNetworkSnapshot.capture()

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    snap_after = HostNetworkSnapshot.capture()
    snap_before.assert_unchanged(snap_after)

    assert result.status == ProbeStatus.SUCCESS
    details = result.details
    assert details["isolation_strategy"] == "origin_netns"
    assert details["socket_in_origin_namespace"] is True
    assert "via 192.168.1.1" in details["origin_endpoint_route"]
    assert mock_backend.created_in_origin is True
    assert mock_backend.moved_to_netns is True

@pytest.mark.asyncio
async def test_amneziawg_interface_setup_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="amneziawg",
        should_pass_setup=False,
        setup_error="Kernel amneziawg module not loaded",
    )
    adapter = AmneziaWGStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/awg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.INTERFACE_SETUP.value
    assert result.details["interface_established"] is False
    assert result.details["tunnel_established"] is False
    assert "Kernel amneziawg module not loaded" in str(result.error)
    assert mock_backend.teardown_called is True

@pytest.mark.asyncio
async def test_amneziawg_missing_peer_handshake(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="amneziawg",
        should_pass_setup=True,
        should_handshake=False,
    )
    adapter = AmneziaWGStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/awg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.details["interface_established"] is True
    assert result.details["peer_handshake_completed"] is False
    assert result.details["tunnel_established"] is False
    assert mock_backend.teardown_called is True

@pytest.mark.asyncio
async def test_amneziawg_traffic_traversal_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="amneziawg",
        should_pass_setup=True,
        should_handshake=True,
        should_traverse_traffic=False,
    )
    adapter = AmneziaWGStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/awg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.TRAFFIC_TRAVERSAL.value
    assert result.details["interface_established"] is True
    assert result.details["peer_handshake_completed"] is True
    assert result.details["tunnel_established"] is True
    assert result.details["traffic_traversed"] is False
    assert mock_backend.teardown_called is True

@pytest.mark.asyncio
async def test_amneziawg_origin_netns_move_failure_cleans_up_host_interface(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="amneziawg",
        origin_namespace_mode=True,
        should_pass_move_netns=False,
    )
    adapter = AmneziaWGStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/awg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.INTERFACE_SETUP.value
    assert mock_backend.teardown_called is True
    assert "cleaned_up_origin_interface" in mock_backend.events

@pytest.mark.asyncio
async def test_amneziawg_cancellation_shielded_teardown(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(driver_name="amneziawg")

    async def slow_workload(*args, **kwargs):
        await asyncio.sleep(5.0)

    mock_backend.execute_workload = slow_workload  # type: ignore[method-assign]
    adapter = AmneziaWGStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/awg"))

    task = asyncio.create_task(adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG))
    await asyncio.sleep(0.05)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert mock_backend.teardown_called is True

def test_amneziawg_declarative_variants_in_catalog():
    catalog = create_default_protocol_catalog()
    profile = catalog.get_profile("amnezia_wg_obfs")

    assert profile is not None
    variant_ids = [v.variant_id for v in profile.default_variants]
    assert variant_ids == ["baseline", "mild_junk", "heavy_junk", "custom_headers"]

    compat = catalog.get_compatibility("amnezia_wg", "amnezia_wg_obfs")
    assert compat is not None
    assert compat.adapter_id == "amnezia_wg_standard"
    assert compat.status == VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED

def test_amneziawg_scenario_generation_all_variants():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()

    plan = generator.generate_explicit(
        engine_ids=["amnezia_wg"],
        profile_ids=["amnezia_wg_obfs"],
        variant_ids=["baseline", "mild_junk", "heavy_junk", "custom_headers"],
        target=SAMPLE_TARGET,
        parameter_overrides={
            "private_key": CLIENT_PRIVKEY,
            "public_key": PEER_PUBKEY,
        },
    )

    assert len(plan.scenarios) == 4
    for scn in plan.scenarios:
        assert scn.adapter_id == "amnezia_wg_standard"
        assert scn.engine_id == "amnezia_wg"
        assert scn.profile_id == "amnezia_wg_obfs"

        is_valid, err, norm = bridge.validate_scenario(scn)
        assert is_valid is True, f"Variant '{scn.variant_id}' failed: {err}"
        assert norm is not None
        assert norm["private_key"] == CLIENT_PRIVKEY

    mild_scn = next(s for s in plan.scenarios if s.variant_id == "mild_junk")
    assert mild_scn.resolved_config["jc"] == 3
    assert mild_scn.resolved_config["s1"] == 32

    heavy_scn = next(s for s in plan.scenarios if s.variant_id == "heavy_junk")
    assert heavy_scn.resolved_config["jc"] == 10
    assert heavy_scn.resolved_config["jmin"] == 100
    assert heavy_scn.resolved_config["jmax"] == 500

    custom_scn = next(s for s in plan.scenarios if s.variant_id == "custom_headers")
    assert custom_scn.resolved_config["h1"] == 1000000001
    assert custom_scn.resolved_config["h4"] == 1000000004

@pytest.mark.asyncio
async def test_coordinator_execution_and_measurement_record_amneziawg(monkeypatch):
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["amnezia_wg"],
        profile_ids=["amnezia_wg_obfs"],
        variant_ids=["baseline", "custom_headers"],
        target=SAMPLE_TARGET,
        parameter_overrides={
            "private_key": CLIENT_PRIVKEY,
            "public_key": PEER_PUBKEY,
        },
    )

    mock_backend = MockLayer3IsolationBackend(driver_name="amneziawg")
    mock_adapter = AmneziaWGStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(mock_adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/awg"))

    reg = AdapterRegistry()
    reg.register(mock_adapter)
    bridge = AdapterMigrationBridge(registry=reg)

    coordinator = ScenarioCoordinator(catalog=catalog, migration_bridge=bridge)
    result = await coordinator.execute_plan(plan, execute=True)

    assert result.summary.executed_scenarios == 2
    assert result.summary.failed_scenarios == 0
    assert len(result.records) == 2

    for rec in result.records:
        assert rec.engine_id == "amnezia_wg"
        assert rec.adapter_id == "amnezia_wg_standard"
        assert rec.profile_id == "amnezia_wg_obfs"
        assert rec.tunnel_established is True
        assert rec.data_transfer_completed is True
        assert rec.execution_mode == "network_interface"

        rec_dict = rec.to_dict()
        assert rec_dict["resolved_config"]["private_key"] == "[REDACTED]"
        assert CLIENT_PRIVKEY not in str(rec_dict)

def test_remote_agent_isolation_from_layer3():
    assert "wireguard" not in SUPPORTED_PROBE_NAMES
    assert "amneziawg" not in SUPPORTED_PROBE_NAMES
    assert "amnezia_wg" not in SUPPORTED_PROBE_NAMES
    assert SUPPORTED_PROBE_NAMES == frozenset({"tcp_connect", "tls_handshake", "http_request", "dns_resolve"})

@pytest.mark.skipif(
    not (
        (
            os.environ.get("CONNSCOPE_ENABLE_REAL_AMNEZIAWG") == "1"
            or os.environ.get("CONNSCOPE_TEST_REAL_AMNEZIAWG") == "1"
        )
        and os.geteuid() == 0
        and Path("/sys/module/amneziawg").exists()
    ),
    reason="Requires CONNSCOPE_ENABLE_REAL_AMNEZIAWG=1, root privileges, and amneziawg kernel module",
)
@pytest.mark.asyncio
async def test_opt_in_real_amneziawg_execution():
    snap_before = HostNetworkSnapshot.capture()

    backend = LinuxNetnsIsolationBackend(driver=AmneziaWGDeviceDriver())
    adapter = AmneziaWGStandardAdapter(isolation_backend=backend)

    real_cfg = {
        "private_key": os.environ.get("CONNSCOPE_TEST_AMNEZIAWG_PRIVKEY", CLIENT_PRIVKEY),
        "public_key": os.environ.get("CONNSCOPE_TEST_AMNEZIAWG_PUBKEY", PEER_PUBKEY),
        "endpoint": os.environ.get("CONNSCOPE_TEST_AMNEZIAWG_ENDPOINT", "198.51.100.1:51820"),
        "address": os.environ.get("CONNSCOPE_TEST_AMNEZIAWG_ADDRESS", "10.0.0.2/32"),
        "mtu": 1420,
        "jc": 4,
        "jmin": 40,
        "jmax": 70,
        "s1": 64,
        "s2": 64,
        "h1": 1,
        "h2": 2,
        "h3": 3,
        "h4": 4,
    }

    try:
        result = await adapter.run(SAMPLE_TARGET, config=real_cfg)
        assert result.details["execution_mode"] == "network_interface"
    finally:
        snap_after = HostNetworkSnapshot.capture()
        snap_before.assert_unchanged(snap_after)
