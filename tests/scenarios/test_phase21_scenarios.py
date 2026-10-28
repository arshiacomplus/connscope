from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import patch

import pytest

from connscope.adapters import (
    EngineType,
    ProfileDrivenAdapter,
    ProtocolType,
    SecurityType,
    TransportType,
)
from connscope.core import Target
from connscope.scenarios import (
    AdapterMigrationBridge,
    ProtocolCatalog,
    ScenarioCoordinator,
    ScenarioGenerator,
    VerificationStatus,
    create_default_protocol_catalog,
)

def test_catalog_registers_all_phase21_profiles():
    catalog = create_default_protocol_catalog()

    expected_profiles = [
        "vless_tcp_tls",
        "vless_tcp_none",
        "vless_ws_tls",
        "vless_grpc_tls",
        "trojan_tcp_tls",
        "shadowsocks_tcp",
    ]

    for p_id in expected_profiles:
        profile = catalog.get_profile(p_id)
        assert profile is not None
        assert profile.profile_id == p_id
        assert len(profile.default_variants) >= 1

        xray_compat = catalog.get_compatibility("xray", p_id)
        assert xray_compat is not None
        assert xray_compat.adapter_id == f"xray_{p_id}"
        assert xray_compat.status == VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED

        sb_compat = catalog.get_compatibility("sing_box", p_id)
        assert sb_compat is not None
        assert sb_compat.adapter_id == f"singbox_{p_id}"
        assert sb_compat.status == VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED

def test_migration_bridge_resolves_all_phase21_adapters():
    bridge = AdapterMigrationBridge()
    adapter_ids = bridge.registry.adapter_ids()

    for eng in ("xray", "singbox"):
        for prof in (
            "vless_tcp_tls",
            "vless_tcp_none",
            "vless_ws_tls",
            "vless_grpc_tls",
            "trojan_tcp_tls",
            "shadowsocks_tcp",
        ):
            aid = f"{eng}_{prof}"
            assert aid in adapter_ids
            adapter = bridge.registry.get(aid)
            assert isinstance(adapter, ProfileDrivenAdapter)
            assert adapter.metadata.adapter_id == aid

def test_generate_and_validate_scenarios_for_phase21_profiles():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()
    target = Target(host="target.domain.com", port=443)

    configs = {
        "vless_tcp_tls": {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "flow": "xtls-rprx-vision",
        },
        "vless_tcp_none": {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        },
        "vless_ws_tls": {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "path": "/ws",
        },
        "vless_grpc_tls": {
            "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "server_name": "target.domain.com",
            "service_name": "test-grpc",
        },
        "trojan_tcp_tls": {
            "password": "my-trojan-password",
            "server_name": "target.domain.com",
        },
        "shadowsocks_tcp": {
            "method": "2022-blake3-aes-128-gcm",
            "password": base64.b64encode(b"0" * 16).decode("ascii"),
        },
    }

    for p_id, p_cfg in configs.items():
        plan = generator.generate_explicit(
            engine_ids=["xray", "sing_box"],
            profile_ids=[p_id],
            variant_ids=["baseline"],
            target=target,
            parameter_overrides=p_cfg,
        )
        assert len(plan.scenarios) == 2

        for scn in plan.scenarios:
            is_valid, err, norm_cfg = bridge.validate_scenario(scn)
            assert is_valid is True, f"Validation failed for scenario {scn.scenario_id}: {err}"
            assert norm_cfg is not None
            dry = bridge.dry_run_scenario(scn)
            assert dry["config_valid"] is True

@pytest.mark.asyncio
async def test_coordinator_dry_run_with_phase21_scenarios(tmp_path):
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()
    target = Target(host="target.domain.com", port=443)

    plan = generator.generate_explicit(
        engine_ids=["xray", "sing_box"],
        profile_ids=["trojan_tcp_tls", "shadowsocks_tcp"],
        variant_ids=["baseline", "baseline_2022_128"],
        target=target,
        parameter_overrides={
            "password": "trojan-password",
            "server_name": "target.domain.com",
            "method": "2022-blake3-aes-128-gcm",
        },
    )
    assert len(plan.scenarios) == 4

    coordinator = ScenarioCoordinator(
        catalog=catalog,
        migration_bridge=bridge,
    )

    records_res = await coordinator.execute_plan(plan, execute=False)
    assert records_res.is_dry_run is True
    assert records_res.summary.planned_scenarios == 4
