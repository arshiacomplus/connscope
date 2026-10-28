
import asyncio
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch
import pytest

from connscope.adapters import AdapterRegistry, EngineAdapter
from connscope.adapters.models import (
    AdapterCapability,
    AdapterMetadata,
    AdapterStatus,
    EngineType,
    ExecutableRequirement,
    FailureStage,
    OperatingMode,
    ProtocolType,
    SecurityType,
    TransportType,
)
from connscope.core import ProbeResult, ProbeStatus, Target
from connscope.scenarios import (
    AdapterMigrationBridge,
    FailurePolicy,
    GenerationMode,
    MatrixPlan,
    MeasurementNode,
    MeasurementWorkload,
    Scenario,
    ScenarioCoordinator,
    ScenarioGenerator,
    VerificationStatus,
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

class MockControlledAdapter(EngineAdapter):

    def __init__(
        self,
        adapter_id: str,
        engine: EngineType = EngineType.XRAY,
        should_succeed: bool = True,
        delay_s: float = 0.0,
    ) -> None:
        self.metadata = AdapterMetadata(
            adapter_id=adapter_id,
            display_name=f"Mock Adapter {adapter_id}",
            engine=engine,
            protocol=ProtocolType.VLESS,
            transport=TransportType.TCP,
            security=SecurityType.REALITY,
            operating_mode=OperatingMode.CLIENT_ONLY,
            capabilities=frozenset({AdapterCapability.HANDSHAKE, AdapterCapability.DATA_TRANSFER}),
            status=AdapterStatus.REAL_ENGINE_INTEGRATION_TESTED,
            executable=ExecutableRequirement(binary_name="mock_bin"),
        )
        self.should_succeed = should_succeed
        self.delay_s = delay_s
        self.call_count = 0
        self.concurrent_active = 0
        self.max_concurrent_observed = 0

    def validate_config(self, config: dict[str, Any] | None) -> dict[str, Any]:
        return dict(config or {})

    def check_executable(self) -> tuple[bool, str | None]:
        return True, "/usr/bin/mock_bin"

    async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
        self.call_count += 1
        self.concurrent_active += 1
        self.max_concurrent_observed = max(self.max_concurrent_observed, self.concurrent_active)

        if self.delay_s > 0:
            await asyncio.sleep(self.delay_s)

        self.concurrent_active -= 1

        if self.should_succeed:
            return ProbeResult(
                probe=self.metadata.adapter_id,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=45.0,
                metrics={"local_ready_ms": 10.0, "handshake_ms": 15.0, "data_transfer_ms": 20.0, "total_ms": 45.0},
                details={
                    "adapter_id": self.metadata.adapter_id,
                    "tunnel_established": True,
                    "data_transfer_completed": True,
                },
            )
        else:
            return ProbeResult(
                probe=self.metadata.adapter_id,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=datetime.now(timezone.utc),
                duration_ms=100.0,
                metrics={"local_ready_ms": 10.0, "handshake_ms": 90.0, "total_ms": 100.0},
                details={
                    "adapter_id": self.metadata.adapter_id,
                    "failure_stage": FailureStage.HANDSHAKE.value,
                    "tunnel_established": False,
                    "data_transfer_completed": False,
                },
                error="Handshake failed to remote mock server",
            )

@pytest.mark.asyncio
async def test_coordinator_dry_run_mode():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=VLESS_CONFIG,
    )

    mock_adapter = MockControlledAdapter("xray_vless_tcp_reality")
    reg = AdapterRegistry()
    reg.register(mock_adapter)
    bridge = AdapterMigrationBridge(registry=reg)

    coordinator = ScenarioCoordinator(catalog=catalog, migration_bridge=bridge)
    result = await coordinator.execute_plan(plan, execute=False)

    assert result.is_dry_run is True
    assert len(result.records) == 0
    assert result.summary.planned_scenarios == 1
    assert result.summary.executed_scenarios == 0
    assert result.summary.excluded_scenarios == 0
    assert mock_adapter.call_count == 0

@pytest.mark.asyncio
async def test_coordinator_execution_and_repetition_indexing():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=VLESS_CONFIG,
    )

    mock_adapter = MockControlledAdapter("xray_vless_tcp_reality", should_succeed=True)
    reg = AdapterRegistry()
    reg.register(mock_adapter)
    bridge = AdapterMigrationBridge(registry=reg)

    events = []
    coordinator = ScenarioCoordinator(
        catalog=catalog,
        migration_bridge=bridge,
        progress_callback=lambda ev: events.append(ev),
    )

    result = await coordinator.execute_plan(plan, execute=True, repetitions_override=3)

    assert result.is_dry_run is False
    assert len(result.records) == 3
    assert mock_adapter.call_count == 3

    for idx, rec in enumerate(result.records):
        assert rec.repetition_index == idx
        assert rec.status == "success"
        assert rec.tunnel_established is True
        assert rec.data_transfer_completed is True

    assert result.summary.planned_scenarios == 1
    assert result.summary.executed_scenarios == 1
    assert result.summary.succeeded_scenarios == 1
    assert result.summary.success_rate == 1.0

    start_events = [e for e in events if e["type"] == "repetition_start"]
    assert len(start_events) == 3

@pytest.mark.asyncio
async def test_coordinator_excludes_catalog_only_profiles():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["aether"],
        profile_ids=["aether_tun"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides={"auth_token": "test-token-123"},
    )

    coordinator = ScenarioCoordinator(catalog=catalog)
    result = await coordinator.execute_plan(plan, execute=True)

    assert len(result.records) == 0
    assert result.summary.planned_scenarios == 1
    assert result.summary.executed_scenarios == 0
    assert result.summary.excluded_scenarios == 1
    detail = result.summary.excluded_scenarios_detail[0]
    assert "No executable adapter" in detail["reason"]

@pytest.mark.asyncio
async def test_coordinator_bounded_concurrency():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline", "vision_flow", "firefox_fp", "safari_fp"],
        target=SAMPLE_TARGET,
        parameter_overrides=VLESS_CONFIG,
    )

    mock_adapter = MockControlledAdapter("xray_vless_tcp_reality", should_succeed=True, delay_s=0.05)
    reg = AdapterRegistry()
    reg.register(mock_adapter)
    bridge = AdapterMigrationBridge(registry=reg)

    coordinator = ScenarioCoordinator(catalog=catalog, migration_bridge=bridge, concurrency=2)
    result = await coordinator.execute_plan(plan, execute=True, repetitions_override=1)

    assert len(result.records) == 4
    assert mock_adapter.max_concurrent_observed <= 2

@pytest.mark.asyncio
async def test_coordinator_failure_policy_continue():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline", "vision_flow"],
        target=SAMPLE_TARGET,
        parameter_overrides=VLESS_CONFIG,
    )

    call_idx = 0
    mock_adapter = MockControlledAdapter("xray_vless_tcp_reality")

    async def dynamic_run(target, config=None):
        nonlocal call_idx
        call_idx += 1
        if call_idx == 1:
            return ProbeResult(
                probe="xray_vless_tcp_reality",
                target=target,
                status=ProbeStatus.FAILED,
                started_at=datetime.now(timezone.utc),
                duration_ms=10.0,
                error="First scenario handshake error",
            )
        return ProbeResult(
            probe="xray_vless_tcp_reality",
            target=target,
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=50.0,
        )

    mock_adapter.run = dynamic_run  # type: ignore[method-assign]
    reg = AdapterRegistry()
    reg.register(mock_adapter)
    bridge = AdapterMigrationBridge(registry=reg)

    coordinator = ScenarioCoordinator(catalog=catalog, migration_bridge=bridge, failure_policy=FailurePolicy.CONTINUE)
    result = await coordinator.execute_plan(plan, execute=True, repetitions_override=1)

    assert len(result.records) == 2
    assert result.records[0].status == "failed"
    assert result.records[1].status == "success"
    assert result.summary.executed_scenarios == 2
    assert result.summary.succeeded_scenarios == 1
    assert result.summary.failed_scenarios == 1

@pytest.mark.asyncio
async def test_coordinator_failure_policy_stop():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline", "vision_flow", "firefox_fp"],
        target=SAMPLE_TARGET,
        parameter_overrides=VLESS_CONFIG,
    )

    mock_adapter = MockControlledAdapter("xray_vless_tcp_reality", should_succeed=False)
    reg = AdapterRegistry()
    reg.register(mock_adapter)
    bridge = AdapterMigrationBridge(registry=reg)

    coordinator = ScenarioCoordinator(catalog=catalog, migration_bridge=bridge, failure_policy=FailurePolicy.STOP_ON_ERROR)
    result = await coordinator.execute_plan(plan, execute=True, repetitions_override=1)

    assert len(result.records) == 1
    assert result.records[0].status == "failed"
    assert result.summary.excluded_scenarios == 2
    assert any("failure_policy=stop" in d["reason"] for d in result.summary.excluded_scenarios_detail)

@pytest.mark.asyncio
async def test_coordinator_backward_compatibility_with_all_four_adapters(monkeypatch):
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()

    plan_vless = generator.generate_explicit(
        engine_ids=["xray", "sing_box"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=VLESS_CONFIG,
    )
    plan_vmess = generator.generate_explicit(
        engine_ids=["xray", "sing_box"],
        profile_ids=["vmess_ws_tls"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=VMESS_CONFIG,
    )

    combined_plan = MatrixPlan(
        plan_id="plan_all_four_adapters",
        generation_mode=GenerationMode.EXPLICIT,
        scenarios=plan_vless.scenarios + plan_vmess.scenarios,
        estimated_count=4,
        actual_count=4,
        deduplicated_count=0,
        invalid_count=0,
    )

    assert len(combined_plan.scenarios) == 4
    expected_adapters = {
        "xray_vless_tcp_reality",
        "singbox_vless_tcp_reality",
        "xray_vmess_ws_tls",
        "singbox_vmess_ws_tls",
    }
    plan_adapters = {s.adapter_id for s in combined_plan.scenarios}
    assert plan_adapters == expected_adapters

    for adapter_id in expected_adapters:
        adapter = bridge.registry.get(adapter_id)
        if adapter:
            monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin"))

    coordinator = ScenarioCoordinator(catalog=catalog, migration_bridge=bridge)
    result = await coordinator.execute_plan(combined_plan, execute=False)

    assert result.is_dry_run is True
    assert result.summary.planned_scenarios == 4
    assert result.summary.excluded_scenarios == 0
