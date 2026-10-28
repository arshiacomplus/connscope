
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from typing import Any
from unittest.mock import MagicMock, patch
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
from connscope.agent import (
    API_VERSION,
    AgentCapabilities,
    ClientConfigurationError,
    RemoteAgentClient,
    RemoteAuthenticationError,
    RemotePolicyError,
    RemoteTimeoutError,
    RemoteUnavailableError,
)
from connscope.core import ProbeResult, ProbeStatus, Target
from connscope.scenarios import (
    GenerationMode,
    MatrixPlan,
    MeasurementNode,
    MeasurementRecord,
    MeasurementWorkload,
    NodeRegistry,
    NodeType,
    Scenario,
    ScenarioCoordinator,
    ScenarioGenerator,
    VerificationStatus,
    aggregate_execution_records,
    create_default_node_registry,
    create_default_protocol_catalog,
    render_execution_summary_table,
    resolve_node_token,
)

SAMPLE_TARGET = Target(host="192.0.2.1", port=443)
SAMPLE_CONFIG = {
    "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
    "server_name": "example.com",
    "short_id": "0123456789abcdef",
}

class TestMeasurementNodeValidation:

    def test_valid_node_creation(self) -> None:
        local_node = MeasurementNode(
            node_id="local-01",
            node_type=NodeType.LOCAL,
            route_context={"isp": "Internal", "region": "lab"},
            operator_labels={"cluster": "test"},
        )
        assert local_node.node_id == "local-01"
        assert local_node.node_type == NodeType.LOCAL
        assert local_node.is_local is True

        remote_node = MeasurementNode(
            node_id="fra-agent-01",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="https://agent.example.com:8443",
            auth_token_ref="FRA_AGENT_TOKEN",
            supported_adapter_ids=["xray_vless_tcp_reality"],
            operator_labels={"site": "frankfurt"},
        )
        assert remote_node.node_id == "fra-agent-01"
        assert remote_node.node_type == NodeType.REMOTE_AGENT
        assert remote_node.is_local is False
        assert remote_node.agent_endpoint == "https://agent.example.com:8443"
        assert remote_node.auth_token_ref == "FRA_AGENT_TOKEN"

    def test_node_id_validation_rules(self) -> None:
        with pytest.raises(ValueError, match="node_id must be a non-empty string"):
            MeasurementNode(node_id="", node_type=NodeType.LOCAL)

        with pytest.raises(ValueError, match="node_id must not contain whitespace"):
            MeasurementNode(node_id="local node 1", node_type=NodeType.LOCAL)

        with pytest.raises(ValueError, match="node_id must contain only alphanumeric"):
            MeasurementNode(node_id="node@berlin!", node_type=NodeType.LOCAL)

    def test_secret_token_protection(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            MeasurementNode(
                node_id="fra-agent",
                node_type=NodeType.REMOTE_AGENT,
                auth_token="raw-secret-token",  # type: ignore
            )

        with pytest.raises(ValueError, match="must not contain embedded userinfo or credentials"):
            MeasurementNode(
                node_id="fra-agent",
                node_type=NodeType.REMOTE_AGENT,
                agent_endpoint="https://user:password@agent.example.com:8443",
            )

    def test_remote_url_scheme_policy(self) -> None:
        with pytest.raises(ValueError, match="Remote agent endpoint must use HTTPS"):
            MeasurementNode(
                node_id="fra-agent",
                node_type=NodeType.REMOTE_AGENT,
                agent_endpoint="http://remote.example.com:8080",
            )

        node = MeasurementNode(
            node_id="local-agent",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="http://127.0.0.1:9090",
        )
        assert node.agent_endpoint == "http://127.0.0.1:9090"

    def test_separation_of_operator_labels_and_grounded_route_context(self) -> None:
        node = MeasurementNode(
            node_id="node-test",
            node_type=NodeType.LOCAL,
            route_context={"outbound_ip": "198.51.100.1", "asn": 64512},
            operator_labels={"assumed_location": "Frankfurt Datacenter", "note": "Unverified"},
        )
        assert node.route_context["asn"] == 64512
        assert node.operator_labels["assumed_location"] == "Frankfurt Datacenter"
        assert "asn" not in node.operator_labels

    def test_node_to_dict_and_from_dict_roundtrip(self) -> None:
        node = MeasurementNode(
            node_id="remote-fra",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="https://agent.example.com:8443",
            auth_token_ref="ENV_FRA_TOKEN",
            supported_adapter_ids=["xray_vless_tcp_reality", "singbox_vless_tcp_reality"],
            allowed_execution_modes=["local_proxy"],
            operator_labels={"site": "fra"},
            route_context={"asn": 13335},
            connection_timeout_s=8.0,
            execution_timeout_s=25.0,
        )
        d = node.to_dict()
        assert "auth_token" not in d
        assert d["auth_token_ref"] == "ENV_FRA_TOKEN"
        assert d["agent_endpoint"] == "https://agent.example.com:8443"

        roundtrip = MeasurementNode.from_dict(d)
        assert roundtrip.node_id == node.node_id
        assert roundtrip.node_type == NodeType.REMOTE_AGENT
        assert roundtrip.agent_endpoint == node.agent_endpoint
        assert roundtrip.supported_adapter_ids == node.supported_adapter_ids
        assert roundtrip.connection_timeout_s == 8.0

class TestNodeRegistryAndTokenResolution:

    def test_node_registry_crud_and_filtering(self) -> None:
        registry = NodeRegistry()
        n1 = MeasurementNode(node_id="node-1", node_type=NodeType.LOCAL)
        n2 = MeasurementNode(
            node_id="node-2",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="https://agent2.example.com",
            supported_adapter_ids=["xray_vless_tcp_reality"],
        )
        registry.register(n1)
        registry.register(n2)

        assert registry.get("node-1") == n1
        assert registry.get("node-2") == n2
        assert registry.get("missing") is None

        assert len(registry.list_all()) == 2
        assert len(registry.list_eligible("xray_vless_tcp_reality")) == 2
        assert len(registry.list_eligible("wireguard_standard")) == 1

    def test_default_node_registry(self) -> None:
        registry = create_default_node_registry()
        assert registry.get("local") is not None
        assert registry.get("local").is_local is True
        assert registry.get("remote-agent-frankfurt") is not None
        assert registry.get("remote-agent-frankfurt").is_local is False

    def test_resolve_node_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        node = MeasurementNode(
            node_id="agent-de",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="https://agent-de.example.com",
            auth_token_ref="CONNSCOPE_DE_TOKEN",
        )

        token = resolve_node_token(node, token_map={"agent-de": "map-token-123"})
        assert token == "map-token-123"

        monkeypatch.setenv("CONNSCOPE_DE_TOKEN", "env-token-456")
        token_env = resolve_node_token(node, token_map=None)
        assert token_env == "env-token-456"

        monkeypatch.delenv("CONNSCOPE_DE_TOKEN", raising=False)
        monkeypatch.setenv("CONNSCOPE_AGENT_TOKEN", "fallback-token-789")
        token_default = resolve_node_token(node)
        assert token_default == "fallback-token-789"

        monkeypatch.delenv("CONNSCOPE_AGENT_TOKEN", raising=False)
        assert resolve_node_token(node) is None

class TestMultiNodeMatrixPlanning:

    def test_generate_explicit_plans_across_multiple_nodes(self) -> None:
        catalog = create_default_protocol_catalog()
        generator = ScenarioGenerator(catalog)

        n1 = MeasurementNode(node_id="local", node_type=NodeType.LOCAL)
        n2 = MeasurementNode(
            node_id="remote-fra",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="https://agent-fra.example.com",
            supported_adapter_ids=["xray_vless_tcp_reality", "singbox_vless_tcp_reality"],
        )

        plan = generator.generate_explicit(
            engine_ids=["xray"],
            profile_ids=["vless_tcp_reality"],
            target=SAMPLE_TARGET,
            nodes=[n1, n2],
        )

        scenarios = plan.scenarios
        assert len(scenarios) > 0
        node_ids = {s.node.node_id for s in scenarios}
        assert node_ids == {"local", "remote-fra"}

        local_scenarios = [s for s in scenarios if s.node.node_id == "local"]
        remote_scenarios = [s for s in scenarios if s.node.node_id == "remote-fra"]
        assert len(local_scenarios) == len(remote_scenarios)
        assert local_scenarios[0].scenario_id != remote_scenarios[0].scenario_id

    def test_remote_node_excludes_layer3_adapters(self) -> None:
        catalog = create_default_protocol_catalog()
        generator = ScenarioGenerator(catalog)

        remote_node = MeasurementNode(
            node_id="remote-fra",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="https://agent-fra.example.com",
            supported_adapter_ids=["wireguard_standard", "xray_vless_tcp_reality"],
        )

        plan_remote = generator.generate_explicit(
            engine_ids=["wireguard"],
            profile_ids=["wireguard_standard"],
            target=SAMPLE_TARGET,
            nodes=[remote_node],
        )
        assert len(plan_remote.scenarios) > 0
        assert all(not s.is_valid for s in plan_remote.scenarios)
        assert all("Layer-3 adapter 'wireguard_standard' is not supported for remote execution" in (s.exclusion_reason or "") for s in plan_remote.scenarios)

    def test_estimate_count_matches_actual_generation(self) -> None:
        catalog = create_default_protocol_catalog()
        generator = ScenarioGenerator(catalog)

        n1 = MeasurementNode(node_id="local", node_type=NodeType.LOCAL)
        n2 = MeasurementNode(
            node_id="remote-fra",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="https://agent-fra.example.com",
            supported_adapter_ids=["xray_vless_tcp_reality"],
        )

        estimated = generator.estimate_count(
            engine_ids=["xray"],
            profile_ids=["vless_tcp_reality"],
            variant_ids=None,
            mode=GenerationMode.EXPLICIT,
            node_count=2,
        )
        plan = generator.generate_explicit(
            engine_ids=["xray"],
            profile_ids=["vless_tcp_reality"],
            target=SAMPLE_TARGET,
            nodes=[n1, n2],
        )
        assert estimated == len(plan.scenarios)

class MockControlledAdapter(EngineAdapter):

    def __init__(self, adapter_id: str) -> None:
        self.metadata = AdapterMetadata(
            adapter_id=adapter_id,
            display_name=f"Mock {adapter_id}",
            engine=EngineType.XRAY,
            protocol=ProtocolType.VLESS,
            transport=TransportType.TCP,
            security=SecurityType.REALITY,
            operating_mode=OperatingMode.CLIENT_ONLY,
            capabilities=frozenset({AdapterCapability.HANDSHAKE, AdapterCapability.DATA_TRANSFER}),
            status=AdapterStatus.REAL_ENGINE_INTEGRATION_TESTED,
            executable=ExecutableRequirement(binary_name="mock_bin"),
        )

        self.call_count = 0

    def validate_config(self, config: dict[str, Any] | None) -> dict[str, Any]:
        return dict(config or {})

    def check_executable(self) -> tuple[bool, str | None]:
        return True, "/usr/bin/mock_bin"

    async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
        self.call_count += 1
        return ProbeResult(
            probe=self.metadata.adapter_id,
            target=target,
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=45.0,
            details={"tunnel_established": True, "data_transfer_completed": True},
        )

class TestScenarioCoordinatorMultiNodeExecution:

    @pytest.mark.asyncio
    async def test_coordinator_preflight_discovery_excludes_unsupported_remote_adapter(self) -> None:
        registry = AdapterRegistry()
        registry.register(MockControlledAdapter("xray_vless_tcp_reality"))

        remote_node = MeasurementNode(
            node_id="remote-fra",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="http://127.0.0.1:9099",
            supported_adapter_ids=["xray_vless_tcp_reality"],
        )

        mock_client = MagicMock(spec=RemoteAgentClient)
        mock_client.get_capabilities.return_value = AgentCapabilities(
            protocol_version=1,
            api_version="1.0",
            supported_operations=["adapter_execute"],
            allowlisted_adapters=["singbox_vless_tcp_reality"],
        )

        coordinator = ScenarioCoordinator(
            adapter_registry=registry,
            client_factory=lambda node, token: mock_client,
            node_tokens={"remote-fra": "token-123"},
        )

        catalog = create_default_protocol_catalog()
        generator = ScenarioGenerator(catalog=catalog)
        plan = generator.generate_explicit(
            engine_ids=["xray"],
            profile_ids=["vless_tcp_reality"],
            variant_ids=["baseline"],
            target=SAMPLE_TARGET,
            node=remote_node,
            workload=MeasurementWorkload(repetitions=2),
            parameter_overrides=SAMPLE_CONFIG,
        )

        result = await coordinator.execute_plan(plan, execute=True)
        assert result.summary.excluded_scenarios == 1
        assert len(result.records) == 0
        assert len(result.summary.excluded_scenarios_detail) == 1
        assert "not allowlisted on remote node" in result.summary.excluded_scenarios_detail[0]["reason"]

    @pytest.mark.asyncio
    async def test_coordinator_remote_execution_success_and_metadata(self) -> None:
        registry = AdapterRegistry()
        mock_adapter = MockControlledAdapter("xray_vless_tcp_reality")
        registry.register(mock_adapter)

        remote_node = MeasurementNode(
            node_id="remote-fra",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="http://127.0.0.1:9099",
            supported_adapter_ids=["xray_vless_tcp_reality"],
            operator_labels={"site": "fra-1"},
            route_context={"asn": 13335},
        )

        mock_client = MagicMock(spec=RemoteAgentClient)
        mock_client.get_capabilities.return_value = AgentCapabilities(
            protocol_version=1,
            api_version="1.0",
            supported_operations=["adapter_execute"],
            allowlisted_adapters=["xray_vless_tcp_reality"],
        )
        mock_client.execute_adapter.return_value = ProbeResult(
            probe="xray_vless_tcp_reality",
            target=SAMPLE_TARGET,
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=38.5,
            details={"tunnel_established": True, "data_transfer_completed": True},
        )

        coordinator = ScenarioCoordinator(
            adapter_registry=registry,
            client_factory=lambda node, token: mock_client,
            node_tokens={"remote-fra": "token-123"},
        )

        catalog = create_default_protocol_catalog()
        generator = ScenarioGenerator(catalog=catalog)
        plan = generator.generate_explicit(
            engine_ids=["xray"],
            profile_ids=["vless_tcp_reality"],
            variant_ids=["baseline"],
            target=SAMPLE_TARGET,
            node=remote_node,
            workload=MeasurementWorkload(repetitions=3),
            parameter_overrides=SAMPLE_CONFIG,
        )

        result = await coordinator.execute_plan(plan, execute=True)
        assert result.summary.succeeded_scenarios == 1
        assert len(result.records) == 3

        for i, rec in enumerate(result.records):
            assert rec.node_id == "remote-fra"
            assert rec.repetition_index == i
            assert rec.status == "success"
            assert rec.duration_ms == 38.5
            assert rec.route_context == {"asn": 13335}
            assert rec.operator_labels == {"site": "fra-1"}

        assert mock_adapter.call_count == 0

    @pytest.mark.asyncio
    async def test_coordinator_remote_failures_have_zero_local_fallback(self) -> None:
        registry = AdapterRegistry()
        mock_adapter = MockControlledAdapter("xray_vless_tcp_reality")
        registry.register(mock_adapter)

        remote_node = MeasurementNode(
            node_id="remote-fra",
            node_type=NodeType.REMOTE_AGENT,
            agent_endpoint="http://127.0.0.1:9099",
            supported_adapter_ids=["xray_vless_tcp_reality"],
        )

        mock_client = MagicMock(spec=RemoteAgentClient)
        mock_client.get_capabilities.return_value = AgentCapabilities(
            protocol_version=1,
            api_version="1.0",
            supported_operations=["adapter_execute"],
            allowlisted_adapters=["xray_vless_tcp_reality"],
        )

        mock_client.execute_adapter.side_effect = RemoteUnavailableError(
            "Agent unavailable", status_code=503, error_code="service_unavailable"
        )

        coordinator = ScenarioCoordinator(
            adapter_registry=registry,
            client_factory=lambda node, token: mock_client,
            node_tokens={"remote-fra": "token-123"},
        )

        catalog = create_default_protocol_catalog()
        generator = ScenarioGenerator(catalog=catalog)
        plan = generator.generate_explicit(
            engine_ids=["xray"],
            profile_ids=["vless_tcp_reality"],
            variant_ids=["baseline"],
            target=SAMPLE_TARGET,
            node=remote_node,
            workload=MeasurementWorkload(repetitions=1),
            parameter_overrides=SAMPLE_CONFIG,
        )

        result = await coordinator.execute_plan(plan, execute=True)
        assert result.summary.failed_scenarios == 1
        assert len(result.records) == 1
        rec = result.records[0]
        assert rec.status == "failed"
        assert rec.failure_stage == "node_unavailable"

        assert mock_adapter.call_count == 0

class TestMultiNodeAggregationAndFormatting:

    def test_cross_node_comparability_notes(self) -> None:
        now_str = "2026-10-23T12:00:00Z"
        r_local = MeasurementRecord(
            scenario_id="scn_local",
            repetition_index=0,
            engine_id="xray",
            profile_id="vless_tcp_reality",
            variant_id="baseline",
            adapter_id="xray_vless_tcp_reality",
            node_id="local",
            target={"host": "192.0.2.1", "port": 443},
            workload={"workload_type": "http_get_204", "repetitions": 1},
            started_at=now_str,
            ended_at=now_str,
            duration_ms=25.0,
            status="success",
            metrics={"total_ms": 25.0},
            tunnel_established=True,
            data_transfer_completed=True,
        )
        r_remote = MeasurementRecord(
            scenario_id="scn_remote",
            repetition_index=0,
            engine_id="xray",
            profile_id="vless_tcp_reality",
            variant_id="baseline",
            adapter_id="xray_vless_tcp_reality",
            node_id="remote-fra",
            target={"host": "192.0.2.1", "port": 443},
            workload={"workload_type": "http_get_204", "repetitions": 1},
            started_at=now_str,
            ended_at=now_str,
            duration_ms=45.0,
            status="success",
            metrics={"total_ms": 45.0},
            tunnel_established=True,
            data_transfer_completed=True,
        )

        summary = aggregate_execution_records(
            records=[r_local, r_remote],
            planned_count=2,
        )
        assert summary.planned_scenarios == 2
        assert len(summary.per_scenario_summaries) == 2

        assert any("under identical target and workload" in note for note in summary.workload_comparability_notes)

    def test_render_table_includes_node_column(self) -> None:
        now_str = "2026-10-23T12:00:00Z"
        rec = MeasurementRecord(
            scenario_id="scn_1",
            repetition_index=0,
            engine_id="xray",
            profile_id="vless_tcp_reality",
            variant_id="baseline",
            adapter_id="xray_vless_tcp_reality",
            node_id="remote-fra",
            target={"host": "192.0.2.1", "port": 443},
            workload={"workload_type": "http_get_204", "repetitions": 1},
            started_at=now_str,
            ended_at=now_str,
            duration_ms=45.0,
            status="success",
            metrics={"total_ms": 45.0},
            tunnel_established=True,
            data_transfer_completed=True,
        )
        summary = aggregate_execution_records(records=[rec], planned_count=1)
        table_output = render_execution_summary_table(summary)

        assert "NODE" in table_output
        assert "remote-fra" in table_output
