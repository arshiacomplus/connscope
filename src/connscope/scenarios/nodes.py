
from __future__ import annotations

import os
from typing import Callable, Sequence

from .models import MeasurementNode, NodeType, VerificationStatus

class NodeRegistry:

    def __init__(self, nodes: Sequence[MeasurementNode] | None = None) -> None:
        self._nodes: dict[str, MeasurementNode] = {}
        if nodes:
            for node in nodes:
                self.register(node)

    def register(self, node: MeasurementNode) -> None:
        if not isinstance(node, MeasurementNode):
            raise TypeError(f"Expected MeasurementNode, got {type(node).__name__}")
        if node.node_id in self._nodes:
            raise ValueError(f"MeasurementNode '{node.node_id}' is already registered")
        self._nodes[node.node_id] = node

    def get(self, node_id: str) -> MeasurementNode | None:
        return self._nodes.get(node_id)

    def list(self) -> tuple[MeasurementNode, ...]:
        return tuple(self._nodes.values())

    def list_all(self) -> tuple[MeasurementNode, ...]:
        return self.list()

    def get_nodes(self, node_ids: Sequence[str] | None = None) -> tuple[MeasurementNode, ...]:
        if node_ids is None:
            return self.list()
        selected: list[MeasurementNode] = []
        for nid in node_ids:
            node = self.get(nid)
            if node is None:
                raise KeyError(f"MeasurementNode '{nid}' not found in registry")
            selected.append(node)
        return tuple(selected)

    def get_eligible_nodes(
        self,
        adapter_id: str | None = None,
        execution_mode: str | None = None,
    ) -> tuple[MeasurementNode, ...]:
        eligible: list[MeasurementNode] = []
        for node in self._nodes.values():
            if adapter_id and node.supported_adapter_ids and adapter_id not in node.supported_adapter_ids:
                continue
            if execution_mode and node.allowed_execution_modes and execution_mode not in node.allowed_execution_modes:
                continue
            eligible.append(node)
        return tuple(eligible)

    def list_eligible(
        self,
        adapter_id: str | None = None,
        execution_mode: str | None = None,
    ) -> tuple[MeasurementNode, ...]:
        return self.get_eligible_nodes(adapter_id=adapter_id, execution_mode=execution_mode)

def resolve_node_token(
    node: MeasurementNode,
    token_map: dict[str, str] | None = None,
    resolver: Callable[[MeasurementNode], str | None] | None = None,
) -> str | None:
    if node.node_type == NodeType.LOCAL.value:
        return None

    if resolver is not None:
        token = resolver(node)
        if token:
            return token

    if token_map and node.node_id in token_map:
        return token_map[node.node_id]

    if node.auth_token_ref and node.auth_token_ref in os.environ:
        val = os.environ[node.auth_token_ref]
        if val:
            return val

    return os.environ.get("CONNSCOPE_AGENT_TOKEN")

def create_default_node_registry() -> NodeRegistry:
    local_node = MeasurementNode(
        node_id="local",
        name="Local Measurement Node",
        node_type=NodeType.LOCAL.value,
        supported_adapter_ids=(
            "xray_vless_tcp_reality",
            "singbox_vless_tcp_reality",
            "xray_vmess_ws_tls",
            "singbox_vmess_ws_tls",
            "wireguard_standard",
            "amnezia_wg_standard",
            "openvpn_standard",
        ),
        allowed_execution_modes=("local_proxy", "network_interface"),
        route_context={"interface": "lo", "type": "loopback"},
        evidence_status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
        description="Local execution environment",
    )
    remote_frankfurt = MeasurementNode(
        node_id="remote-agent-frankfurt",
        name="Frankfurt Edge Node",
        node_type=NodeType.REMOTE_AGENT.value,
        endpoint_url="https://agent-de-01.connscope.net:8443",
        auth_token_ref="CONNSCOPE_AGENT_TOKEN_FRANKFURT",
        supported_adapter_ids=(
            "xray_vless_tcp_reality",
            "singbox_vless_tcp_reality",
            "xray_vmess_ws_tls",
            "singbox_vmess_ws_tls",
        ),
        allowed_execution_modes=("local_proxy",),
        operator_labels={"country": "DE", "city": "Frankfurt", "isp": "Sample ISP"},
        route_context={"asn": 3320, "country": "DE", "city": "Frankfurt", "interface": "eth0"},
        evidence_status=VerificationStatus.CATALOGUED,
        description="Sample remote measurement agent vantage point",
    )
    return NodeRegistry(nodes=(local_node, remote_frankfurt))
