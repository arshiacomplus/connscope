
import asyncio
import os
from pathlib import Path
import pytest

from connscope.adapters import (
    FailureStage,
    HostNetworkSnapshot,
    LinuxNetnsIsolationBackend,
    LinuxOriginNetnsIsolationBackend,
    MockLayer3IsolationBackend,
    WireGuardStandardAdapter,
)
from connscope.core import ProbeStatus, Target
from connscope.scenarios.models import MeasurementNode, MeasurementWorkload, Scenario, VerificationStatus
from connscope.scenarios.records import MeasurementRecord

SAMPLE_TARGET = Target(host="198.51.100.1", port=51820)
CLIENT_PRIVKEY = "YAmZ1y5v+7vX+Z/Qf6s5k1y5v+7vX+Z/Qf6s5k1y5v8="
PEER_PUBKEY = "8n5WzXghUgGfcEzTt+vGU5ZXAij+pc5rVni0dyJ0xhk="
SAMPLE_CONFIG = {
    "private_key": CLIENT_PRIVKEY,
    "public_key": PEER_PUBKEY,
    "endpoint": "198.51.100.1:51820",
    "mtu": 1420,
    "persistent_keepalive": 25,
}

def test_host_network_snapshot_capture():
    snap = HostNetworkSnapshot.capture()

    assert isinstance(snap.interfaces, tuple)
    assert isinstance(snap.routes, str)
    assert snap.ip_forwarding is None or isinstance(snap.ip_forwarding, str)
    assert isinstance(snap.wireguard_interfaces, tuple)

def test_host_network_snapshot_assert_unchanged_passes():
    before = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=(),
    )
    after = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=(),
    )
    before.assert_unchanged(after)

def test_host_network_snapshot_detects_leaked_interface():
    before = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=(),
    )
    after = HostNetworkSnapshot(
        interfaces=("eth0", "lo", "wg-leaked0"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=("wg-leaked0",),
    )
    with pytest.raises(AssertionError, match="Host network leaked new interfaces"):
        before.assert_unchanged(after)

def test_host_network_snapshot_detects_missing_interface():
    before = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=(),
    )
    after = HostNetworkSnapshot(
        interfaces=("lo",),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=(),
    )
    with pytest.raises(AssertionError, match="Host network lost existing interfaces"):
        before.assert_unchanged(after)

def test_host_network_snapshot_detects_leaked_wireguard_device():
    before = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=(),
    )
    after = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=("wg-cs-abc",),
    )
    with pytest.raises(AssertionError, match="Host leaked WireGuard interface"):
        before.assert_unchanged(after)

def test_host_network_snapshot_detects_modified_routes():
    before = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=(),
    )
    after = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 10.0.0.1 dev wg0",
        ip_forwarding="0",
        wireguard_interfaces=(),
    )
    with pytest.raises(AssertionError, match="Host routing table was modified"):
        before.assert_unchanged(after)

def test_host_network_snapshot_detects_modified_forwarding():
    before = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="0",
        wireguard_interfaces=(),
    )
    after = HostNetworkSnapshot(
        interfaces=("eth0", "lo"),
        routes="default via 192.168.1.1 dev eth0",
        ip_forwarding="1",
        wireguard_interfaces=(),
    )
    with pytest.raises(AssertionError, match="Host IP forwarding changed"):
        before.assert_unchanged(after)

@pytest.mark.asyncio
async def test_mock_origin_netns_full_lifecycle(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(origin_namespace_mode=True)
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    snap_before = HostNetworkSnapshot.capture()

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    snap_after = HostNetworkSnapshot.capture()
    snap_before.assert_unchanged(snap_after)

    assert result.status == ProbeStatus.SUCCESS
    assert result.error is None
    assert result.duration_ms > 0.0

    details = result.details
    assert details["execution_mode"] == "network_interface"
    assert details["isolation_strategy"] == "origin_netns"
    assert details["socket_in_origin_namespace"] is True
    assert "via 192.168.1.1" in details["origin_endpoint_route"]
    assert details["interface_established"] is True
    assert details["peer_handshake_completed"] is True
    assert details["tunnel_established"] is True
    assert details["traffic_traversed"] is True
    assert details["data_transfer_completed"] is True
    assert details["cleanup_completed"] is True

    assert mock_backend.created_in_origin is True
    assert mock_backend.moved_to_netns is True
    assert mock_backend.events == ["prepare", "setup_interface", "execute_workload", "teardown", "cleaned_up_netns_interface"]

def test_origin_netns_backend_selection(monkeypatch):
    adapter = WireGuardStandardAdapter()

    monkeypatch.delenv("CONNSCOPE_WIREGUARD_ORIGIN_NETNS", raising=False)
    backend_default = adapter.create_default_isolation_backend()
    assert isinstance(backend_default, LinuxNetnsIsolationBackend)
    assert not isinstance(backend_default, LinuxOriginNetnsIsolationBackend)

    monkeypatch.setenv("CONNSCOPE_WIREGUARD_ORIGIN_NETNS", "1")
    backend_origin = adapter.create_default_isolation_backend()
    assert isinstance(backend_origin, LinuxOriginNetnsIsolationBackend)

@pytest.mark.asyncio
async def test_mock_origin_netns_route_check_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        origin_namespace_mode=True,
        should_pass_origin_route=False,
    )
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.INTERFACE_SETUP.value
    assert "has no route in origin namespace" in str(result.error)
    assert mock_backend.teardown_called is True
    assert mock_backend.created_in_origin is False

@pytest.mark.asyncio
async def test_mock_origin_netns_link_add_origin_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        origin_namespace_mode=True,
        should_pass_link_add_origin=False,
    )
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.INTERFACE_SETUP.value
    assert "Failed to create WireGuard interface" in str(result.error)
    assert mock_backend.teardown_called is True
    assert mock_backend.created_in_origin is False

@pytest.mark.asyncio
async def test_mock_origin_netns_move_netns_failure_cleans_up_host_interface(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        origin_namespace_mode=True,
        should_pass_move_netns=False,
    )
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.INTERFACE_SETUP.value
    assert "Failed to move WireGuard interface" in str(result.error)

    assert mock_backend.teardown_called is True
    assert "cleaned_up_origin_interface" in mock_backend.events

@pytest.mark.asyncio
async def test_origin_netns_cancellation_shielded_teardown(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(origin_namespace_mode=True)

    async def slow_workload(*args, **kwargs):
        await asyncio.sleep(5.0)

    mock_backend.execute_workload = slow_workload  # type: ignore[method-assign]
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    task = asyncio.create_task(adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG))
    await asyncio.sleep(0.05)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert mock_backend.teardown_called is True
    assert "cleaned_up_netns_interface" in mock_backend.events

def test_linux_origin_netns_requires_both_opt_in_flags(monkeypatch):
    backend = LinuxOriginNetnsIsolationBackend()

    monkeypatch.delenv("CONNSCOPE_WIREGUARD_ORIGIN_NETNS", raising=False)
    monkeypatch.delenv("CONNSCOPE_ENABLE_REAL_WIREGUARD", raising=False)
    monkeypatch.delenv("CONNSCOPE_TEST_REAL_WIREGUARD", raising=False)
    ok, reason = backend.check_capabilities()
    assert ok is False
    assert "CONNSCOPE_WIREGUARD_ORIGIN_NETNS=1" in reason

    monkeypatch.setenv("CONNSCOPE_WIREGUARD_ORIGIN_NETNS", "1")
    ok, reason = backend.check_capabilities()
    assert ok is False
    assert "CONNSCOPE_ENABLE_REAL_WIREGUARD=1" in reason

def test_linux_origin_netns_requires_root(monkeypatch):
    backend = LinuxOriginNetnsIsolationBackend()
    monkeypatch.setenv("CONNSCOPE_WIREGUARD_ORIGIN_NETNS", "1")
    monkeypatch.setenv("CONNSCOPE_ENABLE_REAL_WIREGUARD", "1")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    ok, reason = backend.check_capabilities()
    assert ok is False
    assert "root / CAP_NET_ADMIN" in reason

@pytest.mark.asyncio
async def test_origin_netns_route_context_in_measurement_record(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(origin_namespace_mode=True)
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    scenario = Scenario(
        scenario_id="wireguard-udp-direct-baseline",
        engine_id="wireguard",
        profile_id="wireguard-udp-direct",
        variant_id="baseline",
        node=MeasurementNode(
            node_id="local-client",
            name="Local Client",
            route_context={"client_platform": "linux", "gateway": "192.168.1.1"},
        ),
        target=SAMPLE_TARGET,
        workload=MeasurementWorkload(test_url="http://cp.cloudflare.com/generate_204"),
        resolved_config=SAMPLE_CONFIG,
        status=VerificationStatus.CATALOGUED,
        adapter_id="wireguard_standard",
    )

    record = MeasurementRecord.from_probe_result(scenario, result, repetition_index=1)

    assert record.route_context["isolation_strategy"] == "origin_netns"
    assert "via 192.168.1.1" in record.route_context["origin_endpoint_route"]
    assert record.route_context["client_platform"] == "linux"
    assert record.execution_mode == "network_interface"
    assert record.tunnel_established is True
    assert record.data_transfer_completed is True

    record_dict = record.to_dict()
    assert record_dict["route_context"]["isolation_strategy"] == "origin_netns"
    assert "via 192.168.1.1" in record_dict["route_context"]["origin_endpoint_route"]

@pytest.mark.skipif(
    not (
        os.environ.get("CONNSCOPE_WIREGUARD_ORIGIN_NETNS") == "1"
        and (
            os.environ.get("CONNSCOPE_ENABLE_REAL_WIREGUARD") == "1"
            or os.environ.get("CONNSCOPE_TEST_REAL_WIREGUARD") == "1"
        )
        and os.geteuid() == 0
    ),
    reason="Requires CONNSCOPE_WIREGUARD_ORIGIN_NETNS=1, CONNSCOPE_TEST_REAL_WIREGUARD=1, and root privileges",
)
@pytest.mark.asyncio
async def test_opt_in_real_wireguard_origin_netns_execution():
    snap_before = HostNetworkSnapshot.capture()

    backend = LinuxOriginNetnsIsolationBackend()
    adapter = WireGuardStandardAdapter(isolation_backend=backend)

    real_cfg = {
        "private_key": os.environ.get("CONNSCOPE_TEST_WIREGUARD_PRIVKEY", CLIENT_PRIVKEY),
        "public_key": os.environ.get("CONNSCOPE_TEST_WIREGUARD_PUBKEY", PEER_PUBKEY),
        "endpoint": os.environ.get("CONNSCOPE_TEST_WIREGUARD_ENDPOINT", "198.51.100.1:51820"),
        "address": os.environ.get("CONNSCOPE_TEST_WIREGUARD_ADDRESS", "10.0.0.2/32"),
        "mtu": 1420,
        "timeout_s": 5.0,
    }

    try:
        result = await adapter.run(SAMPLE_TARGET, config=real_cfg)
        assert result.details["execution_mode"] == "network_interface"
        assert result.details["isolation_strategy"] == "origin_netns"
    finally:
        snap_after = HostNetworkSnapshot.capture()
        snap_before.assert_unchanged(snap_after)
