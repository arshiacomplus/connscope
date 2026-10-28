
import os
from pathlib import Path
import pytest

from connscope.adapters import (
    EngineType,
    FailureStage,
    LinuxNetnsIsolationBackend,
    MockLayer3IsolationBackend,
    ProtocolType,
    SecurityType,
    TransportType,
    TunnelExecutionMode,
    WireGuardStandardAdapter,
)
from connscope.core import ProbeStatus, Target

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

def test_wireguard_adapter_metadata_and_execution_mode():
    adapter = WireGuardStandardAdapter()
    meta = adapter.metadata

    assert meta.adapter_id == "wireguard_standard"
    assert meta.engine == EngineType.WIREGUARD
    assert meta.protocol == ProtocolType.WIREGUARD
    assert meta.transport == TransportType.UDP
    assert meta.security == SecurityType.NONE
    assert meta.execution_mode == TunnelExecutionMode.NETWORK_INTERFACE

    d = meta.to_dict()
    assert d["execution_mode"] == "network_interface"
    assert d["engine"] == "wireguard"
    assert d["protocol"] == "wireguard"

def test_wireguard_adapter_executable_and_capability_check(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        should_pass_capabilities=False,
        capability_error="Missing CAP_NET_ADMIN privilege",
    )
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)

    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (False, "Executable 'wg' not found"))
    cap_ok, cap_err = adapter.check_capabilities()
    assert cap_ok is False
    assert "CAP_NET_ADMIN" in cap_err

@pytest.mark.asyncio
async def test_wireguard_mock_full_successful_lifecycle(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        should_pass_capabilities=True,
        should_pass_setup=True,
        should_handshake=True,
        should_traverse_traffic=True,
        should_complete_data_transfer=True,
        http_status=204,
    )
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.SUCCESS
    assert result.error is None
    assert result.duration_ms > 0.0

    details = result.details
    assert details["execution_mode"] == "network_interface"
    assert details["interface_established"] is True
    assert details["peer_handshake_completed"] is True
    assert details["tunnel_established"] is True
    assert details["traffic_traversed"] is True
    assert details["data_transfer_completed"] is True
    assert details["cleanup_completed"] is True

    assert "interface_setup_ms" in result.metrics
    assert "handshake_ms" in result.metrics
    assert "data_transfer_ms" in result.metrics
    assert "rx_delta" in result.metrics
    assert "tx_delta" in result.metrics

    assert mock_backend.prepare_called is True
    assert mock_backend.setup_called is True
    assert mock_backend.workload_called is True
    assert mock_backend.teardown_called is True
    assert mock_backend.events == ["prepare", "setup_interface", "execute_workload", "teardown"]

@pytest.mark.asyncio
async def test_wireguard_interface_setup_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        should_pass_setup=False,
        setup_error="Kernel wireguard module not loaded",
    )
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.INTERFACE_SETUP.value
    assert result.details["interface_established"] is False
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False
    assert "Kernel wireguard module not loaded" in str(result.error)

    assert mock_backend.teardown_called is True

@pytest.mark.asyncio
async def test_wireguard_missing_peer_handshake(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        should_pass_setup=True,
        should_handshake=False,
    )
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.details["interface_established"] is True
    assert result.details["peer_handshake_completed"] is False
    assert result.details["tunnel_established"] is False
    assert result.details["data_transfer_completed"] is False
    assert "No WireGuard peer handshake received" in str(result.error)

    assert mock_backend.teardown_called is True

@pytest.mark.asyncio
async def test_wireguard_traffic_traversal_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        should_pass_setup=True,
        should_handshake=True,
        should_traverse_traffic=False,
    )
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.TRAFFIC_TRAVERSAL.value
    assert result.details["interface_established"] is True
    assert result.details["peer_handshake_completed"] is True
    assert result.details["tunnel_established"] is True
    assert result.details["traffic_traversed"] is False
    assert result.details["data_transfer_completed"] is False

    assert mock_backend.teardown_called is True

@pytest.mark.asyncio
async def test_wireguard_data_transfer_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        should_pass_setup=True,
        should_handshake=True,
        should_traverse_traffic=True,
        should_complete_data_transfer=False,
        http_status=502,
        data_transfer_error="HTTP 502 Bad Gateway through tunnel",
    )
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.DATA_TRANSFER.value
    assert result.details["interface_established"] is True
    assert result.details["peer_handshake_completed"] is True
    assert result.details["tunnel_established"] is True
    assert result.details["traffic_traversed"] is True
    assert result.details["data_transfer_completed"] is False
    assert "HTTP 502" in str(result.error)

    assert mock_backend.teardown_called is True

def test_linux_netns_backend_strict_safety_and_opt_in():
    backend = LinuxNetnsIsolationBackend()

    if "CONNSCOPE_ENABLE_REAL_WIREGUARD" in os.environ:
        del os.environ["CONNSCOPE_ENABLE_REAL_WIREGUARD"]
    if "CONNSCOPE_TEST_REAL_WIREGUARD" in os.environ:
        del os.environ["CONNSCOPE_TEST_REAL_WIREGUARD"]

    ok, reason = backend.check_capabilities()
    assert ok is False
    assert "explicit opt-in" in reason.lower()

@pytest.mark.asyncio
async def test_wireguard_interface_addressing_mtu_and_routes_explicitly_applied(monkeypatch):
    mock_backend = MockLayer3IsolationBackend()
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    custom_cfg = {
        **SAMPLE_CONFIG,
        "address": "10.0.0.5/24, fd00::2/64",
        "mtu": 1280,
        "allowed_ips": "0.0.0.0/0, ::/0, 192.168.1.0/24",
    }
    result = await adapter.run(SAMPLE_TARGET, config=custom_cfg)

    assert result.status == ProbeStatus.SUCCESS

    assert mock_backend.applied_mtu == 1280

    assert mock_backend.assigned_addresses == ["10.0.0.5/24", "fd00::2/64"]

    assert mock_backend.configured_routes == ["0.0.0.0/0", "::/0", "192.168.1.0/24"]

    assert mock_backend.wg_setconf_content is not None
    assert "Address =" not in mock_backend.wg_setconf_content
    assert "MTU =" not in mock_backend.wg_setconf_content
    assert "DNS =" not in mock_backend.wg_setconf_content

@pytest.mark.asyncio
async def test_wireguard_rejection_if_wg_setconf_receives_address_or_mtu(tmp_path):
    mock_backend = MockLayer3IsolationBackend()
    invalid_file = tmp_path / "invalid_wg0.conf"
    invalid_file.write_text("[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\nMTU = 1420\n")

    ok, err = await mock_backend.setup_interface(invalid_file, "wg0", {}, {})
    assert ok is False
    assert "Address/MTU/DNS must not be present" in err

@pytest.mark.asyncio
async def test_wireguard_cleanup_on_task_cancellation(monkeypatch):
    import asyncio

    mock_backend = MockLayer3IsolationBackend(handshake_delay_ms=2000.0)

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

@pytest.mark.asyncio
async def test_wireguard_cleanup_on_prepare_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend()

    async def fail_prepare():
        raise RuntimeError("Failed netns creation")

    mock_backend.prepare = fail_prepare  # type: ignore[method-assign]
    adapter = WireGuardStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/wg"))

    with pytest.raises(RuntimeError, match="Failed netns creation"):
        await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

