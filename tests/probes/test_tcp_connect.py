import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from connscope.core import Target, ProbeStatus
from connscope.probes.tcp_connect import TcpConnectProbe

async def test_tcp_connect_missing_port():
    probe = TcpConnectProbe()
    result = await probe.run(Target(host="example.com"))
    
    assert result.status == ProbeStatus.FAILED
    assert "port is required" in result.error

@patch("asyncio.open_connection")
async def test_tcp_connect_success_mocked(mock_open_connection):
    from unittest.mock import MagicMock
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)
    
    probe = TcpConnectProbe()
    result = await probe.run(Target(host="example.com", port=443))
    
    assert result.status == ProbeStatus.SUCCESS
    assert "connect_ms" in result.metrics
    assert result.duration_ms >= 0
    assert result.error is None
    
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@patch("asyncio.open_connection")
async def test_tcp_connect_timeout_mocked(mock_open_connection):
    async def slow_connect(*args, **kwargs):
        await asyncio.sleep(2.0)
        return MagicMock(), MagicMock()
        
    mock_open_connection.side_effect = slow_connect
    
    probe = TcpConnectProbe()
    result = await probe.run(
        Target(host="example.com", port=443),
        config={"timeout_s": 0.01}
    )
    
    assert result.status == ProbeStatus.TIMEOUT
    assert "timed out" in result.error
    assert result.duration_ms >= 0

@patch("asyncio.open_connection")
async def test_tcp_connect_refused_mocked(mock_open_connection):
    mock_open_connection.side_effect = ConnectionRefusedError("Connection refused")
    
    probe = TcpConnectProbe()
    result = await probe.run(Target(host="example.com", port=443))
    
    assert result.status == ProbeStatus.FAILED
    assert "Connection refused" in result.error
    assert result.duration_ms >= 0

async def test_tcp_connect_integration_local_server():
    async def handle_client(reader, writer):
        writer.close()
        await writer.wait_closed()
        
    server = await asyncio.start_server(handle_client, '127.0.0.1', 0)
    
    addr = server.sockets[0].getsockname()
    port = addr[1]
    
    probe = TcpConnectProbe()
    
    async with server:
        result = await probe.run(Target(host="127.0.0.1", port=port))
        assert result.status == ProbeStatus.SUCCESS
        assert "connect_ms" in result.metrics

@pytest.mark.network
async def test_tcp_connect_network_real():
    probe = TcpConnectProbe()
    result = await probe.run(Target(host="example.com", port=443))
    
    assert result.status == ProbeStatus.SUCCESS
    assert "connect_ms" in result.metrics

@patch("asyncio.open_connection")
async def test_tcp_connect_with_pinned_ipv4(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TcpConnectProbe()
    target = Target(host="example.com", port=80)
    result = await probe.run(target, config={"connect_ip": "93.184.216.34"})

    assert result.status == ProbeStatus.SUCCESS
    mock_open_connection.assert_called_once_with("93.184.216.34", 80)
    assert result.target.host == "example.com"
    assert result.details["connect_ip"] == "93.184.216.34"

@patch("asyncio.open_connection")
async def test_tcp_connect_with_pinned_ipv6_bracketed(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TcpConnectProbe()
    target = Target(host="example.com", port=443)
    result = await probe.run(
        target,
        config={"connect_ip": "[2606:2800:220:1:248:1893:25c8:1946]"},
    )

    assert result.status == ProbeStatus.SUCCESS
    mock_open_connection.assert_called_once_with("2606:2800:220:1:248:1893:25c8:1946", 443)
    assert result.target.host == "example.com"
    assert result.details["connect_ip"] == "2606:2800:220:1:248:1893:25c8:1946"

@patch("asyncio.open_connection")
async def test_tcp_connect_with_pinned_ipv4_mapped_ipv6(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TcpConnectProbe()
    target = Target(host="example.com", port=80)
    result = await probe.run(target, config={"connect_ip": "::ffff:93.184.216.34"})

    assert result.status == ProbeStatus.SUCCESS
    mock_open_connection.assert_called_once_with("93.184.216.34", 80)
    assert result.details["connect_ip"] == "93.184.216.34"

@patch("asyncio.open_connection")
async def test_tcp_connect_invalid_connect_ip_rejected(mock_open_connection):
    probe = TcpConnectProbe()
    target = Target(host="example.com", port=80)

    result = await probe.run(target, config={"connect_ip": "evil.com"})
    assert result.status == ProbeStatus.FAILED
    assert "not a valid IPv4 or IPv6 literal" in result.error
    mock_open_connection.assert_not_called()

    result2 = await probe.run(target, config={"connect_ip": 12345})
    assert result2.status == ProbeStatus.FAILED
    assert "Invalid connect_ip" in result2.error
    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tcp_connect_pinned_ip_error_no_fallback(mock_open_connection):
    mock_open_connection.side_effect = ConnectionRefusedError("Connection refused")

    probe = TcpConnectProbe()
    target = Target(host="example.com", port=80)
    result = await probe.run(target, config={"connect_ip": "93.184.216.34"})

    assert result.status == ProbeStatus.FAILED
    assert "Connection refused" in result.error
    mock_open_connection.assert_called_once_with("93.184.216.34", 80)
    assert result.target.host == "example.com"
    assert result.details["connect_ip"] == "93.184.216.34"
