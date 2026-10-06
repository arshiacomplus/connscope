import asyncio
import pytest
from unittest.mock import patch, AsyncMock

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
    # Start a local TCP server
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
