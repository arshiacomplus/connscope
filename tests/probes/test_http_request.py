import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from connscope.core import Target, ProbeStatus
from connscope.probes.http_request import HttpRequestProbe

@patch("asyncio.open_connection")
async def test_http_request_success_mocked(mock_open_connection):
    mock_reader = MagicMock()
    mock_reader.readline = AsyncMock()
    mock_reader.readline.return_value = b"HTTP/1.1 200 OK\r\n"
    
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.write = MagicMock()
    
    mock_open_connection.return_value = (mock_reader, mock_writer)
    
    probe = HttpRequestProbe()
    result = await probe.run(Target(host="example.com"))
    
    assert result.status == ProbeStatus.SUCCESS
    assert "connect_tls_ms" in result.metrics
    assert "first_byte_ms" in result.metrics
    assert "total_ms" in result.metrics
    
    assert result.details["status_code"] == 200
    assert result.details["protocol"] == "HTTP/1.1"
    
    mock_writer.write.assert_called_once()
    assert b"GET / HTTP/1.1" in mock_writer.write.call_args[0][0]

@patch("asyncio.open_connection")
async def test_http_request_timeout_mocked(mock_open_connection):
    async def slow_connect(*args, **kwargs):
        await asyncio.sleep(2.0)
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        return mock_reader, mock_writer
        
    mock_open_connection.side_effect = slow_connect
    
    probe = HttpRequestProbe()
    result = await probe.run(
        Target(host="example.com"),
        config={"timeout_s": 0.01}
    )
    
    assert result.status == ProbeStatus.TIMEOUT

@patch("asyncio.open_connection")
async def test_http_request_failed_mocked(mock_open_connection):
    mock_open_connection.side_effect = ConnectionRefusedError("Connection refused")
    
    probe = HttpRequestProbe()
    result = await probe.run(Target(host="example.com"))
    
    assert result.status == ProbeStatus.FAILED
    assert "Connection refused" in result.error

@patch("asyncio.open_connection")
async def test_http_request_host_header_non_default_port_and_ipv6(mock_open_connection):
    mock_reader = MagicMock()
    mock_reader.readline = AsyncMock()
    mock_reader.readline.return_value = b"HTTP/1.1 200 OK\r\n"

    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.write = MagicMock()

    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = HttpRequestProbe()
    # Test 1: Non-default port for TLS
    await probe.run(Target(host="example.com", port=8443), config={"use_tls": True})
    assert b"Host: example.com:8443\r\n" in mock_writer.write.call_args[0][0]

    # Test 2: IPv6 with non-default port
    await probe.run(Target(host="2001:db8::1", port=8080), config={"use_tls": False})
    assert b"Host: [2001:db8::1]:8080\r\n" in mock_writer.write.call_args[0][0]

    # Test 3: Default port omitted in Host header
    await probe.run(Target(host="example.com", port=443), config={"use_tls": True})
    assert b"Host: example.com\r\n" in mock_writer.write.call_args[0][0]

@pytest.mark.network
async def test_http_request_network_real():
    probe = HttpRequestProbe()
    result = await probe.run(Target(host="example.com"))
    
    assert result.status == ProbeStatus.SUCCESS
    assert result.details["status_code"] in (200, 301, 302, 404)
