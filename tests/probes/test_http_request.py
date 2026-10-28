import asyncio
import ssl
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
    await probe.run(Target(host="example.com", port=8443), config={"use_tls": True})
    assert b"Host: example.com:8443\r\n" in mock_writer.write.call_args[0][0]

    await probe.run(Target(host="2001:db8::1", port=8080), config={"use_tls": False})
    assert b"Host: [2001:db8::1]:8080\r\n" in mock_writer.write.call_args[0][0]

    await probe.run(Target(host="example.com", port=443), config={"use_tls": True})
    assert b"Host: example.com\r\n" in mock_writer.write.call_args[0][0]

@pytest.mark.network
async def test_http_request_network_real():
    probe = HttpRequestProbe()
    result = await probe.run(Target(host="example.com"))
    
    assert result.status == ProbeStatus.SUCCESS
    assert result.details["status_code"] in (200, 301, 302, 404)

@patch("asyncio.open_connection")
async def test_http_request_with_pinned_ipv4_https(mock_open_connection):
    mock_reader = MagicMock()
    mock_reader.readline = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n")
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.write = MagicMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = HttpRequestProbe()
    target = Target(host="example.com")
    result = await probe.run(target, config={"connect_ip": "93.184.216.34", "use_tls": True})

    assert result.status == ProbeStatus.SUCCESS
    mock_open_connection.assert_called_once()
    args, kwargs = mock_open_connection.call_args
    assert args[0] == "93.184.216.34"
    assert args[1] == 443
    assert kwargs["server_hostname"] == "example.com"
    assert kwargs["ssl"] is not None

    written = mock_writer.write.call_args[0][0]
    assert b"Host: example.com\r\n" in written
    assert result.target.host == "example.com"
    assert result.details["connect_ip"] == "93.184.216.34"

@patch("asyncio.open_connection")
async def test_http_request_with_pinned_ipv4_plain_http(mock_open_connection):
    mock_reader = MagicMock()
    mock_reader.readline = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n")
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.write = MagicMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = HttpRequestProbe()
    target = Target(host="example.com")
    result = await probe.run(target, config={"connect_ip": "93.184.216.34", "use_tls": False})

    assert result.status == ProbeStatus.SUCCESS
    mock_open_connection.assert_called_once()
    args, kwargs = mock_open_connection.call_args
    assert args[0] == "93.184.216.34"
    assert args[1] == 80
    assert kwargs["server_hostname"] is None
    assert kwargs["ssl"] is None

    written = mock_writer.write.call_args[0][0]
    assert b"Host: example.com\r\n" in written
    assert result.details["connect_ip"] == "93.184.216.34"

@patch("asyncio.open_connection")
async def test_http_request_with_pinned_ipv6_bracketed(mock_open_connection):
    mock_reader = MagicMock()
    mock_reader.readline = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n")
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.write = MagicMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = HttpRequestProbe()
    target = Target(host="example.com", port=8443)
    result = await probe.run(
        target,
        config={"connect_ip": "[2606:2800:220:1:248:1893:25c8:1946]", "use_tls": True},
    )

    assert result.status == ProbeStatus.SUCCESS
    args, kwargs = mock_open_connection.call_args
    assert args[0] == "2606:2800:220:1:248:1893:25c8:1946"
    assert args[1] == 8443
    assert kwargs["server_hostname"] == "example.com"
    written = mock_writer.write.call_args[0][0]
    assert b"Host: example.com:8443\r\n" in written
    assert result.details["connect_ip"] == "2606:2800:220:1:248:1893:25c8:1946"

@patch("asyncio.open_connection")
async def test_http_request_invalid_connect_ip_rejected(mock_open_connection):
    probe = HttpRequestProbe()
    target = Target(host="example.com")

    result = await probe.run(target, config={"connect_ip": "not-an-ip.org"})
    assert result.status == ProbeStatus.FAILED
    assert "not a valid IPv4 or IPv6 literal" in result.error
    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_http_request_pinned_ip_error_no_fallback(mock_open_connection):
    mock_open_connection.side_effect = ConnectionRefusedError("Connection refused")

    probe = HttpRequestProbe()
    target = Target(host="example.com")
    result = await probe.run(target, config={"connect_ip": "93.184.216.34"})

    assert result.status == ProbeStatus.FAILED
    assert "Connection refused" in result.error
    mock_open_connection.assert_called_once()
    assert result.target.host == "example.com"
    assert result.details["connect_ip"] == "93.184.216.34"

@patch("asyncio.open_connection")
async def test_http_request_pinned_verify_false_rejected(mock_open_connection):
    probe = HttpRequestProbe()
    target = Target(host="example.com")
    result = await probe.run(
        target,
        config={"connect_ip": "93.184.216.34", "verify": False},
    )

    assert result.status == ProbeStatus.FAILED
    assert "Disabling TLS verification is not allowed when connect_ip is pinned" in result.error
    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_http_request_unpinned_verify_false_allowed(mock_open_connection):
    mock_reader = MagicMock()
    mock_reader.readline = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n")
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.write = MagicMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = HttpRequestProbe()
    result = await probe.run(Target(host="example.com"), config={"verify": False})

    assert result.status == ProbeStatus.SUCCESS
    ssl_ctx = mock_open_connection.call_args[1]["ssl"]
    assert ssl_ctx.check_hostname is False
    assert ssl_ctx.verify_mode == ssl.CERT_NONE

@patch("asyncio.open_connection")
async def test_http_request_cancellation_during_read_cleans_up(mock_open_connection):
    started_event = asyncio.Event()
    mock_reader = MagicMock()
    async def slow_read():
        started_event.set()
        await asyncio.sleep(10)
    mock_reader.readline = AsyncMock(side_effect=slow_read)

    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.write = MagicMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = HttpRequestProbe()
    task = asyncio.create_task(probe.run(Target(host="example.com")))
    await started_event.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    mock_writer.close.assert_called()

@patch("asyncio.open_connection")
async def test_http_request_cancellation_during_drain_cleans_up(mock_open_connection):
    started_event = asyncio.Event()
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    async def slow_drain():
        started_event.set()
        await asyncio.sleep(10)
    mock_writer.drain = AsyncMock(side_effect=slow_drain)
    mock_writer.close = MagicMock()
    mock_writer.write = MagicMock()
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = HttpRequestProbe()
    task = asyncio.create_task(probe.run(Target(host="example.com")))
    await started_event.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    mock_writer.close.assert_called()
