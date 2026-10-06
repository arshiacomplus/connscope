import asyncio
import socket
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from connscope.core import Target, ProbeStatus
from connscope.probes.dns_resolve import DnsResolveProbe

@patch("asyncio.get_running_loop")
async def test_dns_resolve_success_mocked(mock_get_running_loop):
    mock_loop = MagicMock()
    mock_loop.getaddrinfo = AsyncMock()
    mock_loop.getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2606:2800:220:1:248:1893:25c8:1946', 0, 0, 0))
    ]
    mock_get_running_loop.return_value = mock_loop
    
    probe = DnsResolveProbe()
    result = await probe.run(Target(host="example.com"))
    
    assert result.status == ProbeStatus.SUCCESS
    assert "resolve_ms" in result.metrics
    assert result.duration_ms >= 0
    assert result.error is None
    
    assert "93.184.216.34" in result.details["addresses"]
    assert "2606:2800:220:1:248:1893:25c8:1946" in result.details["addresses"]
    assert result.details["family"] == "both"

@patch("asyncio.get_running_loop")
async def test_dns_resolve_timeout_mocked(mock_get_running_loop):
    mock_loop = MagicMock()
    mock_loop.getaddrinfo = AsyncMock()
    async def slow_resolve(*args, **kwargs):
        await asyncio.sleep(2.0)
        return []
        
    mock_loop.getaddrinfo.side_effect = slow_resolve
    mock_get_running_loop.return_value = mock_loop
    
    probe = DnsResolveProbe()
    result = await probe.run(
        Target(host="example.com"),
        config={"timeout_s": 0.01}
    )
    
    assert result.status == ProbeStatus.TIMEOUT
    assert "timed out" in result.error
    assert result.duration_ms >= 0

@patch("asyncio.get_running_loop")
async def test_dns_resolve_nxdomain_mocked(mock_get_running_loop):
    mock_loop = MagicMock()
    mock_loop.getaddrinfo = AsyncMock()
    mock_loop.getaddrinfo.side_effect = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    mock_get_running_loop.return_value = mock_loop
    
    probe = DnsResolveProbe()
    result = await probe.run(Target(host="invalid.example.com"))
    
    assert result.status == ProbeStatus.FAILED
    assert "Name or service not known" in result.error
    assert result.duration_ms >= 0

async def test_dns_resolve_integration_local():
    probe = DnsResolveProbe()
    result = await probe.run(Target(host="localhost"))
    
    assert result.status == ProbeStatus.SUCCESS
    assert "resolve_ms" in result.metrics
    assert "127.0.0.1" in result.details["addresses"] or "::1" in result.details["addresses"]

@pytest.mark.network
async def test_dns_resolve_network_real():
    probe = DnsResolveProbe()
    result = await probe.run(Target(host="example.com"))
    
    assert result.status == ProbeStatus.SUCCESS
    assert "resolve_ms" in result.metrics
    assert len(result.details["addresses"]) > 0
