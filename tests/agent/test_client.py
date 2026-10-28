
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import socket
import traceback
from typing import Any, Callable
import pytest

from connscope.agent.client import (
    ClientConfigurationError,
    RemoteAgentClient,
    RemoteAuthenticationError,
    RemoteConnectionError,
    RemoteHttpError,
    RemotePolicyError,
    RemoteProtocolError,
    RemoteRedirectError,
    RemoteTimeoutError,
    RemoteUnavailableError,
    validate_node_url,
)
from connscope.agent.server import AgentServer
from connscope.core import Probe, ProbeEngine, ProbeRegistry, ProbeResult, ProbeStatus, Target

def make_http_response(
    status_line: str,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> bytes:
    h = dict(headers) if headers else {}
    if "Content-Length" not in h and body:
        h["Content-Length"] = str(len(body))
    lines = [status_line] + [f"{k}: {v}" for k, v in h.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body

async def run_raw_http_server(
    handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Any],
) -> tuple[asyncio.Server, int]:
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port

async def read_full_request(reader: asyncio.StreamReader) -> tuple[dict[str, str], bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(4096)
        if not chunk:
            break
        data += chunk
    header_part, _, body_part = data.partition(b"\r\n\r\n")
    headers: dict[str, str] = {}
    for line in header_part.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().decode("iso-8859-1").lower()] = v.strip().decode("iso-8859-1")
    cl = int(headers.get("content-length", "0"))
    while len(body_part) < cl:
        chunk = await reader.read(cl - len(body_part))
        if not chunk:
            break
        body_part += chunk
    return headers, body_part

class TestUrlValidation:

    def test_https_urls_accepted(self) -> None:
        scheme, host, port = validate_node_url("https://agent.example.com")
        assert scheme == "https"
        assert host == "agent.example.com"
        assert port == 443

        scheme, host, port = validate_node_url("https://agent.example.com:8443")
        assert scheme == "https"
        assert host == "agent.example.com"
        assert port == 8443

        scheme, host, port = validate_node_url("https://agent.example.com/")
        assert scheme == "https"
        assert host == "agent.example.com"
        assert port == 443

    def test_loopback_literal_http_accepted(self) -> None:
        scheme, host, port = validate_node_url("http://127.0.0.1:8000")
        assert scheme == "http"
        assert host == "127.0.0.1"
        assert port == 8000

        scheme, host, port = validate_node_url("http://127.0.0.1")
        assert scheme == "http"
        assert host == "127.0.0.1"
        assert port == 80

        scheme, host, port = validate_node_url("http://[::1]:9000")
        assert scheme == "http"
        assert host == "::1"
        assert port == 9000

    def test_hostname_http_rejected(self) -> None:
        with pytest.raises(ClientConfigurationError, match="Plaintext HTTP is not permitted for hostnames"):
            validate_node_url("http://localhost:8000")

        with pytest.raises(ClientConfigurationError, match="Plaintext HTTP is not permitted for hostnames"):
            validate_node_url("http://agent.example.com:8000")

    def test_non_loopback_ip_http_rejected(self) -> None:
        with pytest.raises(ClientConfigurationError, match="Plaintext HTTP is only permitted for literal loopback IPs"):
            validate_node_url("http://192.168.1.1:8000")

        with pytest.raises(ClientConfigurationError, match="Plaintext HTTP is only permitted for literal loopback IPs"):
            validate_node_url("http://10.0.0.1:8000")

        with pytest.raises(ClientConfigurationError, match="Plaintext HTTP is only permitted for literal loopback IPs"):
            validate_node_url("http://8.8.8.8:8000")

    def test_unsupported_scheme_rejected(self) -> None:
        for bad_url in ["ftp://127.0.0.1:8000", "ws://127.0.0.1:8000", "gopher://127.0.0.1"]:
            with pytest.raises(ClientConfigurationError, match="Unsupported node_url scheme"):
                validate_node_url(bad_url)

    def test_credentials_rejected(self) -> None:
        with pytest.raises(ClientConfigurationError, match="must not contain user credentials"):
            validate_node_url("https://user:pass@agent.example.com:8443")

        with pytest.raises(ClientConfigurationError, match="must not contain user credentials"):
            validate_node_url("http://admin@127.0.0.1:8000")

        with pytest.raises(ClientConfigurationError, match="must not contain user credentials"):
            validate_node_url("https://@agent.example")

        with pytest.raises(ClientConfigurationError, match="must not contain user credentials"):
            validate_node_url("https://:@agent.example")

        with pytest.raises(ClientConfigurationError, match="must not contain user credentials"):
            validate_node_url("http://@127.0.0.1:8000")

        with pytest.raises(ClientConfigurationError, match="must not contain user credentials"):
            validate_node_url("http://:@127.0.0.1:8000")

    def test_query_and_fragment_rejected(self) -> None:
        with pytest.raises(ClientConfigurationError, match="must not contain query parameters"):
            validate_node_url("https://agent.example.com?token=xyz")

        with pytest.raises(ClientConfigurationError, match="must not contain query parameters"):
            validate_node_url("https://agent.example?")

        with pytest.raises(ClientConfigurationError, match="must not contain URL fragments"):
            validate_node_url("https://agent.example.com#section")

        with pytest.raises(ClientConfigurationError, match="must not contain URL fragments"):
            validate_node_url("https://agent.example#")

    def test_strict_url_validation_regression_cases(self) -> None:
        with pytest.raises(ClientConfigurationError, match="must not contain query parameters"):
            validate_node_url("https://agent.example?")

        with pytest.raises(ClientConfigurationError, match="must not contain URL fragments"):
            validate_node_url("https://agent.example#")

        with pytest.raises(ClientConfigurationError, match="must not contain user credentials"):
            validate_node_url("https://@agent.example")

        with pytest.raises(ClientConfigurationError, match="must not contain user credentials"):
            validate_node_url("https://:@agent.example")

        assert validate_node_url("https://agent.example") == ("https", "agent.example", 443)
        assert validate_node_url("https://agent.example:8443") == ("https", "agent.example", 8443)
        assert validate_node_url("http://127.0.0.1:8000") == ("http", "127.0.0.1", 8000)
        assert validate_node_url("http://[::1]:9000") == ("http", "::1", 9000)

    def test_path_prefix_rejected(self) -> None:
        with pytest.raises(ClientConfigurationError, match="Unexpected path prefix"):
            validate_node_url("https://agent.example.com/api/v1")

        with pytest.raises(ClientConfigurationError, match="Unexpected path prefix"):
            validate_node_url("http://127.0.0.1:8000/measure")

    def test_invalid_ports_rejected(self) -> None:
        with pytest.raises(ClientConfigurationError, match="must be between 1 and 65535"):
            validate_node_url("https://agent.example.com:0")

        with pytest.raises(ClientConfigurationError, match="Invalid port in node_url"):
            validate_node_url("https://agent.example.com:70000")

        with pytest.raises(ClientConfigurationError):
            validate_node_url("https://agent.example.com:notaport")

    def test_malformed_and_whitespace_urls_rejected(self) -> None:
        for bad in ["", "   ", "https:// agent.example.com", "http://127.0.0.1: 80", None, 123]:
            with pytest.raises(ClientConfigurationError):
                validate_node_url(bad)  # type: ignore[arg-type]

class TestLocalInputValidation:

    def test_token_validation(self) -> None:
        prohibited_tokens = [
            "",
            "   ",
            None,
            12345,
            "secret\ntoken",
            "secret\rtoken",
            "secret\0token",
            "secret\ttoken",
            "secret token",
            "token:with:colons",
            '"quoted_token"',
            "\x1b[31mtoken",
        ]
        for bad_token in prohibited_tokens:
            with pytest.raises(ClientConfigurationError) as exc_info:
                RemoteAgentClient("http://127.0.0.1:8000", token=bad_token)  # type: ignore[arg-type]
            if isinstance(bad_token, str) and bad_token.strip():
                assert bad_token not in str(exc_info.value)
                assert bad_token not in repr(exc_info.value)

    def test_legitimate_tokens_accepted(self) -> None:
        valid_tokens = [
            "secret-token",
            "secret-token-123",
            "c2VjcmV0LXRva2Vu",
            "YWJjZGVm==",
            "a-b_c~d.e+f/g",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
        ]
        for token in valid_tokens:
            client = RemoteAgentClient("http://127.0.0.1:8000", token=token)
            assert client.node_url == "http://127.0.0.1:8000"

    def test_timeout_validation(self) -> None:
        for bad_timeout in [0, -1, -5.0, float("nan"), float("inf"), float("-inf"), True, False, "10"]:
            with pytest.raises(ClientConfigurationError, match="timeout_s must be a finite positive number"):
                RemoteAgentClient("http://127.0.0.1:8000", token="token", timeout_s=bad_timeout)  # type: ignore[arg-type]

    def test_repr_masks_token(self) -> None:
        secret = "SUPER_SECRET_TOKEN_DO_NOT_LEAK"
        client = RemoteAgentClient("http://127.0.0.1:8000", token=secret)
        repr_str = repr(client)
        assert secret not in repr_str
        assert "http://127.0.0.1:8000" in repr_str
        assert "30.0" in repr_str

    def test_measure_probe_name_validation(self) -> None:
        client = RemoteAgentClient("http://127.0.0.1:8000", token="token")
        target = Target(host="example.com", port=80)
        for bad_probe in ["", "   ", None, 123]:
            with pytest.raises(ClientConfigurationError, match="probe_name must be a non-empty string"):
                client.measure(bad_probe, target)  # type: ignore[arg-type]

    def test_measure_target_validation(self) -> None:
        client = RemoteAgentClient("http://127.0.0.1:8000", token="token")
        for bad_target in [None, "example.com", {"host": "example.com", "port": 80}]:
            with pytest.raises(ClientConfigurationError, match="target must be an instance of Target"):
                client.measure("tcp_connect", bad_target)  # type: ignore[arg-type]

    def test_measure_config_validation(self) -> None:
        client = RemoteAgentClient("http://127.0.0.1:8000", token="token")
        target = Target(host="example.com", port=80)

        with pytest.raises(ClientConfigurationError, match="config must be a dictionary or None"):
            client.measure("tcp_connect", target, config="invalid")  # type: ignore[arg-type]

        with pytest.raises(ClientConfigurationError, match="config dictionary keys must be strings"):
            client.measure("tcp_connect", target, config={123: "val"})  # type: ignore[dict-item]

    def test_measure_rejects_client_supplied_connect_ip(self) -> None:
        client = RemoteAgentClient("http://127.0.0.1:8000", token="token")
        target = Target(host="example.com", port=80)
        with pytest.raises(ClientConfigurationError, match="client-supplied 'connect_ip' is not permitted"):
            client.measure("tcp_connect", target, config={"connect_ip": "1.2.3.4"})

    def test_measure_rejects_non_strict_json_config(self) -> None:
        client = RemoteAgentClient("http://127.0.0.1:8000", token="token")
        target = Target(host="example.com", port=80)

        with pytest.raises(ClientConfigurationError, match="config cannot be serialized to strict JSON"):
            client.measure("tcp_connect", target, config={"timeout": float("nan")})

        with pytest.raises(ClientConfigurationError, match="config cannot be serialized to strict JSON"):
            client.measure("tcp_connect", target, config={"timeout": float("inf")})

        with pytest.raises(ClientConfigurationError, match="config cannot be serialized to strict JSON"):
            client.measure("tcp_connect", target, config={"custom_obj": object()})

class TestAgentServerIntegration:

    @pytest.mark.asyncio
    async def test_tcp_measure_round_trip_success(self) -> None:
        class MockTcpProbe(Probe):
            name = "tcp_connect"

            async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
                assert config is not None
                assert config.get("connect_ip") == "93.184.216.34"
                return ProbeResult(
                    probe=self.name,
                    target=target,
                    status=ProbeStatus.SUCCESS,
                    started_at=datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc),
                    duration_ms=12.5,
                    metrics={"rtt_ms": 12.5, "syn_ack_received": 1.0},
                    details={"socket_family": "AF_INET"},
                )

        registry = ProbeRegistry()
        registry.register(MockTcpProbe())
        engine = ProbeEngine(registry=registry)

        async with AgentServer(port=0, auth_token="secret-token-123", engine=engine) as server:
            client = RemoteAgentClient(f"http://127.0.0.1:{server.port}", token="secret-token-123")
            target = Target(host="93.184.216.34", port=80)

            result = await asyncio.to_thread(client.measure, "tcp_connect", target, {"timeout_s": 5.0})

            assert isinstance(result, ProbeResult)
            assert result.probe == "tcp_connect"
            assert result.target.host == "93.184.216.34"
            assert result.target.port == 80
            assert result.status == ProbeStatus.SUCCESS
            assert result.started_at == datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
            assert result.duration_ms == 12.5
            assert result.metrics == {"rtt_ms": 12.5, "syn_ack_received": 1.0}
            assert result.details == {"socket_family": "AF_INET"}
            assert result.error is None

    @pytest.mark.asyncio
    async def test_dns_measure_round_trip_with_hostname_target(self) -> None:
        class MockDnsProbe(Probe):
            name = "dns_resolve"

            async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
                return ProbeResult(
                    probe=self.name,
                    target=target,
                    status=ProbeStatus.SUCCESS,
                    started_at=datetime.now(timezone.utc),
                    duration_ms=8.0,
                    metrics={"query_time_ms": 8.0},
                    details={"records": ["93.184.216.34"]},
                )

        registry = ProbeRegistry()
        registry.register(MockDnsProbe())
        engine = ProbeEngine(registry=registry)

        async with AgentServer(
            port=0,
            auth_token="secret-token-123",
            engine=engine,
            resolver=lambda h: ["93.184.216.34"],
        ) as server:
            client = RemoteAgentClient(f"http://127.0.0.1:{server.port}", token="secret-token-123")
            target = Target(host="example.com", port=53)

            result = await asyncio.to_thread(client.measure, "dns_resolve", target)

            assert result.probe == "dns_resolve"
            assert result.target.host == "example.com"
            assert result.target.port == 53
            assert result.status == ProbeStatus.SUCCESS
            assert result.details == {"records": ["93.184.216.34"]}

    @pytest.mark.asyncio
    async def test_probe_failure_returned_normally_as_result(self) -> None:
        class FailingProbe(Probe):
            name = "tcp_connect"

            async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
                return ProbeResult(
                    probe=self.name,
                    target=target,
                    status=ProbeStatus.FAILED,
                    started_at=datetime.now(timezone.utc),
                    duration_ms=15.0,
                    metrics={},
                    details={},
                    error="Connection reset by peer",
                )

        registry = ProbeRegistry()
        registry.register(FailingProbe())
        engine = ProbeEngine(registry=registry)

        async with AgentServer(port=0, auth_token="secret-token-123", engine=engine) as server:
            client = RemoteAgentClient(f"http://127.0.0.1:{server.port}", token="secret-token-123")
            target = Target(host="93.184.216.34", port=80)

            result = await asyncio.to_thread(client.measure, "tcp_connect", target)

            assert isinstance(result, ProbeResult)
            assert result.status == ProbeStatus.FAILED
            assert result.error == "Connection reset by peer"

    @pytest.mark.asyncio
    async def test_probe_timeout_returned_normally_as_result(self) -> None:
        class TimeoutProbe(Probe):
            name = "tcp_connect"

            async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
                return ProbeResult(
                    probe=self.name,
                    target=target,
                    status=ProbeStatus.TIMEOUT,
                    started_at=datetime.now(timezone.utc),
                    duration_ms=5000.0,
                    metrics={},
                    details={},
                    error="TCP connection timed out after 5.0s",
                )

        registry = ProbeRegistry()
        registry.register(TimeoutProbe())
        engine = ProbeEngine(registry=registry)

        async with AgentServer(port=0, auth_token="secret-token-123", engine=engine) as server:
            client = RemoteAgentClient(f"http://127.0.0.1:{server.port}", token="secret-token-123")
            target = Target(host="93.184.216.34", port=80)

            result = await asyncio.to_thread(client.measure, "tcp_connect", target)

            assert isinstance(result, ProbeResult)
            assert result.status == ProbeStatus.TIMEOUT
            assert result.error == "TCP connection timed out after 5.0s"

    @pytest.mark.asyncio
    async def test_auth_failure_raises_remote_auth_error(self) -> None:
        async with AgentServer(port=0, auth_token="correct-token") as server:
            client = RemoteAgentClient(f"http://127.0.0.1:{server.port}", token="wrong-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteAuthenticationError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.status_code == 401
            assert exc.error_code == "unauthorized"
            assert "Remote agent returned HTTP 401" in str(exc)

    @pytest.mark.asyncio
    async def test_policy_rejection_raises_remote_policy_error(self) -> None:
        async with AgentServer(port=0, auth_token="secret-token") as server:
            client = RemoteAgentClient(f"http://127.0.0.1:{server.port}", token="secret-token")
            target = Target(host="127.0.0.1", port=80)

            with pytest.raises(RemotePolicyError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.status_code == 403
            assert exc.error_code == "forbidden"
            assert "Remote agent returned HTTP 403" in str(exc)

    @pytest.mark.asyncio
    async def test_unknown_probe_raises_remote_http_error(self) -> None:
        async with AgentServer(port=0, auth_token="secret-token") as server:
            client = RemoteAgentClient(f"http://127.0.0.1:{server.port}", token="secret-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteHttpError) as exc_info:
                await asyncio.to_thread(client.measure, "nonexistent_probe", target)

            exc = exc_info.value
            assert exc.status_code == 404
            assert exc.error_code == "unknown_probe"

class TestMockServerErrorMappings:

    @pytest.mark.asyncio
    async def test_redirect_rejected_without_following(self) -> None:
        async def redirect_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            resp = make_http_response(
                "HTTP/1.1 301 Moved Permanently",
                headers={"Location": "http://127.0.0.1:9999/v1/measure", "Content-Length": "0", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(redirect_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteRedirectError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.status_code == 301
            assert "HTTP 301" in str(exc)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_http_429_raises_remote_unavailable_error(self) -> None:
        async def busy_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b'{"error":"too_many_requests","message":"Rate limit exceeded"}'
            resp = make_http_response(
                "HTTP/1.1 429 Too Many Requests",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(busy_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteUnavailableError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.status_code == 429
            assert exc.error_code == "too_many_requests"
            assert "Remote agent returned HTTP 429" in str(exc)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_http_503_raises_remote_unavailable_error(self) -> None:
        async def unavail_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b'{"error":"service_unavailable","message":"Node draining"}'
            resp = make_http_response(
                "HTTP/1.1 503 Service Unavailable",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(unavail_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteUnavailableError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.status_code == 503
            assert exc.error_code == "service_unavailable"
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_http_504_raises_remote_timeout_error(self) -> None:
        async def gateway_timeout_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b'{"error":"gateway_timeout","message":"Probe execution timed out"}'
            resp = make_http_response(
                "HTTP/1.1 504 Gateway Timeout",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(gateway_timeout_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteTimeoutError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.status_code == 504
            assert exc.error_code == "gateway_timeout"
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_http_500_raises_remote_http_error(self) -> None:
        async def err500_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b'{"error":"internal_error","message":"Unexpected fault"}'
            resp = make_http_response(
                "HTTP/1.1 500 Internal Server Error",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(err500_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteHttpError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.status_code == 500
            assert exc.error_code == "internal_error"
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_connection_refused_raises_remote_connection_error(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            unused_port = s.getsockname()[1]

        client = RemoteAgentClient(f"http://127.0.0.1:{unused_port}", token="test-token")
        target = Target(host="93.184.216.34", port=80)

        with pytest.raises(RemoteConnectionError, match="Connection to remote agent failed"):
            await asyncio.to_thread(client.measure, "tcp_connect", target)

    @pytest.mark.asyncio
    async def test_client_socket_timeout_raises_remote_timeout_error(self) -> None:
        async def hanging_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            await asyncio.sleep(2.0)
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(hanging_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token", timeout_s=0.2)
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteTimeoutError, match="Timed out communicating with remote agent"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

class TestResponseProtocolValidation:

    @pytest.mark.asyncio
    async def test_oversized_content_length_rejected(self) -> None:
        async def oversized_cl_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": "2000000",
                    "Connection": "close",
                },
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(oversized_cl_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="exceeds maximum limit"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_oversized_streaming_body_rejected(self) -> None:
        async def streaming_oversized_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n")
            await writer.drain()
            chunk = b"X" * (64 * 1024)
            for _ in range(18):
                try:
                    writer.write(chunk)
                    await writer.drain()
                except (ConnectionResetError, BrokenPipeError):
                    break
            try:
                await reader.read(1)
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        server, port = await run_raw_http_server(streaming_oversized_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="exceeds maximum permitted limit"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_invalid_utf8_rejected(self) -> None:
        async def bad_utf8_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b"\xff\xfe\xfd"
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(bad_utf8_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="not valid UTF-8"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_malformed_json_rejected(self) -> None:
        async def bad_json_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b"not a json object"
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(bad_json_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="Malformed JSON response"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_duplicate_json_keys_rejected(self) -> None:
        async def dup_keys_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b'{"protocol_version": 1, "status": "completed", "status": "completed"}'
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(dup_keys_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="Malformed JSON response"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_non_finite_json_constants_rejected(self) -> None:
        async def nan_json_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b'{"protocol_version": 1, "duration_ms": NaN}'
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(nan_json_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="Malformed JSON response"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_unsupported_protocol_version_rejected(self) -> None:
        for bad_pv in ['"protocol_version": 2', '"protocol_version": true', '"protocol_version": "1"']:
            async def bad_pv_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                await reader.read(4096)
                body = f'{{{bad_pv}, "request_id": "req-1", "status": "completed"}}'.encode("utf-8")
                resp = make_http_response(
                    "HTTP/1.1 200 OK",
                    body=body,
                    headers={"Content-Type": "application/json", "Connection": "close"},
                )
                writer.write(resp)
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            server, port = await run_raw_http_server(bad_pv_handler)
            try:
                client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
                target = Target(host="93.184.216.34", port=80)

                with pytest.raises(RemoteProtocolError, match="Unsupported protocol_version"):
                    await asyncio.to_thread(client.measure, "tcp_connect", target)
            finally:
                server.close()
                await server.wait_closed()

    @pytest.mark.asyncio
    async def test_mismatched_request_id_rejected(self) -> None:
        async def mismatched_req_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b'{"protocol_version": 1, "request_id": "different-req-id", "status": "completed"}'
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(mismatched_req_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="Mismatched request_id"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_non_completed_status_rejected(self) -> None:
        async def bad_status_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _, req_body = await read_full_request(reader)
            req_json = json.loads(req_body.decode("utf-8"))
            body = json.dumps({
                "protocol_version": 1,
                "request_id": req_json["request_id"],
                "status": "running",
            }).encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(bad_status_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="Unexpected status in response: expected 'completed'"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_mismatched_probe_in_result_rejected(self) -> None:
        async def mismatched_probe_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _, req_body = await read_full_request(reader)
            req_json = json.loads(req_body.decode("utf-8"))
            body = json.dumps({
                "protocol_version": 1,
                "request_id": req_json["request_id"],
                "status": "completed",
                "result": {
                    "probe": "dns_resolve",
                    "target": {"host": "93.184.216.34", "port": 80},
                    "status": "success",
                    "started_at": "2026-10-13T12:00:00Z",
                    "duration_ms": 1.0,
                    "metrics": {},
                    "details": {},
                    "error": None,
                },
            }).encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(mismatched_probe_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="Mismatched probe name"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_mismatched_target_in_result_rejected(self) -> None:
        async def mismatched_target_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _, req_body = await read_full_request(reader)
            req_json = json.loads(req_body.decode("utf-8"))
            body = json.dumps({
                "protocol_version": 1,
                "request_id": req_json["request_id"],
                "status": "completed",
                "result": {
                    "probe": "tcp_connect",
                    "target": {"host": "other-host.example.com", "port": 80},
                    "status": "success",
                    "started_at": "2026-10-13T12:00:00Z",
                    "duration_ms": 1.0,
                    "metrics": {},
                    "details": {},
                    "error": None,
                },
            }).encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(mismatched_target_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError, match="Mismatched target in response"):
                await asyncio.to_thread(client.measure, "tcp_connect", target)
        finally:
            server.close()
            await server.wait_closed()

class TestSecretNonLeakage:

    @pytest.mark.asyncio
    async def test_secret_token_never_leaks_in_exceptions(self) -> None:
        secret = "SECRET_MARKER_998877_ALPHA_BETA"

        client = RemoteAgentClient("http://127.0.0.1:1", token=secret)
        target = Target(host="example.com", port=80)
        with pytest.raises(RemoteConnectionError) as exc_info:
            await asyncio.to_thread(client.measure, "tcp_connect", target)
        assert secret not in str(exc_info.value)
        assert secret not in repr(exc_info.value)

        async with AgentServer(port=0, auth_token="server-secret") as server:
            client2 = RemoteAgentClient(f"http://127.0.0.1:{server.port}", token=secret)
            with pytest.raises(RemoteAuthenticationError) as exc_info2:
                await asyncio.to_thread(client2.measure, "tcp_connect", Target(host="93.184.216.34", port=80))
            assert secret not in str(exc_info2.value)
            assert secret not in repr(exc_info2.value)

        with RemoteAgentClient("http://127.0.0.1:8000", token=secret) as ctx_client:
            assert secret not in repr(ctx_client)

    @pytest.mark.asyncio
    async def test_remote_error_message_containing_token_never_leaks(self) -> None:
        secret = "SECRET_TOKEN_IN_ERROR_MSG_999"

        async def err_with_token_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = json.dumps({
                "error": "unauthorized",
                "message": f"Authorization token {secret} was rejected",
            }).encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 401 Unauthorized",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(err_with_token_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token=secret)
            target = Target(host="93.184.216.34", port=80)
            with pytest.raises(RemoteAuthenticationError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert secret not in str(exc)
            assert secret not in repr(exc)
            assert secret not in str(getattr(exc, "__cause__", ""))
            assert secret not in str(getattr(exc, "__context__", ""))
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_mismatched_request_id_containing_token_never_leaks(self) -> None:
        secret = "SECRET_TOKEN_IN_REQ_ID_888"

        async def mismatched_id_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = json.dumps({
                "protocol_version": 1,
                "request_id": f"REQ_MISMATCH_{secret}",
                "status": "completed",
            }).encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(mismatched_id_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token=secret)
            target = Target(host="93.184.216.34", port=80)
            with pytest.raises(RemoteProtocolError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert secret not in str(exc)
            assert secret not in repr(exc)
            assert secret not in str(getattr(exc, "__cause__", ""))
            assert secret not in str(getattr(exc, "__context__", ""))
            assert "Mismatched request_id" in str(exc)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_duplicate_json_key_containing_token_never_leaks(self) -> None:
        secret = "SECRET_KEY_TOKEN_777"

        async def dup_key_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = f'{{"{secret}": 1, "{secret}": 2}}'.encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(dup_key_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token=secret)
            target = Target(host="93.184.216.34", port=80)
            with pytest.raises(RemoteProtocolError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert secret not in str(exc)
            assert secret not in repr(exc)
            assert secret not in str(getattr(exc, "__cause__", ""))
            assert secret not in str(getattr(exc, "__context__", ""))
            assert "Malformed JSON response" in str(exc)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_invalid_content_length_header_never_leaks(self) -> None:
        secret_cl = "9999999999"

        async def cl_leak_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": secret_cl,
                    "Connection": "close",
                },
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(cl_leak_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)
            with pytest.raises(RemoteProtocolError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert secret_cl not in str(exc)
            assert secret_cl not in repr(exc)
            assert "exceeds maximum limit" in str(exc)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_malformed_protocol_values_never_echoed(self) -> None:
        secret_probe = "SECRET_PROBE_VAL_666"
        secret_target = "secret-target-host-val-555"
        secret_status = "secret-status-val-444"

        async def probe_leak_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _, req_body = await read_full_request(reader)
            req_json = json.loads(req_body.decode("utf-8"))
            body = json.dumps({
                "protocol_version": 1,
                "request_id": req_json["request_id"],
                "status": "completed",
                "result": {
                    "probe": secret_probe,
                    "target": {"host": "93.184.216.34", "port": 80},
                    "status": "success",
                    "started_at": "2026-10-13T12:00:00Z",
                    "duration_ms": 1.0,
                    "metrics": {},
                    "details": {},
                    "error": None,
                },
            }).encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(probe_leak_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)
            with pytest.raises(RemoteProtocolError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)
            assert secret_probe not in str(exc_info.value)
            assert secret_probe not in repr(exc_info.value)
            assert "Mismatched probe name in response" in str(exc_info.value)
        finally:
            server.close()
            await server.wait_closed()

        async def target_leak_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _, req_body = await read_full_request(reader)
            req_json = json.loads(req_body.decode("utf-8"))
            body = json.dumps({
                "protocol_version": 1,
                "request_id": req_json["request_id"],
                "status": "completed",
                "result": {
                    "probe": "tcp_connect",
                    "target": {"host": secret_target, "port": 80},
                    "status": "success",
                    "started_at": "2026-10-13T12:00:00Z",
                    "duration_ms": 1.0,
                    "metrics": {},
                    "details": {},
                    "error": None,
                },
            }).encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(target_leak_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)
            with pytest.raises(RemoteProtocolError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)
            assert secret_target not in str(exc_info.value)
            assert secret_target not in repr(exc_info.value)
            assert "Mismatched target in response" in str(exc_info.value)
        finally:
            server.close()
            await server.wait_closed()

        async def status_leak_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _, req_body = await read_full_request(reader)
            req_json = json.loads(req_body.decode("utf-8"))
            body = json.dumps({
                "protocol_version": 1,
                "request_id": req_json["request_id"],
                "status": secret_status,
            }).encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(status_leak_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)
            with pytest.raises(RemoteProtocolError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)
            assert secret_status not in str(exc_info.value)
            assert secret_status not in repr(exc_info.value)
        finally:
            server.close()
            await server.wait_closed()

        async def bad_error_code_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = b'{"error":"UNTRUSTED_CODE_WITH_PUNCTUATION!@#$","message":"Something bad"}'
            resp = make_http_response(
                "HTTP/1.1 400 Bad Request",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(bad_error_code_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token="test-token")
            target = Target(host="93.184.216.34", port=80)
            with pytest.raises(RemoteHttpError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)
            assert exc_info.value.error_code is None
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_legitimate_tokens_work_with_in_process_agent_server(self) -> None:
        class EchoProbe(Probe):
            name = "tcp_connect"

            async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
                return ProbeResult(
                    probe=self.name,
                    target=target,
                    status=ProbeStatus.SUCCESS,
                    started_at=datetime.now(timezone.utc),
                    duration_ms=1.0,
                    metrics={},
                    details={},
                )

        registry = ProbeRegistry()
        registry.register(EchoProbe())
        engine = ProbeEngine(registry=registry)

        valid_tokens = [
            "secret-token-123",
            "c2VjcmV0LXRva2Vu",
            "token_with_dot.and-dash",
        ]

        for token in valid_tokens:
            async with AgentServer(port=0, auth_token=token, engine=engine) as server:
                client = RemoteAgentClient(f"http://127.0.0.1:{server.port}", token=token)
                target = Target(host="93.184.216.34", port=80)
                result = await asyncio.to_thread(client.measure, "tcp_connect", target)
                assert result.status == ProbeStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_malformed_json_response_with_secret_severs_exception_context(self) -> None:
        secret = "SECRET_TOKEN_IN_MALFORMED_JSON_991122"

        async def malformed_json_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = f'{{"reflected_secret": "{secret}", unquoted_syntax:'.encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(malformed_json_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token=secret)
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.__cause__ is None
            assert exc.__context__ is None

            tb_str = "".join(traceback.format_exception(exc))
            assert secret not in tb_str
            assert "JSONDecodeError" not in tb_str

            assert secret not in str(exc)
            assert secret not in repr(exc)
            assert "Malformed JSON response" in str(exc)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_invalid_utf8_response_with_secret_severs_exception_context(self) -> None:
        secret = "SECRET_TOKEN_IN_RAW_BYTES_882233"

        async def invalid_utf8_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = secret.encode("ascii") + b"\xff\xfe\xfd"
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(invalid_utf8_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token=secret)
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.__cause__ is None
            assert exc.__context__ is None

            tb_str = "".join(traceback.format_exception(exc))
            assert secret not in tb_str
            assert "UnicodeDecodeError" not in tb_str

            assert secret not in str(exc)
            assert secret not in repr(exc)
            assert "Response body is not valid UTF-8" in str(exc)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_invalid_probe_result_payload_with_secret_severs_exception_context(self) -> None:
        secret = "SECRET_TOKEN_IN_PROBE_RESULT_773344"

        async def bad_result_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _, req_body = await read_full_request(reader)
            req_json = json.loads(req_body.decode("utf-8"))
            body = json.dumps({
                "protocol_version": 1,
                "request_id": req_json["request_id"],
                "status": "completed",
                "result": {
                    "probe": "tcp_connect",
                    "target": {"host": "93.184.216.34", "port": f"invalid_{secret}"},
                    "status": "success",
                    "started_at": "invalid_date",
                    "duration_ms": 1.0,
                    "metrics": {},
                    "details": {},
                    "error": None,
                },
            }).encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 200 OK",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(bad_result_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token=secret)
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteProtocolError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.__cause__ is None
            assert exc.__context__ is None

            tb_str = "".join(traceback.format_exception(exc))
            assert secret not in tb_str

            assert secret not in str(exc)
            assert secret not in repr(exc)
            assert "Invalid ProbeResult payload in response" in str(exc)
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_http_error_response_with_secret_severs_exception_context(self) -> None:
        secret = "SECRET_TOKEN_IN_HTTP_ERR_664455"

        async def http_err_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(4096)
            body = f'{{"error": "unauthorized", "leak": "{secret}"}}'.encode("utf-8")
            resp = make_http_response(
                "HTTP/1.1 401 Unauthorized",
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await run_raw_http_server(http_err_handler)
        try:
            client = RemoteAgentClient(f"http://127.0.0.1:{port}", token=secret)
            target = Target(host="93.184.216.34", port=80)

            with pytest.raises(RemoteAuthenticationError) as exc_info:
                await asyncio.to_thread(client.measure, "tcp_connect", target)

            exc = exc_info.value
            assert exc.__cause__ is None
            assert exc.__context__ is None

            tb_str = "".join(traceback.format_exception(exc))
            assert secret not in tb_str

            assert secret not in str(exc)
            assert secret not in repr(exc)
        finally:
            server.close()
            await server.wait_closed()
