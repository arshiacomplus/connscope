import asyncio
from datetime import datetime, timezone
import json
from typing import Any
import pytest

from connscope.agent.protocol import PROTOCOL_VERSION
from connscope.agent.security import TargetResolutionError
from connscope.agent.server import AgentServer
from connscope.core import Probe, ProbeEngine, ProbeRegistry, ProbeResult, ProbeStatus, Target

async def send_raw_request(
    host: str,
    port: int,
    request_bytes: bytes,
) -> tuple[int, dict[str, str], bytes]:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(request_bytes)
        await writer.drain()
        raw_response = await reader.read()
    finally:
        writer.close()
        await writer.wait_closed()

    header_part, _, body_part = raw_response.partition(b"\r\n\r\n")
    lines = header_part.split(b"\r\n")
    status_line = lines[0].decode("iso-8859-1")
    status_code = int(status_line.split(" ")[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" in line:
            name, val = line.split(b":", 1)
            headers[name.strip().decode("iso-8859-1").lower()] = val.strip().decode("iso-8859-1")
    return status_code, headers, body_part

async def post_measure_json(
    server: AgentServer,
    payload: dict[str, Any],
    token: str = "secret-token",
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    body = json.dumps(payload).encode("utf-8")
    headers = [
        "POST /v1/measure HTTP/1.1",
        f"Host: {server.host}:{server.port}",
        f"Authorization: Bearer {token}",
        f"Content-Length: {len(body)}",
        "Content-Type: application/json",
    ]
    if extra_headers:
        for k, v in extra_headers.items():
            headers.append(f"{k}: {v}")
    raw_req = "\r\n".join(headers).encode("iso-8859-1") + b"\r\n\r\n" + body
    status_code, resp_headers, resp_body = await send_raw_request(server.host, server.port, raw_req)
    parsed_json = json.loads(resp_body.decode("utf-8")) if resp_body else {}
    return status_code, resp_headers, parsed_json

def test_server_bind_rejects_non_loopback() -> None:
    invalid_hosts = ["0.0.0.0", "192.168.1.1", "localhost", "8.8.8.8", ""]
    for host in invalid_hosts:
        with pytest.raises(ValueError):
            AgentServer(host=host, auth_token="secret")

def test_server_bind_rejects_invalid_parameters() -> None:
    with pytest.raises(ValueError):
        AgentServer(auth_token="")
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", port=-1)
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", port=70000)
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", max_concurrency=0)
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", read_timeout_s=0)

@pytest.mark.asyncio
async def test_server_binds_to_loopback_and_lifecycle() -> None:
    server = AgentServer(host="127.0.0.1", port=0, auth_token="secret-token")
    assert not server.is_running
    assert server.port == 0

    await server.start()
    try:
        assert server.is_running
        assert server.port > 0
        assert server.host == "127.0.0.1"

        raw_req = f"GET /v1/health HTTP/1.1\r\nHost: {server.host}:{server.port}\r\n\r\n".encode("iso-8859-1")
        code, _, body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 200
        assert json.loads(body.decode("utf-8")) == {"status": "ok"}
    finally:
        await server.close()

    assert not server.is_running
    await server.close()

@pytest.mark.asyncio
async def test_server_context_manager() -> None:
    async with AgentServer(host="127.0.0.1", port=0, auth_token="secret-token") as server:
        assert server.is_running
        assert server.port > 0
    assert not server.is_running

@pytest.mark.asyncio
async def test_health_endpoint_success() -> None:
    async with AgentServer(port=0, auth_token="test-token") as server:
        raw_req = f"GET /v1/health HTTP/1.1\r\nHost: {server.host}:{server.port}\r\n\r\n".encode("iso-8859-1")
        code, headers, body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 200
        assert headers["content-type"] == "application/json"
        assert headers["connection"] == "close"
        assert json.loads(body.decode("utf-8")) == {"status": "ok"}

@pytest.mark.asyncio
async def test_health_endpoint_unsupported_methods() -> None:
    async with AgentServer(port=0, auth_token="test-token") as server:
        for method in ["POST", "PUT", "DELETE"]:
            raw_req = f"{method} /v1/health HTTP/1.1\r\nHost: {server.host}:{server.port}\r\n\r\n".encode("iso-8859-1")
            code, headers, body = await send_raw_request(server.host, server.port, raw_req)
            assert code == 405
            assert headers["allow"] == "GET"
            parsed = json.loads(body.decode("utf-8"))
            assert parsed["error"] == "method_not_allowed"

@pytest.mark.asyncio
async def test_unknown_routes() -> None:
    async with AgentServer(port=0, auth_token="test-token") as server:
        for path in ["/", "/v1", "/v1/unknown", "/health"]:
            raw_req = f"GET {path} HTTP/1.1\r\nHost: {server.host}:{server.port}\r\n\r\n".encode("iso-8859-1")
            code, _, body = await send_raw_request(server.host, server.port, raw_req)
            assert code == 404
            parsed = json.loads(body.decode("utf-8"))
            assert parsed["error"] == "not_found"

@pytest.mark.asyncio
async def test_measure_unsupported_method() -> None:
    async with AgentServer(port=0, auth_token="test-token") as server:
        raw_req = f"GET /v1/measure HTTP/1.1\r\nHost: {server.host}:{server.port}\r\n\r\n".encode("iso-8859-1")
        code, headers, body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 405
        assert headers["allow"] == "POST"

@pytest.mark.asyncio
async def test_measure_missing_auth() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        body = b'{"protocol_version": 1}'
        raw_req = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("iso-8859-1") + body
        code, headers, resp_body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 401
        assert "www-authenticate" in headers
        parsed = json.loads(resp_body.decode("utf-8"))
        assert parsed["error"] == "unauthorized"

@pytest.mark.asyncio
async def test_measure_invalid_auth_token() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        payload = {"protocol_version": 1}
        code, _, parsed = await post_measure_json(server, payload, token="wrong-token")
        assert code == 401
        assert parsed["error"] == "unauthorized"
        assert "secret-token" not in str(parsed)
        assert "wrong-token" not in str(parsed)

@pytest.mark.asyncio
async def test_measure_early_auth_check_before_body() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        raw_req = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization: Bearer wrong-token\r\n"
            f"Content-Length: 50000\r\n\r\n"
        ).encode("iso-8859-1")
        code, _, resp_body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 401
        parsed = json.loads(resp_body.decode("utf-8"))
        assert parsed["error"] == "unauthorized"

@pytest.mark.asyncio
async def test_missing_content_length() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        raw_req = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization: Bearer secret-token\r\n\r\n"
        ).encode("iso-8859-1")
        code, _, resp_body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 411
        parsed = json.loads(resp_body.decode("utf-8"))
        assert parsed["error"] == "length_required"

@pytest.mark.asyncio
async def test_oversized_body_rejected() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        raw_req = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization: Bearer secret-token\r\n"
            f"Content-Length: 70000\r\n\r\n"
        ).encode("iso-8859-1")
        code, _, resp_body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 413
        parsed = json.loads(resp_body.decode("utf-8"))
        assert parsed["error"] == "payload_too_large"

@pytest.mark.asyncio
async def test_oversized_headers_rejected() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        large_header = "X-Large: " + ("A" * (17 * 1024)) + "\r\n"
        raw_req = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"{large_header}\r\n"
        ).encode("iso-8859-1")
        code, _, resp_body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 413
        parsed = json.loads(resp_body.decode("utf-8"))
        assert parsed["error"] == "payload_too_large"

@pytest.mark.asyncio
async def test_transfer_encoding_rejected() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        raw_req = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
        ).encode("iso-8859-1")
        code, _, resp_body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 400
        parsed = json.loads(resp_body.decode("utf-8"))
        assert parsed["error"] == "bad_request"

@pytest.mark.asyncio
async def test_duplicate_headers_rejected() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        raw_req = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Host: {server.host}:{server.port}\r\n\r\n"
        ).encode("iso-8859-1")
        code, _, resp_body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 400
        parsed = json.loads(resp_body.decode("utf-8"))
        assert parsed["error"] == "bad_request"

@pytest.mark.asyncio
async def test_read_timeout_headers() -> None:
    async with AgentServer(port=0, auth_token="secret-token", read_timeout_s=0.05) as server:
        reader, writer = await asyncio.open_connection(server.host, server.port)
        try:
            writer.write(b"POST /v1/measure HTTP/1.1\r\n")
            await writer.drain()
            resp = await reader.read()
            assert b"408" in resp
        finally:
            writer.close()
            await writer.wait_closed()

@pytest.mark.asyncio
async def test_measure_target_policy_violation_403() -> None:
    async with AgentServer(port=0, auth_token="secret-token", allow_private=False) as server:
        payload = {
            "protocol_version": 1,
            "request_id": "req-blocked",
            "probe": "tcp_connect",
            "target": {"host": "127.0.0.1", "port": 80},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 403
        assert parsed["error"] == "forbidden"
        assert parsed["request_id"] == "req-blocked"

@pytest.mark.asyncio
async def test_measure_hostname_resolving_prohibited_403() -> None:
    def fake_resolver(hostname: str) -> list[str]:
        return ["93.184.216.34", "127.0.0.1"]

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        allow_private=False,
        resolver=fake_resolver,
    ) as server:
        payload = {
            "protocol_version": 1,
            "request_id": "req-mixed",
            "probe": "tcp_connect",
            "target": {"host": "example.com", "port": 80},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 403
        assert parsed["error"] == "forbidden"

@pytest.mark.asyncio
async def test_measure_hostname_resolution_failure_400() -> None:
    def failing_resolver(hostname: str) -> list[str]:
        raise TargetResolutionError("DNS resolution failed for test host")

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        allow_private=False,
        resolver=failing_resolver,
    ) as server:
        payload = {
            "protocol_version": 1,
            "probe": "tcp_connect",
            "target": {"host": "nonexistent.test", "port": 80},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 400
        assert parsed["error"] == "resolution_error"

@pytest.mark.asyncio
async def test_measure_unknown_probe_404() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        payload = {
            "protocol_version": 1,
            "probe": "invalid_probe",
            "target": {"host": "example.com", "port": 80},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 404
        assert parsed["error"] == "unknown_probe"

@pytest.mark.asyncio
async def test_measure_client_supplied_connect_ip_400() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        payload = {
            "protocol_version": 1,
            "probe": "tcp_connect",
            "target": {"host": "example.com", "port": 80},
            "config": {"connect_ip": "1.2.3.4"},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 400
        assert parsed["error"] == "invalid_config"

@pytest.mark.asyncio
async def test_measure_tcp_connect_success_with_pinned_ip() -> None:
    class MockTcpProbe(Probe):
        name = "tcp_connect"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            assert config is not None
            assert config.get("connect_ip") == "93.184.216.34"
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=4.2,
                metrics={"rtt_ms": 4.2},
                details={},
            )

    registry = ProbeRegistry()
    registry.register(MockTcpProbe())
    test_engine = ProbeEngine(registry=registry)

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        engine=test_engine,
    ) as server:
        payload = {
            "protocol_version": 1,
            "request_id": "req-tcp-ok",
            "probe": "tcp_connect",
            "target": {"host": "93.184.216.34", "port": 80},
            "config": {"timeout_s": 5.0},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 200
        assert parsed["protocol_version"] == 1
        assert parsed["request_id"] == "req-tcp-ok"
        assert parsed["status"] == "completed"
        result = parsed["result"]
        assert result["probe"] == "tcp_connect"
        assert result["status"] == "success"
        assert result["metrics"]["rtt_ms"] == 4.2

@pytest.mark.asyncio
async def test_measure_probe_failure_represented_in_200() -> None:
    class FailingProbe(Probe):
        name = "tcp_connect"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.FAILED,
                started_at=datetime.now(timezone.utc),
                duration_ms=1.5,
                error="Connection refused",
            )

    registry = ProbeRegistry()
    registry.register(FailingProbe())
    test_engine = ProbeEngine(registry=registry)

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        engine=test_engine,
    ) as server:
        payload = {
            "protocol_version": 1,
            "request_id": "req-failed-probe",
            "probe": "tcp_connect",
            "target": {"host": "93.184.216.34", "port": 80},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 200
        assert parsed["status"] == "completed"
        result = parsed["result"]
        assert result["status"] == "failed"
        assert result["error"] == "Connection refused"

@pytest.mark.asyncio
async def test_measure_probe_timeout_represented_in_200() -> None:
    class TimeoutProbe(Probe):
        name = "tcp_connect"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.TIMEOUT,
                started_at=datetime.now(timezone.utc),
                duration_ms=100.0,
                error="Connection timed out",
            )

    registry = ProbeRegistry()
    registry.register(TimeoutProbe())
    test_engine = ProbeEngine(registry=registry)

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        engine=test_engine,
    ) as server:
        payload = {
            "protocol_version": 1,
            "request_id": "req-timeout-probe",
            "probe": "tcp_connect",
            "target": {"host": "93.184.216.34", "port": 80},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 200
        assert parsed["status"] == "completed"
        result = parsed["result"]
        assert result["status"] == "timeout"
        assert result["error"] == "Connection timed out"

@pytest.mark.asyncio
async def test_measure_retains_logical_target_identity_for_tls_and_http() -> None:
    class IdentityCheckProbe(Probe):
        name = "http_request"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            assert target.host == "service.internal.test"
            assert target.port == 8443
            assert config is not None
            assert config.get("connect_ip") == "10.10.1.20"
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=12.0,
                metrics={"ttfb_ms": 10.0},
                details={"status_code": 200},
            )

    registry = ProbeRegistry()
    registry.register(IdentityCheckProbe())
    test_engine = ProbeEngine(registry=registry)

    def resolver_private(host: str) -> list[str]:
        return ["10.10.1.20"]

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        allow_private=True,
        engine=test_engine,
        resolver=resolver_private,
    ) as server:
        payload = {
            "protocol_version": 1,
            "request_id": "req-identity",
            "probe": "http_request",
            "target": {"host": "service.internal.test", "port": 8443},
            "config": {"use_tls": True, "path": "/healthz"},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 200
        assert parsed["status"] == "completed"
        result = parsed["result"]
        assert result["target"]["host"] == "service.internal.test"
        assert result["target"]["port"] == 8443

@pytest.mark.asyncio
async def test_measure_dns_resolve_does_not_pin_ip() -> None:
    class MockDnsProbe(Probe):
        name = "dns_resolve"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            assert "connect_ip" not in (config or {})
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=10.0,
                metrics={"resolution_time_ms": 10.0},
                details={"addresses": ["1.2.3.4"]},
            )

    registry = ProbeRegistry()
    registry.register(MockDnsProbe())
    test_engine = ProbeEngine(registry=registry)

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        engine=test_engine,
    ) as server:
        payload = {
            "protocol_version": 1,
            "request_id": "dns-req-1",
            "probe": "dns_resolve",
            "target": {"host": "example.com"},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 200
        assert parsed["status"] == "completed"
        assert parsed["result"]["status"] == "success"

@pytest.mark.asyncio
async def test_measure_concurrency_limit_429() -> None:
    block_event = asyncio.Event()

    class BlockingProbe(Probe):
        name = "tcp_connect"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            await block_event.wait()
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=5.0,
            )

    registry = ProbeRegistry()
    registry.register(BlockingProbe())
    test_engine = ProbeEngine(registry=registry)

    def resolver_ok(host: str) -> list[str]:
        return ["93.184.216.34"]

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        max_concurrency=1,
        engine=test_engine,
        resolver=resolver_ok,
    ) as server:
        payload = {
            "protocol_version": 1,
            "probe": "tcp_connect",
            "target": {"host": "example.com", "port": 80},
        }

        task1 = asyncio.create_task(post_measure_json(server, payload))
        await asyncio.sleep(0.05)
        assert server.active_measurements == 1

        code2, _, parsed2 = await post_measure_json(server, payload)
        assert code2 == 429
        assert parsed2["error"] == "too_many_requests"

        block_event.set()
        code1, _, parsed1 = await task1
        assert code1 == 200
        assert server.active_measurements == 0

@pytest.mark.asyncio
async def test_measure_outer_execution_timeout_504() -> None:
    class HangingProbe(Probe):
        name = "tcp_connect"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            await asyncio.sleep(1.0)
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=1.0,
            )

    registry = ProbeRegistry()
    registry.register(HangingProbe())
    test_engine = ProbeEngine(registry=registry)

    def resolver_ok(host: str) -> list[str]:
        return ["93.184.216.34"]

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        outer_timeout_slack_s=0.05,
        engine=test_engine,
        resolver=resolver_ok,
    ) as server:
        payload = {
            "protocol_version": 1,
            "request_id": "req-timeout",
            "probe": "tcp_connect",
            "target": {"host": "example.com", "port": 80},
            "config": {"timeout_s": 0.05},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 504
        assert parsed["error"] == "gateway_timeout"
        assert parsed["request_id"] == "req-timeout"

@pytest.mark.asyncio
async def test_measure_engine_internal_error_500() -> None:
    class CrashingProbe(Probe):
        name = "tcp_connect"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            raise RuntimeError("Database exploded")

    registry = ProbeRegistry()
    registry.register(CrashingProbe())
    test_engine = ProbeEngine(registry=registry)

    def resolver_ok(host: str) -> list[str]:
        return ["93.184.216.34"]

    async with AgentServer(
        port=0,
        auth_token="secret-token",
        engine=test_engine,
        resolver=resolver_ok,
    ) as server:
        payload = {
            "protocol_version": 1,
            "request_id": "req-crash",
            "probe": "tcp_connect",
            "target": {"host": "example.com", "port": 80},
        }
        code, _, parsed = await post_measure_json(server, payload)
        assert code == 500
        assert parsed["error"] == "internal_error"
        assert "Database exploded" not in str(parsed)
        assert parsed["request_id"] == "req-crash"

@pytest.mark.asyncio
async def test_client_disconnect_handling() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        reader, writer = await asyncio.open_connection(server.host, server.port)
        writer.write(b"POST /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        writer.close()
        await writer.wait_closed()
        raw_req = f"GET /v1/health HTTP/1.1\r\nHost: {server.host}:{server.port}\r\n\r\n".encode("iso-8859-1")
        code, _, body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 200

def test_server_bind_rejects_invalid_connection_parameters() -> None:
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", max_connections=0)
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", max_connections=-5)
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", max_connections=True)
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", shutdown_grace_s=-1.0)
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", shutdown_grace_s=True)
    with pytest.raises(ValueError):
        AgentServer(auth_token="secret", shutdown_grace_s=float("nan"))

def test_server_allow_private_strict_boolean_validation() -> None:
    s1 = AgentServer(auth_token="secret", allow_private=True)
    assert s1.allow_private is True
    s2 = AgentServer(auth_token="secret", allow_private=False)
    assert s2.allow_private is False

    invalid_values = ["false", "true", 0, 1, None, [], {}, 0.0]
    for val in invalid_values:
        with pytest.raises(ValueError, match="allow_private must be a boolean"):
            AgentServer(auth_token="secret", allow_private=val)  # type: ignore[arg-type]

@pytest.mark.asyncio
async def test_server_graceful_shutdown_allows_active_measurement_to_finish() -> None:
    class SlowProbe(Probe):
        name = "tcp_connect"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            await asyncio.sleep(0.08)
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=80.0,
            )

    registry = ProbeRegistry()
    registry.register(SlowProbe())
    test_engine = ProbeEngine(registry=registry)

    def resolver_ok(host: str) -> list[str]:
        return ["93.184.216.34"]

    server = AgentServer(
        port=0,
        auth_token="secret-token",
        shutdown_grace_s=0.5,
        engine=test_engine,
        resolver=resolver_ok,
    )
    await server.start()

    payload = {
        "protocol_version": 1,
        "request_id": "req-grace-ok",
        "probe": "tcp_connect",
        "target": {"host": "example.com", "port": 80},
    }

    measure_task = asyncio.create_task(post_measure_json(server, payload))
    await asyncio.sleep(0.02)
    assert server.active_measurements == 1

    await server.close()

    code, _, parsed = await measure_task
    assert code == 200
    assert parsed["status"] == "completed"
    assert parsed["result"]["status"] == "success"
    assert server.active_measurements == 0
    assert not server.is_running

@pytest.mark.asyncio
async def test_server_graceful_shutdown_cancels_measurement_after_grace_period() -> None:
    class HangingProbe(Probe):
        name = "tcp_connect"

        async def run(self, target: Target, config: dict[str, Any] | None = None) -> ProbeResult:
            await asyncio.sleep(2.0)
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=2000.0,
            )

    registry = ProbeRegistry()
    registry.register(HangingProbe())
    test_engine = ProbeEngine(registry=registry)

    def resolver_ok(host: str) -> list[str]:
        return ["93.184.216.34"]

    server = AgentServer(
        port=0,
        auth_token="secret-token",
        shutdown_grace_s=0.05,
        engine=test_engine,
        resolver=resolver_ok,
    )
    await server.start()

    payload = {
        "protocol_version": 1,
        "request_id": "req-grace-cancel",
        "probe": "tcp_connect",
        "target": {"host": "example.com", "port": 80},
    }

    measure_task = asyncio.create_task(post_measure_json(server, payload))
    await asyncio.sleep(0.02)
    assert server.active_measurements == 1

    start_time = asyncio.get_running_loop().time()
    await server.close()
    elapsed = asyncio.get_running_loop().time() - start_time

    assert elapsed < 0.5
    assert server.active_measurements == 0
    assert not server.is_running

    try:
        await measure_task
    except Exception:
        pass

@pytest.mark.asyncio
async def test_server_shutdown_cancels_idle_connections_immediately() -> None:
    server = AgentServer(port=0, auth_token="secret-token", shutdown_grace_s=2.0)
    await server.start()

    reader, writer = await asyncio.open_connection(server.host, server.port)
    await asyncio.sleep(0.02)
    assert server.active_connections == 1

    start_time = asyncio.get_running_loop().time()
    await server.close()
    elapsed = asyncio.get_running_loop().time() - start_time

    assert elapsed < 0.2
    assert server.active_connections == 0

    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
async def test_server_connection_limit_rejects_excess_connections_without_task_creation() -> None:
    async with AgentServer(port=0, auth_token="secret-token", max_connections=2) as server:
        r1, w1 = await asyncio.open_connection(server.host, server.port)
        r2, w2 = await asyncio.open_connection(server.host, server.port)
        await asyncio.sleep(0.02)
        assert server.active_connections == 2
        assert len(server._active_tasks) == 2

        r3, w3 = await asyncio.open_connection(server.host, server.port)
        resp3 = await r3.read()
        assert resp3 == b""
        assert len(server._active_tasks) == 2
        assert server.active_connections == 2
        w3.close()
        await w3.wait_closed()

        w1.close()
        await w1.wait_closed()
        await asyncio.sleep(0.02)
        assert server.active_connections == 1
        assert len(server._active_tasks) == 1

        raw_req = f"GET /v1/health HTTP/1.1\r\nHost: {server.host}:{server.port}\r\n\r\n".encode("iso-8859-1")
        code, _, body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 200
        assert json.loads(body.decode("utf-8")) == {"status": "ok"}

        w2.close()
        await w2.wait_closed()

@pytest.mark.asyncio
async def test_server_rejects_connections_during_shutdown_synchronously() -> None:
    server = AgentServer(port=0, auth_token="secret-token")
    await server.start()
    server._is_shutting_down = True

    r, w = await asyncio.open_connection(server.host, server.port)
    resp = await r.read()
    assert resp == b""
    assert len(server._active_tasks) == 0
    w.close()
    await w.wait_closed()

    server._is_shutting_down = False
    await server.close()

@pytest.mark.asyncio
async def test_server_rejects_bare_lf_and_malformed_headers() -> None:
    async with AgentServer(port=0, auth_token="secret-token") as server:
        bare_lf_req = f"GET /v1/health HTTP/1.1\nHost: {server.host}:{server.port}\n\n".encode("iso-8859-1")
        code1, _, _ = await send_raw_request(server.host, server.port, bare_lf_req)
        assert code1 == 400

        ws_colon_req = f"GET /v1/health HTTP/1.1\r\nHost : {server.host}:{server.port}\r\n\r\n".encode("iso-8859-1")
        code2, _, body2 = await send_raw_request(server.host, server.port, ws_colon_req)
        assert code2 == 400
        assert b"bad_request" in body2

@pytest.mark.asyncio
async def test_server_error_sanitization_does_not_leak_secrets() -> None:
    secret = "test-secret-must-not-leak"
    valid_token = "valid-agent-token"

    async with AgentServer(port=0, auth_token=valid_token) as server:
        raw_ws_colon = (
            f"GET /v1/health HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization : Bearer {secret}\r\n\r\n"
        ).encode("iso-8859-1")
        code1, _, body1 = await send_raw_request(server.host, server.port, raw_ws_colon)
        assert code1 == 400
        assert secret.encode("utf-8") not in body1
        assert b"bad_request" in body1
        parsed1 = json.loads(body1.decode("utf-8"))
        assert parsed1["message"] == "Whitespace before colon is not allowed"

        raw_missing_colon = (
            f"GET /v1/health HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization Bearer {secret}\r\n\r\n"
        ).encode("iso-8859-1")
        code2, _, body2 = await send_raw_request(server.host, server.port, raw_missing_colon)
        assert code2 == 400
        assert secret.encode("utf-8") not in body2
        assert b"bad_request" in body2
        parsed2 = json.loads(body2.decode("utf-8"))
        assert parsed2["message"] == "Malformed header line (missing colon)"

        raw_bad_cl = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization: Bearer {valid_token}\r\n"
            f"Content-Length: {secret}\r\n\r\n"
        ).encode("iso-8859-1")
        code3, _, body3 = await send_raw_request(server.host, server.port, raw_bad_cl)
        assert code3 == 400
        assert secret.encode("utf-8") not in body3
        assert b"bad_request" in body3
        parsed3 = json.loads(body3.decode("utf-8"))
        assert parsed3["message"] == "Invalid Content-Length header value"

        raw_dup_hdr = (
            f"GET /v1/health HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"X-Secret-Header: {secret}\r\n"
            f"x-secret-header: {secret}\r\n\r\n"
        ).encode("iso-8859-1")
        code4, _, body4 = await send_raw_request(server.host, server.port, raw_dup_hdr)
        assert code4 == 400
        assert secret.encode("utf-8") not in body4
        assert b"bad_request" in body4
        parsed4 = json.loads(body4.decode("utf-8"))
        assert parsed4["message"] == "Duplicate header"

        raw_bad_req_line = (
            f"GET /v1/health?key={secret} HTTP/1.1 EXTRA\r\n"
            f"Host: {server.host}:{server.port}\r\n\r\n"
        ).encode("iso-8859-1")
        code5, _, body5 = await send_raw_request(server.host, server.port, raw_bad_req_line)
        assert code5 == 400
        assert secret.encode("utf-8") not in body5
        assert b"bad_request" in body5
        parsed5 = json.loads(body5.decode("utf-8"))
        assert parsed5["message"] == "Malformed HTTP request line"

        raw_valid = (
            f"GET /v1/health HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization: Bearer {valid_token}\r\n\r\n"
        ).encode("iso-8859-1")
        code6, _, body6 = await send_raw_request(server.host, server.port, raw_valid)
        assert code6 == 200
        assert json.loads(body6.decode("utf-8")) == {"status": "ok"}

        raw_invalid_auth = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization: Bearer wrong-{secret}\r\n"
            f"Content-Length: 2\r\n\r\n"
            f"{{}}"
        ).encode("iso-8859-1")
        code7, _, body7 = await send_raw_request(server.host, server.port, raw_invalid_auth)
        assert code7 == 401
        assert secret.encode("utf-8") not in body7
        assert valid_token.encode("utf-8") not in body7
        parsed7 = json.loads(body7.decode("utf-8"))
        assert parsed7["error"] == "unauthorized"
        assert parsed7["message"] == "Missing or invalid bearer token"

@pytest.mark.asyncio
async def test_server_measure_tls_handshake_with_sni_and_no_sni() -> None:
    from unittest.mock import AsyncMock, patch
    token = "secret-token"
    async with AgentServer(port=0, auth_token=token, resolver=lambda _: ["45.13.119.236"]) as server:
        mock_result_sni = ProbeResult(
            probe="tls_handshake",
            target=Target(host="con.acp.us.ci", port=443),
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=40.0,
            metrics={"connect_ms": 10.0, "handshake_ms": 30.0, "total_ms": 40.0},
            details={"handshake_completed": True, "sni": "custom.sni.org"},
        )
        with patch.object(server.engine, "run", AsyncMock(return_value=mock_result_sni)) as mock_run:
            payload_sni = {
                "protocol_version": 1,
                "probe": "tls_handshake",
                "target": {"host": "con.acp.us.ci", "port": 443},
                "config": {"sni": "custom.sni.org"},
            }
            body = json.dumps(payload_sni).encode("utf-8")
            raw_req = (
                f"POST /v1/measure HTTP/1.1\r\n"
                f"Host: {server.host}:{server.port}\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode("iso-8859-1") + body

            code, _, resp_body = await send_raw_request(server.host, server.port, raw_req)
            assert code == 200
            data = json.loads(resp_body.decode("utf-8"))
            assert data["status"] == "completed"
            assert data["result"]["details"]["sni"] == "custom.sni.org"
            assert data["result"]["details"]["handshake_completed"] is True
            assert mock_run.call_args[0][2]["sni"] == "custom.sni.org"

        mock_result_no_sni = ProbeResult(
            probe="tls_handshake",
            target=Target(host="con.acp.us.ci", port=443),
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=40.0,
            metrics={"connect_ms": 10.0, "handshake_ms": 30.0, "total_ms": 40.0},
            details={"handshake_completed": True, "sni": None},
        )
        with patch.object(server.engine, "run", AsyncMock(return_value=mock_result_no_sni)) as mock_run:
            payload_no_sni = {
                "protocol_version": 1,
                "probe": "tls_handshake",
                "target": {"host": "con.acp.us.ci", "port": 443},
                "config": {"no_sni": True},
            }
            body = json.dumps(payload_no_sni).encode("utf-8")
            raw_req = (
                f"POST /v1/measure HTTP/1.1\r\n"
                f"Host: {server.host}:{server.port}\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode("iso-8859-1") + body

            code, _, resp_body = await send_raw_request(server.host, server.port, raw_req)
            assert code == 200
            data = json.loads(resp_body.decode("utf-8"))
            assert data["status"] == "completed"
            assert data["result"]["details"]["sni"] is None
            assert data["result"]["details"]["handshake_completed"] is True
            assert mock_run.call_args[0][2]["no_sni"] is True

        payload_connect_ip = {
            "protocol_version": 1,
            "probe": "tls_handshake",
            "target": {"host": "con.acp.us.ci", "port": 443},
            "config": {"connect_ip": "1.2.3.4"},
        }
        body = json.dumps(payload_connect_ip).encode("utf-8")
        raw_req = (
            f"POST /v1/measure HTTP/1.1\r\n"
            f"Host: {server.host}:{server.port}\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("iso-8859-1") + body

        code, _, resp_body = await send_raw_request(server.host, server.port, raw_req)
        assert code == 400
        data = json.loads(resp_body.decode("utf-8"))
        assert data["error"] == "invalid_config"
        assert "connect_ip" in data["message"]

