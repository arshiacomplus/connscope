
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import io
import json
from unittest.mock import patch
import pytest

from connscope.agent import (
    ClientConfigurationError,
    RemoteAgentClient,
    RemoteAuthenticationError,
    RemoteConnectionError,
    RemoteHttpError,
    RemotePolicyError,
    RemoteProtocolError,
    RemoteTimeoutError,
    RemoteUnavailableError,
)
from connscope.agent.server import AgentServer
from connscope.cli.main import (
    ExitCode,
    cli_entry,
    resolve_remote_config,
)
from connscope.core import (
    Probe,
    ProbeEngine,
    ProbeRegistry,
    ProbeResult,
    ProbeStatus,
    Target,
)

class DummyProbe(Probe):

    name = "tcp_connect"

    def __init__(self, status: ProbeStatus = ProbeStatus.SUCCESS, error: str | None = None) -> None:
        self.status = status
        self.error = error
        self.call_count = 0
        self.last_target: Target | None = None
        self.last_config: dict | None = None

    async def run(self, target: Target, config: dict | None = None) -> ProbeResult:
        self.call_count += 1
        self.last_target = target
        self.last_config = config
        return ProbeResult(
            probe=self.name,
            target=target,
            status=self.status,
            started_at=datetime.now(timezone.utc),
            duration_ms=10.0,
            metrics={"rtt_ms": 10.0},
            details={"local_executed": True},
            error=self.error,
        )

class TestRemoteConfigurationPrecedence:

    def test_both_unset_preserves_local_behavior(self) -> None:
        node, token = resolve_remote_config(None, None, env={})
        assert node is None
        assert token is None

    def test_empty_env_vars_preserve_local_behavior(self) -> None:
        node, token = resolve_remote_config(
            None,
            None,
            env={"CONNSCOPE_AGENT_URL": "", "CONNSCOPE_AGENT_TOKEN": "   "},
        )
        assert node is None
        assert token is None

    def test_cli_options_take_precedence_over_env_vars(self) -> None:
        env = {
            "CONNSCOPE_AGENT_URL": "https://env.example.com",
            "CONNSCOPE_AGENT_TOKEN": "env-token-123",
        }
        node, token = resolve_remote_config(
            "https://cli.example.com:8443",
            "cli-token-456",
            env=env,
        )
        assert node == "https://cli.example.com:8443"
        assert token == "cli-token-456"

    def test_cli_node_with_env_token(self) -> None:
        env = {"CONNSCOPE_AGENT_TOKEN": "env-token-123"}
        node, token = resolve_remote_config("https://cli.example.com", None, env=env)
        assert node == "https://cli.example.com"
        assert token == "env-token-123"

    def test_env_node_with_cli_token(self) -> None:
        env = {"CONNSCOPE_AGENT_URL": "https://env.example.com"}
        node, token = resolve_remote_config(None, "cli-token-456", env=env)
        assert node == "https://env.example.com"
        assert token == "cli-token-456"

    def test_env_vars_used_when_cli_omitted(self) -> None:
        env = {
            "CONNSCOPE_AGENT_URL": "http://127.0.0.1:8000",
            "CONNSCOPE_AGENT_TOKEN": "my-secret-token",
        }
        node, token = resolve_remote_config(None, None, env=env)
        assert node == "http://127.0.0.1:8000"
        assert token == "my-secret-token"

    def test_missing_token_when_node_configured_via_cli(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        code = cli_entry(
            ["run", "tcp", "example.com:443", "--node", "http://127.0.0.1:8000"],
            stdout=out,
            stderr=err,
            env={},
        )
        assert code == ExitCode.USAGE_ERROR
        assert out.getvalue() == ""
        assert "Remote node URL configured without an authentication token" in err.getvalue()

    def test_missing_token_when_node_configured_via_env(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        code = cli_entry(
            ["run", "tcp", "example.com:443"],
            stdout=out,
            stderr=err,
            env={"CONNSCOPE_AGENT_URL": "http://127.0.0.1:8000"},
        )
        assert code == ExitCode.USAGE_ERROR
        assert out.getvalue() == ""
        assert "Remote node URL configured without an authentication token" in err.getvalue()

    def test_token_without_node_configured_via_cli(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        code = cli_entry(
            ["run", "tcp", "example.com:443", "--token", "secret-token"],
            stdout=out,
            stderr=err,
            env={},
        )
        assert code == ExitCode.USAGE_ERROR
        assert out.getvalue() == ""
        assert "Authentication token provided without a remote node URL" in err.getvalue()

    def test_token_without_node_configured_via_env(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        code = cli_entry(
            ["run", "tcp", "example.com:443"],
            stdout=out,
            stderr=err,
            env={"CONNSCOPE_AGENT_TOKEN": "secret-token"},
        )
        assert code == ExitCode.USAGE_ERROR
        assert out.getvalue() == ""
        assert "Authentication token provided without a remote node URL" in err.getvalue()

    def test_explicit_empty_node_cli_does_not_fall_back_to_env(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        reg = ProbeRegistry()
        mock_probe = DummyProbe()
        reg.register(mock_probe)

        code = cli_entry(
            ["run", "tcp", "example.com:443", "--node", ""],
            stdout=out,
            stderr=err,
            registry=reg,
            env={
                "CONNSCOPE_AGENT_URL": "http://127.0.0.1:8000",
                "CONNSCOPE_AGENT_TOKEN": "env-secret-token",
            },
        )
        assert code == ExitCode.USAGE_ERROR
        assert out.getvalue() == ""
        assert "Remote node URL cannot be empty" in err.getvalue()
        assert mock_probe.call_count == 0

    def test_explicit_empty_token_cli_does_not_fall_back_to_env(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        reg = ProbeRegistry()
        mock_probe = DummyProbe()
        reg.register(mock_probe)

        code = cli_entry(
            ["run", "tcp", "example.com:443", "--token", "   "],
            stdout=out,
            stderr=err,
            registry=reg,
            env={
                "CONNSCOPE_AGENT_URL": "http://127.0.0.1:8000",
                "CONNSCOPE_AGENT_TOKEN": "env-secret-token",
            },
        )
        assert code == ExitCode.USAGE_ERROR
        assert out.getvalue() == ""
        assert "Remote authentication token cannot be empty" in err.getvalue()
        assert mock_probe.call_count == 0

    def test_explicit_empty_node_cli_without_env_rejected(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        reg = ProbeRegistry()
        mock_probe = DummyProbe()
        reg.register(mock_probe)

        code = cli_entry(
            ["run", "tcp", "example.com:443", "--node", ""],
            stdout=out,
            stderr=err,
            registry=reg,
            env={},
        )
        assert code == ExitCode.USAGE_ERROR
        assert out.getvalue() == ""
        assert "Remote node URL cannot be empty" in err.getvalue()
        assert mock_probe.call_count == 0

    def test_explicit_empty_token_cli_without_env_rejected(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        reg = ProbeRegistry()
        mock_probe = DummyProbe()
        reg.register(mock_probe)

        code = cli_entry(
            ["run", "tcp", "example.com:443", "--token", ""],
            stdout=out,
            stderr=err,
            registry=reg,
            env={},
        )
        assert code == ExitCode.USAGE_ERROR
        assert out.getvalue() == ""
        assert "Remote authentication token cannot be empty" in err.getvalue()
        assert mock_probe.call_count == 0

class TestExecutionRouting:

    def test_local_execution_when_no_remote_configured(self) -> None:
        reg = ProbeRegistry()
        mock_probe = DummyProbe(status=ProbeStatus.SUCCESS)
        reg.register(mock_probe)

        out = io.StringIO()
        err = io.StringIO()
        code = cli_entry(
            ["run", "tcp", "example.com:443"],
            stdout=out,
            stderr=err,
            registry=reg,
            env={},
        )

        assert code == ExitCode.OK
        assert err.getvalue() == ""
        assert mock_probe.call_count == 1
        assert "local_executed: True" in out.getvalue()

    def test_remote_execution_selected_via_cli_flags(self) -> None:
        reg = ProbeRegistry()
        local_probe = DummyProbe()
        reg.register(local_probe)

        remote_result = ProbeResult(
            probe="tcp_connect",
            target=Target(host="example.com", port=443),
            status=ProbeStatus.SUCCESS,
            started_at=datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc),
            duration_ms=25.0,
            metrics={"rtt_ms": 25.0},
            details={"remote_node": "agent-1"},
            error=None,
        )

        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.return_value = remote_result

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "my-token-123",
                ],
                stdout=out,
                stderr=err,
                registry=reg,
                env={},
            )

            assert code == ExitCode.OK
            assert err.getvalue() == ""
            assert local_probe.call_count == 0
            mock_client_cls.assert_called_once_with(
                node_url="http://127.0.0.1:8000",
                token="my-token-123",
                timeout_s=pytest.approx(30.0),
            )
            mock_client.measure.assert_called_once_with(
                "tcp_connect",
                Target(host="example.com", port=443),
                {},
            )
            val = out.getvalue()
            assert "Probe:    tcp_connect" in val
            assert "Status:   success" in val
            assert "remote_node: agent-1" in val

    def test_remote_execution_selected_via_env_vars(self) -> None:
        reg = ProbeRegistry()
        local_probe = DummyProbe()
        reg.register(local_probe)

        remote_result = ProbeResult(
            probe="tcp_connect",
            target=Target(host="example.com", port=443),
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=5.0,
            metrics={"rtt_ms": 5.0},
            details={},
            error=None,
        )

        out = io.StringIO()
        err = io.StringIO()
        env = {
            "CONNSCOPE_AGENT_URL": "https://agent.example.com",
            "CONNSCOPE_AGENT_TOKEN": "env-bearer-token",
        }

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.return_value = remote_result

            code = cli_entry(
                ["run", "tcp", "example.com:443"],
                stdout=out,
                stderr=err,
                registry=reg,
                env=env,
            )

            assert code == ExitCode.OK
            assert local_probe.call_count == 0
            mock_client_cls.assert_called_once_with(
                node_url="https://agent.example.com",
                token="env-bearer-token",
                timeout_s=pytest.approx(30.0),
            )
            mock_client.measure.assert_called_once_with(
                "tcp_connect",
                Target(host="example.com", port=443),
                {},
            )

    def test_remote_failure_never_falls_back_to_local(self) -> None:
        reg = ProbeRegistry()
        local_probe = DummyProbe(status=ProbeStatus.SUCCESS)
        reg.register(local_probe)

        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemoteConnectionError("Connection refused by agent")

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "test-token",
                ],
                stdout=out,
                stderr=err,
                registry=reg,
                env={},
            )

            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "Connection to remote agent failed" in err.getvalue() or "Connection refused" in err.getvalue()
            assert local_probe.call_count == 0

class TestRemoteProbeResultStatuses:

    def test_remote_probe_failed_status_exits_with_code_1(self) -> None:
        remote_result = ProbeResult(
            probe="tcp_connect",
            target=Target(host="example.com", port=80),
            status=ProbeStatus.FAILED,
            started_at=datetime.now(timezone.utc),
            duration_ms=12.0,
            metrics={},
            details={},
            error="Connection reset by peer",
        )

        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.return_value = remote_result

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:80",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )

            assert code == ExitCode.FAILED
            assert err.getvalue() == ""
            val = out.getvalue()
            assert "Status:   failed" in val
            assert "Error: Connection reset by peer" in val

    def test_remote_probe_timeout_status_exits_with_code_2(self) -> None:
        remote_result = ProbeResult(
            probe="tls_handshake",
            target=Target(host="example.com", port=443),
            status=ProbeStatus.TIMEOUT,
            started_at=datetime.now(timezone.utc),
            duration_ms=5000.0,
            metrics={},
            details={},
            error="TLS handshake timed out after 5.0s",
        )

        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.return_value = remote_result

            code = cli_entry(
                [
                    "run",
                    "tls",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )

            assert code == ExitCode.TIMEOUT
            assert err.getvalue() == ""
            val = out.getvalue()
            assert "Status:   timeout" in val
            assert "Error: TLS handshake timed out after 5.0s" in val

class TestRemoteJsonOutput:

    def test_remote_success_json_output(self) -> None:
        remote_result = ProbeResult(
            probe="http_request",
            target=Target(host="example.com", port=443),
            status=ProbeStatus.SUCCESS,
            started_at=datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc),
            duration_ms=45.5,
            metrics={"ttfb_ms": 30.0, "status_code": 200.0},
            details={"proto": "HTTP/1.1"},
            error=None,
        )

        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.return_value = remote_result

            code = cli_entry(
                [
                    "run",
                    "http",
                    "https://example.com",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                    "--json",
                ],
                stdout=out,
                stderr=err,
                env={},
            )

            assert code == ExitCode.OK
            assert err.getvalue() == ""
            data = json.loads(out.getvalue())
            assert data["probe"] == "http_request"
            assert data["status"] == "success"
            assert data["target"] == {"host": "example.com", "port": 443}
            assert data["duration_ms"] == 45.5
            assert data["metrics"] == {"ttfb_ms": 30.0, "status_code": 200.0}
            assert data["details"] == {"proto": "HTTP/1.1"}
            assert data["error"] is None

    def test_remote_failed_json_output(self) -> None:
        remote_result = ProbeResult(
            probe="tcp_connect",
            target=Target(host="example.com", port=80),
            status=ProbeStatus.FAILED,
            started_at=datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc),
            duration_ms=10.0,
            metrics={},
            details={},
            error="Connection refused",
        )

        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.return_value = remote_result

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:80",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                    "--json",
                ],
                stdout=out,
                stderr=err,
                env={},
            )

            assert code == ExitCode.FAILED
            assert err.getvalue() == ""
            data = json.loads(out.getvalue())
            assert data["status"] == "failed"
            assert data["error"] == "Connection refused"

    def test_remote_failure_with_json_flag_leaves_stdout_empty(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemoteConnectionError("Agent unreachable")

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:80",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                    "--json",
                ],
                stdout=out,
                stderr=err,
                env={},
            )

            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "Error:" in err.getvalue()

class TestRemoteClientExceptionHandling:

    def test_client_configuration_error_exits_with_code_3(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        code = cli_entry(
            [
                "run",
                "tcp",
                "example.com:443",
                "--node",
                "https://agent.example.com?",
                "--token",
                "token-123",
            ],
            stdout=out,
            stderr=err,
            env={},
        )
        assert code == ExitCode.USAGE_ERROR
        assert out.getvalue() == ""
        assert "node_url must not contain query parameters" in err.getvalue()

    def test_remote_connection_error_exits_with_code_1(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemoteConnectionError("Connection to remote agent failed: [Errno 111] Connection refused")

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "Connection to remote agent failed" in err.getvalue()

    def test_remote_timeout_error_exits_with_code_2(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemoteTimeoutError("Timed out communicating with remote agent")

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.TIMEOUT
            assert out.getvalue() == ""
            assert "Timed out communicating with remote agent" in err.getvalue()

    def test_remote_gateway_timeout_exits_with_code_2(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemoteTimeoutError(
                "Remote agent returned HTTP 504",
                status_code=504,
                error_code="gateway_timeout",
            )

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.TIMEOUT
            assert out.getvalue() == ""
            assert "gateway timeout (HTTP 504)" in err.getvalue()

    def test_remote_auth_error_exits_with_code_1(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemoteAuthenticationError(
                "Remote agent returned HTTP 401",
                status_code=401,
                error_code="unauthorized",
            )

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "wrong-token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "Remote agent authentication failed (HTTP 401)" in err.getvalue()

    def test_remote_policy_error_exits_with_code_1(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemotePolicyError(
                "Remote agent returned HTTP 403",
                status_code=403,
                error_code="forbidden",
            )

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "security policy rejected measurement (HTTP 403)" in err.getvalue()

    def test_remote_unavailable_error_exits_with_code_1(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemoteUnavailableError(
                "Remote agent returned HTTP 503",
                status_code=503,
                error_code="service_unavailable",
            )

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "currently unavailable (HTTP 503)" in err.getvalue()

    def test_remote_protocol_error_exits_with_code_1(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemoteProtocolError("Malformed JSON response")

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "Remote agent protocol error: Malformed JSON response" in err.getvalue()

    def test_remote_http_error_generic_exits_with_code_1(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = RemoteHttpError(
                "Remote agent returned HTTP 500",
                status_code=500,
            )

            code = cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    "token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "Remote agent returned HTTP 500" in err.getvalue()

class TestSecretNonExposure:

    @pytest.mark.parametrize(
        "exception_factory",
        [
            lambda s: ClientConfigurationError("Invalid token format"),
            lambda s: RemoteAuthenticationError(f"HTTP 401 with secret {s}", status_code=401),
            lambda s: RemotePolicyError(f"HTTP 403 with secret {s}", status_code=403),
            lambda s: RemoteConnectionError(f"Connection failed: {s}"),
            lambda s: RemoteTimeoutError(f"Timeout with {s}"),
            lambda s: RemoteProtocolError(f"Protocol error with {s}"),
            lambda s: RemoteHttpError(f"HTTP 500 with {s}", status_code=500),
        ],
    )
    def test_secret_token_never_printed_on_remote_failure(self, exception_factory) -> None:
        secret_canary = "SUPER_SECRET_CANARY_TOKEN_XYZ_987654"

        out = io.StringIO()
        err = io.StringIO()

        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.side_effect = exception_factory(secret_canary)

            cli_entry(
                [
                    "run",
                    "tcp",
                    "example.com:443",
                    "--node",
                    "http://127.0.0.1:8000",
                    "--token",
                    secret_canary,
                ],
                stdout=out,
                stderr=err,
                env={},
            )

            captured_stdout = out.getvalue()
            captured_stderr = err.getvalue()

            assert secret_canary not in captured_stdout
            assert secret_canary not in captured_stderr

class TestInProcessAgentServerCliIntegration:

    @pytest.mark.asyncio
    async def test_cli_end_to_end_remote_measurement_success(self) -> None:
        class InProcessEchoProbe(Probe):
            name = "tcp_connect"

            async def run(self, target: Target, config: dict | None = None) -> ProbeResult:
                return ProbeResult(
                    probe=self.name,
                    target=target,
                    status=ProbeStatus.SUCCESS,
                    started_at=datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc),
                    duration_ms=18.5,
                    metrics={"rtt_ms": 18.5, "syn_ack_received": 1.0},
                    details={"family": "AF_INET"},
                    error=None,
                )

        registry = ProbeRegistry()
        registry.register(InProcessEchoProbe())
        engine = ProbeEngine(registry=registry)

        async with AgentServer(port=0, auth_token="integration-secret-token", engine=engine) as server:
            node_url = f"http://127.0.0.1:{server.port}"

            out = io.StringIO()
            err = io.StringIO()

            code = await asyncio.to_thread(
                cli_entry,
                [
                    "run",
                    "tcp",
                    "93.184.216.34:80",
                    "--node",
                    node_url,
                    "--token",
                    "integration-secret-token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )

            assert code == ExitCode.OK
            assert err.getvalue() == ""
            val = out.getvalue()
            assert "Probe:    tcp_connect" in val
            assert "Target:   93.184.216.34:80" in val
            assert "Status:   success" in val
            assert "Duration: 18.50 ms" in val

    @pytest.mark.asyncio
    async def test_cli_end_to_end_remote_auth_failure(self) -> None:
        async with AgentServer(port=0, auth_token="correct-secret-token") as server:
            node_url = f"http://127.0.0.1:{server.port}"

            out = io.StringIO()
            err = io.StringIO()

            code = await asyncio.to_thread(
                cli_entry,
                [
                    "run",
                    "tcp",
                    "93.184.216.34:80",
                    "--node",
                    node_url,
                    "--token",
                    "wrong-secret-token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )

            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "Remote agent authentication failed (HTTP 401)" in err.getvalue()

    @pytest.mark.asyncio
    async def test_cli_end_to_end_remote_policy_rejection(self) -> None:
        async with AgentServer(port=0, auth_token="correct-secret-token") as server:
            node_url = f"http://127.0.0.1:{server.port}"

            out = io.StringIO()
            err = io.StringIO()

            code = await asyncio.to_thread(
                cli_entry,
                [
                    "run",
                    "tcp",
                    "127.0.0.1:80",
                    "--node",
                    node_url,
                    "--token",
                    "correct-secret-token",
                ],
                stdout=out,
                stderr=err,
                env={},
            )

            assert code == ExitCode.FAILED
            assert out.getvalue() == ""
            assert "security policy rejected measurement (HTTP 403)" in err.getvalue()

    def test_remote_tls_passes_sni_to_client(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        remote_res = ProbeResult(
            probe="tls_handshake",
            target=Target(host="con.acp.us.ci", port=443),
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=50.0,
            metrics={"connect_ms": 20.0, "handshake_ms": 30.0, "total_ms": 50.0},
            details={"sni": "custom.sni.org", "handshake_completed": True},
        )
        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.return_value = remote_res
            code = cli_entry(
                [
                    "run",
                    "tls",
                    "con.acp.us.ci:443",
                    "--sni",
                    "custom.sni.org",
                    "--node",
                    "https://127.0.0.1:8000",
                    "--token",
                    "token-123",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.OK
            mock_client.measure.assert_called_once_with(
                "tls_handshake",
                Target(host="con.acp.us.ci", port=443),
                {"sni": "custom.sni.org"},
            )

    def test_remote_tls_passes_no_sni_to_client(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        remote_res = ProbeResult(
            probe="tls_handshake",
            target=Target(host="con.acp.us.ci", port=443),
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=50.0,
            metrics={"connect_ms": 20.0, "handshake_ms": 30.0, "total_ms": 50.0},
            details={"sni": None, "handshake_completed": True},
        )
        with patch("connscope.cli.main.RemoteAgentClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.measure.return_value = remote_res
            code = cli_entry(
                [
                    "run",
                    "tls",
                    "con.acp.us.ci:443",
                    "--no-sni",
                    "--node",
                    "https://127.0.0.1:8000",
                    "--token",
                    "token-123",
                ],
                stdout=out,
                stderr=err,
                env={},
            )
            assert code == ExitCode.OK
            mock_client.measure.assert_called_once_with(
                "tls_handshake",
                Target(host="con.acp.us.ci", port=443),
                {"no_sni": True},
            )

    @pytest.mark.asyncio
    async def test_cli_end_to_end_remote_tls_with_sni(self) -> None:
        from unittest.mock import AsyncMock

        async with AgentServer(port=0, auth_token="correct-secret-token", resolver=lambda _: ["45.13.119.236"]) as server:
            node_url = f"http://127.0.0.1:{server.port}"

            out = io.StringIO()
            err = io.StringIO()

            mock_result = ProbeResult(
                probe="tls_handshake",
                target=Target(host="con.acp.us.ci", port=443),
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=45.0,
                metrics={"connect_ms": 15.0, "handshake_ms": 30.0, "total_ms": 45.0},
                details={"handshake_completed": True, "sni": "custom.sni.org"},
            )
            with patch.object(server.engine, "run", AsyncMock(return_value=mock_result)) as mock_run:
                code = await asyncio.to_thread(
                    cli_entry,
                    [
                        "run",
                        "tls",
                        "con.acp.us.ci:443",
                        "--sni",
                        "custom.sni.org",
                        "--node",
                        node_url,
                        "--token",
                        "correct-secret-token",
                        "--json",
                    ],
                    stdout=out,
                    stderr=err,
                    env={},
                )

                assert code == ExitCode.OK
                assert err.getvalue() == ""
                data = json.loads(out.getvalue())
                assert data["probe"] == "tls_handshake"
                assert data["status"] == "success"
                assert data["details"]["sni"] == "custom.sni.org"
                assert data["details"]["handshake_completed"] is True
                assert mock_run.call_args[0][0] == "tls_handshake"
                assert mock_run.call_args[0][2]["sni"] == "custom.sni.org"
                assert "connect_ip" in mock_run.call_args[0][2]

