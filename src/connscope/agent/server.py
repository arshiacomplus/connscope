import asyncio
import ipaddress
import math
from typing import Any, Callable, Sequence

from connscope.core import ProbeEngine, ProbeRegistry
from connscope.probes import register_builtin_probes
from connscope.serialization import result_to_dict

from .execution import (
    UnsupportedProbeError,
    UntrustedConfigError,
    prepare_probe_config,
)
from .protocol import (
    API_VERSION,
    DEFAULT_MAX_PROBE_TIMEOUT_S,
    DEFAULT_READ_TIMEOUT_S,
    MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    PERMITTED_REMOTE_ADAPTERS,
    PROHIBITED_REMOTE_ADAPTERS,
    PROTOCOL_VERSION,
    HttpError,
    format_error_response,
    format_json_response,
    parse_adapter_execute_request,
    parse_http_headers,
    parse_measure_request,
)
from .security import (
    TargetPolicyViolation,
    TargetResolutionError,
    extract_bearer_token,
    verify_bearer_token,
)

def validate_loopback_host(host: str) -> str:
    if not isinstance(host, str) or not host.strip():
        raise ValueError("Host must be a non-empty string loopback IP literal")

    cleaned = host.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]

    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(
            f"Bind host must be a loopback IP literal (e.g. '127.0.0.1', '::1'), not a hostname: {host!r}"
        ) from exc

    if not addr.is_loopback:
        raise ValueError(f"Bind host must be a loopback IP literal, got non-loopback address: {host!r}")

    return host.strip()

class AgentServer:

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        auth_token: str,
        allow_private: bool = False,
        max_concurrency: int = 10,
        read_timeout_s: float = DEFAULT_READ_TIMEOUT_S,
        max_probe_timeout_s: float = DEFAULT_MAX_PROBE_TIMEOUT_S,
        max_connections: int = 50,
        shutdown_grace_s: float = 10.0,
        outer_timeout_slack_s: float = 5.0,
        engine: ProbeEngine | None = None,
        resolver: Callable[[str], Sequence[str | ipaddress.IPv4Address | ipaddress.IPv6Address]] | None = None,
        allowlisted_adapters: Sequence[str] | frozenset[str] = (),
        allowed_execution_modes: Sequence[str] | frozenset[str] = ("local_proxy",),
        executable_versions: dict[str, str] | None = None,
        isolation_prerequisites: dict[str, Any] | None = None,
        adapter_registry: Any | None = None,
    ) -> None:
        self._configured_host = validate_loopback_host(host)

        if isinstance(port, bool) or not isinstance(port, int) or not (0 <= port <= 65535):
            raise ValueError(f"port must be an integer between 0 and 65535, got {port!r}")
        self._configured_port = port

        if not isinstance(auth_token, str) or not auth_token.strip():
            raise ValueError("auth_token must be a non-empty string")
        self.auth_token = auth_token

        if not isinstance(allow_private, bool):
            raise ValueError(
                f"allow_private must be a boolean, got {type(allow_private).__name__}: {allow_private!r}"
            )
        self.allow_private = allow_private

        if isinstance(max_connections, bool) or not isinstance(max_connections, int) or max_connections <= 0:
            raise ValueError("max_connections must be a positive integer")
        self.max_connections = max_connections

        if (
            isinstance(shutdown_grace_s, bool)
            or not isinstance(shutdown_grace_s, (int, float))
            or not math.isfinite(shutdown_grace_s)
            or shutdown_grace_s < 0
        ):
            raise ValueError("shutdown_grace_s must be a non-negative finite number")
        self.shutdown_grace_s = float(shutdown_grace_s)

        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int) or max_concurrency <= 0:
            raise ValueError("max_concurrency must be a positive integer")
        self.max_concurrency = max_concurrency

        if (
            isinstance(read_timeout_s, bool)
            or not isinstance(read_timeout_s, (int, float))
            or not math.isfinite(read_timeout_s)
            or read_timeout_s <= 0
        ):
            raise ValueError("read_timeout_s must be a positive finite number")
        self.read_timeout_s = float(read_timeout_s)

        if (
            isinstance(max_probe_timeout_s, bool)
            or not isinstance(max_probe_timeout_s, (int, float))
            or not math.isfinite(max_probe_timeout_s)
            or max_probe_timeout_s <= 0
        ):
            raise ValueError("max_probe_timeout_s must be a positive finite number")
        self.max_probe_timeout_s = float(max_probe_timeout_s)

        if (
            isinstance(outer_timeout_slack_s, bool)
            or not isinstance(outer_timeout_slack_s, (int, float))
            or not math.isfinite(outer_timeout_slack_s)
            or outer_timeout_slack_s < 0
        ):
            raise ValueError("outer_timeout_slack_s must be a non-negative finite number")
        self.outer_timeout_slack_s = float(outer_timeout_slack_s)

        if engine is None:
            registry = ProbeRegistry()
            register_builtin_probes(registry)
            self.engine = ProbeEngine(registry=registry)
        else:
            self.engine = engine

        self.resolver = resolver

        validated_allowlist: set[str] = set()
        for adp in allowlisted_adapters:
            if not isinstance(adp, str):
                raise ValueError(f"Allowlisted adapter must be a string, got {type(adp).__name__}")
            if adp in PROHIBITED_REMOTE_ADAPTERS:
                raise ValueError(
                    f"Layer-3 adapter '{adp}' is strictly prohibited from remote execution in Phase 20"
                )
            if adp not in PERMITTED_REMOTE_ADAPTERS:
                raise ValueError(
                    f"Adapter '{adp}' is not permitted for remote execution. Permitted adapters: {sorted(PERMITTED_REMOTE_ADAPTERS)}"
                )
            validated_allowlist.add(adp)
        self.allowlisted_adapters: frozenset[str] = frozenset(validated_allowlist)

        for mode in allowed_execution_modes:
            if mode != "local_proxy":
                raise ValueError(
                    f"Execution mode '{mode}' is not permitted for remote execution in Phase 20 (only 'local_proxy' permitted)"
                )
        self.allowed_execution_modes: tuple[str, ...] = tuple(allowed_execution_modes)

        self.executable_versions: dict[str, str] = dict(executable_versions or {})
        self.isolation_prerequisites: dict[str, Any] = dict(isolation_prerequisites or {})
        self.adapter_registry = adapter_registry

        self._server: asyncio.Server | None = None
        self._bound_host: str | None = None
        self._bound_port: int | None = None
        self._is_running: bool = False
        self._is_shutting_down: bool = False
        self._active_connections: int = 0
        self._active_measurements: int = 0
        self._active_tasks: set[asyncio.Task[Any]] = set()
        self._measurement_tasks: set[asyncio.Task[Any]] = set()
        self._active_writers: set[asyncio.StreamWriter] = set()

    @property
    def host(self) -> str:
        return self._bound_host if self._bound_host is not None else self._configured_host

    @property
    def port(self) -> int:
        return self._bound_port if self._bound_port is not None else self._configured_port

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def active_measurements(self) -> int:
        return self._active_measurements

    @property
    def active_connections(self) -> int:
        return self._active_connections

    @property
    def is_shutting_down(self) -> bool:
        return self._is_shutting_down

    async def start(self) -> None:
        if self._is_running:
            raise RuntimeError("AgentServer is already running")

        server = await asyncio.start_server(
            self._on_client_connected,
            self._configured_host,
            self._configured_port,
        )
        self._server = server
        self._is_running = True

        if server.sockets:
            sock = server.sockets[0]
            sockname = sock.getsockname()
            self._bound_host = sockname[0]
            self._bound_port = sockname[1]

    async def close(self) -> None:
        if not self._is_running or self._is_shutting_down:
            return
        self._is_shutting_down = True

        server_instance = self._server
        self._server = None

        if server_instance is not None:
            server_instance.close()

        idle_tasks = [t for t in self._active_tasks if t not in self._measurement_tasks and not t.done()]
        for t in idle_tasks:
            t.cancel()

        if self._measurement_tasks:
            pending = [t for t in self._measurement_tasks if not t.done()]
            if pending and self.shutdown_grace_s > 0:
                try:
                    await asyncio.wait(pending, timeout=self.shutdown_grace_s)
                except Exception:
                    pass

        remaining_tasks = [t for t in self._active_tasks if not t.done()]
        for t in remaining_tasks:
            t.cancel()

        if remaining_tasks:
            await asyncio.gather(*remaining_tasks, return_exceptions=True)

        for writer in list(self._active_writers):
            try:
                writer.close()
            except Exception:
                pass

        for writer in list(self._active_writers):
            try:
                await writer.wait_closed()
            except Exception:
                pass

        if server_instance is not None:
            try:
                await server_instance.wait_closed()
            except Exception:
                pass

        self._active_tasks.clear()
        self._measurement_tasks.clear()
        self._active_writers.clear()
        self._active_connections = 0
        self._is_running = False
        self._is_shutting_down = False

    async def serve_forever(self) -> None:
        if not self._is_running or self._server is None:
            raise RuntimeError("Server is not started")
        await self._server.serve_forever()

    async def __aenter__(self) -> "AgentServer":
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def _on_client_connected(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self._is_running or self._is_shutting_down:
            try:
                writer.close()
            except Exception:
                pass
            return

        if self._active_connections >= self.max_connections:
            try:
                writer.close()
            except Exception:
                pass
            return

        self._active_connections += 1
        self._active_writers.add(writer)

        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(self._handle_client(reader, writer))
            self._active_tasks.add(task)
            task.add_done_callback(self._active_tasks.discard)
        except Exception:
            self._active_connections = max(0, self._active_connections - 1)
            self._active_writers.discard(writer)
            try:
                writer.close()
            except Exception:
                pass
            raise

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        current_task = asyncio.current_task()
        req_id: str | None = None
        try:
            if not self._is_running or self._is_shutting_down:
                try:
                    err_bytes = format_error_response(503, "service_unavailable", "Server is shutting down")
                    writer.write(err_bytes)
                    await writer.drain()
                except Exception:
                    pass
                return

            raw_bytes = bytearray()
            header_bytes: bytes | None = None
            body_prefix: bytes = b""

            while True:
                delim_idx = raw_bytes.find(b"\r\n\r\n")
                if delim_idx != -1:
                    header_bytes = bytes(raw_bytes[:delim_idx])
                    body_prefix = bytes(raw_bytes[delim_idx + 4:])
                    if len(header_bytes) > MAX_HEADER_BYTES:
                        raise HttpError(413, "payload_too_large", "Header section exceeds maximum limit of 16 KiB")
                    break

                if b"\n\n" in raw_bytes:
                    raise HttpError(400, "bad_request", "Bare LF framing is not allowed: HTTP/1.1 requires CRLF line endings")

                if len(raw_bytes) > MAX_HEADER_BYTES:
                    raise HttpError(413, "payload_too_large", "Header section exceeds maximum limit of 16 KiB")

                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=self.read_timeout_s)
                except asyncio.TimeoutError as exc:
                    raise HttpError(408, "request_timeout", "Timed out waiting for request headers") from exc

                if not chunk:
                    if not raw_bytes:
                        return
                    raise HttpError(400, "bad_request", "Incomplete HTTP request headers: CRLF framing required")

                raw_bytes.extend(chunk)

            method, path, version, headers = parse_http_headers(header_bytes)
            clean_path = path.split("?")[0]

            if clean_path == "/v1/health":
                if method != "GET":
                    raise HttpError(
                        405,
                        "method_not_allowed",
                        f"Method '{method}' not allowed for {clean_path}",
                        headers={"Allow": "GET"},
                    )
                response_bytes = format_json_response(200, {"status": "ok"})

            elif clean_path == "/v1/capabilities":
                if method != "GET":
                    raise HttpError(
                        405,
                        "method_not_allowed",
                        f"Method '{method}' not allowed for {clean_path}",
                        headers={"Allow": "GET"},
                    )

                auth_header = headers.get("authorization")
                token = extract_bearer_token(auth_header)
                if not verify_bearer_token(token, self.auth_token):
                    raise HttpError(
                        401,
                        "unauthorized",
                        "Missing or invalid bearer token",
                        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                    )

                ops = ["measure_probe"]
                if self.allowlisted_adapters:
                    ops.append("execute_adapter")

                payload = {
                    "protocol_version": PROTOCOL_VERSION,
                    "api_version": API_VERSION,
                    "supported_operations": ops,
                    "allowlisted_adapters": sorted(list(self.allowlisted_adapters)),
                    "allowed_execution_modes": sorted(list(self.allowed_execution_modes)),
                    "executable_versions": dict(self.executable_versions),
                    "isolation_prerequisites": dict(self.isolation_prerequisites),
                }
                response_bytes = format_json_response(200, payload)

            elif clean_path == "/v1/adapter/execute":
                if method != "POST":
                    raise HttpError(
                        405,
                        "method_not_allowed",
                        f"Method '{method}' not allowed for {clean_path}",
                        headers={"Allow": "POST"},
                    )

                auth_header = headers.get("authorization")
                token = extract_bearer_token(auth_header)
                if not verify_bearer_token(token, self.auth_token):
                    raise HttpError(
                        401,
                        "unauthorized",
                        "Missing or invalid bearer token",
                        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                    )

                if "content-length" not in headers:
                    raise HttpError(411, "length_required", "Missing Content-Length header")

                cl_str = headers["content-length"]
                try:
                    cl = int(cl_str)
                except ValueError as exc:
                    raise HttpError(400, "bad_request", "Invalid Content-Length header value") from exc

                if cl < 0:
                    raise HttpError(400, "bad_request", "Content-Length must be non-negative")

                if cl > MAX_BODY_BYTES:
                    raise HttpError(
                        413,
                        "payload_too_large",
                        f"Request body size ({cl} bytes) exceeds maximum limit ({MAX_BODY_BYTES} bytes)",
                    )

                if len(body_prefix) >= cl:
                    body_bytes = body_prefix[:cl]
                else:
                    needed = cl - len(body_prefix)
                    try:
                        remaining_chunk = await asyncio.wait_for(
                            reader.readexactly(needed),
                            timeout=self.read_timeout_s,
                        )
                    except asyncio.TimeoutError as exc:
                        raise HttpError(408, "request_timeout", "Timed out waiting for request body") from exc
                    except asyncio.IncompleteReadError as exc:
                        raise HttpError(400, "bad_request", "Incomplete request body") from exc
                    body_bytes = body_prefix + remaining_chunk

                req, clamped_timeout_s = parse_adapter_execute_request(
                    body_bytes,
                    max_timeout_s=self.max_probe_timeout_s,
                )
                req_id = req.request_id

                if self._is_shutting_down:
                    raise HttpError(503, "service_unavailable", "Server is shutting down", request_id=req_id)

                if req.adapter_id not in self.allowlisted_adapters:
                    raise HttpError(
                        403,
                        "forbidden",
                        f"Adapter '{req.adapter_id}' is not allowlisted for remote execution on this agent",
                        request_id=req_id,
                    )

                if self._active_measurements >= self.max_concurrency:
                    raise HttpError(
                        429,
                        "too_many_requests",
                        "Server measurement concurrency limit reached",
                        request_id=req_id,
                    )

                registry = self.adapter_registry
                if registry is None:
                    from connscope.adapters import (
                        AdapterRegistry,
                        SingBoxVlessTcpRealityAdapter,
                        SingBoxVmessWebSocketTlsAdapter,
                        XrayVlessTcpRealityAdapter,
                        XrayVmessWebSocketTlsAdapter,
                    )
                    registry = AdapterRegistry()
                    registry.register(XrayVlessTcpRealityAdapter())
                    registry.register(SingBoxVlessTcpRealityAdapter())
                    registry.register(XrayVmessWebSocketTlsAdapter())
                    registry.register(SingBoxVmessWebSocketTlsAdapter())

                try:
                    adapter = registry.get(req.adapter_id)
                except KeyError:
                    raise HttpError(404, "unknown_adapter", f"Adapter '{req.adapter_id}' is not registered on this agent", request_id=req_id)

                try:
                    validated_config = adapter.validate_config(req.config)
                except Exception as exc:
                    raise HttpError(400, "invalid_config", f"Configuration validation failed: {exc}", request_id=req_id) from exc

                exe_ok, exe_path = adapter.check_executable()
                if not exe_ok:
                    raise HttpError(
                        503,
                        "executable_unavailable",
                        f"Required executable not available on agent: {exe_path}",
                        request_id=req_id,
                    )

                self._active_measurements += 1
                if current_task is not None:
                    self._measurement_tasks.add(current_task)
                try:
                    outer_timeout_s = clamped_timeout_s + self.outer_timeout_slack_s
                    try:
                        probe_result = await asyncio.wait_for(
                            adapter.run(req.target, config=validated_config),
                            timeout=outer_timeout_s,
                        )
                    except asyncio.TimeoutError:
                        raise HttpError(
                            504,
                            "gateway_timeout",
                            "Adapter execution exceeded agent execution deadline",
                            request_id=req_id,
                        )
                    except Exception as exc:
                        raise HttpError(
                            500,
                            "internal_error",
                            f"An internal error occurred during adapter execution: {exc}",
                            request_id=req_id,
                        ) from exc

                    serialized = result_to_dict(probe_result)
                    response_payload = {
                        "protocol_version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "status": "completed",
                        "result": serialized,
                    }
                    response_bytes = format_json_response(200, response_payload)
                finally:
                    if current_task is not None:
                        self._measurement_tasks.discard(current_task)
                    self._active_measurements -= 1

            elif clean_path == "/v1/measure":
                if method != "POST":
                    raise HttpError(
                        405,
                        "method_not_allowed",
                        f"Method '{method}' not allowed for {clean_path}",
                        headers={"Allow": "POST"},
                    )

                auth_header = headers.get("authorization")
                token = extract_bearer_token(auth_header)
                if not verify_bearer_token(token, self.auth_token):
                    raise HttpError(
                        401,
                        "unauthorized",
                        "Missing or invalid bearer token",
                        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                    )

                if "content-length" not in headers:
                    raise HttpError(411, "length_required", "Missing Content-Length header")

                cl_str = headers["content-length"]
                try:
                    cl = int(cl_str)
                except ValueError as exc:
                    raise HttpError(400, "bad_request", "Invalid Content-Length header value") from exc

                if cl < 0:
                    raise HttpError(400, "bad_request", "Content-Length must be non-negative")

                if cl > MAX_BODY_BYTES:
                    raise HttpError(
                        413,
                        "payload_too_large",
                        f"Request body size ({cl} bytes) exceeds maximum limit ({MAX_BODY_BYTES} bytes)",
                    )

                if len(body_prefix) >= cl:
                    body_bytes = body_prefix[:cl]
                else:
                    needed = cl - len(body_prefix)
                    try:
                        remaining_chunk = await asyncio.wait_for(
                            reader.readexactly(needed),
                            timeout=self.read_timeout_s,
                        )
                    except asyncio.TimeoutError as exc:
                        raise HttpError(408, "request_timeout", "Timed out waiting for request body") from exc
                    except asyncio.IncompleteReadError as exc:
                        raise HttpError(400, "bad_request", "Incomplete request body") from exc
                    body_bytes = body_prefix + remaining_chunk

                req, clamped_timeout_s = parse_measure_request(
                    body_bytes,
                    max_probe_timeout_s=self.max_probe_timeout_s,
                )
                req_id = req.request_id

                if self._is_shutting_down:
                    raise HttpError(503, "service_unavailable", "Server is shutting down", request_id=req_id)

                if self._active_measurements >= self.max_concurrency:
                    raise HttpError(
                        429,
                        "too_many_requests",
                        "Server measurement concurrency limit reached",
                        request_id=req_id,
                    )

                self._active_measurements += 1
                if current_task is not None:
                    self._measurement_tasks.add(current_task)
                try:
                    try:
                        prepared_config = await asyncio.to_thread(
                            prepare_probe_config,
                            req.probe,
                            req.target,
                            req.config,
                            allow_private=self.allow_private,
                            resolver=self.resolver,
                        )
                    except UnsupportedProbeError as exc:
                        raise HttpError(404, "unknown_probe", str(exc), request_id=req_id) from exc
                    except UntrustedConfigError as exc:
                        raise HttpError(400, "untrusted_config", str(exc), request_id=req_id) from exc
                    except TargetPolicyViolation as exc:
                        raise HttpError(403, "forbidden", str(exc), request_id=req_id) from exc
                    except TargetResolutionError as exc:
                        raise HttpError(400, "resolution_error", str(exc), request_id=req_id) from exc

                    outer_timeout_s = clamped_timeout_s + self.outer_timeout_slack_s
                    try:
                        probe_result = await asyncio.wait_for(
                            self.engine.run(req.probe, req.target, prepared_config),
                            timeout=outer_timeout_s,
                        )
                    except asyncio.TimeoutError:
                        raise HttpError(
                            504,
                            "gateway_timeout",
                            "Probe execution exceeded agent execution deadline",
                            request_id=req_id,
                        )
                    except KeyError as exc:
                        raise HttpError(404, "unknown_probe", str(exc), request_id=req_id) from exc
                    except Exception as exc:
                        raise HttpError(
                            500,
                            "internal_error",
                            "An internal error occurred during probe execution",
                            request_id=req_id,
                        ) from exc

                    serialized = result_to_dict(probe_result)
                    response_payload = {
                        "protocol_version": PROTOCOL_VERSION,
                        "request_id": req_id,
                        "status": "completed",
                        "result": serialized,
                    }
                    response_bytes = format_json_response(200, response_payload)
                finally:
                    if current_task is not None:
                        self._measurement_tasks.discard(current_task)
                    self._active_measurements -= 1

            else:
                raise HttpError(404, "not_found", f"Route not found: {clean_path}")

            writer.write(response_bytes)
            await writer.drain()

        except asyncio.CancelledError:
            raise

        except HttpError as exc:
            effective_req_id = exc.request_id if exc.request_id is not None else req_id
            err_bytes = format_error_response(
                exc.status_code,
                exc.error,
                exc.message,
                request_id=effective_req_id,
                extra_headers=exc.headers,
            )
            try:
                writer.write(err_bytes)
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                pass

        except Exception:
            err_bytes = format_error_response(
                500,
                "internal_error",
                "An unexpected internal error occurred",
                request_id=req_id,
            )
            try:
                writer.write(err_bytes)
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                pass

        finally:
            if current_task is not None:
                self._active_tasks.discard(current_task)
            self._active_connections = max(0, self._active_connections - 1)
            self._active_writers.discard(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
