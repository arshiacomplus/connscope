
from __future__ import annotations

import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
from typing import Any
from urllib.parse import urlsplit
import uuid

from connscope.core import ProbeResult, Target
from connscope.serialization import result_from_dict
from .protocol import (
    API_VERSION,
    AgentCapabilities,
    PERMITTED_REMOTE_ADAPTERS,
    PROHIBITED_REMOTE_ADAPTERS,
)

DEFAULT_CLIENT_TIMEOUT_S: float = 30.0
MAX_RESPONSE_BYTES: int = 1024 * 1024

_BEARER_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")

_SAFE_ERROR_CODE_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")

class RemoteClientError(Exception):
    pass

class ClientConfigurationError(RemoteClientError):
    pass

class RemoteConnectionError(RemoteClientError):
    pass

class RemoteTimeoutError(RemoteClientError):

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.request_id = request_id

class RemoteProtocolError(RemoteClientError):
    pass

class RemoteHttpError(RemoteClientError):

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        error_code: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.request_id = request_id

class RemoteAuthenticationError(RemoteHttpError):
    pass

class RemotePolicyError(RemoteHttpError):
    pass

class RemoteUnavailableError(RemoteHttpError):
    pass

class RemoteRedirectError(RemoteHttpError):
    pass

def _reject_duplicate_keys(ordered_pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in ordered_pairs:
        if key in result:
            raise ValueError("Duplicate key in JSON object")
        result[key] = value
    return result

def _reject_constant(val: str) -> None:
    raise ValueError("Non-standard JSON constant is not allowed")

def _parse_strict_json(body_str: str) -> Any:
    return json.loads(
        body_str,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )

def validate_node_url(node_url: str) -> tuple[str, str, int]:
    if not isinstance(node_url, str) or not node_url.strip():
        raise ClientConfigurationError("node_url must be a non-empty string")

    if any(c.isspace() for c in node_url):
        raise ClientConfigurationError("node_url must not contain whitespace")

    if "?" in node_url:
        raise ClientConfigurationError("node_url must not contain query parameters")

    if "#" in node_url:
        raise ClientConfigurationError("node_url must not contain URL fragments")

    try:
        parts = urlsplit(node_url)
    except Exception as exc:
        raise ClientConfigurationError(f"Malformed node_url: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ClientConfigurationError(
            f"Unsupported node_url scheme: {scheme!r}. Must be 'https' (or 'http' for loopback IP literals only)"
        )

    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ClientConfigurationError("node_url must not contain user credentials")

    if parts.path not in ("", "/"):
        raise ClientConfigurationError(
            f"Unexpected path prefix in node_url: {parts.path!r}. Path components are not allowed"
        )

    hostname = parts.hostname
    if not hostname:
        raise ClientConfigurationError("node_url must contain a valid hostname or IP address")

    clean_host = hostname.strip("[]")

    if scheme == "http":
        try:
            ip = ipaddress.ip_address(clean_host)
            if not ip.is_loopback:
                raise ClientConfigurationError(
                    f"Plaintext HTTP is only permitted for literal loopback IPs (e.g. '127.0.0.1', '::1'), "
                    f"got non-loopback IP: {hostname!r}"
                )
        except ValueError:
            raise ClientConfigurationError(
                f"Plaintext HTTP is not permitted for hostnames (including 'localhost'); "
                f"production node URLs must use HTTPS, got: {hostname!r}"
            )

    try:
        port = parts.port
    except ValueError as exc:
        raise ClientConfigurationError(f"Invalid port in node_url: {exc}") from exc

    if port is None:
        port = 443 if scheme == "https" else 80
    elif not (1 <= port <= 65535):
        raise ClientConfigurationError(f"Port in node_url must be between 1 and 65535, got {port}")

    return scheme, hostname, port

def _read_bounded_body(
    response: http.client.HTTPResponse,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> bytes:
    cl_header = response.getheader("Content-Length")
    if cl_header is not None:
        cl_val: int | None = None
        try:
            cl_val = int(cl_header)
        except ValueError:
            pass
        if cl_val is not None and cl_val > max_bytes:
            err_cl = RemoteProtocolError(
                f"Response Content-Length exceeds maximum limit ({max_bytes} bytes)"
            )
            err_cl.__cause__ = None
            err_cl.__context__ = None
            raise err_cl

    chunks: list[bytes] = []
    total_bytes = 0
    chunk_size = 64 * 1024

    while True:
        try:
            chunk = response.read(chunk_size)
        except (TimeoutError, socket.timeout) as exc:
            raise RemoteTimeoutError("Timed out reading response from agent") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise RemoteConnectionError(f"Error reading response from agent: {exc}") from exc

        if not chunk:
            break

        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise RemoteProtocolError(
                f"Response body exceeds maximum permitted limit ({max_bytes} bytes)"
            )
        chunks.append(chunk)

    return b"".join(chunks)

class RemoteAgentClient:

    def __init__(
        self,
        node_url: str,
        token: str,
        timeout_s: float = DEFAULT_CLIENT_TIMEOUT_S,
    ) -> None:
        self._scheme, self._host, self._port = validate_node_url(node_url)
        self._node_url = node_url

        if not isinstance(token, str) or not token or not _BEARER_TOKEN_PATTERN.match(token):
            raise ClientConfigurationError(
                "token must be a valid non-empty HTTP Bearer token (RFC 6750 format)"
            )
        self._token = token

        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s)
            or timeout_s <= 0
        ):
            raise ClientConfigurationError(
                f"timeout_s must be a finite positive number, got {timeout_s!r}"
            )
        self.timeout_s = float(timeout_s)

    @property
    def node_url(self) -> str:
        return self._node_url

    def __repr__(self) -> str:
        return f"RemoteAgentClient(node_url={self._node_url!r}, timeout_s={self.timeout_s})"

    def close(self) -> None:
        pass

    def __enter__(self) -> RemoteAgentClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def get_capabilities(self) -> AgentCapabilities:
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Connection": "close",
        }

        conn: http.client.HTTPConnection | None = None
        try:
            if self._scheme == "https":
                context = ssl.create_default_context()
                conn = http.client.HTTPSConnection(
                    host=self._host,
                    port=self._port,
                    timeout=self.timeout_s,
                    context=context,
                )
            else:
                conn = http.client.HTTPConnection(
                    host=self._host,
                    port=self._port,
                    timeout=self.timeout_s,
                )

            conn.request("GET", "/v1/capabilities", headers=headers)
            response = conn.getresponse()

            status = response.status
            if status != 200:
                try:
                    raw_err_body = _read_bounded_body(response, max_bytes=MAX_RESPONSE_BYTES)
                except Exception:
                    raw_err_body = b""

                error_code: str | None = None
                if raw_err_body:
                    try:
                        err_text = raw_err_body.decode("utf-8")
                        err_json = _parse_strict_json(err_text)
                        if isinstance(err_json, dict):
                            ec = err_json.get("error")
                            if isinstance(ec, str) and _SAFE_ERROR_CODE_PATTERN.match(ec):
                                error_code = ec
                    except Exception:
                        pass

                msg = f"Remote agent returned HTTP {status} for capability discovery"
                if status == 401:
                    raise RemoteAuthenticationError(msg, status_code=status, error_code=error_code)
                elif status in (429, 503):
                    raise RemoteUnavailableError(msg, status_code=status, error_code=error_code)
                elif status == 504:
                    raise RemoteTimeoutError(msg, status_code=status, error_code=error_code)
                else:
                    raise RemoteHttpError(msg, status_code=status, error_code=error_code)

            raw_body = _read_bounded_body(response, max_bytes=MAX_RESPONSE_BYTES)
            try:
                body_text = raw_body.decode("utf-8")
                body_data = _parse_strict_json(body_text)
            except Exception as exc:
                raise RemoteProtocolError(f"Malformed JSON response for capabilities: {exc}") from exc

            if not isinstance(body_data, dict):
                raise RemoteProtocolError("Capabilities response body must be a JSON object")

            try:
                return AgentCapabilities.from_dict(body_data)
            except ValueError as exc:
                raise RemoteProtocolError(f"Invalid AgentCapabilities response schema: {exc}") from exc

        except RemoteClientError:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise RemoteTimeoutError("Timed out communicating with remote agent") from exc
        except ssl.SSLError as exc:
            raise RemoteConnectionError(f"TLS connection error: {exc}") from exc
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, socket.gaierror, OSError) as exc:
            raise RemoteConnectionError(f"Connection to remote agent failed: {exc}") from exc
        except http.client.HTTPException as exc:
            raise RemoteConnectionError(f"HTTP protocol error: {exc}") from exc
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def execute_adapter(
        self,
        adapter_id: str,
        target: Target,
        config: dict[str, Any] | None = None,
        timeout_s: float | None = None,
    ) -> ProbeResult:
        if not isinstance(adapter_id, str) or not adapter_id.strip():
            raise ClientConfigurationError("adapter_id must be a non-empty string")

        if adapter_id in PROHIBITED_REMOTE_ADAPTERS:
            raise ClientConfigurationError(
                f"Layer-3 adapter '{adapter_id}' is not supported for remote execution"
            )

        if not isinstance(target, Target):
            raise ClientConfigurationError(f"target must be an instance of Target, got {type(target).__name__}")

        if config is None:
            effective_config: dict[str, Any] = {}
        elif not isinstance(config, dict):
            raise ClientConfigurationError(f"config must be a dictionary or None, got {type(config).__name__}")
        else:
            if any(not isinstance(k, str) for k in config):
                raise ClientConfigurationError("config dictionary keys must be strings")
            effective_config = dict(config)

        try:
            json.dumps(effective_config, allow_nan=False)
        except (ValueError, TypeError) as exc:
            raise ClientConfigurationError(f"config cannot be serialized to strict JSON: {exc}") from exc

        effective_timeout = float(timeout_s) if timeout_s is not None else self.timeout_s
        if effective_timeout <= 0 or not math.isfinite(effective_timeout):
            raise ClientConfigurationError("timeout_s must be a finite positive number")

        request_id = str(uuid.uuid4())
        target_payload: dict[str, Any] = {"host": target.host}
        if target.port is not None:
            target_payload["port"] = target.port

        payload: dict[str, Any] = {
            "protocol_version": 1,
            "request_id": request_id,
            "adapter_id": adapter_id,
            "target": target_payload,
            "config": effective_config,
            "timeout_s": effective_timeout,
        }

        try:
            body_bytes = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
        except Exception as exc:
            raise ClientConfigurationError(f"Failed to serialize adapter execute payload: {exc}") from exc

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Content-Length": str(len(body_bytes)),
            "Connection": "close",
        }

        conn: http.client.HTTPConnection | None = None
        try:
            if self._scheme == "https":
                context = ssl.create_default_context()
                conn = http.client.HTTPSConnection(
                    host=self._host,
                    port=self._port,
                    timeout=max(self.timeout_s, effective_timeout + 5.0),
                    context=context,
                )
            else:
                conn = http.client.HTTPConnection(
                    host=self._host,
                    port=self._port,
                    timeout=max(self.timeout_s, effective_timeout + 5.0),
                )

            conn.request("POST", "/v1/adapter/execute", body=body_bytes, headers=headers)
            response = conn.getresponse()

            status = response.status
            if status != 200:
                try:
                    raw_err_body = _read_bounded_body(response, max_bytes=MAX_RESPONSE_BYTES)
                except Exception:
                    raw_err_body = b""

                error_code: str | None = None
                err_req_id: str | None = None
                if raw_err_body:
                    try:
                        err_text = raw_err_body.decode("utf-8")
                        err_json = _parse_strict_json(err_text)
                        if isinstance(err_json, dict):
                            ec = err_json.get("error")
                            if isinstance(ec, str) and _SAFE_ERROR_CODE_PATTERN.match(ec):
                                error_code = ec
                            rid = err_json.get("request_id")
                            if isinstance(rid, str) and rid == request_id:
                                err_req_id = rid
                    except Exception:
                        pass

                msg = f"Remote agent returned HTTP {status}"
                if error_code:
                    msg += f" ({error_code})"
                effective_req_id = err_req_id or request_id

                if status == 401:
                    raise RemoteAuthenticationError(msg, status_code=status, error_code=error_code, request_id=effective_req_id)
                elif status == 403:
                    raise RemotePolicyError(msg, status_code=status, error_code=error_code, request_id=effective_req_id)
                elif status in (429, 503):
                    raise RemoteUnavailableError(msg, status_code=status, error_code=error_code, request_id=effective_req_id)
                elif status == 504:
                    raise RemoteTimeoutError(msg, status_code=status, error_code=error_code, request_id=effective_req_id)
                else:
                    raise RemoteHttpError(msg, status_code=status, error_code=error_code, request_id=effective_req_id)

            raw_body = _read_bounded_body(response, max_bytes=MAX_RESPONSE_BYTES)
            try:
                body_text = raw_body.decode("utf-8")
                body_data = _parse_strict_json(body_text)
            except Exception as exc:
                raise RemoteProtocolError(f"Malformed JSON response: {exc}") from exc

            if not isinstance(body_data, dict):
                raise RemoteProtocolError("Response body must be a JSON object")

            pv = body_data.get("protocol_version")
            if isinstance(pv, bool) or not isinstance(pv, int) or pv != 1:
                raise RemoteProtocolError("Unsupported protocol_version in response: expected integer 1")

            resp_req_id = body_data.get("request_id")
            if resp_req_id != request_id:
                raise RemoteProtocolError("Mismatched request_id in response")

            if body_data.get("status") != "completed":
                raise RemoteProtocolError("Unexpected status in response: expected 'completed'")

            result_obj = body_data.get("result")
            if not isinstance(result_obj, dict):
                raise RemoteProtocolError("Response missing 'result' object")

            try:
                probe_result = result_from_dict(result_obj)
            except (TypeError, ValueError) as exc:
                raise RemoteProtocolError(f"Invalid ProbeResult payload in response: {exc}") from exc

            return probe_result

        except RemoteClientError:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise RemoteTimeoutError("Timed out communicating with remote agent") from exc
        except ssl.SSLError as exc:
            raise RemoteConnectionError(f"TLS connection error: {exc}") from exc
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, socket.gaierror, OSError) as exc:
            raise RemoteConnectionError(f"Connection to remote agent failed: {exc}") from exc
        except http.client.HTTPException as exc:
            raise RemoteConnectionError(f"HTTP protocol error: {exc}") from exc
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def measure(
        self,
        probe_name: str,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ProbeResult:
        if not isinstance(probe_name, str) or not probe_name.strip():
            raise ClientConfigurationError("probe_name must be a non-empty string")

        if not isinstance(target, Target):
            raise ClientConfigurationError(
                f"target must be an instance of Target, got {type(target).__name__}"
            )

        if config is None:
            effective_config: dict[str, Any] = {}
        elif not isinstance(config, dict):
            raise ClientConfigurationError(
                f"config must be a dictionary or None, got {type(config).__name__}"
            )
        else:
            if any(not isinstance(k, str) for k in config):
                raise ClientConfigurationError("config dictionary keys must be strings")
            effective_config = dict(config)

        if "connect_ip" in effective_config:
            raise ClientConfigurationError(
                "client-supplied 'connect_ip' is not permitted; target IP policy is enforced exclusively by the agent"
            )

        try:
            json.dumps(effective_config, allow_nan=False)
        except (ValueError, TypeError) as exc:
            raise ClientConfigurationError(
                f"config cannot be serialized to strict JSON: {exc}"
            ) from exc

        request_id = str(uuid.uuid4())
        target_payload: dict[str, Any] = {"host": target.host}
        if target.port is not None:
            target_payload["port"] = target.port

        payload = {
            "protocol_version": 1,
            "request_id": request_id,
            "probe": probe_name,
            "target": target_payload,
            "config": effective_config,
        }

        try:
            body_bytes = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
        except Exception as exc:
            raise ClientConfigurationError(f"Failed to serialize request payload: {exc}") from exc

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Content-Length": str(len(body_bytes)),
            "Connection": "close",
        }

        conn: http.client.HTTPConnection | None = None
        try:
            if self._scheme == "https":
                context = ssl.create_default_context()
                conn = http.client.HTTPSConnection(
                    host=self._host,
                    port=self._port,
                    timeout=self.timeout_s,
                    context=context,
                )
            else:
                conn = http.client.HTTPConnection(
                    host=self._host,
                    port=self._port,
                    timeout=self.timeout_s,
                )

            conn.request("POST", "/v1/measure", body=body_bytes, headers=headers)
            response = conn.getresponse()

            status = response.status
            if status != 200:
                try:
                    raw_err_body = _read_bounded_body(response, max_bytes=MAX_RESPONSE_BYTES)
                except Exception:
                    raw_err_body = b""

                error_code: str | None = None
                err_req_id: str | None = None

                if raw_err_body:
                    try:
                        err_text = raw_err_body.decode("utf-8")
                        err_json = _parse_strict_json(err_text)
                        if isinstance(err_json, dict):
                            ec = err_json.get("error")
                            if isinstance(ec, str) and _SAFE_ERROR_CODE_PATTERN.match(ec):
                                error_code = ec
                            rid = err_json.get("request_id")
                            if isinstance(rid, str) and rid == request_id:
                                err_req_id = rid
                    except Exception:
                        pass

                msg = f"Remote agent returned HTTP {status}"
                if error_code:
                    msg += f" ({error_code})"
                effective_req_id = err_req_id or request_id

                err_http: RemoteHttpError
                if 300 <= status < 400:
                    err_http = RemoteRedirectError(
                        msg, status_code=status, error_code=error_code, request_id=effective_req_id
                    )
                elif status == 401:
                    err_http = RemoteAuthenticationError(
                        msg, status_code=status, error_code=error_code, request_id=effective_req_id
                    )
                elif status == 403:
                    err_http = RemotePolicyError(
                        msg, status_code=status, error_code=error_code, request_id=effective_req_id
                    )
                elif status in (429, 503):
                    err_http = RemoteUnavailableError(
                        msg, status_code=status, error_code=error_code, request_id=effective_req_id
                    )
                elif status == 504:
                    err_http = RemoteTimeoutError(
                        msg, status_code=status, error_code=error_code, request_id=effective_req_id
                    )
                else:
                    err_http = RemoteHttpError(
                        msg, status_code=status, error_code=error_code, request_id=effective_req_id
                    )
                err_http.__cause__ = None
                err_http.__context__ = None
                raise err_http

            raw_body = _read_bounded_body(response, max_bytes=MAX_RESPONSE_BYTES)

            body_text: str | None = None
            try:
                body_text = raw_body.decode("utf-8")
            except UnicodeDecodeError:
                pass

            if body_text is None:
                err_utf8 = RemoteProtocolError("Response body is not valid UTF-8")
                err_utf8.__cause__ = None
                err_utf8.__context__ = None
                raise err_utf8

            body_data: Any = None
            json_failed = False
            try:
                body_data = _parse_strict_json(body_text)
            except Exception:
                json_failed = True

            if json_failed:
                err_json = RemoteProtocolError("Malformed JSON response")
                err_json.__cause__ = None
                err_json.__context__ = None
                raise err_json

            if not isinstance(body_data, dict):
                raise RemoteProtocolError("Response body must be a JSON object")

            pv = body_data.get("protocol_version")
            if isinstance(pv, bool) or not isinstance(pv, int) or pv != 1:
                raise RemoteProtocolError(
                    "Unsupported protocol_version in response: expected integer 1"
                )

            resp_req_id = body_data.get("request_id")
            if resp_req_id != request_id:
                raise RemoteProtocolError("Mismatched request_id in response")

            resp_status = body_data.get("status")
            if resp_status != "completed":
                raise RemoteProtocolError("Unexpected status in response: expected 'completed'")

            result_obj = body_data.get("result")
            if not isinstance(result_obj, dict):
                raise RemoteProtocolError("Response missing 'result' object")

            probe_result: ProbeResult | None = None
            result_failed = False
            try:
                probe_result = result_from_dict(result_obj)
            except (TypeError, ValueError):
                result_failed = True

            if result_failed or probe_result is None:
                err_res = RemoteProtocolError("Invalid ProbeResult payload in response")
                err_res.__cause__ = None
                err_res.__context__ = None
                raise err_res

            if probe_result.probe != probe_name:
                raise RemoteProtocolError("Mismatched probe name in response")

            if probe_result.target.host != target.host or probe_result.target.port != target.port:
                raise RemoteProtocolError("Mismatched target in response")

            return probe_result

        except RemoteClientError:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise RemoteTimeoutError("Timed out communicating with remote agent") from exc
        except ssl.SSLError as exc:
            raise RemoteConnectionError(f"TLS connection error: {exc}") from exc
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, socket.gaierror, OSError) as exc:
            raise RemoteConnectionError(f"Connection to remote agent failed: {exc}") from exc
        except http.client.HTTPException as exc:
            raise RemoteConnectionError(f"HTTP protocol error: {exc}") from exc
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
