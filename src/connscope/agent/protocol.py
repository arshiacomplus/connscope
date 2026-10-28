from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import re
from typing import Any
import uuid

from connscope.core import Target
from connscope.probes._utils import validate_sni
from .execution import SUPPORTED_PROBE_NAMES

PROTOCOL_VERSION: int = 1
API_VERSION: str = "1.0"
MAX_HEADER_BYTES: int = 16 * 1024
MAX_BODY_BYTES: int = 64 * 1024
DEFAULT_READ_TIMEOUT_S: float = 10.0
DEFAULT_MAX_PROBE_TIMEOUT_S: float = 30.0

PERMITTED_REMOTE_ADAPTERS: frozenset[str] = frozenset({
    "xray_vless_tcp_reality",
    "singbox_vless_tcp_reality",
    "xray_vmess_ws_tls",
    "singbox_vmess_ws_tls",
})

PROHIBITED_REMOTE_ADAPTERS: frozenset[str] = frozenset({
    "wireguard_standard",
    "amnezia_wg_standard",
    "openvpn_standard",
})

PROBE_CONFIG_ALLOWLIST: dict[str, frozenset[str]] = {
    "tcp_connect": frozenset({"timeout_s"}),
    "tls_handshake": frozenset({"timeout_s", "verify", "sni", "no_sni"}),
    "http_request": frozenset({"timeout_s", "use_tls", "verify", "path", "method"}),
    "dns_resolve": frozenset({"timeout_s"}),
}

_HTTP_METHOD_REGEX = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,32}$")

_HTTP_STATUS_PHRASES: dict[int, str] = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    411: "Length Required",
    413: "Payload Too Large",
    429: "Too Many Requests",
    500: "Internal Server Error",
    504: "Gateway Timeout",
}

class HttpError(Exception):

    def __init__(
        self,
        status_code: int,
        error: str,
        message: str,
        headers: dict[str, str] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error = error
        self.message = message
        self.headers = headers or {}
        self.request_id = request_id

@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes

@dataclass(frozen=True, slots=True)
class MeasureRequest:
    protocol_version: int
    request_id: str
    probe: str
    target: Target
    config: dict[str, Any]

@dataclass(frozen=True, slots=True)
class AgentCapabilities:
    protocol_version: int
    api_version: str
    supported_operations: tuple[str, ...]
    allowlisted_adapters: tuple[str, ...] = ()
    allowed_execution_modes: tuple[str, ...] = ("local_proxy",)
    executable_versions: dict[str, str] = field(default_factory=dict)
    isolation_prerequisites: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.supported_operations, list):
            object.__setattr__(self, "supported_operations", tuple(self.supported_operations))
        if isinstance(self.allowlisted_adapters, list):
            object.__setattr__(self, "allowlisted_adapters", tuple(self.allowlisted_adapters))
        if isinstance(self.allowed_execution_modes, list):
            object.__setattr__(self, "allowed_execution_modes", tuple(self.allowed_execution_modes))

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "api_version": self.api_version,
            "supported_operations": list(self.supported_operations),
            "allowlisted_adapters": list(self.allowlisted_adapters),
            "allowed_execution_modes": list(self.allowed_execution_modes),
            "executable_versions": dict(self.executable_versions),
            "isolation_prerequisites": dict(self.isolation_prerequisites),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentCapabilities:
        if not isinstance(data, dict):
            raise ValueError("Capabilities response must be a JSON object")

        pv = data.get("protocol_version")
        if isinstance(pv, bool) or not isinstance(pv, int) or pv != PROTOCOL_VERSION:
            raise ValueError(f"Incompatible protocol_version: expected integer {PROTOCOL_VERSION}, got {pv!r}")

        api_ver = data.get("api_version")
        if not isinstance(api_ver, str) or not api_ver.strip():
            raise ValueError("api_version must be a non-empty string")
        if not api_ver.startswith("1."):
            raise ValueError(f"Incompatible agent api_version: {api_ver!r}")

        ops = data.get("supported_operations")
        if not isinstance(ops, list) or not all(isinstance(x, str) for x in ops):
            raise ValueError("supported_operations must be a list of strings")

        adapters = data.get("allowlisted_adapters")
        if not isinstance(adapters, list) or not all(isinstance(x, str) for x in adapters):
            raise ValueError("allowlisted_adapters must be a list of strings")

        modes = data.get("allowed_execution_modes")
        if not isinstance(modes, list) or not all(isinstance(x, str) for x in modes):
            raise ValueError("allowed_execution_modes must be a list of strings")

        exe_versions = data.get("executable_versions", {})
        if not isinstance(exe_versions, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in exe_versions.items()
        ):
            raise ValueError("executable_versions must be a dictionary of string key-values")

        isolation = data.get("isolation_prerequisites", {})
        if not isinstance(isolation, dict):
            raise ValueError("isolation_prerequisites must be a dictionary")

        return cls(
            protocol_version=pv,
            api_version=api_ver,
            supported_operations=tuple(ops),
            allowlisted_adapters=tuple(adapters),
            allowed_execution_modes=tuple(modes),
            executable_versions=dict(exe_versions),
            isolation_prerequisites=dict(isolation),
        )

@dataclass(frozen=True, slots=True)
class AdapterExecuteRequest:
    protocol_version: int
    request_id: str
    adapter_id: str
    target: Target
    config: dict[str, Any]
    timeout_s: float | None = None

def _reject_duplicate_keys(ordered_pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in ordered_pairs:
        if key in result:
            raise ValueError("Duplicate key in JSON object")
        result[key] = value
    return result

def _reject_constant(val: str) -> None:
    raise ValueError(f"Non-standard JSON constant {val!r} is not allowed")

def parse_strict_json(body_str: str) -> Any:
    try:
        return json.loads(
            body_str,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise HttpError(400, "bad_request", f"Malformed JSON: {exc}") from exc

_HEADER_NAME_REGEX = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")

def parse_http_headers(header_bytes: bytes) -> tuple[str, str, str, dict[str, str]]:
    if not header_bytes:
        raise HttpError(400, "bad_request", "Empty HTTP request")

    crlf_count = header_bytes.count(b"\r\n")
    if header_bytes.count(b"\n") != crlf_count:
        raise HttpError(400, "bad_request", "Bare LF is not allowed: HTTP/1.1 requires CRLF line endings")
    if header_bytes.count(b"\r") != crlf_count:
        raise HttpError(400, "bad_request", "Bare CR is not allowed: HTTP/1.1 requires CRLF line endings")

    raw_lines = header_bytes.split(b"\r\n")
    while raw_lines and raw_lines[-1] == b"":
        raw_lines.pop()

    if not raw_lines or raw_lines[0] == b"":
        raise HttpError(400, "bad_request", "Empty HTTP request line")

    try:
        request_line = raw_lines[0].decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise HttpError(400, "bad_request", "Malformed request line encoding") from exc

    if request_line.startswith(" ") or request_line.endswith(" "):
        raise HttpError(400, "bad_request", "Leading or trailing whitespace in request line is not allowed")

    parts = request_line.split(" ")
    if len(parts) != 3:
        raise HttpError(400, "bad_request", "Malformed HTTP request line")

    method, path, version = parts
    if not _HTTP_METHOD_REGEX.match(method):
        raise HttpError(400, "bad_request", "Invalid HTTP method token in request line")

    if not path.startswith("/"):
        raise HttpError(400, "bad_request", "Invalid request target in request line")

    if version != "HTTP/1.1":
        raise HttpError(400, "bad_request", "Unsupported HTTP version")

    headers: dict[str, str] = {}
    seen_names: set[str] = set()

    for raw_line in raw_lines[1:]:
        try:
            line = raw_line.decode("iso-8859-1")
        except UnicodeDecodeError as exc:
            raise HttpError(400, "bad_request", "Malformed header line encoding") from exc

        if line == "":
            raise HttpError(400, "bad_request", "Empty line within header section is not allowed")

        if line.startswith(" ") or line.startswith("\t"):
            raise HttpError(
                400,
                "bad_request",
                "Leading whitespace or obsolete line folding is not allowed in header lines",
            )

        if ":" not in line:
            raise HttpError(400, "bad_request", "Malformed header line (missing colon)")

        raw_name, raw_value = line.split(":", 1)

        if raw_name.endswith(" ") or raw_name.endswith("\t"):
            raise HttpError(400, "bad_request", "Whitespace before colon is not allowed")

        if not _HEADER_NAME_REGEX.match(raw_name):
            raise HttpError(400, "bad_request", "Invalid header name syntax")

        lower_name = raw_name.lower()
        if lower_name in seen_names:
            raise HttpError(400, "bad_request", "Duplicate header")
        seen_names.add(lower_name)

        for c in raw_value:
            code = ord(c)
            if (code < 32 and code != 9) or code == 127:
                raise HttpError(
                    400,
                    "bad_request",
                    "Header value contains prohibited control character",
                )

        clean_val = raw_value.strip(" \t")
        headers[lower_name] = clean_val

    if "host" not in headers:
        raise HttpError(400, "bad_request", "Missing required Host header")

    if "transfer-encoding" in headers:
        raise HttpError(400, "bad_request", "Transfer-Encoding is not supported")

    return method, path, version, headers

def parse_measure_request(
    body_bytes: bytes,
    max_probe_timeout_s: float = DEFAULT_MAX_PROBE_TIMEOUT_S,
) -> tuple[MeasureRequest, float]:
    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HttpError(400, "bad_request", "Request body is not valid UTF-8") from exc

    data = parse_strict_json(body_str)
    if not isinstance(data, dict):
        raise HttpError(400, "invalid_schema", "Request body must be a JSON object")

    pv = data.get("protocol_version")
    if isinstance(pv, bool) or not isinstance(pv, int) or pv != PROTOCOL_VERSION:
        raise HttpError(
            400,
            "invalid_schema",
            f"Unsupported protocol_version: expected integer {PROTOCOL_VERSION}",
        )

    rid = data.get("request_id")
    if rid is None:
        request_id = str(uuid.uuid4())
    elif isinstance(rid, str) and rid and len(rid) <= 128 and not any(ord(c) < 32 or ord(c) == 127 for c in rid):
        request_id = rid
    else:
        raise HttpError(
            400,
            "invalid_schema",
            "request_id must be a non-empty string up to 128 characters without control characters",
        )

    probe = data.get("probe")
    if not isinstance(probe, str) or not probe:
        raise HttpError(400, "invalid_schema", "probe must be a non-empty string", request_id=request_id)
    if probe not in SUPPORTED_PROBE_NAMES:
        raise HttpError(404, "unknown_probe", f"Unsupported probe: {probe!r}", request_id=request_id)

    target_obj = data.get("target")
    if not isinstance(target_obj, dict):
        raise HttpError(400, "invalid_schema", "target must be a JSON object", request_id=request_id)

    host = target_obj.get("host")
    if not isinstance(host, str) or not host:
        raise HttpError(400, "invalid_schema", "target.host must be a non-empty string", request_id=request_id)
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in host):
        raise HttpError(
            400,
            "invalid_schema",
            "target.host contains whitespace or control characters",
            request_id=request_id,
        )

    port = target_obj.get("port")
    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            raise HttpError(
                400,
                "invalid_schema",
                "target.port must be an integer between 1 and 65535",
                request_id=request_id,
            )

    try:
        target = Target(host=host, port=port)
    except ValueError as exc:
        raise HttpError(400, "invalid_schema", f"Invalid target: {exc}", request_id=request_id) from exc

    config_obj = data.get("config")
    if config_obj is None:
        raw_config: dict[str, Any] = {}
    elif not isinstance(config_obj, dict):
        raise HttpError(400, "invalid_schema", "config must be a JSON object", request_id=request_id)
    else:
        raw_config = config_obj

    allowed_keys = PROBE_CONFIG_ALLOWLIST.get(probe, frozenset())
    for key in raw_config:
        if key not in allowed_keys:
            raise HttpError(
                400,
                "invalid_config",
                f"Unknown or disallowed config key for probe {probe!r}: {key!r}",
                request_id=request_id,
            )

    validated_config: dict[str, Any] = {}
    clamped_timeout_s = 10.0

    if "timeout_s" in raw_config:
        ts = raw_config["timeout_s"]
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts) or ts <= 0:
            raise HttpError(
                400,
                "invalid_config",
                "timeout_s must be a finite positive number",
                request_id=request_id,
            )
        clamped_timeout_s = min(float(ts), max_probe_timeout_s)
        validated_config["timeout_s"] = clamped_timeout_s

    if "verify" in raw_config:
        v = raw_config["verify"]
        if not isinstance(v, bool):
            raise HttpError(400, "invalid_config", "verify must be a boolean", request_id=request_id)
        if not v:
            raise HttpError(
                400,
                "invalid_config",
                "Disabling TLS verification is not permitted on the agent",
                request_id=request_id,
            )
        validated_config["verify"] = True

    if "sni" in raw_config:
        s = raw_config["sni"]
        try:
            validated_config["sni"] = validate_sni(s)
        except ValueError as exc:
            raise HttpError(400, "invalid_config", f"Invalid sni: {exc}", request_id=request_id) from exc

    if "no_sni" in raw_config:
        ns = raw_config["no_sni"]
        if not isinstance(ns, bool):
            raise HttpError(400, "invalid_config", "no_sni must be a boolean", request_id=request_id)
        validated_config["no_sni"] = ns

    if validated_config.get("sni") is not None and validated_config.get("no_sni") is True:
        raise HttpError(400, "invalid_config", "Cannot specify both sni and no_sni", request_id=request_id)

    if "use_tls" in raw_config:
        ut = raw_config["use_tls"]
        if not isinstance(ut, bool):
            raise HttpError(400, "invalid_config", "use_tls must be a boolean", request_id=request_id)
        validated_config["use_tls"] = ut

    if "method" in raw_config:
        m = raw_config["method"]
        if not isinstance(m, str) or not _HTTP_METHOD_REGEX.match(m):
            raise HttpError(400, "invalid_config", f"Invalid HTTP method token: {m!r}", request_id=request_id)
        validated_config["method"] = m

    if "path" in raw_config:
        p = raw_config["path"]
        if not isinstance(p, str) or not p.startswith("/"):
            raise HttpError(400, "invalid_config", "path must be a string starting with '/'", request_id=request_id)
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in p):
            raise HttpError(
                400,
                "invalid_config",
                "path contains unescaped whitespace or control characters",
                request_id=request_id,
            )
        validated_config["path"] = p

    req = MeasureRequest(
        protocol_version=PROTOCOL_VERSION,
        request_id=request_id,
        probe=probe,
        target=target,
        config=validated_config,
    )
    return req, clamped_timeout_s

_ADAPTER_ID_REGEX = re.compile(r"^[a-z0-9_]{1,64}$")
_DISALLOWED_CONFIG_KEYS = frozenset({
    "binary_path", "executable", "command", "sh", "bash", "cmd", "exec", "script",
    "plugin", "up", "down", "route-up", "route_up", "client_connect",
})

def parse_adapter_execute_request(
    body_bytes: bytes,
    max_timeout_s: float = DEFAULT_MAX_PROBE_TIMEOUT_S,
) -> tuple[AdapterExecuteRequest, float]:
    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HttpError(400, "bad_request", "Request body is not valid UTF-8") from exc

    data = parse_strict_json(body_str)
    if not isinstance(data, dict):
        raise HttpError(400, "invalid_schema", "Request body must be a JSON object")

    pv = data.get("protocol_version")
    if isinstance(pv, bool) or not isinstance(pv, int) or pv != PROTOCOL_VERSION:
        raise HttpError(
            400,
            "invalid_schema",
            f"Unsupported protocol_version: expected integer {PROTOCOL_VERSION}",
        )

    rid = data.get("request_id")
    if rid is None:
        request_id = str(uuid.uuid4())
    elif isinstance(rid, str) and rid and len(rid) <= 128 and not any(ord(c) < 32 or ord(c) == 127 for c in rid):
        request_id = rid
    else:
        raise HttpError(
            400,
            "invalid_schema",
            "request_id must be a non-empty string up to 128 characters without control characters",
        )

    adapter_id = data.get("adapter_id")
    if not isinstance(adapter_id, str) or not _ADAPTER_ID_REGEX.match(adapter_id):
        raise HttpError(400, "invalid_schema", "adapter_id must be a valid identifier", request_id=request_id)

    if adapter_id in PROHIBITED_REMOTE_ADAPTERS:
        raise HttpError(
            403,
            "forbidden",
            f"Layer-3 adapter '{adapter_id}' is not supported for remote execution",
            request_id=request_id,
        )

    if adapter_id not in PERMITTED_REMOTE_ADAPTERS:
        raise HttpError(
            403,
            "forbidden",
            f"Adapter '{adapter_id}' is not permitted for remote execution",
            request_id=request_id,
        )

    target_obj = data.get("target")
    if not isinstance(target_obj, dict):
        raise HttpError(400, "invalid_schema", "target must be a JSON object", request_id=request_id)

    host = target_obj.get("host")
    if not isinstance(host, str) or not host:
        raise HttpError(400, "invalid_schema", "target.host must be a non-empty string", request_id=request_id)
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in host):
        raise HttpError(
            400,
            "invalid_schema",
            "target.host contains whitespace or control characters",
            request_id=request_id,
        )

    port = target_obj.get("port")
    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            raise HttpError(
                400,
                "invalid_schema",
                "target.port must be an integer between 1 and 65535",
                request_id=request_id,
            )

    try:
        target = Target(host=host, port=port)
    except ValueError as exc:
        raise HttpError(400, "invalid_schema", f"Invalid target: {exc}", request_id=request_id) from exc

    config_obj = data.get("config")
    if config_obj is None:
        raw_config: dict[str, Any] = {}
    elif not isinstance(config_obj, dict):
        raise HttpError(400, "invalid_schema", "config must be a JSON object", request_id=request_id)
    else:
        raw_config = dict(config_obj)

    for k in raw_config:
        if not isinstance(k, str):
            raise HttpError(400, "invalid_config", "config keys must be strings", request_id=request_id)
        if k in _DISALLOWED_CONFIG_KEYS or any(dis in k.lower() for dis in ("exec", "cmd", "shell", "script")):
            raise HttpError(400, "untrusted_config", f"Disallowed configuration key '{k}'", request_id=request_id)

    clamped_timeout_s = 15.0
    if "timeout_s" in data:
        ts = data["timeout_s"]
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts) or ts <= 0:
            raise HttpError(400, "invalid_config", "timeout_s must be a finite positive number", request_id=request_id)
        clamped_timeout_s = min(float(ts), max_timeout_s)
    elif "timeout_s" in raw_config:
        ts = raw_config["timeout_s"]
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts) or ts <= 0:
            raise HttpError(400, "invalid_config", "timeout_s must be a finite positive number", request_id=request_id)
        clamped_timeout_s = min(float(ts), max_timeout_s)

    req = AdapterExecuteRequest(
        protocol_version=PROTOCOL_VERSION,
        request_id=request_id,
        adapter_id=adapter_id,
        target=target,
        config=raw_config,
        timeout_s=clamped_timeout_s,
    )
    return req, clamped_timeout_s

def format_http_response(
    status_code: int,
    body: bytes,
    content_type: str = "application/json",
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    phrase = _HTTP_STATUS_PHRASES.get(status_code, "Unknown")
    headers = [
        f"HTTP/1.1 {status_code} {phrase}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if extra_headers:
        for k, v in extra_headers.items():
            headers.append(f"{k}: {v}")
    header_text = "\r\n".join(headers) + "\r\n\r\n"
    return header_text.encode("iso-8859-1") + body

def format_json_response(
    status_code: int,
    data: dict[str, Any],
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    body = json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return format_http_response(status_code, body, content_type="application/json", extra_headers=extra_headers)

def format_error_response(
    status_code: int,
    error: str,
    message: str,
    request_id: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    payload: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "error": error,
        "message": message,
    }
    if request_id is not None:
        payload["request_id"] = request_id
    return format_json_response(status_code, payload, extra_headers=extra_headers)
