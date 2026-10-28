import json
import pytest

from connscope.agent.protocol import (
    DEFAULT_MAX_PROBE_TIMEOUT_S,
    PROTOCOL_VERSION,
    HttpError,
    format_error_response,
    format_http_response,
    format_json_response,
    parse_http_headers,
    parse_measure_request,
    parse_strict_json,
)
from connscope.core import Target

def test_parse_strict_json_valid() -> None:
    data = parse_strict_json('{"key": "value", "num": 42, "flag": true}')
    assert data == {"key": "value", "num": 42, "flag": True}

def test_parse_strict_json_rejects_nan_and_infinity() -> None:
    for invalid_val in ["NaN", "Infinity", "-Infinity"]:
        with pytest.raises(HttpError) as exc_info:
            parse_strict_json(f'{{"val": {invalid_val}}}')
        assert exc_info.value.status_code == 400
        assert exc_info.value.error == "bad_request"

def test_parse_strict_json_rejects_duplicate_keys() -> None:
    with pytest.raises(HttpError) as exc_info:
        parse_strict_json('{"name": "a", "name": "b"}')
    assert exc_info.value.status_code == 400
    assert exc_info.value.error == "bad_request"
    assert "Duplicate key" in exc_info.value.message

def test_parse_strict_json_rejects_malformed_syntax() -> None:
    with pytest.raises(HttpError) as exc_info:
        parse_strict_json("{invalid json")
    assert exc_info.value.status_code == 400
    assert exc_info.value.error == "bad_request"

def test_parse_http_headers_valid() -> None:
    raw = (
        b"POST /v1/measure HTTP/1.1\r\n"
        b"Host: 127.0.0.1:8000\r\n"
        b"Authorization: Bearer test-token\r\n"
        b"Content-Length: 42\r\n"
        b"\r\n"
    )
    method, path, version, headers = parse_http_headers(raw)
    assert method == "POST"
    assert path == "/v1/measure"
    assert version == "HTTP/1.1"
    assert headers["host"] == "127.0.0.1:8000"
    assert headers["authorization"] == "Bearer test-token"
    assert headers["content-length"] == "42"

def test_parse_http_headers_case_insensitive() -> None:
    raw = (
        b"GET /v1/health HTTP/1.1\r\n"
        b"HOST: 127.0.0.1\r\n"
        b"aUtHoRiZaTiOn: Bearer abc\r\n"
        b"\r\n"
    )
    _, _, _, headers = parse_http_headers(raw)
    assert headers["host"] == "127.0.0.1"
    assert headers["authorization"] == "Bearer abc"

def test_parse_http_headers_rejects_duplicate_headers() -> None:
    raw = (
        b"POST /v1/measure HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Authorization: Bearer token1\r\n"
        b"authorization: Bearer token2\r\n"
        b"\r\n"
    )
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw)
    assert exc_info.value.status_code == 400
    assert "Duplicate header" in exc_info.value.message

def test_parse_http_headers_rejects_duplicate_content_length() -> None:
    raw = (
        b"POST /v1/measure HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Length: 10\r\n"
        b"content-length: 10\r\n"
        b"\r\n"
    )
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw)
    assert exc_info.value.status_code == 400
    assert "Duplicate header" in exc_info.value.message

def test_parse_http_headers_rejects_missing_host() -> None:
    raw = b"GET /v1/health HTTP/1.1\r\n\r\n"
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw)
    assert exc_info.value.status_code == 400
    assert "Missing required Host header" in exc_info.value.message

def test_parse_http_headers_rejects_transfer_encoding() -> None:
    raw = (
        b"POST /v1/measure HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
    )
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw)
    assert exc_info.value.status_code == 400
    assert "Transfer-Encoding is not supported" in exc_info.value.message

def test_parse_http_headers_rejects_bare_lf() -> None:
    bare_lf_requests = [
        b"GET /v1/health HTTP/1.1\nHost: 127.0.0.1\r\n\r\n",
        b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\n\r\n",
        b"GET /v1/health HTTP/1.1\nHost: 127.0.0.1\n\n",
    ]
    for raw in bare_lf_requests:
        with pytest.raises(HttpError) as exc_info:
            parse_http_headers(raw)
        assert exc_info.value.status_code == 400
        assert "Bare LF" in exc_info.value.message

def test_parse_http_headers_rejects_bare_cr() -> None:
    raw = b"GET /v1/health HTTP/1.1\rHost: 127.0.0.1\r\n\r\n"
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw)
    assert exc_info.value.status_code == 400
    assert "Bare CR" in exc_info.value.message

def test_parse_http_headers_rejects_whitespace_prefixed_and_folded_headers() -> None:
    folded_requests = [
        b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n Folded: value\r\n\r\n",
        b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\tFolded: value\r\n\r\n",
    ]
    for raw in folded_requests:
        with pytest.raises(HttpError) as exc_info:
            parse_http_headers(raw)
        assert exc_info.value.status_code == 400
        assert "Leading whitespace or obsolete line folding" in exc_info.value.message

def test_parse_http_headers_rejects_whitespace_before_colon() -> None:
    whitespace_colon_requests = [
        b"GET /v1/health HTTP/1.1\r\nHost : 127.0.0.1\r\n\r\n",
        b"GET /v1/health HTTP/1.1\r\nHost\t: 127.0.0.1\r\n\r\n",
        b"GET /v1/health HTTP/1.1\r\nHost  : 127.0.0.1\r\n\r\n",
    ]
    for raw in whitespace_colon_requests:
        with pytest.raises(HttpError) as exc_info:
            parse_http_headers(raw)
        assert exc_info.value.status_code == 400
        assert "Whitespace before colon" in exc_info.value.message

def test_parse_http_headers_rejects_malformed_header_names() -> None:
    bad_names = [
        b"GET /v1/health HTTP/1.1\r\nHo st: 127.0.0.1\r\n\r\n",
        b"GET /v1/health HTTP/1.1\r\nHost@name: 127.0.0.1\r\n\r\n",
        b"GET /v1/health HTTP/1.1\r\n: 127.0.0.1\r\n\r\n",
    ]
    for raw in bad_names:
        with pytest.raises(HttpError) as exc_info:
            parse_http_headers(raw)
        assert exc_info.value.status_code == 400

def test_parse_http_headers_rejects_prohibited_control_characters_in_value() -> None:
    bad_values = [
        b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer test\x00token\r\n\r\n",
        b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer test\x08token\r\n\r\n",
        b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer test\x7ftoken\r\n\r\n",
    ]
    for raw in bad_values:
        with pytest.raises(HttpError) as exc_info:
            parse_http_headers(raw)
        assert exc_info.value.status_code == 400
        assert "control character" in exc_info.value.message

def test_parse_http_headers_allows_tab_in_value() -> None:
    raw = b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nCustom: val\twith\ttabs\r\n\r\n"
    _, _, _, headers = parse_http_headers(raw)
    assert headers["custom"] == "val\twith\ttabs"

def test_parse_http_headers_rejects_leading_trailing_whitespace_in_request_line() -> None:
    bad_request_lines = [
        b" GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        b"GET /v1/health HTTP/1.1 \r\nHost: 127.0.0.1\r\n\r\n",
        b"GET  /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    ]
    for raw in bad_request_lines:
        with pytest.raises(HttpError) as exc_info:
            parse_http_headers(raw)
        assert exc_info.value.status_code == 400

def test_parse_http_headers_error_sanitization_does_not_leak_secrets() -> None:
    secret = "test-secret-must-not-leak"

    raw_ws_colon = f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization : Bearer {secret}\r\n\r\n".encode("iso-8859-1")
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw_ws_colon)
    assert exc_info.value.status_code == 400
    assert secret not in exc_info.value.message
    assert secret not in str(exc_info.value)
    assert exc_info.value.message == "Whitespace before colon is not allowed"

    raw_missing_colon = f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization Bearer {secret}\r\n\r\n".encode("iso-8859-1")
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw_missing_colon)
    assert exc_info.value.status_code == 400
    assert secret not in exc_info.value.message
    assert secret not in str(exc_info.value)
    assert exc_info.value.message == "Malformed header line (missing colon)"

    raw_bad_request_line = f"GET /v1/health?token={secret} HTTP/1.1 EXTRA\r\nHost: 127.0.0.1\r\n\r\n".encode("iso-8859-1")
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw_bad_request_line)
    assert exc_info.value.status_code == 400
    assert secret not in exc_info.value.message
    assert secret not in str(exc_info.value)
    assert exc_info.value.message == "Malformed HTTP request line"

    raw_bad_method = f"GET@{secret} /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode("iso-8859-1")
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw_bad_method)
    assert exc_info.value.status_code == 400
    assert secret not in exc_info.value.message
    assert secret not in str(exc_info.value)
    assert exc_info.value.message == "Invalid HTTP method token in request line"

    raw_bad_target = f"GET {secret} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode("iso-8859-1")
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw_bad_target)
    assert exc_info.value.status_code == 400
    assert secret not in exc_info.value.message
    assert secret not in str(exc_info.value)
    assert exc_info.value.message == "Invalid request target in request line"

    raw_bad_version = f"GET /v1/health {secret}\r\nHost: 127.0.0.1\r\n\r\n".encode("iso-8859-1")
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw_bad_version)
    assert exc_info.value.status_code == 400
    assert secret not in exc_info.value.message
    assert secret not in str(exc_info.value)
    assert exc_info.value.message == "Unsupported HTTP version"

    raw_bad_header_name = f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nBad@{secret}: val\r\n\r\n".encode("iso-8859-1")
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw_bad_header_name)
    assert exc_info.value.status_code == 400
    assert secret not in exc_info.value.message
    assert secret not in str(exc_info.value)
    assert exc_info.value.message == "Invalid header name syntax"

    raw_dup_header = f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n{secret}: 1\r\n{secret}: 2\r\n\r\n".encode("iso-8859-1")
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw_dup_header)
    assert exc_info.value.status_code == 400
    assert secret not in exc_info.value.message
    assert secret not in str(exc_info.value)
    assert exc_info.value.message == "Duplicate header"

    raw_control_char = f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {secret}\x00val\r\n\r\n".encode("iso-8859-1")
    with pytest.raises(HttpError) as exc_info:
        parse_http_headers(raw_control_char)
    assert exc_info.value.status_code == 400
    assert secret not in exc_info.value.message
    assert secret not in str(exc_info.value)
    assert exc_info.value.message == "Header value contains prohibited control character"

def test_parse_measure_request_valid() -> None:
    payload = {
        "protocol_version": 1,
        "request_id": "req-custom-123",
        "probe": "tcp_connect",
        "target": {"host": "example.com", "port": 443},
        "config": {"timeout_s": 5.0},
    }
    raw = json.dumps(payload).encode("utf-8")
    req, clamped_timeout = parse_measure_request(raw)
    assert req.protocol_version == 1
    assert req.request_id == "req-custom-123"
    assert req.probe == "tcp_connect"
    assert req.target == Target(host="example.com", port=443)
    assert req.config == {"timeout_s": 5.0}
    assert clamped_timeout == 5.0

def test_parse_measure_request_generates_uuid_if_request_id_missing() -> None:
    payload = {
        "protocol_version": 1,
        "probe": "dns_resolve",
        "target": {"host": "example.com"},
    }
    raw = json.dumps(payload).encode("utf-8")
    req, clamped_timeout = parse_measure_request(raw)
    assert isinstance(req.request_id, str)
    assert len(req.request_id) > 10
    assert req.config == {}
    assert clamped_timeout == 10.0

def test_parse_measure_request_rejects_invalid_protocol_version() -> None:
    for bad_pv in [2, 0, -1, "1", None]:
        payload = {
            "protocol_version": bad_pv,
            "probe": "dns_resolve",
            "target": {"host": "example.com"},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400
        assert exc_info.value.error == "invalid_schema"

def test_parse_measure_request_rejects_boolean_protocol_version() -> None:
    payload = {
        "protocol_version": True,
        "probe": "dns_resolve",
        "target": {"host": "example.com"},
    }
    with pytest.raises(HttpError) as exc_info:
        parse_measure_request(json.dumps(payload).encode("utf-8"))
    assert exc_info.value.status_code == 400
    assert exc_info.value.error == "invalid_schema"

def test_parse_measure_request_rejects_unknown_probe() -> None:
    payload = {
        "protocol_version": 1,
        "request_id": "test-req",
        "probe": "nonexistent_probe",
        "target": {"host": "example.com"},
    }
    with pytest.raises(HttpError) as exc_info:
        parse_measure_request(json.dumps(payload).encode("utf-8"))
    assert exc_info.value.status_code == 404
    assert exc_info.value.error == "unknown_probe"
    assert exc_info.value.request_id == "test-req"

def test_parse_measure_request_rejects_whitespace_and_control_chars_in_host() -> None:
    invalid_hosts = [
        "example.com\r\nInjected-Header: evil",
        "example.com\n",
        "example. com",
        "example\t.com",
        "example.com\x00",
    ]
    for bad_host in invalid_hosts:
        payload = {
            "protocol_version": 1,
            "probe": "tcp_connect",
            "target": {"host": bad_host, "port": 80},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400
        assert "whitespace or control characters" in exc_info.value.message

def test_parse_measure_request_rejects_boolean_port() -> None:
    payload = {
        "protocol_version": 1,
        "probe": "tcp_connect",
        "target": {"host": "example.com", "port": True},
    }
    with pytest.raises(HttpError) as exc_info:
        parse_measure_request(json.dumps(payload).encode("utf-8"))
    assert exc_info.value.status_code == 400
    assert "target.port must be an integer" in exc_info.value.message

def test_parse_measure_request_rejects_out_of_range_port() -> None:
    for bad_port in [0, 65536, -80]:
        payload = {
            "protocol_version": 1,
            "probe": "tcp_connect",
            "target": {"host": "example.com", "port": bad_port},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400

def test_parse_measure_request_rejects_disallowed_config_keys() -> None:
    payload = {
        "protocol_version": 1,
        "probe": "tcp_connect",
        "target": {"host": "example.com", "port": 80},
        "config": {"timeout_s": 5.0, "unexpected_key": "not_allowed"},
    }
    with pytest.raises(HttpError) as exc_info:
        parse_measure_request(json.dumps(payload).encode("utf-8"))
    assert exc_info.value.status_code == 400
    assert exc_info.value.error == "invalid_config"
    assert "Unknown or disallowed config key" in exc_info.value.message

def test_parse_measure_request_rejects_client_connect_ip() -> None:
    payload = {
        "protocol_version": 1,
        "probe": "tcp_connect",
        "target": {"host": "example.com", "port": 80},
        "config": {"connect_ip": "1.2.3.4"},
    }
    with pytest.raises(HttpError) as exc_info:
        parse_measure_request(json.dumps(payload).encode("utf-8"))
    assert exc_info.value.status_code == 400
    assert exc_info.value.error == "invalid_config"

def test_parse_measure_request_clamps_excessive_timeout() -> None:
    payload = {
        "protocol_version": 1,
        "probe": "tcp_connect",
        "target": {"host": "example.com", "port": 80},
        "config": {"timeout_s": 120.0},
    }
    req, clamped = parse_measure_request(json.dumps(payload).encode("utf-8"), max_probe_timeout_s=30.0)
    assert req.config["timeout_s"] == 30.0
    assert clamped == 30.0

def test_parse_measure_request_rejects_invalid_timeout() -> None:
    for bad_ts in [0, -5.0, "5", True, None]:
        payload = {
            "protocol_version": 1,
            "probe": "tcp_connect",
            "target": {"host": "example.com", "port": 80},
            "config": {"timeout_s": bad_ts},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400
        assert "timeout_s must be a finite positive number" in exc_info.value.message

def test_parse_measure_request_rejects_verify_false() -> None:
    payload = {
        "protocol_version": 1,
        "probe": "tls_handshake",
        "target": {"host": "example.com", "port": 443},
        "config": {"verify": False},
    }
    with pytest.raises(HttpError) as exc_info:
        parse_measure_request(json.dumps(payload).encode("utf-8"))
    assert exc_info.value.status_code == 400
    assert "Disabling TLS verification is not permitted" in exc_info.value.message

def test_parse_measure_request_validates_http_method_and_path() -> None:
    payload = {
        "protocol_version": 1,
        "probe": "http_request",
        "target": {"host": "example.com", "port": 443},
        "config": {"method": "HEAD", "path": "/api/v1/status?query=1"},
    }
    req, _ = parse_measure_request(json.dumps(payload).encode("utf-8"))
    assert req.config["method"] == "HEAD"
    assert req.config["path"] == "/api/v1/status?query=1"

def test_parse_measure_request_rejects_http_path_injection() -> None:
    bad_paths = [
        "not_starting_with_slash",
        "/path with spaces",
        "/path\r\nInjected: yes",
        "/path\n",
    ]
    for bad_path in bad_paths:
        payload = {
            "protocol_version": 1,
            "probe": "http_request",
            "target": {"host": "example.com", "port": 443},
            "config": {"path": bad_path},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400

def test_parse_measure_request_rejects_invalid_http_method() -> None:
    bad_methods = ["GET WITH SPACES", "GET\r\n", ""]
    for bad_method in bad_methods:
        payload = {
            "protocol_version": 1,
            "probe": "http_request",
            "target": {"host": "example.com", "port": 443},
            "config": {"method": bad_method},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400

def test_format_http_response() -> None:
    body = b'{"status":"ok"}'
    resp = format_http_response(200, body)
    assert resp.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Length: 15\r\n" in resp
    assert b"Connection: close\r\n" in resp
    assert resp.endswith(b"\r\n\r\n" + body)

def test_format_json_response() -> None:
    data = {"protocol_version": 1, "status": "ok"}
    resp = format_json_response(200, data)
    assert b"Content-Type: application/json\r\n" in resp
    header_part, body_part = resp.split(b"\r\n\r\n", 1)
    assert json.loads(body_part.decode("utf-8")) == data

def test_format_error_response() -> None:
    resp = format_error_response(401, "unauthorized", "Missing token", request_id="req-99")
    _, body_part = resp.split(b"\r\n\r\n", 1)
    parsed = json.loads(body_part.decode("utf-8"))
    assert parsed["protocol_version"] == 1
    assert parsed["error"] == "unauthorized"
    assert parsed["message"] == "Missing token"
    assert parsed["request_id"] == "req-99"

def test_parse_measure_request_tls_handshake_with_valid_sni() -> None:
    payload = {
        "protocol_version": 1,
        "probe": "tls_handshake",
        "target": {"host": "con.acp.us.ci", "port": 443},
        "config": {"sni": "custom.sni.org"},
    }
    raw = json.dumps(payload).encode("utf-8")
    req, _ = parse_measure_request(raw)
    assert req.probe == "tls_handshake"
    assert req.config["sni"] == "custom.sni.org"

def test_parse_measure_request_tls_handshake_with_valid_no_sni() -> None:
    for no_sni_val in [True, False]:
        payload = {
            "protocol_version": 1,
            "probe": "tls_handshake",
            "target": {"host": "con.acp.us.ci", "port": 443},
            "config": {"no_sni": no_sni_val},
        }
        raw = json.dumps(payload).encode("utf-8")
        req, _ = parse_measure_request(raw)
        assert req.config["no_sni"] is no_sni_val

def test_parse_measure_request_tls_handshake_rejects_invalid_sni() -> None:
    invalid_snis = [
        "127.0.0.1",
        "1.1.1.1",
        "::1",
        "[2001:db8::1]",
        "foo bar.com",
        "foo\x00bar.com",
        "",
        "a" * 254,
        "example..com",
        "-bad.com",
        123,
        True,
    ]
    for bad_sni in invalid_snis:
        payload = {
            "protocol_version": 1,
            "probe": "tls_handshake",
            "target": {"host": "con.acp.us.ci", "port": 443},
            "config": {"sni": bad_sni},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400
        assert exc_info.value.error == "invalid_config"
        assert "Invalid sni" in exc_info.value.message

def test_parse_measure_request_tls_handshake_rejects_non_bool_no_sni() -> None:
    for bad_no_sni in ["yes", "true", 1, 0, None, ["true"]]:
        payload = {
            "protocol_version": 1,
            "probe": "tls_handshake",
            "target": {"host": "con.acp.us.ci", "port": 443},
            "config": {"no_sni": bad_no_sni},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400
        assert exc_info.value.error == "invalid_config"
        assert "no_sni must be a boolean" in exc_info.value.message

def test_parse_measure_request_tls_handshake_rejects_conflicting_sni_and_no_sni() -> None:
    payload = {
        "protocol_version": 1,
        "probe": "tls_handshake",
        "target": {"host": "con.acp.us.ci", "port": 443},
        "config": {"sni": "custom.sni.org", "no_sni": True},
    }
    with pytest.raises(HttpError) as exc_info:
        parse_measure_request(json.dumps(payload).encode("utf-8"))
    assert exc_info.value.status_code == 400
    assert exc_info.value.error == "invalid_config"
    assert "Cannot specify both sni and no_sni" in exc_info.value.message

def test_parse_measure_request_rejects_sni_for_unsupported_probes() -> None:
    for probe in ["tcp_connect", "dns_resolve", "http_request"]:
        payload = {
            "protocol_version": 1,
            "probe": probe,
            "target": {"host": "example.com", "port": 80},
            "config": {"sni": "custom.sni.org"},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400
        assert exc_info.value.error == "invalid_config"
        assert "Unknown or disallowed config key" in exc_info.value.message

def test_parse_measure_request_rejects_no_sni_for_unsupported_probes() -> None:
    for probe in ["tcp_connect", "dns_resolve", "http_request"]:
        payload = {
            "protocol_version": 1,
            "probe": probe,
            "target": {"host": "example.com", "port": 80},
            "config": {"no_sni": True},
        }
        with pytest.raises(HttpError) as exc_info:
            parse_measure_request(json.dumps(payload).encode("utf-8"))
        assert exc_info.value.status_code == 400
        assert exc_info.value.error == "invalid_config"
        assert "Unknown or disallowed config key" in exc_info.value.message

