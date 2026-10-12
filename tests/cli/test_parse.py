import math
import pytest

from connscope.core import ProbeRegistry, Target
from connscope.cli.parse import (
    parse_http_target,
    parse_target,
    resolve_probe_name,
    validate_timeout,
)


def test_parse_target_hostname():
    t = parse_target("example.com")
    assert t.host == "example.com"
    assert t.port is None

    t = parse_target("localhost")
    assert t.host == "localhost"
    assert t.port is None


def test_parse_target_hostname_with_port():
    t = parse_target("example.com:443")
    assert t.host == "example.com"
    assert t.port == 443

    t = parse_target("internal.corp:8080")
    assert t.host == "internal.corp"
    assert t.port == 8080


def test_parse_target_ipv4():
    t = parse_target("192.168.1.1")
    assert t.host == "192.168.1.1"
    assert t.port is None


def test_parse_target_ipv4_with_port():
    t = parse_target("192.168.1.1:80")
    assert t.host == "192.168.1.1"
    assert t.port == 80


def test_parse_target_bracketed_ipv6():
    t = parse_target("[2001:db8::1]")
    assert t.host == "2001:db8::1"
    assert t.port is None

    t = parse_target("[::1]")
    assert t.host == "::1"
    assert t.port is None


def test_parse_target_bracketed_ipv6_with_port():
    t = parse_target("[2001:db8::1]:443")
    assert t.host == "2001:db8::1"
    assert t.port == 443

    t = parse_target("[::1]:8080")
    assert t.host == "::1"
    assert t.port == 8080


def test_parse_target_bare_ipv6():
    t = parse_target("2001:db8::1")
    assert t.host == "2001:db8::1"
    assert t.port is None

    t = parse_target("::1")
    assert t.host == "::1"
    assert t.port is None


def test_parse_target_invalid_inputs():
    with pytest.raises(ValueError, match="empty"):
        parse_target("")

    with pytest.raises(ValueError, match="empty"):
        parse_target("   ")

    with pytest.raises(ValueError, match="empty"):
        parse_target(":443")

    with pytest.raises(ValueError, match="Invalid port"):
        parse_target("example.com:abc")

    with pytest.raises(ValueError, match="out of valid range"):
        parse_target("example.com:0")

    with pytest.raises(ValueError, match="out of valid range"):
        parse_target("example.com:70000")

    with pytest.raises(ValueError, match="missing ']'"):
        parse_target("[2001:db8::1")

    with pytest.raises(ValueError, match="Malformed bracket syntax"):
        parse_target("2001:db8::1]")

    with pytest.raises(ValueError, match="Invalid IPv6 address inside brackets"):
        parse_target("[not-an-ip]:443")

    with pytest.raises(ValueError, match="Generic target must not contain URL scheme"):
        parse_target("http://example.com")

    with pytest.raises(ValueError, match="Invalid character '/'"):
        parse_target("example.com/path")


def test_parse_http_target_urls():
    t, cfg = parse_http_target("https://example.com/api?v=1#section")
    assert t.host == "example.com"
    assert t.port == 443
    assert cfg["use_tls"] is True
    assert cfg["path"] == "/api?v=1"

    t, cfg = parse_http_target("http://example.com:8080/test")
    assert t.host == "example.com"
    assert t.port == 8080
    assert cfg["use_tls"] is False
    assert cfg["path"] == "/test"

    t, cfg = parse_http_target("http://[2001:db8::1]:8000/")
    assert t.host == "2001:db8::1"
    assert t.port == 8000
    assert cfg["use_tls"] is False
    assert cfg["path"] == "/"


def test_parse_http_target_plain_hosts():
    t, cfg = parse_http_target("example.com")
    assert t.host == "example.com"
    assert t.port == 443
    assert cfg["use_tls"] is True
    assert cfg["path"] == "/"

    t, cfg = parse_http_target("example.com:80")
    assert t.host == "example.com"
    assert t.port == 80
    assert cfg["use_tls"] is False
    assert cfg["path"] == "/"

    t, cfg = parse_http_target("example.com:8443")
    assert t.host == "example.com"
    assert t.port == 8443
    assert cfg["use_tls"] is True
    assert cfg["path"] == "/"


def test_parse_http_target_invalid():
    with pytest.raises(ValueError, match="empty"):
        parse_http_target("")

    with pytest.raises(ValueError, match="Unsupported URL scheme 'ftp'"):
        parse_http_target("ftp://example.com")

    with pytest.raises(ValueError, match="missing valid hostname"):
        parse_http_target("https:///path")

    with pytest.raises(ValueError, match="Invalid port in URL"):
        parse_http_target("http://example.com:abc/")

    with pytest.raises(ValueError, match="Target contains a path but no scheme"):
        parse_http_target("example.com/path")


def test_resolve_probe_name():
    reg = ProbeRegistry()
    class DummyProbe:
        def __init__(self, name):
            self.name = name

    reg.register(DummyProbe("tcp_connect"))
    reg.register(DummyProbe("dns_resolve"))
    reg.register(DummyProbe("tls_handshake"))
    reg.register(DummyProbe("http_request"))

    # Short aliases, case-insensitive
    assert resolve_probe_name("tcp", reg) == "tcp_connect"
    assert resolve_probe_name("TCP", reg) == "tcp_connect"
    assert resolve_probe_name("Dns", reg) == "dns_resolve"
    assert resolve_probe_name("tls", reg) == "tls_handshake"
    assert resolve_probe_name("HTTP", reg) == "http_request"

    # Canonical names
    assert resolve_probe_name("tcp_connect", reg) == "tcp_connect"
    assert resolve_probe_name("HTTP_REQUEST", reg) == "http_request"

    # Unknown
    with pytest.raises(KeyError, match="Unknown probe 'udp'"):
        resolve_probe_name("udp", reg)


def test_validate_timeout():
    assert validate_timeout(None) is None
    assert validate_timeout(5) == 5.0
    assert validate_timeout(2.5) == 2.5
    assert validate_timeout("10.0") == 10.0

    with pytest.raises(ValueError, match="positive finite number"):
        validate_timeout(0)

    with pytest.raises(ValueError, match="positive finite number"):
        validate_timeout(-1.5)

    with pytest.raises(ValueError, match="positive finite number"):
        validate_timeout(math.nan)

    with pytest.raises(ValueError, match="positive finite number"):
        validate_timeout(math.inf)

    with pytest.raises(ValueError, match="positive number"):
        validate_timeout("abc")
