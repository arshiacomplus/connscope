import pytest
from connscope.probes._utils import (
    normalize_ascii_domain,
    parse_connect_ip,
    to_ascii_domain,
    validate_a_label,
)

def test_parse_connect_ip_absent():
    assert parse_connect_ip(None) == (None, None)
    assert parse_connect_ip({}) == (None, None)
    assert parse_connect_ip({"timeout_s": 5.0}) == (None, None)

def test_parse_connect_ip_valid_ipv4():
    ip, err = parse_connect_ip({"connect_ip": "192.0.2.1"})
    assert ip == "192.0.2.1"
    assert err is None

def test_parse_connect_ip_valid_ipv6_bare():
    ip, err = parse_connect_ip({"connect_ip": "2001:db8::1"})
    assert ip == "2001:db8::1"
    assert err is None

def test_parse_connect_ip_valid_ipv6_bracketed():
    ip, err = parse_connect_ip({"connect_ip": "[2001:db8::1]"})
    assert ip == "2001:db8::1"
    assert err is None

def test_parse_connect_ip_ipv4_mapped_ipv6():
    ip, err = parse_connect_ip({"connect_ip": "::ffff:192.0.2.1"})
    assert ip == "192.0.2.1"
    assert err is None

def test_parse_connect_ip_invalid_hostname():
    ip, err = parse_connect_ip({"connect_ip": "example.com"})
    assert ip is None
    assert "not a valid IPv4 or IPv6 literal" in err

def test_parse_connect_ip_invalid_empty_or_whitespace():
    ip, err = parse_connect_ip({"connect_ip": ""})
    assert ip is None
    assert "non-empty" in err

    ip2, err2 = parse_connect_ip({"connect_ip": "   "})
    assert ip2 is None
    assert "non-empty" in err2

def test_parse_connect_ip_invalid_type():
    ip, err = parse_connect_ip({"connect_ip": 12345})
    assert ip is None
    assert "non-empty IP literal string" in err

def test_normalize_ascii_domain_valid():
    norm, err = normalize_ascii_domain("example.com")
    assert norm == "example.com"
    assert err is None

    norm, err = normalize_ascii_domain("ExAmPlE.CoM.")
    assert norm == "example.com"
    assert err is None

    norm, err = normalize_ascii_domain("xn--mnchen-3ya.de")
    assert norm == "xn--mnchen-3ya.de"
    assert err is None

    norm, err = normalize_ascii_domain("xn--fa-hia.de")
    assert norm == "xn--fa-hia.de"
    assert err is None

def test_normalize_ascii_domain_non_ascii_fails_closed():
    for raw in ["münchen.de", "faß.de", "tést.com", "домен.рф"]:
        norm, err = normalize_ascii_domain(raw)
        assert norm is None
        assert err == "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required"

def test_normalize_ascii_domain_invalid_syntax():
    assert normalize_ascii_domain(None) == (None, "Hostname must be a string")
    assert normalize_ascii_domain(123) == (None, "Hostname must be a string")
    assert normalize_ascii_domain("") == (None, "Hostname cannot be empty")
    assert normalize_ascii_domain(".") == (None, "Hostname cannot be empty")
    assert "whitespace or control" in normalize_ascii_domain("foo bar.com")[1]
    assert "whitespace or control" in normalize_ascii_domain("foo\x00bar.com")[1]
    assert "cannot contain empty labels" in normalize_ascii_domain("foo..bar.com")[1]
    assert "exceeds maximum length" in normalize_ascii_domain("a." * 130 + "com")[1]
    assert "exceeds 63 characters" in normalize_ascii_domain("a" * 64 + ".com")[1]
    assert "Invalid characters" in normalize_ascii_domain("-foo.com")[1]

def test_normalize_ascii_domain_wildcards():
    norm, err = normalize_ascii_domain("*.example.com", allow_wildcard=True)
    assert norm == "*.example.com"
    assert err is None

    norm, err = normalize_ascii_domain("*.example.com", allow_wildcard=False)
    assert norm is None
    assert "Invalid characters" in err

    assert normalize_ascii_domain("foo.*.example.com", allow_wildcard=True)[0] is None
    assert normalize_ascii_domain("f*.example.com", allow_wildcard=True)[0] is None
    assert normalize_ascii_domain("*.*.example.com", allow_wildcard=True)[0] is None

def test_to_ascii_domain_backward_compatibility():
    assert to_ascii_domain("example.com") == "example.com"
    assert to_ascii_domain("ExAmPlE.CoM.") == "example.com"
    assert to_ascii_domain("xn--mnchen-3ya.de") == "xn--mnchen-3ya.de"
    assert to_ascii_domain("*.example.com") == "*.example.com"
    assert to_ascii_domain("münchen.de") is None
    assert to_ascii_domain("faß.de") is None

def test_validate_a_label_valid():
    assert validate_a_label("xn--mnchen-3ya") == (True, None)
    assert validate_a_label("xn--fa-hia") == (True, None)
    assert validate_a_label("XN--MNCHEN-3YA") == (True, None)
    assert validate_a_label("xn--d1abbgf6aiiy") == (True, None)
    assert validate_a_label("example") == (True, None)
    assert validate_a_label("com") == (True, None)

def test_validate_a_label_invalid_cases():
    assert validate_a_label(123)[0] is False
    ok, err = validate_a_label("xn--")
    assert ok is False
    assert "empty Punycode payload" in err

    for bad in ["xn--test", "xn--0", "xn--9999999999a"]:
        ok, err = validate_a_label(bad)
        assert ok is False
        assert "malformed Punycode" in err

    for all_ascii in ["xn--abc-", "xn--example-", "xn---"]:
        ok, err = validate_a_label(all_ascii)
        assert ok is False
        assert "all-ASCII" in err

    ok, err = validate_a_label("xn---bbb")
    assert ok is False
    assert "fails Punycode round-trip encoding" in err

    ok, err = validate_a_label("xn--ib9b")
    assert ok is False
    assert "surrogate" in err

    ok, err = validate_a_label("xn--a")
    assert ok is False
    assert "control characters" in err

    ok, err = validate_a_label("xn--munchen-gie")
    assert ok is False
    assert "non-NFC" in err

def test_normalize_ascii_domain_a_label_validation():
    norm, err = normalize_ascii_domain("sub.xn--mnchen-3ya.de")
    assert norm == "sub.xn--mnchen-3ya.de"
    assert err is None

    norm, err = normalize_ascii_domain("XN--MNCHEN-3YA.DE")
    assert norm == "xn--mnchen-3ya.de"
    assert err is None

    norm, err = normalize_ascii_domain("xn--test.example.com")
    assert norm is None
    assert "malformed Punycode" in err

    norm, err = normalize_ascii_domain("xn--abc-.example.com")
    assert norm is None
    assert "all-ASCII" in err

    norm, err = normalize_ascii_domain("xn---bbb.example.com")
    assert norm is None
    assert "round-trip" in err

    norm, err = normalize_ascii_domain("xn--ib9b.example.com")
    assert norm is None
    assert "surrogate" in err

