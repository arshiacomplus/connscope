import ipaddress
import socket
import pytest

from connscope.core import Target
from connscope.agent.security import (
    TargetPolicyViolation,
    TargetResolutionError,
    check_ip_address,
    extract_bearer_token,
    is_ip_allowed,
    normalize_ip_address,
    validate_ip_address,
    validate_target,
    verify_bearer_token,
)

def test_verify_bearer_token_matching():
    assert verify_bearer_token("secret123", "secret123") is True
    assert verify_bearer_token("abc-xyz_789", "abc-xyz_789") is True

def test_verify_bearer_token_mismatched():
    assert verify_bearer_token("wrong-secret", "secret123") is False
    assert verify_bearer_token("secret124", "secret123") is False

def test_verify_bearer_token_missing_or_empty_supplied():
    assert verify_bearer_token(None, "secret123") is False
    assert verify_bearer_token("", "secret123") is False
    assert verify_bearer_token("   ", "secret123") is False

def test_verify_bearer_token_missing_or_empty_expected():
    assert verify_bearer_token("secret123", None) is False
    assert verify_bearer_token("secret123", "") is False
    assert verify_bearer_token("secret123", "   ") is False

def test_verify_bearer_token_both_empty_or_none():
    assert verify_bearer_token(None, None) is False
    assert verify_bearer_token("", "") is False
    assert verify_bearer_token("  ", "  ") is False

@pytest.mark.parametrize("invalid_val", [123, [], {}, True, 3.14])
def test_verify_bearer_token_malformed_types(invalid_val):
    assert verify_bearer_token(invalid_val, "secret123") is False  # type: ignore
    assert verify_bearer_token("secret123", invalid_val) is False  # type: ignore

def test_verify_bearer_token_unicode():
    assert verify_bearer_token("tökén-🔐", "tökén-🔐") is True
    assert verify_bearer_token("tökén-🔑", "tökén-🔐") is False

def test_extract_bearer_token_valid():
    assert extract_bearer_token("Bearer my-token-123") == "my-token-123"
    assert extract_bearer_token("bearer my-token-123") == "my-token-123"
    assert extract_bearer_token("BEARER my-token-123") == "my-token-123"
    assert extract_bearer_token("Bearer   padded-token   ") == "padded-token"

def test_extract_bearer_token_invalid_or_missing():
    assert extract_bearer_token(None) is None
    assert extract_bearer_token("") is None
    assert extract_bearer_token("   ") is None
    assert extract_bearer_token(123) is None  # type: ignore
    assert extract_bearer_token("Bearer") is None
    assert extract_bearer_token("Bearer ") is None
    assert extract_bearer_token("Basic dXNlcjpwYXNz") is None
    assert extract_bearer_token("Token 12345") is None

def test_normalize_ip_address_ipv4_mapped():
    mapped = ipaddress.IPv6Address("::ffff:127.0.0.1")
    norm = normalize_ip_address(mapped)
    assert norm == ipaddress.IPv4Address("127.0.0.1")
    assert isinstance(norm, ipaddress.IPv4Address)

def test_normalize_ip_address_native():
    ipv4 = ipaddress.IPv4Address("8.8.8.8")
    assert normalize_ip_address(ipv4) == ipv4

    ipv6 = ipaddress.IPv6Address("2001:db8::1")
    assert normalize_ip_address(ipv6) == ipv6

@pytest.mark.parametrize(
    "prohibited_ip, reason_substr",
    [
        ("127.0.0.1", "loopback"),
        ("127.0.0.2", "loopback"),
        ("127.255.255.255", "loopback"),
        ("::1", "loopback"),
        ("[::1]", "loopback"),
        ("10.0.0.1", "private"),
        ("10.255.255.254", "private"),
        ("172.16.0.1", "private"),
        ("172.31.255.254", "private"),
        ("192.168.0.1", "private"),
        ("192.168.1.100", "private"),
        ("fc00::1", "private"),
        ("fd00::1", "private"),
        ("169.254.1.1", "link-local"),
        ("169.254.254.254", "link-local"),
        ("fe80::1", "link-local"),
        ("0.0.0.0", "unspecified"),
        ("::", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("239.255.255.250", "multicast"),
        ("ff02::1", "multicast"),
        ("169.254.169.254", "cloud metadata"),
        ("fd00:ec2::254", "cloud metadata"),
        ("100.100.100.200", "cloud metadata"),
        ("240.0.0.1", "reserved"),
        ("255.255.255.255", "reserved"),
        ("100.64.0.1", "non-global"),
        ("::ffff:127.0.0.1", "loopback"),
        ("::ffff:10.0.0.1", "private"),
        ("::ffff:169.254.169.254", "cloud metadata"),
        ("::ffff:0.0.0.0", "unspecified"),
    ],
)
def test_target_policy_rejects_prohibited_ips(prohibited_ip: str, reason_substr: str):
    target = Target(host=prohibited_ip, port=80)
    assert is_ip_allowed(prohibited_ip) is False
    with pytest.raises(TargetPolicyViolation) as exc_info:
        validate_target(target, allow_private=False)
    assert reason_substr in str(exc_info.value).lower()

@pytest.mark.parametrize(
    "allowed_ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
        "[2606:2800:220:1:248:1893:25c8:1946]",
        "::ffff:8.8.8.8",
    ],
)
def test_target_policy_allows_public_ips(allowed_ip: str):
    target = Target(host=allowed_ip, port=443)
    assert is_ip_allowed(allowed_ip) is True
    validated = validate_target(target, allow_private=False)
    assert len(validated) == 1
    validate_ip_address(allowed_ip)

@pytest.mark.parametrize(
    "private_ip",
    [
        "10.0.0.1",
        "10.255.0.1",
        "172.16.0.1",
        "172.31.1.1",
        "192.168.1.1",
        "192.168.0.254",
        "fc00::1",
        "fd12:3456::1",
    ],
)
def test_target_policy_allows_private_when_flag_enabled(private_ip: str):
    target = Target(host=private_ip, port=8080)
    assert is_ip_allowed(private_ip, allow_private=True) is True
    validated = validate_target(target, allow_private=True)
    assert len(validated) == 1
    validate_ip_address(private_ip, allow_private=True)

@pytest.mark.parametrize(
    "still_prohibited_ip, reason_substr",
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("::ffff:127.0.0.1", "loopback"),
        ("169.254.169.254", "cloud metadata"),
        ("fd00:ec2::254", "cloud metadata"),
        ("100.100.100.200", "cloud metadata"),
        ("169.254.1.1", "link-local"),
        ("fe80::1", "link-local"),
        ("0.0.0.0", "unspecified"),
        ("::", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("ff02::1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("255.255.255.255", "reserved"),
        ("100.64.0.1", "non-global"),
        ("192.0.2.1", "private"),
        ("198.51.100.1", "private"),
        ("203.0.113.1", "private"),
        ("2001:db8::1", "private"),
        ("198.18.0.1", "private"),
        ("::ffff:100.64.0.1", "non-global"),
        ("::ffff:192.0.2.1", "private"),
    ],
)
def test_target_policy_still_rejects_unsafe_when_allow_private_enabled(
    still_prohibited_ip: str, reason_substr: str
):
    target = Target(host=still_prohibited_ip, port=80)
    assert is_ip_allowed(still_prohibited_ip, allow_private=True) is False
    with pytest.raises(TargetPolicyViolation) as exc_info:
        validate_target(target, allow_private=True)
    assert reason_substr in str(exc_info.value).lower()

def test_validate_target_returns_normalized_ipv4_for_mapped_ipv6():
    target = Target(host="::ffff:8.8.8.8", port=443)
    validated = validate_target(target, allow_private=False)
    assert len(validated) == 1
    addr = validated[0]
    assert isinstance(addr, ipaddress.IPv4Address)
    assert addr == ipaddress.IPv4Address("8.8.8.8")

    target_bracketed = Target(host="[::ffff:8.8.8.8]", port=443)
    validated_b = validate_target(target_bracketed, allow_private=False)
    assert len(validated_b) == 1
    assert isinstance(validated_b[0], ipaddress.IPv4Address)
    assert validated_b[0] == ipaddress.IPv4Address("8.8.8.8")

    target_host = Target(host="mapped-public.example", port=443)

    def mock_resolver(_host: str):
        return ["::ffff:8.8.8.8"]

    validated_host = validate_target(target_host, resolver=mock_resolver)
    assert len(validated_host) == 1
    assert isinstance(validated_host[0], ipaddress.IPv4Address)
    assert validated_host[0] == ipaddress.IPv4Address("8.8.8.8")

def test_validate_target_mapped_private_when_allow_private_enabled():
    target = Target(host="::ffff:10.0.0.1", port=443)
    validated = validate_target(target, allow_private=True)
    assert len(validated) == 1
    addr = validated[0]
    assert isinstance(addr, ipaddress.IPv4Address)
    assert addr == ipaddress.IPv4Address("10.0.0.1")

def test_validate_target_hostname_all_public():
    target = Target(host="example.com", port=443)

    def mock_resolver(_host: str):
        return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

    validated = validate_target(target, resolver=mock_resolver)
    assert len(validated) == 2
    assert ipaddress.IPv4Address("93.184.216.34") in validated
    assert ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946") in validated

def test_validate_target_hostname_resolves_to_loopback():
    target = Target(host="localhost.example", port=80)

    def mock_resolver(_host: str):
        return ["127.0.0.1"]

    with pytest.raises(TargetPolicyViolation, match="loopback"):
        validate_target(target, resolver=mock_resolver)

def test_validate_target_hostname_resolves_to_private():
    target = Target(host="internal.corp", port=80)

    def mock_resolver(_host: str):
        return ["10.0.0.1"]

    with pytest.raises(TargetPolicyViolation, match="private"):
        validate_target(target, resolver=mock_resolver)

def test_validate_target_hostname_mixed_public_and_prohibited():
    target = Target(host="dual.example", port=80)

    def mock_resolver(_host: str):
        return ["93.184.216.34", "127.0.0.1"]

    with pytest.raises(TargetPolicyViolation, match="resolves to prohibited address '127.0.0.1'"):
        validate_target(target, resolver=mock_resolver)

def test_validate_target_hostname_mixed_public_and_metadata():
    target = Target(host="rebinding.example", port=80)

    def mock_resolver(_host: str):
        return ["8.8.8.8", "169.254.169.254"]

    with pytest.raises(TargetPolicyViolation, match="cloud metadata"):
        validate_target(target, resolver=mock_resolver)

def test_validate_target_hostname_resolves_to_mapped_ipv4():
    target = Target(host="mapped.example", port=80)

    def mock_resolver(_host: str):
        return ["::ffff:127.0.0.1"]

    with pytest.raises(TargetPolicyViolation, match="loopback"):
        validate_target(target, resolver=mock_resolver)

def test_validate_target_hostname_empty_resolution():
    target = Target(host="empty.example", port=80)

    def mock_resolver(_host: str):
        return []

    with pytest.raises(TargetResolutionError, match="resolved to no usable IP addresses"):
        validate_target(target, resolver=mock_resolver)

def test_validate_target_hostname_resolver_failure():
    target = Target(host="failing.example", port=80)

    def mock_resolver(host: str):
        raise socket.gaierror(-2, f"Name or service not known for {host}")

    with pytest.raises(TargetResolutionError, match="DNS resolution failed"):
        validate_target(target, resolver=mock_resolver)

def test_validate_target_hostname_invalid_resolved_address():
    target = Target(host="bad.example", port=80)

    def mock_resolver(_host: str):
        return ["not_an_ip_address"]

    with pytest.raises(TargetResolutionError, match="yielded invalid address"):
        validate_target(target, resolver=mock_resolver)

def test_validate_target_rejects_non_target_instance():
    with pytest.raises(TypeError, match="Expected Target instance"):
        validate_target("example.com")  # type: ignore

def test_default_resolver_offline_gaierror(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    target = Target(host="some-test-host.invalid", port=80)
    with pytest.raises(TargetResolutionError, match="DNS resolution failed"):
        validate_target(target)
