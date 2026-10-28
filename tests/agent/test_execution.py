import ipaddress
import socket
import pytest

from connscope.core import Target
from connscope.agent.execution import (
    CONNECTION_PROBE_NAMES,
    SUPPORTED_PROBE_NAMES,
    UnsupportedProbeError,
    UntrustedConfigError,
    prepare_probe_config,
    select_connection_ip,
)
from connscope.agent.security import (
    TargetPolicyViolation,
    TargetResolutionError,
)

@pytest.mark.parametrize("probe_name", sorted(CONNECTION_PROBE_NAMES))
def test_prepare_probe_config_public_ipv4_literal(probe_name: str):
    target = Target(host="93.184.216.34", port=443)
    cfg = prepare_probe_config(probe_name, target)

    assert cfg == {"connect_ip": "93.184.216.34"}
    assert isinstance(cfg["connect_ip"], str)

@pytest.mark.parametrize("probe_name", sorted(CONNECTION_PROBE_NAMES))
def test_prepare_probe_config_public_ipv6_literal_bare_and_bracketed(probe_name: str):
    bare_target = Target(host="2606:2800:220:1:248:1893:25c8:1946", port=443)
    bare_cfg = prepare_probe_config(probe_name, bare_target)
    assert bare_cfg["connect_ip"] == "2606:2800:220:1:248:1893:25c8:1946"

    bracketed_target = Target(host="[2606:2800:220:1:248:1893:25c8:1946]", port=443)
    bracketed_cfg = prepare_probe_config(probe_name, bracketed_target)
    assert bracketed_cfg["connect_ip"] == "2606:2800:220:1:248:1893:25c8:1946"

def test_prepare_probe_config_hostname_selects_first_permitted_address():
    target = Target(host="example.com", port=443)

    def mock_resolver(_host: str):
        return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

    cfg = prepare_probe_config("http_request", target, resolver=mock_resolver)
    assert cfg["connect_ip"] == "93.184.216.34"

    def mock_resolver_ipv6_first(_host: str):
        return ["2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"]

    cfg_ipv6 = prepare_probe_config("http_request", target, resolver=mock_resolver_ipv6_first)
    assert cfg_ipv6["connect_ip"] == "2606:2800:220:1:248:1893:25c8:1946"

def test_select_connection_ip_policy():
    ipv4 = ipaddress.IPv4Address("93.184.216.34")
    ipv6 = ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946")

    assert select_connection_ip((ipv4, ipv6)) == ipv4
    assert select_connection_ip((ipv6, ipv4)) == ipv6

    with pytest.raises(ValueError, match="No validated IP addresses"):
        select_connection_ip(())

def test_prepare_probe_config_rejects_mixed_public_and_loopback():
    target = Target(host="dual.example", port=80)

    def mock_resolver(_host: str):
        return ["93.184.216.34", "127.0.0.1"]

    with pytest.raises(TargetPolicyViolation, match="loopback"):
        prepare_probe_config("tcp_connect", target, resolver=mock_resolver)

def test_prepare_probe_config_rejects_mixed_public_and_cloud_metadata():
    target = Target(host="metadata-rebinding.example", port=80)

    def mock_resolver(_host: str):
        return ["8.8.8.8", "169.254.169.254"]

    with pytest.raises(TargetPolicyViolation, match="cloud metadata"):
        prepare_probe_config("tls_handshake", target, resolver=mock_resolver)

@pytest.mark.parametrize(
    "private_ip",
    [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "fc00::1",
        "fd00::1",
    ],
)
def test_prepare_probe_config_private_rejected_by_default(private_ip: str):
    target = Target(host=private_ip, port=80)
    with pytest.raises(TargetPolicyViolation, match="private"):
        prepare_probe_config("tcp_connect", target, allow_private=False)

@pytest.mark.parametrize(
    "private_ip",
    [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "fc00::1",
        "fd00::1",
    ],
)
def test_prepare_probe_config_rfc1918_and_rfc4193_allowed_when_flag_enabled(private_ip: str):
    target = Target(host=private_ip, port=80)
    cfg = prepare_probe_config("tcp_connect", target, allow_private=True)
    assert cfg["connect_ip"] == private_ip

@pytest.mark.parametrize(
    "unsafe_ip, reason",
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("169.254.169.254", "cloud metadata"),
        ("169.254.1.1", "link-local"),
        ("100.64.0.1", "non-global"),
    ],
)
def test_prepare_probe_config_unsafe_destinations_still_rejected_with_allow_private(
    unsafe_ip: str, reason: str
):
    target = Target(host=unsafe_ip, port=80)
    with pytest.raises(TargetPolicyViolation, match=reason):
        prepare_probe_config("tcp_connect", target, allow_private=True)

def test_prepare_probe_config_rejects_empty_resolution():
    target = Target(host="empty.example", port=80)

    def mock_resolver(_host: str):
        return []

    with pytest.raises(TargetResolutionError, match="no usable IP addresses"):
        prepare_probe_config("http_request", target, resolver=mock_resolver)

def test_prepare_probe_config_rejects_resolver_failure():
    target = Target(host="failing.example", port=80)

    def mock_resolver(host: str):
        raise socket.gaierror(-2, f"Name or service not known for {host}")

    with pytest.raises(TargetResolutionError, match="DNS resolution failed"):
        prepare_probe_config("http_request", target, resolver=mock_resolver)

def test_prepare_probe_config_preserves_caller_config_without_mutation():
    original_config = {
        "timeout_s": 5.0,
        "method": "POST",
        "path": "/metrics",
        "use_tls": True,
        "headers": {"X-Custom": "test"},
    }
    config_copy = dict(original_config)

    target = Target(host="93.184.216.34", port=443)
    new_config = prepare_probe_config("http_request", target, original_config)

    assert original_config == config_copy
    assert "connect_ip" not in original_config

    assert new_config is not original_config
    assert new_config["timeout_s"] == 5.0
    assert new_config["method"] == "POST"
    assert new_config["path"] == "/metrics"
    assert new_config["use_tls"] is True
    assert new_config["headers"] == {"X-Custom": "test"}
    assert new_config["connect_ip"] == "93.184.216.34"

def test_prepare_probe_config_handles_none_config():
    target = Target(host="93.184.216.34", port=80)
    new_config = prepare_probe_config("tcp_connect", target, None)

    assert new_config == {"connect_ip": "93.184.216.34"}

@pytest.mark.parametrize("probe_name", sorted(SUPPORTED_PROBE_NAMES))
@pytest.mark.parametrize(
    "untrusted_connect_ip",
    [
        "1.2.3.4",
        "127.0.0.1",
        "",
        None,
    ],
)
def test_prepare_probe_config_rejects_client_supplied_connect_ip(
    probe_name: str, untrusted_connect_ip: str | None
):
    target = Target(host="example.com", port=80)
    caller_config = {"connect_ip": untrusted_connect_ip, "timeout_s": 5.0}

    with pytest.raises(UntrustedConfigError, match="Client-supplied 'connect_ip' is not allowed"):
        prepare_probe_config(probe_name, target, caller_config)

def test_prepare_probe_config_dns_resolve_does_not_call_resolver_or_inject_ip():
    resolver_called = False

    def guarded_resolver(_host: str):
        nonlocal resolver_called
        resolver_called = True
        raise AssertionError("Resolver must not be called for dns_resolve")

    target = Target(host="internal.corp", port=53)
    dns_config = {"timeout_s": 2.5, "record_type": "A"}

    prepared = prepare_probe_config(
        "dns_resolve",
        target,
        dns_config,
        resolver=guarded_resolver,
    )

    assert resolver_called is False
    assert "connect_ip" not in prepared
    assert prepared["timeout_s"] == 2.5
    assert prepared["record_type"] == "A"
    assert prepared is not dns_config

@pytest.mark.parametrize(
    "unknown_probe",
    [
        "custom_probe",
        "ping",
        "traceroute",
        "TCP_CONNECT",
        "",
        "unknown",
    ],
)
def test_prepare_probe_config_unknown_probe_fails_closed(unknown_probe: str):
    target = Target(host="8.8.8.8", port=53)
    with pytest.raises(UnsupportedProbeError, match="Unsupported probe"):
        prepare_probe_config(unknown_probe, target)

def test_prepare_probe_config_ipv4_mapped_ipv6_normalized():
    target = Target(host="::ffff:93.184.216.34", port=80)
    cfg = prepare_probe_config("tcp_connect", target)
    assert cfg["connect_ip"] == "93.184.216.34"

    def mock_resolver(_host: str):
        return ["::ffff:93.184.216.34"]

    host_target = Target(host="mapped.example", port=80)
    cfg_host = prepare_probe_config("tcp_connect", host_target, resolver=mock_resolver)
    assert cfg_host["connect_ip"] == "93.184.216.34"

def test_prepare_probe_config_type_validations():
    target = Target(host="example.com", port=80)

    with pytest.raises(TypeError, match="Expected probe_name to be str"):
        prepare_probe_config(123, target)  # type: ignore

    with pytest.raises(TypeError, match="Expected target to be Target"):
        prepare_probe_config("tcp_connect", "example.com")  # type: ignore

    with pytest.raises(TypeError, match="Expected config to be dict or None"):
        prepare_probe_config("tcp_connect", target, "invalid_config")  # type: ignore
