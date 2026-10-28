import asyncio
import ssl
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from connscope.core import Target, ProbeStatus
from connscope.probes.tls_handshake import TlsHandshakeProbe

@patch("asyncio.open_connection")
async def test_tls_handshake_success_mocked(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {
        "subject": [[("commonName", "example.com")]],
        "subjectAltName": [("DNS", "example.com")],
    }

    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com"))

    assert result.status == ProbeStatus.SUCCESS
    assert "connect_ms" in result.metrics
    assert "handshake_ms" in result.metrics
    assert "total_ms" in result.metrics

    assert result.details["tls_version"] == "TLSv1.3"
    assert result.details["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result.details["cert_subject"] == "example.com"

    mock_writer.start_tls.assert_called_once()
    assert mock_writer.start_tls.call_args[1]["server_hostname"] == "example.com"
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@patch("asyncio.open_connection")
async def test_tls_handshake_tcp_failed_mocked(mock_open_connection):
    mock_open_connection.side_effect = ConnectionRefusedError("Connection refused")

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com"))

    assert result.status == ProbeStatus.FAILED
    assert "Connection refused" in result.error

@patch("asyncio.open_connection")
async def test_tls_handshake_tls_failed_mocked(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock(side_effect=ssl.SSLError("CERTIFICATE_VERIFY_FAILED"))
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com"))

    assert result.status == ProbeStatus.FAILED
    assert "CERTIFICATE_VERIFY_FAILED" in result.error
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@patch("asyncio.open_connection")
async def test_tls_handshake_timeout_mocked(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()

    async def slow_handshake(*args, **kwargs):
        await asyncio.sleep(2.0)

    mock_writer.start_tls = AsyncMock(side_effect=slow_handshake)
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com"), config={"timeout_s": 0.01})

    assert result.status == ProbeStatus.TIMEOUT
    assert "timed out" in result.error
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@patch("asyncio.open_connection")
async def test_tls_handshake_with_pinned_ipv4(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {
        "subject": [[("commonName", "example.com")]],
        "subjectAltName": [("DNS", "example.com")],
    }
    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)
    result = await probe.run(target, config={"connect_ip": "93.184.216.34"})

    assert result.status == ProbeStatus.SUCCESS
    mock_open_connection.assert_called_once_with("93.184.216.34", 443)
    assert mock_writer.start_tls.call_args[1]["server_hostname"] == "example.com"
    assert result.target.host == "example.com"
    assert result.details["connect_ip"] == "93.184.216.34"
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@patch("asyncio.open_connection")
async def test_tls_handshake_with_pinned_ipv6_bracketed(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()
    mock_writer.get_extra_info.return_value = None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)
    result = await probe.run(
        target,
        config={"connect_ip": "[2606:2800:220:1:248:1893:25c8:1946]"},
    )

    assert result.status == ProbeStatus.SUCCESS
    mock_open_connection.assert_called_once_with("2606:2800:220:1:248:1893:25c8:1946", 443)
    assert mock_writer.start_tls.call_args[1]["server_hostname"] == "example.com"
    assert result.details["connect_ip"] == "2606:2800:220:1:248:1893:25c8:1946"
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@patch("asyncio.open_connection")
async def test_tls_handshake_invalid_connect_ip_rejected(mock_open_connection):
    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)

    result = await probe.run(target, config={"connect_ip": "not-an-ip.org"})
    assert result.status == ProbeStatus.FAILED
    assert "not a valid IPv4 or IPv6 literal" in result.error
    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_pinned_verify_false_rejected(mock_open_connection):
    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)
    result = await probe.run(
        target,
        config={"connect_ip": "93.184.216.34", "verify": False},
    )

    assert result.status == ProbeStatus.FAILED
    assert "Disabling TLS verification is not allowed when connect_ip is pinned" in result.error
    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_unpinned_verify_false_allowed(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()
    mock_writer.get_extra_info.return_value = None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com", port=443), config={"verify": False})

    assert result.status == ProbeStatus.SUCCESS
    ssl_ctx = mock_writer.start_tls.call_args[0][0]
    assert ssl_ctx.check_hostname is False
    assert ssl_ctx.verify_mode == ssl.CERT_NONE
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@patch("asyncio.open_connection")
async def test_tls_handshake_pinned_ip_tls_failure_no_fallback(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock(side_effect=ssl.SSLError("CERTIFICATE_VERIFY_FAILED"))
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)
    result = await probe.run(target, config={"connect_ip": "93.184.216.34"})

    assert result.status == ProbeStatus.FAILED
    assert "CERTIFICATE_VERIFY_FAILED" in result.error
    mock_open_connection.assert_called_once_with("93.184.216.34", 443)
    assert result.target.host == "example.com"
    assert result.details["connect_ip"] == "93.184.216.34"
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@patch("asyncio.open_connection")
async def test_tls_handshake_cancellation_during_handshake_cleans_up(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()

    async def slow_handshake(*args, **kwargs):
        await asyncio.sleep(10)

    mock_writer.start_tls = AsyncMock(side_effect=slow_handshake)
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    task = asyncio.create_task(probe.run(Target(host="example.com", port=443)))
    await asyncio.sleep(0.01)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()

@pytest.mark.network
async def test_tls_handshake_network_real():
    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com", port=443))

    assert result.status == ProbeStatus.SUCCESS
    assert "connect_ms" in result.metrics
    assert "handshake_ms" in result.metrics
    assert "tls_version" in result.details
    assert result.details["handshake_completed"] is True
    assert result.details["hostname_verified"] is True
    assert result.details["sni"] == "example.com"

from connscope.probes._utils import validate_sni, verify_certificate_hostname

def test_validate_sni_helper_valid():
    assert validate_sni("example.com") == "example.com"
    assert validate_sni("sub.domain.co.uk") == "sub.domain.co.uk"
    assert validate_sni("my-host-1.test") == "my-host-1.test"
    assert validate_sni("con.acp.us.ci") == "con.acp.us.ci"
    assert validate_sni("a" * 63 + ".com") == "a" * 63 + ".com"
    assert validate_sni("xn--mnchen-3ya.de") == "xn--mnchen-3ya.de"
    assert validate_sni("xn--fa-hia.de") == "xn--fa-hia.de"

def test_validate_sni_helper_invalid():
    invalid_inputs = [
        (None, "must be a string"),
        (123, "must be a string"),
        (True, "must be a string"),
        ("", "between 1 and 253"),
        ("a" * 254, "between 1 and 253"),
        ("a" * 64 + ".com", "cannot exceed 63"),
        ("127.0.0.1", "must not be an IP address literal"),
        ("1.1.1.1", "must not be an IP address literal"),
        ("::1", "must not be an IP address literal"),
        ("[2001:db8::1]", "must not be an IP address literal"),
        ("example..com", "cannot have empty labels"),
        (".example.com", "cannot have empty labels"),
        ("example.com.", "cannot have empty labels"),
        ("-example.com", "Invalid characters in SNI label"),
        ("example-.com", "Invalid characters in SNI label"),
        ("example com", "contains whitespace or control characters"),
        ("example\tcom", "contains whitespace or control characters"),
        ("example\x00com", "contains whitespace or control characters"),
        ("münchen.de", "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required"),
        ("faß.de", "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required"),
        ("xn--test.com", "malformed Punycode"),
        ("xn--abc-.com", "all-ASCII"),
        ("xn---bbb.com", "fails Punycode round-trip encoding"),
    ]
    for inp, expected_err in invalid_inputs:
        with pytest.raises(ValueError) as exc_info:
            validate_sni(inp)
        assert expected_err in str(exc_info.value)

def test_verify_certificate_hostname_helper():
    cert_dns = {"subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")]}
    matched, err = verify_certificate_hostname(cert_dns, "example.com")
    assert matched is True
    assert err is None

    cert_cn_only = {"subject": [[("commonName", "example.com")]]}
    matched, err = verify_certificate_hostname(cert_cn_only, "example.com")
    assert matched is False
    assert "certificate does not match hostname 'example.com'" in err
    assert "DNS SANs: none" in err

    cert_cn_mismatch_san = {
        "subject": [[("commonName", "example.com")]],
        "subjectAltName": [("DNS", "other.com")],
    }
    matched, err = verify_certificate_hostname(cert_cn_mismatch_san, "example.com")
    assert matched is False
    assert "certificate does not match hostname 'example.com'" in err
    assert "'other.com'" in err

    cert_wildcard = {"subjectAltName": [("DNS", "*.example.com")]}
    matched, err = verify_certificate_hostname(cert_wildcard, "sub.example.com")
    assert matched is True
    assert err is None

    matched, err = verify_certificate_hostname(cert_wildcard, "foo.bar.example.com")
    assert matched is False
    assert "certificate does not match hostname 'foo.bar.example.com'" in err

    matched, err = verify_certificate_hostname(cert_wildcard, "example.com")
    assert matched is False

    for invalid_pat in ["f*.example.com", "*f.example.com", "*.*.example.com", "foo.*.example.com", "*", "*.com"]:
        c = {"subjectAltName": [("DNS", invalid_pat)]}
        m, _ = verify_certificate_hostname(c, "foo.example.com")
        assert m is False, f"Wildcard pattern '{invalid_pat}' must not match 'foo.example.com'"

    cert_ip4 = {"subjectAltName": [("IP Address", "1.1.1.1"), ("IP Address", "1.0.0.1")]}
    matched, err = verify_certificate_hostname(cert_ip4, "1.1.1.1")
    assert matched is True
    assert err is None

    cert_ip6 = {"subjectAltName": [("IP Address", "2001:db8::1")]}
    matched, err = verify_certificate_hostname(cert_ip6, "2001:db8::1")
    assert matched is True
    assert err is None

    matched, err = verify_certificate_hostname(cert_ip6, "[2001:db8::1]")
    assert matched is True
    assert err is None

    matched, err = verify_certificate_hostname(cert_ip4, "1.2.3.4")
    assert matched is False
    assert "certificate does not match IP '1.2.3.4'" in err

    cert_dns_as_ip = {
        "subject": [[("commonName", "1.1.1.1")]],
        "subjectAltName": [("DNS", "1.1.1.1")],
    }
    matched, err = verify_certificate_hostname(cert_dns_as_ip, "1.1.1.1")
    assert matched is False
    assert "certificate does not match IP '1.1.1.1'" in err
    assert "IP SANs: none" in err

    cert_upper = {"subjectAltName": [("DNS", "ExAmPlE.CoM")]}
    matched, err = verify_certificate_hostname(cert_upper, "example.com")
    assert matched is True
    assert err is None

    matched, err = verify_certificate_hostname({"subjectAltName": [("DNS", "example.com")]}, "ExAmPlE.CoM")
    assert matched is True
    assert err is None

    cert_idna_a = {"subjectAltName": [("DNS", "xn--mnchen-3ya.de")]}
    matched, err = verify_certificate_hostname(cert_idna_a, "xn--mnchen-3ya.de")
    assert matched is True
    assert err is None

    cert_idna_upper = {"subjectAltName": [("DNS", "XN--MNCHEN-3YA.DE")]}
    matched, err = verify_certificate_hostname(cert_idna_upper, "xn--mnchen-3ya.de")
    assert matched is True
    assert err is None

    cert_idna_wildcard = {"subjectAltName": [("DNS", "*.xn--mnchen-3ya.de")]}
    matched, err = verify_certificate_hostname(cert_idna_wildcard, "sub.xn--mnchen-3ya.de")
    assert matched is True
    assert err is None

    matched, err = verify_certificate_hostname(cert_idna_a, "münchen.de")
    assert matched is False
    assert err == "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required"

    cert_idna_u = {"subjectAltName": [("DNS", "münchen.de")]}
    matched, err = verify_certificate_hostname(cert_idna_u, "xn--mnchen-3ya.de")
    assert matched is False
    assert "certificate does not match hostname 'xn--mnchen-3ya.de'" in err

    cert_fass = {"subjectAltName": [("DNS", "fass.de")]}
    matched, err = verify_certificate_hostname(cert_fass, "faß.de")
    assert matched is False
    assert err == "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required"

    cert_fass_u = {"subjectAltName": [("DNS", "faß.de")]}
    matched, err = verify_certificate_hostname(cert_fass_u, "fass.de")
    assert matched is False
    assert "certificate does not match hostname 'fass.de'" in err

    cert_fass_a = {"subjectAltName": [("DNS", "xn--fa-hia.de")]}
    matched, err = verify_certificate_hostname(cert_fass_a, "xn--fa-hia.de")
    assert matched is True
    assert err is None

    matched, err = verify_certificate_hostname(cert_fass_a, "xn--test.de")
    assert matched is False
    assert "malformed Punycode" in err

    matched, err = verify_certificate_hostname(cert_fass_a, "xn--abc-.de")
    assert matched is False
    assert "all-ASCII" in err

    matched, err = verify_certificate_hostname(cert_fass_a, "xn---bbb.de")
    assert matched is False
    assert "fails Punycode round-trip encoding" in err

    cert_bad_a_san = {"subjectAltName": [("DNS", "xn--test.de"), ("DNS", "valid.example.com")]}
    matched, err = verify_certificate_hostname(cert_bad_a_san, "valid.example.com")
    assert matched is True
    assert err is None

    matched, err = verify_certificate_hostname(cert_bad_a_san, "xn--test.de")
    assert matched is False
    assert "malformed Punycode" in err

    matched, err = verify_certificate_hostname({"subjectAltName": [("DNS", "example.com")]}, "invalid\x00host")
    assert matched is False

    cert_unsupported = {
        "subjectAltName": [
            ("email", "admin@example.com"),
            ("otherName", "something"),
            ("DNS", 12345),
            ("IP Address", "invalid-ip-string"),
            ("URI", "https://example.com"),
            ("DNS", "valid.example.com"),
        ]
    }
    matched, err = verify_certificate_hostname(cert_unsupported, "valid.example.com")
    assert matched is True
    assert err is None

    matched, err = verify_certificate_hostname(cert_unsupported, "admin@example.com")
    assert matched is False

@patch("asyncio.open_connection")
async def test_tls_handshake_custom_sni_independent_of_destination(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {"subjectAltName": [("DNS", "target.example.com")]}

    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    target = Target(host="target.example.com", port=443)
    result = await probe.run(
        target,
        config={"connect_ip": "45.13.119.236", "sni": "custom.sni.org"},
    )

    assert result.status == ProbeStatus.SUCCESS
    mock_open_connection.assert_called_once_with("45.13.119.236", 443)
    assert mock_writer.start_tls.call_args[1]["server_hostname"] == "custom.sni.org"
    assert result.details["sni"] == "custom.sni.org"
    assert result.details["connect_ip"] == "45.13.119.236"
    assert result.details["handshake_completed"] is True
    assert result.details["hostname_verified"] is True

@patch("asyncio.open_connection")
async def test_tls_handshake_custom_sni_hostname_mismatch_reports_handshake_completed(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {
        "subjectAltName": [("DNS", "custom.sni.org")],
        "subject": [[("commonName", "custom.sni.org")]],
    }

    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    target = Target(host="target.example.com", port=443)
    result = await probe.run(
        target,
        config={"connect_ip": "45.13.119.236", "sni": "custom.sni.org"},
    )

    assert result.status == ProbeStatus.FAILED
    assert "Certificate hostname mismatch" in result.error
    assert "target.example.com" in result.error
    assert result.details["handshake_completed"] is True
    assert result.details["hostname_verified"] is False
    assert result.details["sni"] == "custom.sni.org"
    assert result.details["tls_version"] == "TLSv1.3"
    assert result.details["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result.details["cert_subject"] == "custom.sni.org"
    assert "connect_ms" in result.metrics
    assert "handshake_ms" in result.metrics
    assert "total_ms" in result.metrics

@patch("asyncio.open_connection")
async def test_tls_handshake_no_sni_omits_extension(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {"subjectAltName": [("DNS", "example.com")]}

    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)
    result = await probe.run(target, config={"no_sni": True})

    assert result.status == ProbeStatus.SUCCESS
    assert mock_writer.start_tls.call_args[1]["server_hostname"] is None
    assert result.details["sni"] is None
    assert result.details["handshake_completed"] is True
    assert result.details["hostname_verified"] is True

@patch("asyncio.open_connection")
async def test_tls_handshake_cert_chain_failure_reports_handshake_not_completed(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock(
        side_effect=ssl.SSLCertVerificationError("certificate verify failed: self-signed certificate")
    )
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com", port=443))

    assert result.status == ProbeStatus.FAILED
    assert "TLS certificate verification failed" in result.error
    assert result.details["handshake_completed"] is False

@patch("asyncio.open_connection")
async def test_tls_handshake_tcp_failure_reports_handshake_not_completed(mock_open_connection):
    mock_open_connection.side_effect = ConnectionRefusedError("Connection refused")

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com", port=443))

    assert result.status == ProbeStatus.FAILED
    assert "TCP connection failed" in result.error
    assert result.details["handshake_completed"] is False

@patch("asyncio.open_connection")
async def test_tls_handshake_invalid_sni_rejected_early(mock_open_connection):
    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)

    res = await probe.run(target, config={"sni": "foo bar.com"})
    assert res.status == ProbeStatus.FAILED
    assert "Invalid SNI" in res.error
    assert res.details["handshake_completed"] is False

    res = await probe.run(target, config={"sni": "127.0.0.1"})
    assert res.status == ProbeStatus.FAILED
    assert "IP address literal" in res.error

    res = await probe.run(target, config={"sni": 123})
    assert res.status == ProbeStatus.FAILED
    assert "sni must be a string" in res.error

    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_conflicting_sni_and_no_sni_rejected_early(mock_open_connection):
    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)

    res = await probe.run(target, config={"sni": "custom.com", "no_sni": True})
    assert res.status == ProbeStatus.FAILED
    assert "Cannot specify both sni and no_sni" in res.error
    assert res.details["handshake_completed"] is False

    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_invalid_no_sni_type_rejected_early(mock_open_connection):
    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)

    res = await probe.run(target, config={"no_sni": "yes"})
    assert res.status == ProbeStatus.FAILED
    assert "no_sni must be a boolean" in res.error
    assert res.details["handshake_completed"] is False

    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_common_name_only_fails_hostname_verification(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {"subject": [[("commonName", "example.com")]]}

    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com", port=443))

    assert result.status == ProbeStatus.FAILED
    assert "Certificate hostname mismatch" in result.error
    assert "DNS SANs: none" in result.error
    assert result.details["handshake_completed"] is True
    assert result.details["hostname_verified"] is False
    assert result.details["cert_subject"] == "example.com"
    assert "connect_ms" in result.metrics
    assert "handshake_ms" in result.metrics

@patch("asyncio.open_connection")
async def test_tls_handshake_common_name_cannot_override_mismatching_dns_san(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {
        "subject": [[("commonName", "example.com")]],
        "subjectAltName": [("DNS", "other.com")],
    }

    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="example.com", port=443))

    assert result.status == ProbeStatus.FAILED
    assert "Certificate hostname mismatch" in result.error
    assert "'other.com'" in result.error
    assert result.details["handshake_completed"] is True
    assert result.details["hostname_verified"] is False

@patch("asyncio.open_connection")
async def test_tls_handshake_ip_literal_target_rejects_dns_san_alone(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {
        "subject": [[("commonName", "1.1.1.1")]],
        "subjectAltName": [("DNS", "1.1.1.1")],
    }

    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    result = await probe.run(Target(host="1.1.1.1", port=443))

    assert result.status == ProbeStatus.FAILED
    assert "Certificate hostname mismatch" in result.error
    assert "IP SANs: none" in result.error
    assert result.details["handshake_completed"] is True
    assert result.details["hostname_verified"] is False

@patch("asyncio.open_connection")
async def test_tls_handshake_raw_non_ascii_sni_fails_closed(mock_open_connection):
    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)

    res = await probe.run(target, config={"sni": "münchen.de"})
    assert res.status == ProbeStatus.FAILED
    assert "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required" in res.error
    assert res.details["handshake_completed"] is False

    res2 = await probe.run(target, config={"sni": "faß.de"})
    assert res2.status == ProbeStatus.FAILED
    assert "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required" in res2.error
    assert res2.details["handshake_completed"] is False

    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_raw_non_ascii_target_fails_closed(mock_open_connection):
    probe = TlsHandshakeProbe()

    res = await probe.run(Target(host="münchen.de", port=443))
    assert res.status == ProbeStatus.FAILED
    assert "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required" in res.error
    assert res.details["handshake_completed"] is False

    res2 = await probe.run(Target(host="faß.de", port=443))
    assert res2.status == ProbeStatus.FAILED
    assert "Non-ASCII hostname is not supported; an ASCII A-label hostname (e.g. 'xn--...') is required" in res2.error
    assert res2.details["handshake_completed"] is False

    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_a_label_target_and_sni_success(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {
        "subjectAltName": [("DNS", "xn--mnchen-3ya.de")],
    }

    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    target = Target(host="xn--mnchen-3ya.de", port=443)
    result = await probe.run(target, config={"sni": "xn--fa-hia.de"})

    assert result.status == ProbeStatus.SUCCESS
    assert mock_writer.start_tls.call_args[1]["server_hostname"] == "xn--fa-hia.de"
    assert result.details["sni"] == "xn--fa-hia.de"
    assert result.details["handshake_completed"] is True
    assert result.details["hostname_verified"] is True

@patch("asyncio.open_connection")
async def test_tls_handshake_ssl_context_uses_cert_required(mock_open_connection):
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.start_tls = AsyncMock()

    mock_ssl_object = MagicMock()
    mock_ssl_object.version.return_value = "TLSv1.3"
    mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_object.getpeercert.return_value = {"subjectAltName": [("DNS", "example.com")]}

    mock_writer.get_extra_info.side_effect = lambda name: mock_ssl_object if name == "ssl_object" else None
    mock_open_connection.return_value = (mock_reader, mock_writer)

    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)
    await probe.run(target)

    ssl_ctx = mock_writer.start_tls.call_args[0][0]
    assert ssl_ctx.verify_mode == ssl.CERT_REQUIRED

@patch("asyncio.open_connection")
async def test_tls_handshake_malformed_a_label_sni_fails_closed(mock_open_connection):
    probe = TlsHandshakeProbe()
    target = Target(host="example.com", port=443)

    res = await probe.run(target, config={"sni": "xn--test.com"})
    assert res.status == ProbeStatus.FAILED
    assert "malformed Punycode" in res.error
    assert res.details["handshake_completed"] is False

    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_malformed_a_label_target_fails_closed(mock_open_connection):
    probe = TlsHandshakeProbe()

    res = await probe.run(Target(host="xn--test.com", port=443))
    assert res.status == ProbeStatus.FAILED
    assert "malformed Punycode" in res.error
    assert res.details["handshake_completed"] is False

    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_all_ascii_a_label_target_fails_closed(mock_open_connection):
    probe = TlsHandshakeProbe()

    res = await probe.run(Target(host="xn--abc-.com", port=443))
    assert res.status == ProbeStatus.FAILED
    assert "all-ASCII" in res.error
    assert res.details["handshake_completed"] is False

    mock_open_connection.assert_not_called()

@patch("asyncio.open_connection")
async def test_tls_handshake_non_roundtrip_a_label_target_fails_closed(mock_open_connection):
    probe = TlsHandshakeProbe()

    res = await probe.run(Target(host="xn---bbb.com", port=443))
    assert res.status == ProbeStatus.FAILED
    assert "fails Punycode round-trip encoding" in res.error
    assert res.details["handshake_completed"] is False

    mock_open_connection.assert_not_called()
