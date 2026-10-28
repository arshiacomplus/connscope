
import asyncio
import os
from pathlib import Path
import pytest

from connscope.adapters import (
    ALLOWED_OPENVPN_CONFIG_KEYS,
    AdapterRegistry,
    EngineType,
    FailureStage,
    HostNetworkSnapshot,
    LinuxNetnsIsolationBackend,
    LinuxOriginNetnsIsolationBackend,
    MockLayer3IsolationBackend,
    OpenVPNDeviceDriver,
    OpenVPNStandardAdapter,
    ProtocolType,
    SecurityType,
    TransportType,
    TunnelExecutionMode,
    UNSUPPORTED_OPENVPN_DIRECTIVES,
    WireGuardDeviceDriver,
    generate_openvpn_client_config,
    validate_openvpn_config,
)
from connscope.agent.execution import SUPPORTED_PROBE_NAMES
from connscope.core import ProbeStatus, Target
from connscope.scenarios import (
    AdapterMigrationBridge,
    MeasurementRecord,
    ScenarioCoordinator,
    ScenarioGenerator,
    create_default_protocol_catalog,
)

SAMPLE_TARGET = Target(host="198.51.100.1", port=1194)

DUMMY_CA = """-----BEGIN CERTIFICATE-----
MIIB/zCCAaagAwIBAgIUQW1uZXppYVdHTW9jazANBgkqhkiG9w0BAQsFADAVMRMw
EQYDVQQDEwpDb25uU2NvcGVDQTAeFw0yNjEwMjEwMDAwMDBaFw0zNjEwMjEwMDAw
MDBaMBUxEzARBgNVBAMTCkNvbm5TY29wZUNBMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQC3r7YxGvM1yJ4L5V8G0QIDAQAB
-----END CERTIFICATE-----"""

DUMMY_CLIENT_CERT = """-----BEGIN CERTIFICATE-----
MIICBjCCAb8CFQC7u8xHvN2zK5V8G0QIDAQABo1AwTjAdBgNVHQ4EFgQU0w==
-----END CERTIFICATE-----"""

DUMMY_CLIENT_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3r7YxGvM1yJ4L
5V8G0QIDAQAB
-----END PRIVATE KEY-----"""

DUMMY_TLS_AUTH = """-----BEGIN OpenVPN Static key V1-----
e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6
-----END OpenVPN Static key V1-----"""

SAMPLE_CONFIG = {
    "endpoint": "198.51.100.1:1194",
    "proto": "udp",
    "ca_cert": DUMMY_CA,
    "cipher": "AES-256-GCM",
    "tun_mtu": 1500,
    "route_nopull": True,
    "remote_cert_tls": True,
}

def test_openvpn_adapter_metadata_and_execution_mode():
    adapter = OpenVPNStandardAdapter()
    meta = adapter.metadata

    assert meta.adapter_id == "openvpn_standard"
    assert meta.engine == EngineType.OPENVPN
    assert meta.protocol == ProtocolType.OPENVPN
    assert meta.transport == TransportType.UDP
    assert meta.security == SecurityType.TLS
    assert meta.execution_mode == TunnelExecutionMode.NETWORK_INTERFACE
    assert adapter.default_interface_name == "tun0"

def test_openvpn_adapter_executable_detection():
    adapter = OpenVPNStandardAdapter()
    ok, exe_path = adapter.check_executable()
    if ok:
        assert "openvpn" in str(exe_path).lower()
        assert Path(exe_path).is_file()
    else:
        assert "openvpn" in exe_path.lower()

def test_validate_openvpn_config_valid_defaults():
    validated = validate_openvpn_config(SAMPLE_CONFIG)

    assert validated["remote_host"] == "198.51.100.1"
    assert validated["remote_port"] == 1194
    assert validated["endpoint"] == "198.51.100.1:1194"
    assert validated["proto"] == "udp"
    assert validated["dev_type"] == "tun"
    assert validated["interface_name"] == "tun0"
    assert validated["tun_mtu"] == 1500
    assert validated["cipher"] == "AES-256-GCM"
    assert validated["route_nopull"] is True
    assert validated["remote_cert_tls"] is True
    assert validated["ca_cert"] == DUMMY_CA

def test_validate_openvpn_config_tcp_variant():
    for raw_tcp in ("tcp", "tcp-client", "tcp4-client"):
        cfg = {**SAMPLE_CONFIG, "proto": raw_tcp}
        validated = validate_openvpn_config(cfg)
        assert validated["proto"] == "tcp-client"

def test_validate_openvpn_config_missing_ca_cert_rejected():
    cfg = dict(SAMPLE_CONFIG)
    del cfg["ca_cert"]
    with pytest.raises(ValueError, match="Missing required trusted CA certificate"):
        validate_openvpn_config(cfg)

def test_validate_openvpn_config_mtu_bounds():
    cfg_1280 = validate_openvpn_config({**SAMPLE_CONFIG, "tun_mtu": 1280})
    assert cfg_1280["tun_mtu"] == 1280

    cfg_1500 = validate_openvpn_config({**SAMPLE_CONFIG, "tun_mtu": 1500})
    assert cfg_1500["tun_mtu"] == 1500

    with pytest.raises(ValueError, match="tun_mtu must be between 1280 and 1500"):
        validate_openvpn_config({**SAMPLE_CONFIG, "tun_mtu": 1279})

    with pytest.raises(ValueError, match="tun_mtu must be between 1280 and 1500"):
        validate_openvpn_config({**SAMPLE_CONFIG, "tun_mtu": 1501})

def test_validate_openvpn_config_cipher_suites():
    for c in ("AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"):
        validated = validate_openvpn_config({**SAMPLE_CONFIG, "cipher": c})
        assert validated["cipher"] == c

    for bad_cipher in ("none", "BF-CBC", "DES-EDE3-CBC", "RC4-MD5"):
        with pytest.raises(ValueError, match="Unsupported cipher"):
            validate_openvpn_config({**SAMPLE_CONFIG, "cipher": bad_cipher})

def test_validate_openvpn_config_route_nopull_enforced():
    with pytest.raises(ValueError, match="route_nopull must be True"):
        validate_openvpn_config({**SAMPLE_CONFIG, "route_nopull": False})

def test_validate_openvpn_config_mutual_tls_pairing():
    with pytest.raises(ValueError, match="Both client_cert and client_key must be provided"):
        validate_openvpn_config({**SAMPLE_CONFIG, "client_cert": DUMMY_CLIENT_CERT})

    with pytest.raises(ValueError, match="Both client_cert and client_key must be provided"):
        validate_openvpn_config({**SAMPLE_CONFIG, "client_key": DUMMY_CLIENT_KEY})

    val = validate_openvpn_config({
        **SAMPLE_CONFIG,
        "client_cert": DUMMY_CLIENT_CERT,
        "client_key": DUMMY_CLIENT_KEY,
    })
    assert val["client_cert"] is not None
    assert val["client_key"] is not None

def test_validate_openvpn_config_tls_auth_vs_tls_crypt_mutual_exclusion():
    with pytest.raises(ValueError, match="Cannot specify both tls_auth_key and tls_crypt_key"):
        validate_openvpn_config({
            **SAMPLE_CONFIG,
            "tls_auth_key": DUMMY_TLS_AUTH,
            "tls_crypt_key": DUMMY_TLS_AUTH,
        })

def test_validate_openvpn_config_rejection_of_unsafe_directives():
    for unsafe_key in UNSUPPORTED_OPENVPN_DIRECTIVES:
        with pytest.raises(ValueError, match="is unsafe and rejected by ConnScope"):
            validate_openvpn_config({**SAMPLE_CONFIG, unsafe_key: "some_value"})

def test_validate_openvpn_config_rejection_of_newline_and_command_injection():
    with pytest.raises(ValueError, match="Newline characters are not permitted"):
        validate_openvpn_config({**SAMPLE_CONFIG, "remote_host": "198.51.100.1\nup /bin/sh"})

    with pytest.raises(ValueError, match="Command substitution characters are not permitted"):
        validate_openvpn_config({**SAMPLE_CONFIG, "remote_host": "198.51.100.1`id`"})

    with pytest.raises(ValueError, match="Command substitution characters are not permitted"):
        validate_openvpn_config({**SAMPLE_CONFIG, "remote_host": "198.51.100.1$(id)"})

    with pytest.raises(ValueError, match="Shell control characters are not permitted"):
        validate_openvpn_config({**SAMPLE_CONFIG, "remote_host": "198.51.100.1; rm -rf /"})

def test_generate_openvpn_client_config_hardened_format(tmp_path: Path):
    cfg = {
        **SAMPLE_CONFIG,
        "client_cert": DUMMY_CLIENT_CERT,
        "client_key": DUMMY_CLIENT_KEY,
        "tls_auth_key": DUMMY_TLS_AUTH,
        "tls_auth_direction": "1",
        "verify_x509_name": "vpn.example.com",
    }
    content = generate_openvpn_client_config(cfg)

    assert "client" in content
    assert "dev tun0" in content
    assert "dev-type tun" in content
    assert "proto udp" in content
    assert "remote 198.51.100.1 1194" in content
    assert "nobind" in content
    assert "persist-key" in content
    assert "persist-tun" in content
    assert "remote-cert-tls server" in content
    assert "cipher AES-256-GCM" in content
    assert "tun-mtu 1500" in content
    assert "route-nopull" in content
    assert "verify-x509-name vpn.example.com name" in content
    assert "key-direction 1" in content

    assert "<ca>" in content and "</ca>" in content
    assert "<cert>" in content and "</cert>" in content
    assert "<key>" in content and "</key>" in content
    assert "<tls-auth>" in content and "</tls-auth>" in content

    for unsafe in ("up ", "down ", "script-security", "plugin ", "config ", "redirect-gateway"):
        assert unsafe not in content

    adapter = OpenVPNStandardAdapter()
    cfg_file = adapter.generate_config_file(cfg, SAMPLE_TARGET, tmp_path)
    assert cfg_file.is_file()
    mode = oct(cfg_file.stat().st_mode & 0o777)
    assert mode == "0o600"

def test_device_driver_properties_and_origin_netns_rejection():
    ovpn_driver = OpenVPNDeviceDriver()
    wg_driver = WireGuardDeviceDriver()

    assert ovpn_driver.driver_name == "openvpn"
    assert ovpn_driver.link_type == "tun"
    assert ovpn_driver.tool_binary == "openvpn"
    assert ovpn_driver.default_interface_prefix == "tun-cs-"
    assert ovpn_driver.supports_origin_netns is False
    assert wg_driver.supports_origin_netns is True

    ok_orig, err_orig = ovpn_driver.check_capabilities(require_origin_netns=True)
    assert ok_orig is False
    assert "origin-namespace socket placement is not supported" in err_orig

    ok_real, err_real = ovpn_driver.check_capabilities(require_origin_netns=False)
    assert ok_real is False
    assert "explicit opt-in" in err_real or "host safety invariants" in err_real

def test_origin_netns_backend_strictly_rejects_openvpn():
    backend = LinuxOriginNetnsIsolationBackend(driver=OpenVPNDeviceDriver())
    ok, err = backend.check_capabilities()
    assert ok is False
    assert "does not support origin-namespace socket placement" in err

@pytest.mark.asyncio
async def test_openvpn_mock_full_successful_lifecycle(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="openvpn",
        should_pass_capabilities=True,
        should_pass_setup=True,
        should_handshake=True,
        should_traverse_traffic=True,
        should_complete_data_transfer=True,
        http_status=204,
    )
    adapter = OpenVPNStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/openvpn"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.SUCCESS
    assert result.duration_ms > 0
    assert result.details["interface_established"] is True
    assert result.details["peer_handshake_completed"] is True
    assert result.details["traffic_traversed"] is True
    assert result.details["execution_mode"] == "network_interface"
    assert result.details["proto"] == "udp"
    assert result.details["tun_mtu"] == 1500
    assert result.details["cleanup_completed"] is True
    assert mock_backend.teardown_called is True
    assert "cleaned_up_tun_interface" in mock_backend.events

@pytest.mark.asyncio
async def test_openvpn_mock_interface_setup_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="openvpn",
        should_pass_setup=False,
        setup_error="Mock TUN device creation permission denied",
    )
    adapter = OpenVPNStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/openvpn"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.INTERFACE_SETUP.value
    assert result.details["interface_established"] is False
    assert "permission denied" in str(result.error)
    assert mock_backend.teardown_called is True

@pytest.mark.asyncio
async def test_openvpn_mock_tls_handshake_timeout(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="openvpn",
        should_handshake=False,
    )
    adapter = OpenVPNStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/openvpn"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.HANDSHAKE.value
    assert result.details["interface_established"] is True
    assert result.details["peer_handshake_completed"] is False
    assert "No OpenVPN peer handshake or TLS authentication" in str(result.error)
    assert mock_backend.teardown_called is True

@pytest.mark.asyncio
async def test_openvpn_mock_traffic_traversal_failure(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(
        driver_name="openvpn",
        should_traverse_traffic=False,
    )
    adapter = OpenVPNStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/openvpn"))

    result = await adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG)

    assert result.status == ProbeStatus.FAILED
    assert result.details["failure_stage"] == FailureStage.TRAFFIC_TRAVERSAL.value
    assert result.details["traffic_traversed"] is False
    assert mock_backend.teardown_called is True

@pytest.mark.asyncio
async def test_openvpn_cancellation_shielded_teardown(monkeypatch):
    mock_backend = MockLayer3IsolationBackend(driver_name="openvpn")
    adapter = OpenVPNStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/openvpn"))

    async def slow_workload(*args, **kwargs):
        await asyncio.sleep(10.0)

    monkeypatch.setattr(mock_backend, "execute_workload", slow_workload)

    task = asyncio.create_task(adapter.run(SAMPLE_TARGET, config=SAMPLE_CONFIG))
    await asyncio.sleep(0.05)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert mock_backend.teardown_called is True
    assert "cleaned_up_tun_interface" in mock_backend.events

def test_openvpn_secret_redaction_in_scenario_and_records():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["openvpn"],
        profile_ids=["openvpn_udp"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides={
            "ca_cert": DUMMY_CA,
            "client_cert": DUMMY_CLIENT_CERT,
            "client_key": DUMMY_CLIENT_KEY,
            "auth_user": "testuser",
            "auth_password": "supersecretpassword",
            "tls_auth_key": DUMMY_TLS_AUTH,
        },
    )
    scn = plan.scenarios[0]
    redacted = scn.get_redacted_config()

    assert redacted["client_key"] == "[REDACTED]"
    assert redacted["auth_password"] == "[REDACTED]"
    assert redacted["tls_auth_key"] == "[REDACTED]"
    assert redacted["auth_user"] == "testuser"
    assert DUMMY_CLIENT_KEY not in str(redacted)
    assert "supersecretpassword" not in str(redacted)

def test_openvpn_declarative_variants_in_catalog():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)
    bridge = AdapterMigrationBridge()

    plan = generator.generate_explicit(
        engine_ids=["openvpn"],
        profile_ids=["openvpn_udp"],
        variant_ids=["baseline", "tcp_baseline", "low_mtu"],
        target=SAMPLE_TARGET,
        parameter_overrides={"ca_cert": DUMMY_CA},
    )

    assert len(plan.scenarios) == 3
    for scn in plan.scenarios:
        assert scn.adapter_id == "openvpn_standard"
        assert scn.engine_id == "openvpn"
        assert scn.profile_id == "openvpn_udp"

        is_valid, err, norm_cfg = bridge.validate_scenario(scn)
        assert is_valid is True, f"Variant '{scn.variant_id}' failed: {err}"
        assert norm_cfg is not None

        if scn.variant_id == "tcp_baseline":
            assert norm_cfg["proto"] == "tcp-client"
        elif scn.variant_id == "low_mtu":
            assert norm_cfg["tun_mtu"] == 1280

    plan_tcp = generator.generate_explicit(
        engine_ids=["openvpn"],
        profile_ids=["openvpn_tcp"],
        variant_ids=["baseline", "low_mtu"],
        target=SAMPLE_TARGET,
        parameter_overrides={"ca_cert": DUMMY_CA},
    )
    assert len(plan_tcp.scenarios) == 2
    for scn in plan_tcp.scenarios:
        assert scn.adapter_id == "openvpn_standard"
        assert scn.engine_id == "openvpn"
        assert scn.profile_id == "openvpn_tcp"
        is_valid, err, norm_cfg = bridge.validate_scenario(scn)
        assert is_valid is True
        assert norm_cfg["proto"] == "tcp-client"

@pytest.mark.asyncio
async def test_coordinator_execution_and_measurement_record_openvpn(monkeypatch):
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["openvpn"],
        profile_ids=["openvpn_udp"],
        variant_ids=["baseline", "tcp_baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides={"ca_cert": DUMMY_CA},
    )

    mock_backend = MockLayer3IsolationBackend(driver_name="openvpn")
    mock_adapter = OpenVPNStandardAdapter(isolation_backend=mock_backend)
    monkeypatch.setattr(mock_adapter, "check_executable", lambda *args, **kwargs: (True, "/mock/bin/openvpn"))

    reg = AdapterRegistry()
    reg.register(mock_adapter)
    bridge = AdapterMigrationBridge(registry=reg)

    coordinator = ScenarioCoordinator(catalog=catalog, migration_bridge=bridge)
    result = await coordinator.execute_plan(plan, execute=True)

    assert result.summary.executed_scenarios == 2
    assert result.summary.failed_scenarios == 0
    assert len(result.records) == 2

    for rec in result.records:
        assert rec.engine_id == "openvpn"
        assert rec.adapter_id == "openvpn_standard"
        assert rec.status == "success"
        assert rec.execution_mode == "network_interface"
        assert "ca_cert" in rec.resolved_config

def test_remote_agent_isolation_from_openvpn():
    from connscope.agent.execution import UnsupportedProbeError, prepare_probe_config

    assert "openvpn_standard" not in SUPPORTED_PROBE_NAMES

    target = Target(host="example.com", port=1194)
    with pytest.raises(UnsupportedProbeError, match="Unsupported probe 'openvpn_standard'"):
        prepare_probe_config("openvpn_standard", target, config={})

@pytest.mark.skipif(
    os.environ.get("CONNSCOPE_TEST_REAL_OPENVPN", "0") != "1",
    reason="Requires opt-in via CONNSCOPE_TEST_REAL_OPENVPN=1",
)
def test_opt_in_real_openvpn_binary_version():
    adapter = OpenVPNStandardAdapter()
    ok, exe_path = adapter.check_executable()
    assert ok is True, f"OpenVPN executable not found: {exe_path}"
    assert Path(exe_path).is_file()
