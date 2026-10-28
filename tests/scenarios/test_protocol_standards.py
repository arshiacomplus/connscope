from __future__ import annotations

import pytest

from connscope.scenarios.catalog import create_default_protocol_catalog
from connscope.scenarios.models import CapabilityCategory, VerificationStatus

def test_rfc_9298_vs_rfc_9484_standards_assignment():
    catalog = create_default_protocol_catalog()
    
    udp_cap = catalog.get_capability("exclave_connect_udp")
    assert udp_cap is not None
    assert udp_cap.standards_reference is not None
    assert "9298" in udp_cap.standards_reference
    assert "9484" not in udp_cap.standards_reference
    assert "Proxying UDP in HTTP" in udp_cap.standards_reference or "RFC 9298" in udp_cap.standards_reference

    ip_cap = catalog.get_capability("exclave_masque_connect_ip")
    assert ip_cap is not None
    assert ip_cap.standards_reference is not None
    assert "9484" in ip_cap.standards_reference
    assert "9298" not in ip_cap.standards_reference
    assert "Proxying IP in HTTP" in ip_cap.standards_reference or "RFC 9484" in ip_cap.standards_reference

def test_protocol_standards_references_accuracy():
    catalog = create_default_protocol_catalog()

    http_cap = catalog.get_capability("exclave_http_connect")
    assert http_cap is not None
    assert http_cap.standards_reference is not None
    assert "7231" in http_cap.standards_reference or "9110" in http_cap.standards_reference

    s5_cap = catalog.get_capability("exclave_socks5")
    assert s5_cap is not None
    assert s5_cap.standards_reference is not None
    assert "1928" in s5_cap.standards_reference

    s4_cap = catalog.get_capability("exclave_socks4")
    assert s4_cap is not None
    assert s4_cap.standards_reference is not None
    assert "SOCKS" in s4_cap.standards_reference

    ssh_cap = catalog.get_capability("exclave_ssh")
    assert ssh_cap is not None
    assert ssh_cap.standards_reference is not None
    assert "4251" in ssh_cap.standards_reference or "4253" in ssh_cap.standards_reference

    tuic_cap = catalog.get_capability("exclave_tuic_v5")
    assert tuic_cap is not None
    assert tuic_cap.standards_reference is not None
    assert "9000" in tuic_cap.standards_reference

def test_exclave_immutable_commit_provenance():
    catalog = create_default_protocol_catalog()
    eng = catalog.get_engine("exclave")
    assert eng is not None
    assert eng.source_reference is not None
    assert eng.source_reference.pinned_commit == "71ae3bca4217f78d704713dbb6328aad067404a1"
    assert eng.source_reference.pinned_version == "0.17.66"
    assert eng.source_reference.verification_status == VerificationStatus.CATALOGUED

    for cap in catalog.list_capabilities(engine_id="exclave"):
        assert cap.source_reference is not None
        assert cap.source_reference.pinned_commit == "71ae3bca4217f78d704713dbb6328aad067404a1"
        assert cap.source_reference.pinned_version == "0.17.66"
        assert cap.source_reference.verification_status == VerificationStatus.CATALOGUED

def test_all_capabilities_have_valid_taxonomy_categories():
    catalog = create_default_protocol_catalog()
    valid_categories = set(CapabilityCategory)

    for cap in catalog.list_capabilities():
        assert cap.category in valid_categories or isinstance(cap.category, CapabilityCategory)

def test_exclave_zero_executable_guarantee():
    catalog = create_default_protocol_catalog()
    exclave_caps = catalog.list_capabilities(engine_id="exclave")
    assert len(exclave_caps) == 30
    for cap in exclave_caps:
        assert cap.is_executable is False
        assert cap.status == VerificationStatus.CATALOGUED
        assert cap.unsupported_reason is not None

def test_taxonomy_categorization_semantics():
    catalog = create_default_protocol_catalog()

    tun_cap = catalog.get_capability("exclave_tun")
    assert tun_cap is not None
    assert tun_cap.category == CapabilityCategory.RUNTIME_MODE
    assert tun_cap.category != CapabilityCategory.PROTOCOL

    gvisor = catalog.get_capability("exclave_netstack_gvisor")
    assert gvisor is not None
    assert gvisor.category == CapabilityCategory.NETWORK_STACK

    system_stack = catalog.get_capability("exclave_tun_system")
    assert system_stack is not None
    assert system_stack.category == CapabilityCategory.NETWORK_STACK

    sniffing = catalog.get_capability("exclave_traffic_sniffing")
    assert sniffing is not None
    assert sniffing.category == CapabilityCategory.INBOUND_PROCESSING

    eyeballs = catalog.get_capability("exclave_happy_eyeballs")
    assert eyeballs is not None
    assert eyeballs.category == CapabilityCategory.GLOBAL_SETTING

    icmp = catalog.get_capability("exclave_icmp_policy")
    assert icmp is not None
    assert icmp.category == CapabilityCategory.GLOBAL_SETTING
