
import json
from pathlib import Path
import pytest

from connscope.adapters.models import (
    EngineType,
    ExecutableRequirement,
    ProtocolType,
    SecurityType,
    TransportType,
)
from connscope.scenarios import (
    EngineDefinition,
    EngineProfileCompatibility,
    MeasurementNode,
    ParameterDefinition,
    ParameterType,
    ParameterVariant,
    ProtocolCatalog,
    ProtocolProfile,
    SourceReference,
    VerificationStatus,
    create_default_protocol_catalog,
)

def test_default_catalog_is_valid():
    catalog = create_default_protocol_catalog()
    errors = catalog.validate_catalog()
    assert errors == [], f"Default catalog has validation errors: {errors}"

    engines = {e.engine_id: e for e in catalog.list_engines()}
    assert "xray" in engines
    assert "sing_box" in engines
    assert "wireguard" in engines
    assert "amnezia_wg" in engines
    assert "openvpn" in engines
    assert "aether" in engines

    profiles = {p.profile_id: p for p in catalog.list_profiles()}
    assert "vless_tcp_reality" in profiles
    assert "vmess_ws_tls" in profiles
    assert "wireguard_standard" in profiles
    assert "amnezia_wg_obfs" in profiles
    assert "openvpn_udp" in profiles
    assert "aether_tun" in profiles

def test_catalog_serialization_roundtrip(tmp_path: Path):
    catalog = create_default_protocol_catalog()
    data = catalog.to_dict()

    assert isinstance(data, dict)
    assert "engines" in data
    assert "profiles" in data
    assert "compatibilities" in data
    assert "nodes" in data

    json_path = tmp_path / "catalog.json"
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    restored = ProtocolCatalog.from_json_file(json_path)
    errors = restored.validate_catalog()
    assert errors == []

    assert restored.get_engine("xray") is not None
    assert restored.get_engine("sing_box") is not None
    assert restored.get_profile("vless_tcp_reality") is not None
    assert restored.get_compatibility("xray", "vless_tcp_reality") is not None

def test_catalog_validation_detects_unknown_engine():
    catalog = ProtocolCatalog()
    catalog.register_profile(
        ProtocolProfile(
            profile_id="test_profile",
            display_name="Test Profile",
            protocol=ProtocolType.TCP,
            transport=TransportType.TCP,
            security=SecurityType.NONE,
        )
    )
    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="ghost_engine",
            profile_id="test_profile",
            status=VerificationStatus.CATALOGUED,
        )
    )

    errors = catalog.validate_catalog()
    assert any("unknown engine 'ghost_engine'" in e for e in errors)

def test_catalog_validation_detects_unknown_profile():
    catalog = ProtocolCatalog()
    catalog.register_engine(
        EngineDefinition(
            engine_id="test_engine",
            display_name="Test Engine",
        )
    )
    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="test_engine",
            profile_id="ghost_profile",
            status=VerificationStatus.CATALOGUED,
        )
    )

    errors = catalog.validate_catalog()
    assert any("unknown profile 'ghost_profile'" in e for e in errors)

def test_catalog_validation_detects_duplicate_parameters():
    catalog = ProtocolCatalog()
    p1 = ParameterDefinition(param_id="dup_param", display_name="Dup 1", param_type=ParameterType.STRING)
    p2 = ParameterDefinition(param_id="dup_param", display_name="Dup 2", param_type=ParameterType.STRING)

    catalog.register_profile(
        ProtocolProfile(
            profile_id="dup_prof",
            display_name="Dup Profile",
            protocol=ProtocolType.TCP,
            transport=TransportType.TCP,
            security=SecurityType.NONE,
            parameters=(p1, p2),
        )
    )

    errors = catalog.validate_catalog()
    assert any("duplicate parameter 'dup_param'" in e for e in errors)

def test_catalog_validation_detects_variant_overriding_unknown_parameter():
    catalog = ProtocolCatalog()
    p = ParameterDefinition(param_id="known_param", display_name="Known", param_type=ParameterType.STRING)
    v = ParameterVariant(variant_id="bad_var", display_name="Bad Var", overrides={"unknown_param": "foo"})

    catalog.register_profile(
        ProtocolProfile(
            profile_id="var_prof",
            display_name="Var Profile",
            protocol=ProtocolType.TCP,
            transport=TransportType.TCP,
            security=SecurityType.NONE,
            parameters=(p,),
            default_variants=(v,),
        )
    )

    errors = catalog.validate_catalog()
    assert any("overrides unknown parameter 'unknown_param'" in e for e in errors)

def test_catalog_validation_detects_missing_conditional_dependency():
    catalog = ProtocolCatalog()
    p = ParameterDefinition(
        param_id="child_param",
        display_name="Child",
        param_type=ParameterType.STRING,
        requires={"parent_param": "expected_val"},
    )

    catalog.register_profile(
        ProtocolProfile(
            profile_id="cond_prof",
            display_name="Cond Profile",
            protocol=ProtocolType.TCP,
            transport=TransportType.TCP,
            security=SecurityType.NONE,
            parameters=(p,),
        )
    )

    errors = catalog.validate_catalog()
    assert any("requires parameter 'parent_param' which is not in profile" in e for e in errors)

def test_catalog_amnezia_wg_schema_and_variants():
    catalog = create_default_protocol_catalog()
    awg_prof = catalog.get_profile("amnezia_wg_obfs")
    assert awg_prof is not None

    param_ids = {p.param_id for p in awg_prof.parameters}
    assert "private_key" in param_ids
    assert "public_key" in param_ids
    assert "mtu" in param_ids
    assert "persistent_keepalive" in param_ids

    assert "jc" in param_ids
    assert "jmin" in param_ids
    assert "jmax" in param_ids
    assert "s1" in param_ids
    assert "s2" in param_ids
    assert "h1" in param_ids
    assert "h2" in param_ids
    assert "h3" in param_ids
    assert "h4" in param_ids

    variant_ids = {v.variant_id for v in awg_prof.default_variants}
    assert "baseline" in variant_ids
    assert "mild_junk" in variant_ids
    assert "heavy_junk" in variant_ids
    assert "custom_headers" in variant_ids

def test_catalog_aether_requires_source_confirmation():
    catalog = create_default_protocol_catalog()
    aether = catalog.get_engine("aether")
    assert aether is not None
    assert aether.evidence_status == VerificationStatus.CATALOGUED
    assert aether.source_reference is not None
    assert aether.source_reference.requires_source_confirmation is True
    assert "source confirmation" in aether.source_reference.notes.lower()

    compat = catalog.get_compatibility("aether", "aether_tun")
    assert compat is not None
    assert compat.adapter_id is None
    assert any("source confirmation" in lim.lower() for lim in compat.known_limitations)

def test_catalog_wireguard_parameters_and_variants():
    catalog = create_default_protocol_catalog()
    wg_prof = catalog.get_profile("wireguard_standard")
    assert wg_prof is not None

    mtu_param = wg_prof.get_parameter("mtu")
    assert mtu_param is not None
    assert mtu_param.min_value == 1280
    assert mtu_param.max_value == 1500
    assert mtu_param.default == 1420

    keepalive_param = wg_prof.get_parameter("persistent_keepalive")
    assert keepalive_param is not None
    assert keepalive_param.default == 25

    variants = {v.variant_id: v for v in wg_prof.default_variants}
    assert "baseline" in variants
    assert "low_mtu" in variants
    assert variants["low_mtu"].overrides.get("mtu") == 1280
    assert "keepalive_disabled" in variants
    assert variants["keepalive_disabled"].overrides.get("persistent_keepalive") == 0
