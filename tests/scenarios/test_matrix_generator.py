
import json
import pytest

from connscope.core import Target
from connscope.scenarios import (
    GenerationMode,
    MatrixPlan,
    MatrixSizeExceededError,
    MeasurementNode,
    MeasurementWorkload,
    Scenario,
    ScenarioGenerator,
    create_default_protocol_catalog,
)

SAMPLE_TARGET = Target(host="192.0.2.1", port=443)
SAMPLE_CONFIG = {
    "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
    "server_name": "example.com",
}

def test_generator_explicit_mode():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog, max_scenarios=20)

    plan = generator.generate_explicit(
        engine_ids=["xray", "sing_box"],
        profile_ids=["vless_tcp_reality"],
        target=SAMPLE_TARGET,
        parameter_overrides=SAMPLE_CONFIG,
    )

    assert plan.generation_mode == GenerationMode.EXPLICIT
    assert plan.actual_count == 8
    assert plan.invalid_count == 0
    assert plan.deduplicated_count == 0

    ids = [s.scenario_id for s in plan.scenarios]
    assert len(set(ids)) == len(ids)
    assert all(s.is_valid for s in plan.scenarios)

def test_generator_deterministic_output_and_stable_ids():
    catalog = create_default_protocol_catalog()
    gen1 = ScenarioGenerator(catalog=catalog)
    gen2 = ScenarioGenerator(catalog=catalog)

    plan1 = gen1.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        target=SAMPLE_TARGET,
        parameter_overrides=SAMPLE_CONFIG,
    )
    plan2 = gen2.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        target=SAMPLE_TARGET,
        parameter_overrides=SAMPLE_CONFIG,
    )

    assert plan1.plan_id == plan2.plan_id
    ids1 = [s.scenario_id for s in plan1.scenarios]
    ids2 = [s.scenario_id for s in plan2.scenarios]
    assert ids1 == ids2

def test_generator_deduplication():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline", "baseline", "vision_flow"],
        target=SAMPLE_TARGET,
        parameter_overrides=SAMPLE_CONFIG,
    )

    assert plan.actual_count == 2
    assert plan.deduplicated_count == 1

def test_generator_ofat_mode():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_ofat(
        engine_id="xray",
        profile_id="vless_tcp_reality",
        baseline_variant_id="baseline",
        target=SAMPLE_TARGET,
        factors_to_vary=["variant", "engine"],
        baseline_overrides=SAMPLE_CONFIG,
    )

    assert plan.generation_mode == GenerationMode.OFAT
    assert plan.actual_count == 5

    baseline_scenarios = [s for s in plan.scenarios if s.metadata.get("is_baseline")]
    assert len(baseline_scenarios) == 1
    assert baseline_scenarios[0].engine_id == "xray"
    assert baseline_scenarios[0].variant_id == "baseline"

    varied = [s.metadata.get("varied_factor") for s in plan.scenarios]
    assert "baseline" in varied
    assert "engine:sing_box" in varied

def test_generator_pairwise_coverage_on_sample_model():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    custom_factors = {
        "cipher": ["auto", "aes-128-gcm", "chacha20-poly1305"],
        "path": ["/ws1", "/ws2"],
    }

    plan = generator.generate_pairwise(
        engine_ids=["xray", "sing_box"],
        profile_ids=["vmess_ws_tls"],
        factors=custom_factors,
        target=SAMPLE_TARGET,
        base_overrides={"uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "server_name": "example.com"},
    )

    assert plan.generation_mode == GenerationMode.PAIRWISE
    assert "pairwise" in plan.metadata["strategy"]
    assert "NOT exhaustive" in plan.metadata["coverage"]

    assert plan.actual_count < 25
    assert plan.actual_count > 0

    covered_engine_cipher_pairs = set()
    for s in plan.scenarios:
        eng = s.engine_id
        vec = s.metadata.get("pairwise_vector", {})
        ciph = vec.get("cipher")
        if ciph:
            covered_engine_cipher_pairs.add((eng, ciph))

    expected_pairs = {
        ("xray", "auto"),
        ("xray", "aes-128-gcm"),
        ("xray", "chacha20-poly1305"),
        ("sing_box", "auto"),
        ("sing_box", "aes-128-gcm"),
        ("sing_box", "chacha20-poly1305"),
    }
    assert expected_pairs.issubset(covered_engine_cipher_pairs)

def test_generator_bounds_enforcement_raises_on_large_matrix():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog, max_scenarios=3, allow_exhaustive=False)

    with pytest.raises(MatrixSizeExceededError, match="exceeds maximum allowed"):
        generator.generate_exhaustive(
            engine_ids=["xray", "sing_box"],
            profile_ids=["vless_tcp_reality"],
            target=SAMPLE_TARGET,
            parameter_overrides=SAMPLE_CONFIG,
        )

    gen_allowed = ScenarioGenerator(catalog=catalog, max_scenarios=3, allow_exhaustive=True)
    plan = gen_allowed.generate_exhaustive(
        engine_ids=["xray", "sing_box"],
        profile_ids=["vless_tcp_reality"],
        target=SAMPLE_TARGET,
        parameter_overrides=SAMPLE_CONFIG,
    )
    assert plan.actual_count == 8

def test_generator_secret_redaction():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    plan = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        parameter_overrides=SAMPLE_CONFIG,
    )

    scn = plan.scenarios[0]
    data = scn.to_dict(redact_secrets=True)

    assert scn.resolved_config["uuid"] == "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    assert scn.resolved_config["public_key"] == "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk"

    assert data["resolved_config"]["uuid"] == "[REDACTED]"
    assert data["resolved_config"]["public_key"] == "[REDACTED]"
    assert data["resolved_config"]["server_name"] == "example.com"

def test_generator_measurement_node_separation():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    local_node = catalog.get_node("local")
    remote_node = catalog.get_node("remote-agent-frankfurt")

    plan_local = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        node=local_node,
        parameter_overrides=SAMPLE_CONFIG,
    )
    plan_remote = generator.generate_explicit(
        engine_ids=["xray"],
        profile_ids=["vless_tcp_reality"],
        variant_ids=["baseline"],
        target=SAMPLE_TARGET,
        node=remote_node,
        parameter_overrides=SAMPLE_CONFIG,
    )

    scn_l = plan_local.scenarios[0]
    scn_r = plan_remote.scenarios[0]

    assert scn_l.node.node_id == "local"
    assert scn_l.node.route_context.get("type") == "loopback"

    assert scn_r.node.node_id == "remote-agent-frankfurt"
    assert scn_r.node.route_context.get("asn") == 3320
    assert scn_r.node.route_context.get("city") == "Frankfurt"
