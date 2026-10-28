from __future__ import annotations

import pytest

from connscope.core import Target
from connscope.scenarios import (
    ScenarioGenerator,
    create_default_protocol_catalog,
)

def test_parameter_generator_ofat():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    target = Target(host="127.0.0.1", port=443)
    plan = generator.generate_parameter_matrix(
        engine_id="xray",
        profile_id="vless_tcp_reality",
        strategy="ofat",
        target=target,
        include_invalid=False,
    )

    assert plan.plan_id.startswith("plan_params_xray_vless_tcp_reality_ofat_")
    assert plan.generation_mode == "ofat"
    assert len(plan.scenarios) > 10

    baseline_scns = [s for s in plan.scenarios if s.metadata.get("is_baseline")]
    assert len(baseline_scns) == 1
    baseline = baseline_scns[0]
    assert baseline.is_valid
    assert baseline.variant_id == "baseline"
    assert baseline.metadata["varied_factor"] == "baseline"

    varied_scns = [s for s in plan.scenarios if not s.metadata.get("is_baseline")]
    assert len(varied_scns) > 0
    for s in varied_scns:
        assert s.is_valid
        assert s.metadata["varied_factor"] == f"{s.metadata['parameter_name']}:{s.metadata['parameter_value']}"
        assert "parameter_name" in s.metadata
        assert "parameter_value" in s.metadata
        assert "parameter_category" in s.metadata
        assert s.metadata["expected_validation_stage"] == "real_binary_validation"

def test_parameter_generator_pairwise():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    target = Target(host="127.0.0.1", port=443)
    plan = generator.generate_parameter_matrix(
        engine_id="sing_box",
        profile_id="vmess_ws_tls",
        strategy="pairwise",
        target=target,
        include_invalid=False,
    )

    assert plan.plan_id.startswith("plan_params_sing_box_vmess_ws_tls_pairwise_")
    assert plan.generation_mode == "pairwise"
    assert len(plan.scenarios) == 24
    assert plan.invalid_count == 0

    for s in plan.scenarios:
        assert s.is_valid
        if not s.metadata.get("is_baseline"):
            assert s.metadata["varied_factor"] == "pairwise_combination"
            assert "pairwise_vector" in s.metadata
            assert isinstance(s.metadata["pairwise_vector"], dict)

def test_parameter_generator_invalid_rejection():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    target = Target(host="127.0.0.1", port=443)
    plan = generator.generate_parameter_matrix(
        engine_id="xray",
        profile_id="vless_tcp_reality",
        strategy="ofat",
        target=target,
        include_invalid=True,
    )

    assert plan.invalid_count > 0
    invalid_scns = [s for s in plan.scenarios if not s.is_valid]
    assert len(invalid_scns) == plan.invalid_count

    for s in invalid_scns:
        assert s.is_valid is False
        assert s.exclusion_reason is not None
        assert len(s.exclusion_reason) > 0
        assert s.metadata["expected_validation_stage"] == "pre_execution_validation"

    invalid_uuid = [s for s in invalid_scns if s.metadata.get("parameter_name") == "uuid"]
    assert len(invalid_uuid) >= 1
    assert "UUID" in invalid_uuid[0].exclusion_reason

    invalid_short_id = [s for s in invalid_scns if s.metadata.get("parameter_name") == "short_id"]
    assert len(invalid_short_id) >= 1

def test_parameter_generator_secret_redaction():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    target = Target(host="127.0.0.1", port=443)
    plan = generator.generate_parameter_matrix(
        engine_id="sing_box",
        profile_id="shadowsocks_tcp",
        strategy="ofat",
        target=target,
        include_invalid=False,
    )

    for s in plan.scenarios:
        assert s.get_redacted_config().get("password") == "[REDACTED]"
        assert s.to_dict()["resolved_config"].get("password") == "[REDACTED]"

def test_parameter_generator_filter():
    catalog = create_default_protocol_catalog()
    generator = ScenarioGenerator(catalog=catalog)

    target = Target(host="127.0.0.1", port=443)
    plan = generator.generate_parameter_matrix(
        engine_id="xray",
        profile_id="vless_tcp_reality",
        strategy="ofat",
        target=target,
        include_invalid=False,
        parameters_to_test=["fingerprint"],
    )

    varied_params = {s.metadata["parameter_name"] for s in plan.scenarios if not s.metadata.get("is_baseline")}
    assert varied_params == {"fingerprint"}
