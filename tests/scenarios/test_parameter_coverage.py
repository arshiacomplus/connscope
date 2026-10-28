from __future__ import annotations

import json
import pytest

from connscope.scenarios import (
    ParameterCoverageStage,
    create_default_protocol_catalog,
    evaluate_parameter_coverage,
    render_parameter_coverage_json,
    render_parameter_coverage_table,
)

def test_parameter_coverage_denominators():
    catalog = create_default_protocol_catalog()
    summary = evaluate_parameter_coverage(catalog, validate_binaries=False)

    assert summary.total_applicable_parameters == 171
    assert summary.total_covered_parameters == 171
    assert summary.total_uncovered_parameters == 0

    assert summary.by_engine["xray"]["applicable"] == 87
    assert summary.by_engine["sing_box"]["applicable"] == 84

    expected_xray_denoms = {
        "vless_tcp_reality": 14,
        "vless_tcp_tls": 11,
        "vless_tcp_none": 4,
        "vless_ws_tls": 13,
        "vless_grpc_tls": 13,
        "vmess_ws_tls": 16,
        "trojan_tcp_tls": 10,
        "shadowsocks_tcp": 6,
    }

    expected_singbox_denoms = {
        "vless_tcp_reality": 13,
        "vless_tcp_tls": 11,
        "vless_tcp_none": 4,
        "vless_ws_tls": 13,
        "vless_grpc_tls": 12,
        "vmess_ws_tls": 16,
        "trojan_tcp_tls": 10,
        "shadowsocks_tcp": 5,
    }

    prof_cov = { (cov.engine_id, cov.profile_id): cov for cov in summary.profiles }

    for prof_id, expected_denom in expected_xray_denoms.items():
        cov = prof_cov[("xray", prof_id)]
        assert cov.applicable_denominator == expected_denom
        assert cov.covered_count == expected_denom
        assert cov.uncovered_count == 0

    for prof_id, expected_denom in expected_singbox_denoms.items():
        cov = prof_cov[("sing_box", prof_id)]
        assert cov.applicable_denominator == expected_denom
        assert cov.covered_count == expected_denom
        assert cov.uncovered_count == 0

def test_parameter_coverage_unsupported_reasons():
    catalog = create_default_protocol_catalog()
    summary = evaluate_parameter_coverage(catalog, validate_binaries=False)

    all_records = [r for p in summary.profiles for r in p.records]
    records = { (r.engine_id, r.profile_id, r.param_id): r for r in all_records }

    uot_rec = records[("sing_box", "shadowsocks_tcp", "uot")]
    assert not uot_rec.is_applicable
    assert uot_rec.unsupported_reason is not None
    assert "UOT" in uot_rec.unsupported_reason

    mm_rec = records[("sing_box", "vless_grpc_tls", "multi_mode")]
    assert not mm_rec.is_applicable
    assert mm_rec.unsupported_reason is not None
    assert "multi_mode" in mm_rec.unsupported_reason

    spider_rec = records[("sing_box", "vless_tcp_reality", "spider_x")]
    assert not spider_rec.is_applicable
    assert spider_rec.unsupported_reason is not None
    assert "spiderX" in spider_rec.unsupported_reason

def test_parameter_coverage_categories():
    catalog = create_default_protocol_catalog()
    summary = evaluate_parameter_coverage(catalog, validate_binaries=False)

    expected_categories = {
        "auth_encryption": 26,
        "multiplexing": 32,
        "network_behavior": 7,
        "security_tls": 73,
        "transport": 33,
    }

    assert summary.by_category == {
        k: {"applicable": v, "covered": v, "uncovered": 0}
        for k, v in expected_categories.items()
    }
    assert sum(expected_categories.values()) == 171

def test_parameter_coverage_stages():
    catalog = create_default_protocol_catalog()
    summary = evaluate_parameter_coverage(catalog, validate_binaries=False)

    stages = summary.stage_totals
    assert stages[ParameterCoverageStage.SOURCE_VERIFIED.value] == 171
    assert stages[ParameterCoverageStage.SCHEMA_DEFINED.value] == 171
    assert stages[ParameterCoverageStage.CONSTRAINTS_VALIDATED.value] == 171
    assert stages[ParameterCoverageStage.CONFIG_MAPPED.value] == 171
    assert stages[ParameterCoverageStage.CONFIG_GENERATED.value] == 171
    assert stages[ParameterCoverageStage.BINARY_VALIDATED.value] == 171
    assert stages[ParameterCoverageStage.SCENARIO_GENERATED.value] == 171
    assert stages[ParameterCoverageStage.INVALID_TESTED.value] == 171
    assert stages[ParameterCoverageStage.LIVE_VERIFIED.value] == 0

def test_parameter_coverage_rendering():
    catalog = create_default_protocol_catalog()
    summary = evaluate_parameter_coverage(catalog, validate_binaries=False)

    table = render_parameter_coverage_table(summary)
    assert "ConnScope Parameter-Space Coverage Report" in table
    assert "Total Applicable Denominator:  171" in table
    assert "Implementation Coverage:       100.0%" in table
    assert "vless_tcp_reality" in table
    assert "auth_encryption" in table

    raw_json = render_parameter_coverage_json(summary)
    parsed = json.loads(raw_json)
    assert parsed["total_applicable_parameters"] == 171
    assert parsed["total_covered_parameters"] == 171
    assert "by_engine" in parsed
    assert "by_category" in parsed
    assert "stage_totals" in parsed
    assert len(parsed["profiles"]) == 16
