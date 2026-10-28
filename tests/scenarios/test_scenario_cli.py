
import io
import json
from pathlib import Path
import pytest

from connscope.cli.main import ExitCode, cli_entry

def test_cli_catalog_validate_default():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "validate"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    assert "Catalog is valid" in out.getvalue()

def test_cli_catalog_validate_json():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "validate", "--json"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    data = json.loads(out.getvalue())
    assert data["valid"] is True
    assert data["engines_count"] >= 6
    assert data["profiles_count"] >= 6

def test_cli_catalog_validate_missing_file():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "validate", "/nonexistent/catalog.json"], stdout=out, stderr=err)
    assert code == ExitCode.USAGE_ERROR
    assert "not found" in err.getvalue()

def test_cli_catalog_list_table():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "list"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    text = out.getvalue()
    assert "Engines:" in text
    assert "xray" in text
    assert "sing_box" in text
    assert "vless_tcp_reality" in text
    assert "amnezia_wg_obfs" in text

def test_cli_catalog_list_json():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "list", "--json"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    data = json.loads(out.getvalue())
    assert "engines" in data
    assert "profiles" in data
    assert "compatibilities" in data

def test_cli_catalog_show_engine():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "show", "xray"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    assert "Xray-core" in out.getvalue()
    assert "min version: 1.8.0" in out.getvalue()

def test_cli_catalog_show_profile():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "show", "vless_tcp_reality"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    assert "VLESS over TCP with REALITY" in out.getvalue()
    assert "uuid" in out.getvalue()

def test_cli_catalog_show_unknown():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "show", "nonexistent_id"], stdout=out, stderr=err)
    assert code == ExitCode.USAGE_ERROR
    assert "Unknown engine or profile ID" in err.getvalue()

def test_cli_matrix_estimate_table():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["matrix", "estimate", "--engine", "xray", "--profile", "vless_tcp_reality"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    assert "Estimated scenarios:" in out.getvalue()

def test_cli_matrix_estimate_json():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["matrix", "estimate", "--engine", "xray", "--profile", "vless_tcp_reality", "--json"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    data = json.loads(out.getvalue())
    assert data["estimated_scenarios"] == 4
    assert data["engines"] == ["xray"]
    assert data["profiles"] == ["vless_tcp_reality"]

def test_cli_matrix_preview_table():
    out = io.StringIO()
    err = io.StringIO()
    cfg_json = json.dumps({
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
        "server_name": "example.com",
    })
    code = cli_entry(
        ["matrix", "preview", "--engine", "xray", "--profile", "vless_tcp_reality", "--config", cfg_json],
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.OK
    text = out.getvalue()
    assert "Scenario Matrix Preview" in text
    assert "VALID" in text
    assert "xray_vless_tcp_reality" in text
    assert "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d" not in text
    assert "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk" not in text

def test_cli_matrix_preview_json():
    out = io.StringIO()
    err = io.StringIO()
    cfg_json = json.dumps({
        "uuid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "public_key": "8n5WzXghUgGfcEzTt-vGU5ZXAij-pc5rVni0dyJ0xhk",
        "server_name": "example.com",
    })
    code = cli_entry(
        ["matrix", "preview", "--engine", "xray", "--profile", "vless_tcp_reality", "--config", cfg_json, "--json"],
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.OK
    data = json.loads(out.getvalue())
    assert "scenarios" in data
    assert len(data["scenarios"]) == 4
    for s in data["scenarios"]:
        assert s["resolved_config"]["uuid"] == "[REDACTED]"
        assert s["resolved_config"]["public_key"] == "[REDACTED]"

def test_cli_matrix_preview_bounds_enforcement():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(
        ["matrix", "preview", "--engine", "xray", "--max-scenarios", "2", "--mode", "exhaustive"],
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.USAGE_ERROR
    assert "exceeds maximum allowed threshold" in err.getvalue()

    out2 = io.StringIO()
    err2 = io.StringIO()
    code2 = cli_entry(
        ["matrix", "preview", "--engine", "xray", "--max-scenarios", "2", "--mode", "exhaustive", "--allow-exhaustive"],
        stdout=out2,
        stderr=err2,
    )
    assert code2 == ExitCode.OK

def test_cli_catalog_parameter_coverage_table():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "parameter-coverage"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    text = out.getvalue()
    assert "ConnScope Parameter-Space Coverage Report" in text
    assert "Total Applicable Denominator:  171" in text
    assert "Implementation Coverage:       100.0%" in text

def test_cli_catalog_parameter_coverage_json():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(["catalog", "parameter-coverage", "--json"], stdout=out, stderr=err)
    assert code == ExitCode.OK
    data = json.loads(out.getvalue())
    assert data["total_applicable_parameters"] == 171
    assert data["total_covered_parameters"] == 171
    assert "by_engine" in data
    assert "by_category" in data

def test_cli_matrix_preview_parameters_ofat():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(
        ["matrix", "preview-parameters", "--engine", "xray", "--profile", "vless_tcp_reality", "--strategy", "ofat"],
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.OK
    text = out.getvalue()
    assert "Scenario Matrix Preview" in text
    assert "OFAT" in text
    assert "vless_tcp_reality" in text

def test_cli_matrix_preview_parameters_pairwise_json():
    out = io.StringIO()
    err = io.StringIO()
    code = cli_entry(
        ["matrix", "preview-parameters", "--engine", "sing_box", "--profile", "vmess_ws_tls", "--strategy", "pairwise", "--json"],
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.OK
    data = json.loads(out.getvalue())
    assert data["generation_mode"] == "pairwise"
    assert len(data["scenarios"]) == 24

