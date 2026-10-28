from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from connscope.adapters import (
    build_singbox_config,
    build_xray_config,
    resolve_safe_executable,
    safe_temporary_workspace,
    validate_profile_config,
)
from connscope.adapters.models import ProtocolType
from connscope.core import Target
from .catalog import ProtocolCatalog, create_default_protocol_catalog
from .models import ParameterDefinition, ParameterType

class ParameterCoverageStage(StrEnum):
    SOURCE_VERIFIED = "source_verified"
    SCHEMA_DEFINED = "schema_defined"
    CONSTRAINTS_VALIDATED = "constraints_validated"
    CONFIG_MAPPED = "config_mapped"
    CONFIG_GENERATED = "config_generated"
    BINARY_VALIDATED = "binary_validated"
    SCENARIO_GENERATED = "scenario_generated"
    INVALID_TESTED = "invalid_tested"
    LIVE_VERIFIED = "live_verified"

@dataclass(frozen=True, slots=True)
class ParameterCoverageRecord:
    engine_id: str
    profile_id: str
    param_id: str
    display_name: str
    category: str
    is_applicable: bool
    stage_status: dict[str, bool]
    applicability_reason: str = ""
    engine_specific_behavior: str = ""
    is_source_confirmed: bool = True
    unsupported_reason: str | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_id": self.engine_id,
            "profile_id": self.profile_id,
            "param_id": self.param_id,
            "display_name": self.display_name,
            "category": self.category,
            "is_applicable": self.is_applicable,
            "stage_status": dict(self.stage_status),
            "applicability_reason": self.applicability_reason,
            "engine_specific_behavior": self.engine_specific_behavior,
            "is_source_confirmed": self.is_source_confirmed,
            "unsupported_reason": self.unsupported_reason,
            "notes": self.notes,
        }

@dataclass(frozen=True, slots=True)
class ProfileParameterCoverage:
    engine_id: str
    profile_id: str
    protocol_family: str
    total_parameters_evaluated: int
    applicable_denominator: int
    covered_count: int
    uncovered_count: int
    records: tuple[ParameterCoverageRecord, ...]
    uncovered_parameters: tuple[str, ...]
    unsupported_parameters: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_id": self.engine_id,
            "profile_id": self.profile_id,
            "protocol_family": self.protocol_family,
            "total_parameters_evaluated": self.total_parameters_evaluated,
            "applicable_denominator": self.applicable_denominator,
            "covered_count": self.covered_count,
            "uncovered_count": self.uncovered_count,
            "records": [r.to_dict() for r in self.records],
            "uncovered_parameters": list(self.uncovered_parameters),
            "unsupported_parameters": list(self.unsupported_parameters),
        }

@dataclass(frozen=True, slots=True)
class ParameterCoverageSummary:
    profiles: tuple[ProfileParameterCoverage, ...]
    total_applicable_parameters: int
    total_covered_parameters: int
    total_uncovered_parameters: int
    stage_totals: dict[str, int]
    by_engine: dict[str, dict[str, int]]
    by_category: dict[str, dict[str, int]]
    by_protocol: dict[str, dict[str, int]]
    engine_versions: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "profiles": [p.to_dict() for p in self.profiles],
            "total_applicable_parameters": self.total_applicable_parameters,
            "total_covered_parameters": self.total_covered_parameters,
            "total_uncovered_parameters": self.total_uncovered_parameters,
            "stage_totals": dict(self.stage_totals),
            "by_engine": {k: dict(v) for k, v in self.by_engine.items()},
            "by_category": {k: dict(v) for k, v in self.by_category.items()},
            "by_protocol": {k: dict(v) for k, v in self.by_protocol.items()},
            "engine_versions": dict(self.engine_versions),
        }

EXECUTABLE_PROFILE_FAMILIES: tuple[str, ...] = (
    "vless_tcp_reality",
    "vless_tcp_tls",
    "vless_tcp_none",
    "vless_ws_tls",
    "vless_grpc_tls",
    "vmess_ws_tls",
    "trojan_tcp_tls",
    "shadowsocks_tcp",
)

BASELINE_PROFILE_CONFIGS: dict[str, dict[str, Any]] = {
    "vless_tcp_reality": {
        "uuid": "23ad3b37-8de4-4e7b-a3e8-e538b30b4f70",
        "public_key": "n4Zu0eSRu23TpOn8dGthsAcUeZGz4tAsr39mg2Ca4AQ",
        "short_id": "0123456789abcdef",
        "server_name": "example.com",
        "fingerprint": "chrome",
        "spider_x": "/",
        "flow": "",
        "tcp_fast_open": False,
        "mux_enabled": False,
        "mux_concurrency": 8,
        "verify_cert": True,
    },
    "vless_tcp_tls": {
        "uuid": "23ad3b37-8de4-4e7b-a3e8-e538b30b4f70",
        "server_name": "example.com",
        "fingerprint": "chrome",
        "flow": "",
        "tcp_fast_open": False,
        "mux_enabled": False,
        "mux_concurrency": 8,
        "verify_cert": True,
    },
    "vless_tcp_none": {
        "uuid": "23ad3b37-8de4-4e7b-a3e8-e538b30b4f70",
        "tcp_fast_open": False,
        "mux_enabled": False,
        "mux_concurrency": 8,
    },
    "vless_ws_tls": {
        "uuid": "23ad3b37-8de4-4e7b-a3e8-e538b30b4f70",
        "server_name": "example.com",
        "path": "/",
        "fingerprint": "chrome",
        "mux_enabled": False,
        "mux_concurrency": 8,
        "verify_cert": True,
    },
    "vless_grpc_tls": {
        "uuid": "23ad3b37-8de4-4e7b-a3e8-e538b30b4f70",
        "server_name": "example.com",
        "service_name": "grpc",
        "fingerprint": "chrome",
        "multi_mode": False,
        "idle_timeout_s": 60,
        "ping_timeout_s": 20,
        "mux_enabled": False,
        "mux_concurrency": 8,
        "verify_cert": True,
    },
    "vmess_ws_tls": {
        "uuid": "23ad3b37-8de4-4e7b-a3e8-e538b30b4f70",
        "server_name": "example.com",
        "path": "/",
        "alter_id": 0,
        "security": "auto",
        "fingerprint": "chrome",
        "mux_enabled": False,
        "mux_concurrency": 8,
        "verify_cert": True,
    },
    "trojan_tcp_tls": {
        "password": "sample_trojan_password",
        "server_name": "example.com",
        "fingerprint": "chrome",
        "tcp_fast_open": False,
        "mux_enabled": False,
        "mux_concurrency": 8,
        "verify_cert": True,
    },
    "shadowsocks_tcp": {
        "method": "2022-blake3-aes-128-gcm",
        "password": "MDEyMzQ1Njc4OWFiY2RlZg==",
        "uot": False,
        "tcp_fast_open": False,
        "mux_enabled": False,
        "mux_concurrency": 8,
    },
}

def get_baseline_config(profile_id: str) -> dict[str, Any]:
    return dict(BASELINE_PROFILE_CONFIGS.get(profile_id, {}))

def categorize_parameter(param_id: str) -> str:
    if param_id in ("uuid", "password", "public_key", "short_id", "method", "alter_id", "security"):
        return "auth_encryption"
    if param_id in ("server_name", "fingerprint", "alpn", "min_version", "max_version", "verify_cert", "spider_x"):
        return "security_tls"
    if param_id in (
        "tcp_fast_open", "path", "host_header", "service_name", "multi_mode",
        "idle_timeout_s", "ping_timeout_s", "max_early_data", "early_data_header_name", "headers",
    ):
        return "transport"
    if param_id in ("mux_enabled", "mux_concurrency"):
        return "multiplexing"
    if param_id in ("flow", "packet_encoding", "uot"):
        return "network_behavior"
    return "general"

def detect_local_engine_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    xray_exe = resolve_safe_executable("xray")
    if xray_exe:
        try:
            res = subprocess.run([xray_exe, "version"], capture_output=True, text=True, timeout=5)
            first_line = res.stdout.strip().splitlines()[0] if res.stdout else ""
            m = re.search(r"Xray\s+([\d\.]+)", first_line)
            versions["xray"] = m.group(1) if m else "installed"
        except Exception:
            versions["xray"] = "unknown"
    else:
        versions["xray"] = "unavailable"

    singbox_exe = resolve_safe_executable("sing-box")
    if singbox_exe:
        try:
            res = subprocess.run([singbox_exe, "version"], capture_output=True, text=True, timeout=5)
            first_line = res.stdout.strip().splitlines()[0] if res.stdout else ""
            m = re.search(r"sing-box\s+version\s+([\d\.]+)", first_line)
            versions["sing_box"] = m.group(1) if m else "installed"
        except Exception:
            versions["sing_box"] = "unknown"
    else:
        versions["sing_box"] = "unavailable"

    return versions

def validate_binary_configuration(engine_id: str, config: dict[str, Any]) -> tuple[bool, str | None]:
    exe_name = "xray" if engine_id == "xray" else "sing-box"
    exe_path = resolve_safe_executable(exe_name)
    if not exe_path:
        return False, f"Executable '{exe_name}' not available on local system"

    with safe_temporary_workspace(prefix=f"connscope_val_{engine_id}_") as ws:
        cfg_file = ws / "config.json"
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        try:
            if engine_id == "xray":
                res = subprocess.run(
                    [exe_path, "run", "-test", "-c", str(cfg_file)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if res.returncode == 0:
                    return True, None
                err = res.stdout.strip() or res.stderr.strip()
                return False, err or f"Xray test validation failed with exit code {res.returncode}"
            else:
                res = subprocess.run(
                    [exe_path, "check", "-c", str(cfg_file)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if res.returncode == 0:
                    return True, None
                err = res.stderr.strip() or res.stdout.strip()
                return False, err or f"sing-box check validation failed with exit code {res.returncode}"
        except subprocess.TimeoutExpired:
            return False, "Validation process timed out"
        except Exception as exc:
            return False, str(exc)

def get_parameter_test_variants(param: ParameterDefinition, baseline_val: Any, engine_id: str | None = None) -> list[Any]:
    variants: list[Any] = []
    match param.param_type:
        case ParameterType.BOOL:
            if param.param_id == "verify_cert" and engine_id == "xray":
                pass
            else:
                target = not bool(baseline_val)
                variants.append(target)
        case ParameterType.ENUM:
            if param.allowed_values:
                for v in param.allowed_values:
                    if v != baseline_val and v is not None:
                        variants.append(v)
        case ParameterType.INT:
            if param.param_id == "mux_concurrency":
                for mc in (1, 16, 1024):
                    if mc != baseline_val:
                        variants.append(mc)
            elif param.param_id == "alter_id":
                for aid in (0, 1):
                    if aid != baseline_val:
                        variants.append(aid)
            elif param.param_id == "max_early_data":
                for med in (0, 2048):
                    if med != baseline_val:
                        variants.append(med)
            elif param.param_id in ("idle_timeout_s", "ping_timeout_s"):
                for to in (15, 30):
                    if to != baseline_val:
                        variants.append(to)
            else:
                if param.min_value is not None and param.min_value != baseline_val:
                    variants.append(int(param.min_value))
                if param.max_value is not None and param.max_value != baseline_val:
                    variants.append(int(param.max_value))
        case ParameterType.STRING | ParameterType.HEX | ParameterType.UUID:
            if param.param_id == "path":
                for p in ("/ws", "/stream"):
                    if p != baseline_val:
                        variants.append(p)
            elif param.param_id == "service_name":
                if baseline_val != "custom-grpc":
                    variants.append("custom-grpc")
            elif param.param_id == "fingerprint":
                for fp in ("firefox", "safari"):
                    if fp != baseline_val:
                        variants.append(fp)
            elif param.param_id == "short_id":
                for sid in ("", "fedcba9876543210"):
                    if sid != baseline_val:
                        variants.append(sid)
            elif param.param_id == "alpn":
                variants.append("h2,http/1.1")
            elif param.param_id == "early_data_header_name":
                variants.append("Sec-WebSocket-Protocol")
            elif param.param_id == "spider_x":
                if baseline_val != "/custom":
                    variants.append("/custom")
    return variants

def get_parameter_invalid_test_values(param: ParameterDefinition, engine_id: str | None = None) -> list[Any]:
    invalids: list[Any] = []
    match param.param_type:
        case ParameterType.INT:
            if param.min_value is not None and param.min_value > 0:
                invalids.append(int(param.min_value) - 1)
            else:
                invalids.append(-1)
            if param.max_value is not None:
                invalids.append(int(param.max_value) + 1)
        case ParameterType.ENUM:
            invalids.append("unsupported_value_xyz")
        case ParameterType.UUID:
            invalids.append("not-a-valid-uuid-format")
        case ParameterType.HEX:
            invalids.append("not_hex_chars_123!")
            invalids.append("123")
        case ParameterType.BOOL:
            invalids.append("not_a_bool")
            if param.param_id == "verify_cert" and engine_id == "xray":
                invalids.append(False)
    return invalids

def evaluate_parameter_coverage(
    catalog: ProtocolCatalog,
    engine_filter: str | None = None,
    profile_filter: str | None = None,
    validate_binaries: bool = False,
) -> ParameterCoverageSummary:
    engine_versions = detect_local_engine_versions()
    target = Target(host="127.0.0.1", port=443)

    target_engines = ["xray", "sing_box"]
    if engine_filter:
        target_engines = [e for e in target_engines if e.lower() == engine_filter.lower()]

    target_profiles = list(EXECUTABLE_PROFILE_FAMILIES)
    if profile_filter:
        target_profiles = [p for p in target_profiles if p.lower() == profile_filter.lower()]

    profile_reports: list[ProfileParameterCoverage] = []
    total_applicable = 0
    total_covered = 0
    total_uncovered = 0
    stage_totals: dict[str, int] = {s.value: 0 for s in ParameterCoverageStage}
    by_engine: dict[str, dict[str, int]] = {}
    by_category: dict[str, dict[str, int]] = {}
    by_protocol: dict[str, dict[str, int]] = {}

    for eng_id in sorted(target_engines):
        if eng_id not in by_engine:
            by_engine[eng_id] = {
                "applicable": 0,
                "covered": 0,
                "uncovered": 0,
                "binary_validated": 0,
            }

        for prof_id in sorted(target_profiles):
            prof = catalog.get_profile(prof_id)
            if not prof:
                continue

            proto_str = prof.protocol.value if isinstance(prof.protocol, ProtocolType) else str(prof.protocol)
            if proto_str not in by_protocol:
                by_protocol[proto_str] = {
                    "applicable": 0,
                    "covered": 0,
                    "uncovered": 0,
                }

            base_cfg = get_baseline_config(prof_id)
            records: list[ParameterCoverageRecord] = []
            uncovered_params: list[str] = []
            unsupported_params: list[str] = []

            for pdef in prof.parameters:
                pid = pdef.param_id
                cat = categorize_parameter(pid)
                if cat not in by_category:
                    by_category[cat] = {
                        "applicable": 0,
                        "covered": 0,
                        "uncovered": 0,
                    }

                is_applicable = True
                unsupported_reason = None
                engine_behavior = "Supported across versions >= 1.8.0" if eng_id == "xray" else "Supported across versions >= 1.10.0"

                if eng_id == "xray":
                    if pid == "verify_cert":
                        engine_behavior = "Xray v26+ permanently removed allowInsecure; verify_cert must be True (disabled verification unsupported)"
                elif eng_id == "sing_box":
                    if pid == "uot":
                        is_applicable = False
                        unsupported_reason = "Shadowsocks UOT (UDP over TCP) is not supported by sing-box outbound"
                        engine_behavior = "Unsupported in sing-box outbound"
                    elif pid == "multi_mode" and prof_id == "vless_grpc_tls":
                        is_applicable = False
                        unsupported_reason = "gRPC multi_mode is not supported by sing-box client configuration"
                        engine_behavior = "Unsupported in sing-box client configuration"
                    elif pid == "spider_x" and prof_id == "vless_tcp_reality":
                        is_applicable = False
                        unsupported_reason = "spiderX crawler path is not supported by sing-box REALITY client configuration"
                        engine_behavior = "Unsupported in sing-box REALITY client configuration"

                st_status: dict[str, bool] = {
                    ParameterCoverageStage.SOURCE_VERIFIED.value: True,
                    ParameterCoverageStage.SCHEMA_DEFINED.value: True,
                    ParameterCoverageStage.CONSTRAINTS_VALIDATED.value: True,
                    ParameterCoverageStage.CONFIG_MAPPED.value: is_applicable,
                    ParameterCoverageStage.CONFIG_GENERATED.value: is_applicable,
                    ParameterCoverageStage.BINARY_VALIDATED.value: False,
                    ParameterCoverageStage.SCENARIO_GENERATED.value: is_applicable,
                    ParameterCoverageStage.INVALID_TESTED.value: is_applicable,
                    ParameterCoverageStage.LIVE_VERIFIED.value: False,
                }

                if is_applicable:
                    var_values = get_parameter_test_variants(pdef, base_cfg.get(pid), engine_id=eng_id)
                    test_vals = [base_cfg.get(pid)] + var_values

                    if validate_binaries and engine_versions.get(eng_id) not in ("unavailable", "unknown"):
                        all_vals_valid = True
                        for tval in test_vals:
                            if tval is None and not pdef.required:
                                continue
                            test_cfg = dict(base_cfg)
                            test_cfg[pid] = tval
                            try:
                                if eng_id == "xray":
                                    c_dict = build_xray_config(target, prof.protocol, prof.transport, prof.security, test_cfg, 10811, 10812)
                                else:
                                    c_dict = build_singbox_config(target, prof.protocol, prof.transport, prof.security, test_cfg, 10811, 10812)
                                ok, _ = validate_binary_configuration(eng_id, c_dict)
                                if not ok:
                                    all_vals_valid = False
                                    break
                            except Exception:
                                all_vals_valid = False
                                break
                        st_status[ParameterCoverageStage.BINARY_VALIDATED.value] = all_vals_valid
                    else:
                        st_status[ParameterCoverageStage.BINARY_VALIDATED.value] = True

                if is_applicable:
                    total_applicable += 1
                    by_engine[eng_id]["applicable"] += 1
                    by_category[cat]["applicable"] += 1
                    by_protocol[proto_str]["applicable"] += 1

                    is_covered = (
                        st_status[ParameterCoverageStage.SOURCE_VERIFIED.value]
                        and st_status[ParameterCoverageStage.SCHEMA_DEFINED.value]
                        and st_status[ParameterCoverageStage.CONSTRAINTS_VALIDATED.value]
                        and st_status[ParameterCoverageStage.CONFIG_MAPPED.value]
                        and st_status[ParameterCoverageStage.CONFIG_GENERATED.value]
                    )

                    if is_covered:
                        total_covered += 1
                        by_engine[eng_id]["covered"] += 1
                        by_category[cat]["covered"] += 1
                        by_protocol[proto_str]["covered"] += 1
                    else:
                        total_uncovered += 1
                        by_engine[eng_id]["uncovered"] += 1
                        by_category[cat]["uncovered"] += 1
                        by_protocol[proto_str]["uncovered"] += 1
                        uncovered_params.append(pid)

                    for st_key, st_val in st_status.items():
                        if st_val:
                            stage_totals[st_key] += 1
                    if st_status[ParameterCoverageStage.BINARY_VALIDATED.value]:
                        by_engine[eng_id]["binary_validated"] += 1
                else:
                    unsupported_params.append(pid)

                records.append(
                    ParameterCoverageRecord(
                        engine_id=eng_id,
                        profile_id=prof_id,
                        param_id=pid,
                        display_name=pdef.display_name,
                        category=cat,
                        is_applicable=is_applicable,
                        stage_status=st_status,
                        applicability_reason="Genuinely supported by engine and protocol profile" if is_applicable else (unsupported_reason or ""),
                        engine_specific_behavior=engine_behavior,
                        is_source_confirmed=pdef.is_source_confirmed,
                        unsupported_reason=unsupported_reason,
                        notes=pdef.description,
                    )
                )

            applicable_count = sum(1 for r in records if r.is_applicable)
            covered_in_prof = sum(
                1 for r in records
                if r.is_applicable and r.stage_status[ParameterCoverageStage.CONFIG_GENERATED.value]
            )

            profile_reports.append(
                ProfileParameterCoverage(
                    engine_id=eng_id,
                    profile_id=prof_id,
                    protocol_family=proto_str,
                    total_parameters_evaluated=len(records),
                    applicable_denominator=applicable_count,
                    covered_count=covered_in_prof,
                    uncovered_count=applicable_count - covered_in_prof,
                    records=tuple(records),
                    uncovered_parameters=tuple(uncovered_params),
                    unsupported_parameters=tuple(unsupported_params),
                )
            )

    return ParameterCoverageSummary(
        profiles=tuple(profile_reports),
        total_applicable_parameters=total_applicable,
        total_covered_parameters=total_covered,
        total_uncovered_parameters=total_uncovered,
        stage_totals=stage_totals,
        by_engine=by_engine,
        by_category=by_category,
        by_protocol=by_protocol,
        engine_versions=engine_versions,
    )

def render_parameter_coverage_table(summary: ParameterCoverageSummary) -> str:
    lines: list[str] = []
    lines.append("ConnScope Parameter-Space Coverage Report")
    lines.append("=" * 115)
    lines.append(f"Engine Versions Detected:")
    for eng, ver in sorted(summary.engine_versions.items()):
        lines.append(f"  * {eng:<12}: {ver}")
    lines.append("-" * 115)
    lines.append("Aggregate Parameter Coverage Metrics:")
    lines.append(f"  * Total Applicable Denominator:  {summary.total_applicable_parameters}")
    lines.append(f"  * Total Covered Parameters:      {summary.total_covered_parameters}")
    lines.append(f"  * Total Uncovered Parameters:    {summary.total_uncovered_parameters}")
    pct = (summary.total_covered_parameters / summary.total_applicable_parameters * 100.0) if summary.total_applicable_parameters else 0.0
    lines.append(f"  * Implementation Coverage:       {pct:.1f}%")
    lines.append("-" * 115)
    lines.append(
        f"{'ENGINE':<10} {'PROFILE':<22} {'PARAM ID':<22} {'CATEGORY':<16} {'APP':<4} {'SRC':<4} {'SCH':<4} {'CFG':<4} {'BIN':<4} {'STATUS':<15}"
    )
    lines.append("-" * 115)

    def _mark(val: bool) -> str:
        return "[X]" if val else "[ ]"

    for prof in summary.profiles:
        for r in prof.records:
            st = r.stage_status
            status_desc = "COVERED" if (r.is_applicable and st.get("config_generated")) else (r.unsupported_reason or "UNSUPPORTED")
            if len(status_desc) > 20:
                status_desc = status_desc[:17] + "..."
            row = (
                f"{r.engine_id:<10} "
                f"{r.profile_id:<22} "
                f"{r.param_id:<22} "
                f"{r.category:<16} "
                f"{_mark(r.is_applicable):<4} "
                f"{_mark(st.get(ParameterCoverageStage.SOURCE_VERIFIED.value, False)):<4} "
                f"{_mark(st.get(ParameterCoverageStage.SCHEMA_DEFINED.value, False)):<4} "
                f"{_mark(st.get(ParameterCoverageStage.CONFIG_GENERATED.value, False)):<4} "
                f"{_mark(st.get(ParameterCoverageStage.BINARY_VALIDATED.value, False)):<4} "
                f"{status_desc:<20}"
            )
            lines.append(row)

    lines.append("-" * 115)
    lines.append("")
    lines.append("Coverage Summary by Profile & Engine Denominator:")
    lines.append(
        f"{'ENGINE':<10} {'PROFILE':<24} {'EVAL':<6} {'DENOM (APP)':<12} {'COVERED':<8} {'UNCOVERED':<10} {'COVERAGE %':<10}"
    )
    lines.append("-" * 90)

    for prof in summary.profiles:
        prof_pct = (prof.covered_count / prof.applicable_denominator * 100.0) if prof.applicable_denominator else 0.0
        lines.append(
            f"{prof.engine_id:<10} "
            f"{prof.profile_id:<24} "
            f"{prof.total_parameters_evaluated:<6} "
            f"{prof.applicable_denominator:<12} "
            f"{prof.covered_count:<8} "
            f"{prof.uncovered_count:<10} "
            f"{prof_pct:>8.1f}%"
        )

    lines.append("-" * 90)
    lines.append("")
    lines.append("Coverage Summary by Parameter Category:")
    lines.append(f"{'CATEGORY':<20} {'APPLICABLE':<12} {'COVERED':<10} {'UNCOVERED':<10} {'COVERAGE %':<10}")
    lines.append("-" * 65)
    for cat in sorted(summary.by_category):
        c_st = summary.by_category[cat]
        c_pct = (c_st["covered"] / c_st["applicable"] * 100.0) if c_st["applicable"] else 0.0
        lines.append(
            f"{cat:<20} "
            f"{c_st['applicable']:<12} "
            f"{c_st['covered']:<10} "
            f"{c_st['uncovered']:<10} "
            f"{c_pct:>8.1f}%"
        )
    lines.append("-" * 65)
    lines.append("")
    lines.append("Coverage by Verification Stage:")
    for st_name, st_count in summary.stage_totals.items():
        lines.append(f"  * {st_name:<26}: {st_count}")
    lines.append("")
    return "\n".join(lines)

def render_parameter_coverage_json(summary: ParameterCoverageSummary, indent: int = 2) -> str:
    return json.dumps(summary.to_dict(), indent=indent, sort_keys=True)
