
from __future__ import annotations

import json
from typing import Any

from .catalog import ProtocolCatalog
from .models import MatrixPlan, Scenario

def render_scenario_matrix_table(plan: MatrixPlan, catalog: ProtocolCatalog | None = None) -> str:
    lines: list[str] = []
    lines.append(f"Scenario Matrix Preview: {plan.plan_id}")
    lines.append(f"Strategy: {plan.generation_mode.value.upper()} | Total Scenarios: {plan.actual_count} (Estimated: {plan.estimated_count}, Deduplicated: {plan.deduplicated_count}, Invalid: {plan.invalid_count})")
    if plan.metadata.get("coverage"):
        lines.append(f"Coverage Notice: {plan.metadata['coverage']}")
    lines.append("-" * 110)

    header = f"{'SCENARIO ID':<34} {'ENGINE':<10} {'PROFILE':<20} {'VARIANT':<14} {'TARGET':<18} {'COMPAT':<10}"
    lines.append(header)
    lines.append("-" * 110)

    for scn in plan.scenarios:
        status_flag = "VALID" if scn.is_valid else "INVALID"
        target_str = f"{scn.target.host}:{scn.target.port}"
        row = f"{scn.scenario_id:<34} {scn.engine_id:<10} {scn.profile_id:<20} {scn.variant_id:<14} {target_str:<18} {status_flag:<10}"
        lines.append(row)

        req_exe = ""
        if catalog:
            eng = catalog.get_engine(scn.engine_id)
            if eng and eng.executable:
                min_v = f" (min {eng.executable.min_version})" if eng.executable.min_version else ""
                req_exe = f"Executable: {eng.executable.binary_name}{min_v} | "

        workload_str = f"Workload: {scn.workload.workload_type} -> {scn.workload.test_url}"
        node_str = f"Node: {scn.node.node_id} ({scn.node.name})"
        lines.append(f"   + {req_exe}{node_str} | {workload_str}")

        if not scn.is_valid:
            lines.append(f"   ! EXCLUDED: {scn.exclusion_reason}")
        else:
            lines.append(f"   * Status: {scn.status.value} (Adapter: {scn.adapter_id or 'none'})")

        clean_cfg = scn.get_redacted_config()
        cfg_summary = ", ".join(f"{k}={v}" for k, v in sorted(clean_cfg.items()) if k not in ("uuid", "password", "public_key", "private_key", "preshared_key"))
        if cfg_summary:
            lines.append(f"     Params: {cfg_summary}")
        lines.append("")

    return "\n".join(lines)

def render_scenario_matrix_json(plan: MatrixPlan, redact_secrets: bool = True) -> str:
    return json.dumps(plan.to_dict(redact_secrets=redact_secrets), indent=2)

def render_catalog_summary(catalog: ProtocolCatalog) -> str:
    lines: list[str] = []
    lines.append("ConnScope Declarative Protocol Catalog")
    lines.append("=" * 60)
    lines.append("")

    lines.append("1. Engines:")
    for eng in catalog.list_engines():
        exe_str = f"binary='{eng.executable.binary_name}'" if eng.executable else "no binary"
        v_str = f" min_version='{eng.executable.min_version}'" if eng.executable and eng.executable.min_version else ""
        lines.append(f"   - {eng.engine_id:<12} ({eng.display_name}): {exe_str}{v_str} [Status: {eng.evidence_status.value}]")
        if eng.source_reference and eng.source_reference.requires_source_confirmation:
            lines.append(f"     * Source Confirmation Required: {eng.source_reference.notes}")

    lines.append("")
    lines.append("2. Protocol Profiles:")
    for prof in catalog.list_profiles():
        proto_desc = f"{prof.protocol} / {prof.transport} / {prof.security}"
        lines.append(f"   - {prof.profile_id:<22} ({prof.display_name}): {proto_desc}")
        lines.append(f"     Variants: {', '.join(v.variant_id for v in prof.default_variants)}")

    lines.append("")
    lines.append("3. Compatibility Rules:")
    for comp in catalog.list_compatibilities():
        adapt = f"adapter='{comp.adapter_id}'" if comp.adapter_id else "no adapter"
        lines.append(f"   - ({comp.engine_id}, {comp.profile_id}) -> {comp.status.value} [{adapt}]")
        if comp.known_limitations:
            for lim in comp.known_limitations:
                lines.append(f"     * Limitation: {lim}")

    return "\n".join(lines)
