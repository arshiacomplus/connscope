from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any

from connscope.adapters.models import ProtocolType
from .catalog import ProtocolCatalog
from .models import (
    CapabilityDefinition,
    CoverageTier,
    EngineProfileCompatibility,
    VerificationStatus,
)

@dataclass(frozen=True, slots=True)
class CoverageEntry:
    item_id: str
    engine_id: str
    category: str
    display_name: str
    tier_status: dict[str, bool]
    is_executable: bool
    source_reference: str = ""
    notes: str = ""
    unsupported_reason: str | None = None
    missing_schema: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "engine_id": self.engine_id,
            "category": self.category,
            "display_name": self.display_name,
            "tier_status": dict(self.tier_status),
            "is_executable": self.is_executable,
            "source_reference": self.source_reference,
            "notes": self.notes,
            "unsupported_reason": self.unsupported_reason,
            "missing_schema": self.missing_schema,
        }

@dataclass(frozen=True, slots=True)
class CoverageReport:
    entries: tuple[CoverageEntry, ...]
    engine_statistics: dict[str, dict[str, int]]
    tier_totals: dict[str, int]
    missing_schemas: tuple[str, ...]
    unimplemented_parameters: tuple[str, ...]
    unresolved_rules: tuple[str, ...]
    pending_tests: tuple[str, ...]
    canonical_capabilities_count: int = 0
    engine_capabilities_count: int = 0
    profile_compatibilities_count: int = 0
    parameter_definitions_count: int = 0
    variants_count: int = 0
    compatibility_rules_count: int = 0
    category_statistics: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "engine_statistics": {k: dict(v) for k, v in self.engine_statistics.items()},
            "tier_totals": dict(self.tier_totals),
            "missing_schemas": list(self.missing_schemas),
            "unimplemented_parameters": list(self.unimplemented_parameters),
            "unresolved_rules": list(self.unresolved_rules),
            "pending_tests": list(self.pending_tests),
            "canonical_capabilities_count": self.canonical_capabilities_count,
            "engine_capabilities_count": self.engine_capabilities_count,
            "profile_compatibilities_count": self.profile_compatibilities_count,
            "parameter_definitions_count": self.parameter_definitions_count,
            "variants_count": self.variants_count,
            "compatibility_rules_count": self.compatibility_rules_count,
            "category_statistics": {k: dict(v) for k, v in self.category_statistics.items()},
        }

def generate_coverage_report(
    catalog: ProtocolCatalog,
    engine_filter: str | None = None,
    protocol_filter: str | None = None,
    category_filter: str | None = None,
) -> CoverageReport:
    entries: list[CoverageEntry] = []
    missing_schemas: list[str] = []
    unimplemented_params: list[str] = []
    unresolved_rules: list[str] = []
    pending_tests: list[str] = []

    for comp in catalog.list_compatibilities():
        if engine_filter and comp.engine_id != engine_filter:
            continue
        if category_filter and category_filter.lower() != "profile_compatibility":
            continue
        prof = catalog.get_profile(comp.profile_id)
        if protocol_filter and prof:
            p_val = prof.protocol.value if isinstance(prof.protocol, ProtocolType) else str(prof.protocol)
            if p_val.lower() != protocol_filter.lower():
                continue
        eng = catalog.get_engine(comp.engine_id)
        item_id = f"{comp.engine_id}:{comp.profile_id}"
        display_name = f"{eng.display_name if eng else comp.engine_id} + {prof.display_name if prof else comp.profile_id}"

        has_schema = bool(prof and prof.parameters)
        has_config_gen = comp.adapter_id is not None
        has_binary_val = comp.status in (
            VerificationStatus.REAL_BINARY_CONFIG_VALIDATED,
            VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            VerificationStatus.REAL_TUNNEL_VERIFIED,
            VerificationStatus.REAL_DATA_TRANSFER_TESTED,
        )
        has_live = comp.status in (
            VerificationStatus.REAL_TUNNEL_VERIFIED,
            VerificationStatus.REAL_DATA_TRANSFER_TESTED,
        )
        has_data_xfer = comp.status == VerificationStatus.REAL_DATA_TRANSFER_TESTED

        tier_status = {
            CoverageTier.CATALOGUED.value: True,
            CoverageTier.SCHEMA_VALIDATED.value: has_schema,
            CoverageTier.CONFIG_GENERATED.value: has_config_gen,
            CoverageTier.BINARY_VALIDATED.value: has_binary_val,
            CoverageTier.LIVE_CONNECTED.value: has_live,
            CoverageTier.DATA_TRANSFERRED.value: has_data_xfer,
        }

        src_ref = ""
        if eng and eng.source_reference and eng.source_reference.repository_url:
            src_ref = eng.source_reference.repository_url

        notes_parts: list[str] = []
        if comp.known_limitations:
            notes_parts.extend(comp.known_limitations)
        notes = "; ".join(notes_parts)

        is_exec = has_config_gen and has_binary_val
        if not is_exec:
            unimplemented_params.append(item_id)
        if not has_live:
            pending_tests.append(f"{item_id} (live connection)")
        if comp.known_limitations:
            for lim in comp.known_limitations:
                unresolved_rules.append(f"{item_id}: {lim}")

        entries.append(
            CoverageEntry(
                item_id=item_id,
                engine_id=comp.engine_id,
                category="profile_compatibility",
                display_name=display_name,
                tier_status=tier_status,
                is_executable=is_exec,
                source_reference=src_ref,
                notes=notes,
                unsupported_reason=None if is_exec else "Adapter implementation or binary test required",
                missing_schema=not has_schema,
            )
        )

    for cap in catalog.list_capabilities():
        if engine_filter and cap.engine_id != engine_filter:
            continue
        cap_cat = cap.category.value if hasattr(cap.category, "value") else str(cap.category)
        if category_filter and cap_cat.lower() != category_filter.lower():
            continue
        if protocol_filter and cap.protocol:
            p_val = cap.protocol.value if isinstance(cap.protocol, ProtocolType) else str(cap.protocol)
            if p_val.lower() != protocol_filter.lower():
                continue
        elif protocol_filter and not cap.protocol:
            continue
        item_id = cap.capability_id
        eng = catalog.get_engine(cap.engine_id)

        has_schema = bool(cap.parameters or cap.config_mapping)
        has_config_gen = cap.is_executable
        has_binary_val = cap.status in (
            VerificationStatus.REAL_BINARY_CONFIG_VALIDATED,
            VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            VerificationStatus.REAL_TUNNEL_VERIFIED,
            VerificationStatus.REAL_DATA_TRANSFER_TESTED,
        )
        has_live = cap.status in (
            VerificationStatus.REAL_TUNNEL_VERIFIED,
            VerificationStatus.REAL_DATA_TRANSFER_TESTED,
        )
        has_data_xfer = cap.status == VerificationStatus.REAL_DATA_TRANSFER_TESTED

        tier_status = {
            CoverageTier.CATALOGUED.value: True,
            CoverageTier.SCHEMA_VALIDATED.value: has_schema,
            CoverageTier.CONFIG_GENERATED.value: has_config_gen,
            CoverageTier.BINARY_VALIDATED.value: has_binary_val,
            CoverageTier.LIVE_CONNECTED.value: has_live,
            CoverageTier.DATA_TRANSFERRED.value: has_data_xfer,
        }

        src_ref = ""
        if cap.source_reference and cap.source_reference.repository_url:
            src_ref = cap.source_reference.repository_url
        elif eng and eng.source_reference and eng.source_reference.repository_url:
            src_ref = eng.source_reference.repository_url

        if not has_schema:
            missing_schemas.append(item_id)
        if not cap.is_executable:
            unimplemented_params.append(item_id)
        if cap.unsupported_reason:
            unresolved_rules.append(f"{item_id}: {cap.unsupported_reason}")
        if not has_live:
            pending_tests.append(f"{item_id} (live connection)")

        entries.append(
            CoverageEntry(
                item_id=item_id,
                engine_id=cap.engine_id,
                category=cap_cat,
                display_name=cap.display_name,
                tier_status=tier_status,
                is_executable=cap.is_executable,
                source_reference=src_ref,
                notes=cap.description,
                unsupported_reason=cap.unsupported_reason,
                missing_schema=not has_schema,
            )
        )

    for eng in catalog.list_engines():
        if engine_filter and eng.engine_id != engine_filter:
            continue
        if eng.source_reference and eng.source_reference.requires_source_confirmation:
            unresolved_rules.append(f"engine:{eng.engine_id}: {eng.source_reference.notes}")

    engine_stats: dict[str, dict[str, int]] = {}
    category_stats: dict[str, dict[str, int]] = {}
    tier_totals: dict[str, int] = {t.value: 0 for t in CoverageTier}

    for entry in entries:
        eng_id = entry.engine_id
        if eng_id not in engine_stats:
            engine_stats[eng_id] = {t.value: 0 for t in CoverageTier}
            engine_stats[eng_id]["total_items"] = 0
            engine_stats[eng_id]["executable_items"] = 0

        engine_stats[eng_id]["total_items"] += 1
        if entry.is_executable:
            engine_stats[eng_id]["executable_items"] += 1

        cat_id = entry.category
        if cat_id not in category_stats:
            category_stats[cat_id] = {t.value: 0 for t in CoverageTier}
            category_stats[cat_id]["total_items"] = 0
            category_stats[cat_id]["executable_items"] = 0

        category_stats[cat_id]["total_items"] += 1
        if entry.is_executable:
            category_stats[cat_id]["executable_items"] += 1

        for tier in CoverageTier:
            if entry.tier_status.get(tier.value):
                engine_stats[eng_id][tier.value] += 1
                category_stats[cat_id][tier.value] += 1
                tier_totals[tier.value] += 1

    active_compatibilities = [
        c for c in catalog.list_compatibilities()
        if (not engine_filter or c.engine_id == engine_filter)
    ]
    active_capabilities = [
        c for c in catalog.list_capabilities()
        if (not engine_filter or c.engine_id == engine_filter)
    ]
    if category_filter:
        active_compatibilities = [
            c for c in active_compatibilities
            if "profile_compatibility" == category_filter.lower()
        ]
        active_capabilities = [
            c for c in active_capabilities
            if (c.category.value if hasattr(c.category, "value") else str(c.category)).lower() == category_filter.lower()
        ]
    if protocol_filter:
        filt_comps = []
        for c in active_compatibilities:
            prof = catalog.get_profile(c.profile_id)
            if prof:
                p_val = prof.protocol.value if isinstance(prof.protocol, ProtocolType) else str(prof.protocol)
                if p_val.lower() == protocol_filter.lower():
                    filt_comps.append(c)
        active_compatibilities = filt_comps

        filt_caps = []
        for c in active_capabilities:
            if c.protocol:
                p_val = c.protocol.value if isinstance(c.protocol, ProtocolType) else str(c.protocol)
                if p_val.lower() == protocol_filter.lower():
                    filt_caps.append(c)
        active_capabilities = filt_caps

    canonical_caps = {
        re.sub(r"^(xray_|singbox_|exclave_)", "", c.capability_id)
        for c in active_capabilities
    }
    canonical_capabilities_count = len(canonical_caps)
    engine_capabilities_count = len(active_capabilities)
    profile_compatibilities_count = len(active_compatibilities)

    all_params: set[str] = set()
    for p in catalog.list_profiles():
        if protocol_filter:
            p_val = p.protocol.value if isinstance(p.protocol, ProtocolType) else str(p.protocol)
            if p_val.lower() != protocol_filter.lower():
                continue
        for param in p.parameters:
            all_params.add(f"profile:{p.profile_id}:{param.param_id}")
    for c in active_capabilities:
        for param in c.parameters:
            all_params.add(f"cap:{c.capability_id}:{param.param_id}")
    parameter_definitions_count = len(all_params)

    variants_count = sum(
        len(p.default_variants)
        for p in catalog.list_profiles()
        if not protocol_filter or (p.protocol.value if isinstance(p.protocol, ProtocolType) else str(p.protocol)).lower() == protocol_filter.lower()
    )

    comp_rules_count = 0
    for comp in active_compatibilities:
        comp_rules_count += (
            len(comp.known_limitations)
            + len(comp.required_features)
            + len(comp.conflicting_features)
            + len(comp.parameter_constraints)
        )
    for cap in active_capabilities:
        comp_rules_count += len(cap.exclusions) + len(cap.dependencies) + (1 if cap.unsupported_reason else 0)
    compatibility_rules_count = comp_rules_count

    return CoverageReport(
        entries=tuple(entries),
        engine_statistics=engine_stats,
        tier_totals=tier_totals,
        missing_schemas=tuple(sorted(set(missing_schemas))),
        unimplemented_parameters=tuple(sorted(set(unimplemented_params))),
        unresolved_rules=tuple(sorted(set(unresolved_rules))),
        pending_tests=tuple(sorted(set(pending_tests))),
        canonical_capabilities_count=canonical_capabilities_count,
        engine_capabilities_count=engine_capabilities_count,
        profile_compatibilities_count=profile_compatibilities_count,
        parameter_definitions_count=parameter_definitions_count,
        variants_count=variants_count,
        compatibility_rules_count=compatibility_rules_count,
        category_statistics=category_stats,
    )

def render_coverage_table(report: CoverageReport) -> str:
    lines: list[str] = []
    lines.append("ConnScope Capability & Parameter Coverage Report")
    lines.append("=" * 115)
    lines.append("Counting Model Reconciliation:")
    lines.append(f"  * Canonical Capabilities:     {report.canonical_capabilities_count}")
    lines.append(f"  * Engine Capabilities:        {report.engine_capabilities_count}")
    lines.append(f"  * Profile Compatibilities:    {report.profile_compatibilities_count}")
    lines.append(f"  * Parameter Definitions:      {report.parameter_definitions_count}")
    lines.append(f"  * Parameter Variants:         {report.variants_count}")
    lines.append(f"  * Compatibility Rules:        {report.compatibility_rules_count}")
    lines.append("-" * 115)
    lines.append(
        f"{'ITEM IDENTIFIER':<38} {'ENGINE':<12} {'CAT':<4} {'SCH':<4} {'CFG':<4} {'BIN':<4} {'LIV':<4} {'XFR':<4} {'STATUS':<20}"
    )
    lines.append("-" * 115)

    def _mark(val: bool) -> str:
        return "[X]" if val else "[ ]"

    for e in report.entries:
        ts = e.tier_status
        status_desc = "EXECUTABLE" if e.is_executable else (e.unsupported_reason or "INVENTORY ONLY")
        if len(status_desc) > 30:
            status_desc = status_desc[:27] + "..."
        row = (
            f"{e.item_id:<38} "
            f"{e.engine_id:<12} "
            f"{_mark(ts.get(CoverageTier.CATALOGUED.value, False)):<4} "
            f"{_mark(ts.get(CoverageTier.SCHEMA_VALIDATED.value, False)):<4} "
            f"{_mark(ts.get(CoverageTier.CONFIG_GENERATED.value, False)):<4} "
            f"{_mark(ts.get(CoverageTier.BINARY_VALIDATED.value, False)):<4} "
            f"{_mark(ts.get(CoverageTier.LIVE_CONNECTED.value, False)):<4} "
            f"{_mark(ts.get(CoverageTier.DATA_TRANSFERRED.value, False)):<4} "
            f"{status_desc:<30}"
        )
        lines.append(row)

    lines.append("-" * 115)
    lines.append("")
    lines.append("Coverage Statistics by Engine:")
    lines.append(
        f"{'ENGINE':<14} {'ITEMS':<7} {'EXEC':<7} {'CATALOG':<9} {'SCHEMA':<8} {'CONFIG':<8} {'BINARY':<8} {'LIVE':<6} {'DATA_XFR':<8}"
    )
    lines.append("-" * 85)

    for eng in sorted(report.engine_statistics):
        st = report.engine_statistics[eng]
        row = (
            f"{eng:<14} "
            f"{st['total_items']:<7} "
            f"{st['executable_items']:<7} "
            f"{st['catalogued']:<9} "
            f"{st['schema_validated']:<8} "
            f"{st['config_generated']:<8} "
            f"{st['binary_validated']:<8} "
            f"{st['live_connected']:<6} "
            f"{st['data_transferred']:<8}"
        )
        lines.append(row)

    lines.append("-" * 85)
    tot = report.tier_totals
    total_items = sum(st["total_items"] for st in report.engine_statistics.values())
    total_exec = sum(st["executable_items"] for st in report.engine_statistics.values())
    lines.append(
        f"{'TOTAL':<14} "
        f"{total_items:<7} "
        f"{total_exec:<7} "
        f"{tot['catalogued']:<9} "
        f"{tot['schema_validated']:<8} "
        f"{tot['config_generated']:<8} "
        f"{tot['binary_validated']:<8} "
        f"{tot['live_connected']:<6} "
        f"{tot['data_transferred']:<8}"
    )
    lines.append("")

    if report.category_statistics:
        lines.append("Coverage Statistics by Category:")
        lines.append(
            f"{'CATEGORY':<24} {'ITEMS':<7} {'EXEC':<7} {'CATALOG':<9} {'SCHEMA':<8} {'CONFIG':<8} {'BINARY':<8} {'LIVE':<6} {'DATA_XFR':<8}"
        )
        lines.append("-" * 95)
        for cat in sorted(report.category_statistics):
            st = report.category_statistics[cat]
            row = (
                f"{cat:<24} "
                f"{st['total_items']:<7} "
                f"{st['executable_items']:<7} "
                f"{st['catalogued']:<9} "
                f"{st['schema_validated']:<8} "
                f"{st['config_generated']:<8} "
                f"{st['binary_validated']:<8} "
                f"{st['live_connected']:<6} "
                f"{st['data_transferred']:<8}"
            )
            lines.append(row)
        lines.append("-" * 95)
        lines.append("")

    if report.unresolved_rules:
        lines.append("Unresolved Rules & Known Limitations:")
        for rule in report.unresolved_rules:
            lines.append(f"  * {rule}")
        lines.append("")

    if report.missing_schemas:
        lines.append("Items Awaiting Schema Formalization:")
        for ms in report.missing_schemas:
            lines.append(f"  * {ms}")
        lines.append("")

    return "\n".join(lines)

def render_coverage_json(report: CoverageReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=True)
