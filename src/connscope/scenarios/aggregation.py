
from __future__ import annotations

from dataclasses import dataclass, field
import json
import statistics
from typing import Any, Sequence

from .records import MeasurementRecord

def _safe_median(values: Sequence[float]) -> float | None:
    if not values:
        return None
    return round(float(statistics.median(values)), 2)

def _safe_min(values: Sequence[float]) -> float | None:
    if not values:
        return None
    return round(float(min(values)), 2)

def _safe_max(values: Sequence[float]) -> float | None:
    if not values:
        return None
    return round(float(max(values)), 2)

@dataclass(frozen=True, slots=True)
class ScenarioSummary:
    scenario_id: str
    engine_id: str
    profile_id: str
    variant_id: str
    adapter_id: str
    target: dict[str, Any]
    workload_type: str
    total_repetitions: int
    successful_repetitions: int
    success_rate: float
    median_total_ms: float | None
    min_total_ms: float | None
    max_total_ms: float | None
    median_handshake_ms: float | None
    median_data_transfer_ms: float | None
    failure_stages: dict[str, int] = field(default_factory=dict)
    node_id: str = "local"
    route_context: dict[str, Any] = field(default_factory=dict)
    operator_labels: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "node_id": self.node_id,
            "engine_id": self.engine_id,
            "profile_id": self.profile_id,
            "variant_id": self.variant_id,
            "adapter_id": self.adapter_id,
            "target": self.target,
            "workload_type": self.workload_type,
            "route_context": dict(self.route_context),
            "operator_labels": dict(self.operator_labels),
            "total_repetitions": self.total_repetitions,
            "successful_repetitions": self.successful_repetitions,
            "success_rate": round(self.success_rate, 4),
            "median_total_ms": self.median_total_ms,
            "min_total_ms": self.min_total_ms,
            "max_total_ms": self.max_total_ms,
            "median_handshake_ms": self.median_handshake_ms,
            "median_data_transfer_ms": self.median_data_transfer_ms,
            "failure_stages": dict(self.failure_stages),
        }

@dataclass(frozen=True, slots=True)
class MatrixExecutionSummary:
    planned_scenarios: int
    executed_scenarios: int
    succeeded_scenarios: int
    failed_scenarios: int
    excluded_scenarios: int
    total_measurements: int
    successful_measurements: int
    failed_measurements: int
    success_rate: float
    timing_stats: dict[str, float | None]
    failure_stage_distribution: dict[str, int]
    per_scenario_summaries: tuple[ScenarioSummary, ...]
    excluded_scenarios_detail: tuple[dict[str, str], ...]
    is_comparable: bool
    workload_comparability_notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "planned_scenarios": self.planned_scenarios,
            "executed_scenarios": self.executed_scenarios,
            "succeeded_scenarios": self.succeeded_scenarios,
            "failed_scenarios": self.failed_scenarios,
            "excluded_scenarios": self.excluded_scenarios,
            "total_measurements": self.total_measurements,
            "successful_measurements": self.successful_measurements,
            "failed_measurements": self.failed_measurements,
            "success_rate": round(self.success_rate, 4),
            "timing_stats": dict(self.timing_stats),
            "failure_stage_distribution": dict(self.failure_stage_distribution),
            "is_comparable": self.is_comparable,
            "workload_comparability_notes": list(self.workload_comparability_notes),
            "per_scenario_summaries": [s.to_dict() for s in self.per_scenario_summaries],
            "excluded_scenarios_detail": [dict(x) for x in self.excluded_scenarios_detail],
        }

def aggregate_execution_records(
    records: Sequence[MeasurementRecord],
    planned_count: int,
    excluded_details: Sequence[dict[str, str]] | None = None,
) -> MatrixExecutionSummary:
    excluded_list = tuple(excluded_details or ())
    excluded_count = len(excluded_list)

    if not records:
        return MatrixExecutionSummary(
            planned_scenarios=planned_count,
            executed_scenarios=0,
            succeeded_scenarios=0,
            failed_scenarios=0,
            excluded_scenarios=excluded_count,
            total_measurements=0,
            successful_measurements=0,
            failed_measurements=0,
            success_rate=0.0,
            timing_stats={
                "median_total_ms": None,
                "min_total_ms": None,
                "max_total_ms": None,
                "median_handshake_ms": None,
                "median_data_transfer_ms": None,
            },
            failure_stage_distribution={},
            per_scenario_summaries=(),
            excluded_scenarios_detail=excluded_list,
            is_comparable=True,
            workload_comparability_notes=(),
        )

    records_by_scenario: dict[str, list[MeasurementRecord]] = {}
    for r in records:
        records_by_scenario.setdefault(r.scenario_id, []).append(r)

    executed_scenarios = len(records_by_scenario)
    total_measurements = len(records)
    successful_measurements = sum(1 for r in records if r.status == "success")
    failed_measurements = total_measurements - successful_measurements
    overall_success_rate = (successful_measurements / total_measurements) if total_measurements > 0 else 0.0

    success_records = [r for r in records if r.status == "success"]
    all_total_ms = [r.duration_ms for r in success_records]
    all_handshake_ms = [
        r.metrics["handshake_ms"] for r in success_records
        if "handshake_ms" in r.metrics
    ]
    all_data_ms = [
        r.metrics["data_transfer_ms"] for r in success_records
        if "data_transfer_ms" in r.metrics
    ]

    overall_timings = {
        "median_total_ms": _safe_median(all_total_ms),
        "min_total_ms": _safe_min(all_total_ms),
        "max_total_ms": _safe_max(all_total_ms),
        "median_handshake_ms": _safe_median(all_handshake_ms),
        "median_data_transfer_ms": _safe_median(all_data_ms),
    }

    stage_dist: dict[str, int] = {}
    for r in records:
        if r.status != "success":
            stage = r.failure_stage or "unknown"
            stage_dist[stage] = stage_dist.get(stage, 0) + 1

    per_scenario: list[ScenarioSummary] = []
    succeeded_scenarios_count = 0
    failed_scenarios_count = 0

    for scn_id in sorted(records_by_scenario.keys()):
        scn_recs = records_by_scenario[scn_id]
        rep_count = len(scn_recs)
        succ_reps = sum(1 for r in scn_recs if r.status == "success")
        scn_rate = (succ_reps / rep_count) if rep_count > 0 else 0.0

        if succ_reps > 0 and succ_reps == rep_count:
            succeeded_scenarios_count += 1
        else:
            failed_scenarios_count += 1

        succ_scn_recs = [r for r in scn_recs if r.status == "success"]
        scn_totals = [r.duration_ms for r in succ_scn_recs]
        scn_handshakes = [
            r.metrics["handshake_ms"] for r in succ_scn_recs
            if "handshake_ms" in r.metrics
        ]
        scn_datas = [
            r.metrics["data_transfer_ms"] for r in succ_scn_recs
            if "data_transfer_ms" in r.metrics
        ]

        scn_stages: dict[str, int] = {}
        for r in scn_recs:
            if r.status != "success":
                st = r.failure_stage or "unknown"
                scn_stages[st] = scn_stages.get(st, 0) + 1

        sample_r = scn_recs[0]
        per_scenario.append(
            ScenarioSummary(
                scenario_id=scn_id,
                node_id=sample_r.node_id,
                engine_id=sample_r.engine_id,
                profile_id=sample_r.profile_id,
                variant_id=sample_r.variant_id,
                adapter_id=sample_r.adapter_id,
                target=sample_r.target,
                workload_type=sample_r.workload.get("workload_type", "unknown"),
                route_context=sample_r.route_context,
                total_repetitions=rep_count,
                successful_repetitions=succ_reps,
                success_rate=scn_rate,
                median_total_ms=_safe_median(scn_totals),
                min_total_ms=_safe_min(scn_totals),
                max_total_ms=_safe_max(scn_totals),
                median_handshake_ms=_safe_median(scn_handshakes),
                median_data_transfer_ms=_safe_median(scn_datas),
                failure_stages=scn_stages,
            )
        )

    is_comparable = True
    comp_notes: list[str] = []

    distinct_targets = {
        f"{r.target.get('host')}:{r.target.get('port')}" for r in records
    }
    distinct_workloads = {
        f"{r.workload.get('workload_type')}:{r.workload.get('test_url')}" for r in records
    }
    distinct_nodes = {r.node_id for r in records}

    if len(distinct_targets) > 1:
        is_comparable = False
        comp_notes.append(
            f"Measurements spanned {len(distinct_targets)} different target endpoints ({', '.join(sorted(distinct_targets))}); timing distributions cannot be combined into a single benchmark."
        )

    if len(distinct_workloads) > 1:
        is_comparable = False
        comp_notes.append(
            f"Measurements used {len(distinct_workloads)} distinct workloads/URLs ({', '.join(sorted(distinct_workloads))}); data transfer metrics are not directly comparable."
        )

    if len(distinct_nodes) > 1 and is_comparable:
        comp_notes.append(
            f"Measurements compared across {len(distinct_nodes)} nodes ({', '.join(sorted(distinct_nodes))}) under identical target and workload."
        )

    return MatrixExecutionSummary(
        planned_scenarios=planned_count,
        executed_scenarios=executed_scenarios,
        succeeded_scenarios=succeeded_scenarios_count,
        failed_scenarios=failed_scenarios_count,
        excluded_scenarios=excluded_count,
        total_measurements=total_measurements,
        successful_measurements=successful_measurements,
        failed_measurements=failed_measurements,
        success_rate=overall_success_rate,
        timing_stats=overall_timings,
        failure_stage_distribution=stage_dist,
        per_scenario_summaries=tuple(per_scenario),
        excluded_scenarios_detail=excluded_list,
        is_comparable=is_comparable,
        workload_comparability_notes=tuple(comp_notes),
    )

def render_execution_summary_table(summary: MatrixExecutionSummary) -> str:
    lines: list[str] = []
    lines.append("Scenario Matrix Execution Summary")
    lines.append("=" * 80)
    lines.append(
        f"Scenarios: Planned={summary.planned_scenarios} | Executed={summary.executed_scenarios} "
        f"(Succeeded={summary.succeeded_scenarios}, Failed={summary.failed_scenarios}) | Excluded={summary.excluded_scenarios}"
    )
    timeouts_count = summary.failure_stage_distribution.get("timeout", 0)
    lines.append(
        f"Measurements: Total={summary.total_measurements} | Passed={summary.successful_measurements} | "
        f"Failed={summary.failed_measurements} | Timeouts={timeouts_count} | Success Rate={summary.success_rate * 100:.1f}%"
    )

    if not summary.is_comparable:
        lines.append("")
        lines.append("! COMPARABILITY NOTICE:")
        for note in summary.workload_comparability_notes:
            lines.append(f"  * {note}")

    lines.append("")
    lines.append("Timing Overview (Successful Measurements):")
    t_stats = summary.timing_stats
    med_tot = f"{t_stats['median_total_ms']}ms" if t_stats['median_total_ms'] is not None else "N/A"
    min_tot = f"{t_stats['min_total_ms']}ms" if t_stats['min_total_ms'] is not None else "N/A"
    max_tot = f"{t_stats['max_total_ms']}ms" if t_stats['max_total_ms'] is not None else "N/A"
    med_hs = f"{t_stats['median_handshake_ms']}ms" if t_stats['median_handshake_ms'] is not None else "N/A"
    med_dt = f"{t_stats['median_data_transfer_ms']}ms" if t_stats['median_data_transfer_ms'] is not None else "N/A"
    lines.append(f"  - Total Duration: Median={med_tot} (Min={min_tot}, Max={max_tot})")
    lines.append(f"  - Handshake: Median={med_hs} | Data Transfer: Median={med_dt}")

    if summary.failure_stage_distribution:
        lines.append("")
        lines.append("Failure Stage Distribution:")
        for stage, cnt in sorted(summary.failure_stage_distribution.items()):
            lines.append(f"  - {stage}: {cnt}")

    if summary.per_scenario_summaries:
        lines.append("")
        lines.append("-" * 92)
        lines.append(f"{'SCENARIO ID':<34} {'NODE':<12} {'ENGINE':<10} {'SUCCESS':<12} {'MEDIAN TOTAL':<14} {'MEDIAN HS':<10}")
        lines.append("-" * 92)
        for s in summary.per_scenario_summaries:
            succ_str = f"{s.successful_repetitions}/{s.total_repetitions} ({s.success_rate * 100:.0f}%)"
            tot_str = f"{s.median_total_ms}ms" if s.median_total_ms is not None else "—"
            hs_str = f"{s.median_handshake_ms}ms" if s.median_handshake_ms is not None else "—"
            lines.append(f"{s.scenario_id:<34} {s.node_id:<12} {s.engine_id:<10} {succ_str:<12} {tot_str:<14} {hs_str:<10}")

    if summary.excluded_scenarios_detail:
        lines.append("")
        lines.append("Excluded / Skipped Scenarios:")
        for exc in summary.excluded_scenarios_detail:
            lines.append(f"  - {exc.get('scenario_id')}: {exc.get('reason')}")

    return "\n".join(lines)

def render_execution_summary_json(summary: MatrixExecutionSummary) -> str:
    return json.dumps(summary.to_dict(), indent=2)
