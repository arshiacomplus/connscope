
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import math
from pathlib import Path
from typing import Any, Iterable, TextIO

from connscope.adapters.security import SENSITIVE_FIELD_NAMES, redact_sensitive_data
from connscope.core import ProbeResult, ProbeStatus, Target
from .models import Scenario, VerificationStatus

SCHEMA_VERSION: str = "1.0"

def _sanitize_metrics(metrics: dict[str, Any]) -> dict[str, float]:
    clean: dict[str, float] = {}
    for k, v in metrics.items():
        if isinstance(v, (int, float)) and math.isfinite(v):
            clean[k] = float(v)
    return clean

@dataclass(frozen=True, slots=True)
class MeasurementRecord:
    scenario_id: str
    repetition_index: int
    engine_id: str
    profile_id: str
    variant_id: str
    adapter_id: str
    node_id: str
    target: dict[str, Any]
    workload: dict[str, Any]
    started_at: str
    ended_at: str
    duration_ms: float
    status: str
    metrics: dict[str, float] = field(default_factory=dict)
    failure_stage: str | None = None
    tunnel_established: bool = False
    tls_verified: bool | None = None
    data_transfer_completed: bool = False
    verified_data_transfer: bool | None = None
    execution_mode: str = "local_proxy"
    interface_established: bool | None = None
    peer_handshake_completed: bool | None = None
    traffic_traversed: bool | None = None
    error: str | None = None
    evidence_status: str = VerificationStatus.CATALOGUED.value
    executable_version: str | None = None
    route_context: dict[str, Any] = field(default_factory=dict)
    operator_labels: dict[str, str] = field(default_factory=dict)
    resolved_config: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_probe_result(
        cls,
        scenario: Scenario,
        result: ProbeResult,
        repetition_index: int,
        ended_at: datetime | None = None,
        executable_version: str | None = None,
    ) -> MeasurementRecord:
        start_ts = result.started_at
        if start_ts.tzinfo is None:
            start_ts = start_ts.replace(tzinfo=timezone.utc)

        end_ts = ended_at or datetime.now(timezone.utc)
        if end_ts.tzinfo is None:
            end_ts = end_ts.replace(tzinfo=timezone.utc)

        details = result.details or {}
        raw_error = str(result.error) if result.error else None

        redacted_config = scenario.get_redacted_config()

        clean_error = raw_error
        if clean_error:
            for s_key in SENSITIVE_FIELD_NAMES:
                raw_val = scenario.resolved_config.get(s_key)
                if raw_val and isinstance(raw_val, str) and raw_val in clean_error:
                    clean_error = clean_error.replace(raw_val, "[REDACTED]")

        failure_stage = details.get("failure_stage")
        tunnel_established = bool(details.get("tunnel_established", False))
        tls_verified = details.get("tls_verified")
        data_transfer_completed = bool(details.get("data_transfer_completed", False))
        verified_data_transfer = details.get("verified_data_transfer")
        execution_mode = str(details.get("execution_mode", "local_proxy"))
        if scenario.status == VerificationStatus.LOCAL_DIAGNOSTIC_VERIFIED or scenario.metadata.get("diagnostic"):
            execution_mode = "local_diagnostic"
        interface_established = details.get("interface_established")
        peer_handshake_completed = details.get("peer_handshake_completed")
        traffic_traversed = details.get("traffic_traversed")

        combined_metrics = dict(result.metrics)
        if "metrics" in details and isinstance(details["metrics"], dict):
            combined_metrics.update(details["metrics"])
        clean_metrics = _sanitize_metrics(combined_metrics)

        route_ctx = dict(scenario.node.route_context)
        if "origin_endpoint_route" in details and details["origin_endpoint_route"] is not None:
            route_ctx["origin_endpoint_route"] = details["origin_endpoint_route"]
        elif "extra" in details and isinstance(details["extra"], dict) and details["extra"].get("origin_endpoint_route"):
            route_ctx["origin_endpoint_route"] = details["extra"]["origin_endpoint_route"]

        if "isolation_strategy" in details and details["isolation_strategy"] is not None:
            route_ctx["isolation_strategy"] = details["isolation_strategy"]
        elif "extra" in details and isinstance(details["extra"], dict) and details["extra"].get("isolation_strategy"):
            route_ctx["isolation_strategy"] = details["extra"]["isolation_strategy"]

        return cls(
            scenario_id=scenario.scenario_id,
            repetition_index=repetition_index,
            engine_id=scenario.engine_id,
            profile_id=scenario.profile_id,
            variant_id=scenario.variant_id,
            adapter_id=scenario.adapter_id or details.get("adapter_id", "unknown"),
            node_id=scenario.node.node_id,
            target={"host": scenario.target.host, "port": scenario.target.port},
            workload=scenario.workload.to_dict(),
            started_at=start_ts.isoformat(),
            ended_at=end_ts.isoformat(),
            duration_ms=max(0.0, float(result.duration_ms)),
            status=result.status.value,
            metrics=clean_metrics,
            failure_stage=str(failure_stage) if failure_stage else None,
            tunnel_established=tunnel_established,
            tls_verified=bool(tls_verified) if tls_verified is not None else None,
            data_transfer_completed=data_transfer_completed,
            verified_data_transfer=bool(verified_data_transfer) if verified_data_transfer is not None else None,
            execution_mode=execution_mode,
            interface_established=bool(interface_established) if interface_established is not None else None,
            peer_handshake_completed=bool(peer_handshake_completed) if peer_handshake_completed is not None else None,
            traffic_traversed=bool(traffic_traversed) if traffic_traversed is not None else None,
            error=clean_error,
            evidence_status=scenario.status.value,
            executable_version=executable_version,
            route_context=route_ctx,
            operator_labels=dict(scenario.node.operator_labels),
            resolved_config=redacted_config,
            schema_version=SCHEMA_VERSION,
        )

    def to_dict(self) -> dict[str, Any]:
        clean_config = dict(self.resolved_config)
        for k in clean_config:
            if k in SENSITIVE_FIELD_NAMES:
                clean_config[k] = "[REDACTED]"

        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "repetition_index": self.repetition_index,
            "engine_id": self.engine_id,
            "profile_id": self.profile_id,
            "variant_id": self.variant_id,
            "adapter_id": self.adapter_id,
            "node_id": self.node_id,
            "target": dict(self.target),
            "workload": dict(self.workload),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "metrics": dict(self.metrics),
            "failure_stage": self.failure_stage,
            "tunnel_established": self.tunnel_established,
            "tls_verified": self.tls_verified,
            "data_transfer_completed": self.data_transfer_completed,
            "verified_data_transfer": self.verified_data_transfer,
            "execution_mode": self.execution_mode,
            "interface_established": self.interface_established,
            "peer_handshake_completed": self.peer_handshake_completed,
            "traffic_traversed": self.traffic_traversed,
            "error": self.error,
            "evidence_status": self.evidence_status,
            "executable_version": self.executable_version,
            "route_context": dict(self.route_context),
            "operator_labels": dict(self.operator_labels),
            "resolved_config": clean_config,
        }

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MeasurementRecord:
        return cls(
            scenario_id=data["scenario_id"],
            repetition_index=int(data["repetition_index"]),
            engine_id=data["engine_id"],
            profile_id=data["profile_id"],
            variant_id=data["variant_id"],
            adapter_id=data["adapter_id"],
            node_id=data["node_id"],
            target=dict(data["target"]),
            workload=dict(data["workload"]),
            started_at=data["started_at"],
            ended_at=data["ended_at"],
            duration_ms=float(data["duration_ms"]),
            status=data["status"],
            metrics=dict(data.get("metrics", {})),
            failure_stage=data.get("failure_stage"),
            tunnel_established=bool(data.get("tunnel_established", False)),
            tls_verified=data.get("tls_verified"),
            data_transfer_completed=bool(data.get("data_transfer_completed", False)),
            verified_data_transfer=data.get("verified_data_transfer"),
            execution_mode=str(data.get("execution_mode", "local_proxy")),
            interface_established=data.get("interface_established"),
            peer_handshake_completed=data.get("peer_handshake_completed"),
            traffic_traversed=data.get("traffic_traversed"),
            error=data.get("error"),
            evidence_status=data.get("evidence_status", VerificationStatus.CATALOGUED.value),
            executable_version=data.get("executable_version"),
            route_context=dict(data.get("route_context", {})),
            operator_labels=dict(data.get("operator_labels", {})),
            resolved_config=dict(data.get("resolved_config", {})),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
        )

    @classmethod
    def from_json_line(cls, line: str) -> MeasurementRecord:
        return cls.from_dict(json.loads(line.strip()))

def write_jsonl(records: Iterable[MeasurementRecord], path_or_stream: str | Path | TextIO) -> int:
    count = 0
    if isinstance(path_or_stream, (str, Path)):
        p = Path(path_or_stream)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(rec.to_json_line() + "\n")
                count += 1
    else:
        for rec in records:
            path_or_stream.write(rec.to_json_line() + "\n")
            count += 1
    return count

def read_jsonl(path_or_stream: str | Path | TextIO) -> list[MeasurementRecord]:
    records: list[MeasurementRecord] = []
    if isinstance(path_or_stream, (str, Path)):
        with open(path_or_stream, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    records.append(MeasurementRecord.from_json_line(line_str))
    else:
        for line in path_or_stream:
            line_str = line.strip()
            if line_str:
                records.append(MeasurementRecord.from_json_line(line_str))
    return records
