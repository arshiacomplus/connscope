
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable, Sequence

from connscope.adapters import AdapterRegistry, EngineAdapter, SecurityType
from connscope.agent.client import (
    RemoteAgentClient,
    RemoteAuthenticationError,
    RemoteConnectionError,
    RemoteHttpError,
    RemotePolicyError,
    RemoteProtocolError,
    RemoteTimeoutError,
    RemoteUnavailableError,
)
from connscope.agent.protocol import AgentCapabilities, PROHIBITED_REMOTE_ADAPTERS
from connscope.core import ProbeResult, ProbeStatus, Target
from .aggregation import MatrixExecutionSummary, aggregate_execution_records
from .catalog import ProtocolCatalog, create_default_protocol_catalog
from .migration import AdapterMigrationBridge
from .models import MatrixPlan, MeasurementNode, NodeType, Scenario, VerificationStatus
from .nodes import NodeRegistry, resolve_node_token
from .parameter_coverage import detect_local_engine_versions
from .records import MeasurementRecord

class FailurePolicy(StrEnum):
    CONTINUE = "continue"
    STOP_ON_ERROR = "stop"

@dataclass(frozen=True, slots=True)
class MatrixExecutionResult:
    plan: MatrixPlan
    records: tuple[MeasurementRecord, ...]
    summary: MatrixExecutionSummary
    is_dry_run: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan.plan_id,
            "is_dry_run": self.is_dry_run,
            "records_count": len(self.records),
            "summary": self.summary.to_dict(),
            "metadata": dict(self.metadata),
        }

class ScenarioCoordinator:

    def __init__(
        self,
        catalog: ProtocolCatalog | None = None,
        migration_bridge: AdapterMigrationBridge | None = None,
        adapter_registry: AdapterRegistry | None = None,
        concurrency: int = 1,
        failure_policy: FailurePolicy = FailurePolicy.CONTINUE,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        node_registry: NodeRegistry | None = None,
        node_tokens: dict[str, str] | None = None,
        token_resolver: Callable[[MeasurementNode], str | None] | None = None,
        client_factory: Callable[..., RemoteAgentClient] | None = None,
    ) -> None:
        self.catalog = catalog if catalog is not None else create_default_protocol_catalog()
        if adapter_registry is not None:
            self.migration_bridge = AdapterMigrationBridge(registry=adapter_registry)
        elif migration_bridge is not None:
            self.migration_bridge = migration_bridge
        else:
            self.migration_bridge = AdapterMigrationBridge()
        self.concurrency = max(1, int(concurrency))
        self.failure_policy = failure_policy
        self.progress_callback = progress_callback
        self.node_registry = node_registry
        self.node_tokens = dict(node_tokens or {})
        self.token_resolver = token_resolver
        self.client_factory = client_factory
        self._capabilities_cache: dict[str, AgentCapabilities] = {}

    def _get_client(self, endpoint_url: str, token: str, timeout_s: float) -> RemoteAgentClient:
        if self.client_factory is not None:
            try:
                return self.client_factory(endpoint_url, token, timeout_s)
            except TypeError:
                return self.client_factory(endpoint_url, token)
        return RemoteAgentClient(node_url=endpoint_url, token=token, timeout_s=timeout_s)

    def _notify_progress(self, event_type: str, **kwargs: Any) -> None:
        if self.progress_callback:
            try:
                self.progress_callback({"type": event_type, "timestamp": datetime.now(timezone.utc).isoformat(), **kwargs})
            except Exception:
                pass

    async def execute_plan(
        self,
        plan: MatrixPlan,
        execute: bool = False,
        repetitions_override: int | None = None,
    ) -> MatrixExecutionResult:
        self._notify_progress(
            "plan_start",
            plan_id=plan.plan_id,
            total_scenarios=len(plan.scenarios),
            is_dry_run=not execute,
        )

        excluded_details: list[dict[str, str]] = []
        executable_scenarios: list[tuple[Scenario, Any, dict[str, Any], str | None, str | None]] = []

        for scn in plan.scenarios:
            if not scn.is_valid:
                reason = scn.exclusion_reason or "Scenario configuration is invalid"
                excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                continue

            if not scn.adapter_id:
                reason = f"No executable adapter for profile '{scn.profile_id}' (status: {scn.status.value})"
                excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                continue

            is_remote = (scn.node.node_type == NodeType.REMOTE_AGENT.value or scn.node.node_type == "remote_agent")
            if is_remote:
                if scn.adapter_id in PROHIBITED_REMOTE_ADAPTERS:
                    reason = f"Layer-3 adapter '{scn.adapter_id}' is not supported for remote execution on node '{scn.node.node_id}'"
                    excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                    self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                    continue

                if not scn.node.endpoint_url:
                    reason = f"Remote node '{scn.node.node_id}' has no endpoint URL"
                    excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                    self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                    continue

                token = resolve_node_token(scn.node, token_map=self.node_tokens, resolver=self.token_resolver)
                if not token:
                    reason = f"Missing authentication token for remote node '{scn.node.node_id}'"
                    excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                    self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                    continue

                is_valid, val_err, norm_cfg = self.migration_bridge.validate_scenario(scn)
                if not is_valid:
                    reason = val_err or "Configuration validation failed"
                    excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                    self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                    continue

                if scn.node.node_id not in self._capabilities_cache:
                    client = self._get_client(scn.node.endpoint_url, token, scn.node.connection_timeout_s)
                    try:
                        caps = await asyncio.to_thread(client.get_capabilities)
                        self._capabilities_cache[scn.node.node_id] = caps
                    except Exception as exc:
                        reason = f"Capability discovery failed for node '{scn.node.node_id}': {exc}"
                        excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                        self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                        continue

                caps = self._capabilities_cache[scn.node.node_id]

                if scn.adapter_id not in caps.allowlisted_adapters:
                    reason = (
                        f"Adapter '{scn.adapter_id}' is not allowlisted on remote node '{scn.node.node_id}' "
                        f"(allowlisted: {sorted(list(caps.allowlisted_adapters))})"
                    )
                    excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                    self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                    continue

                if not caps.api_version.startswith("1."):
                    reason = f"Incompatible agent API version '{caps.api_version}' on remote node '{scn.node.node_id}'"
                    excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                    self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                    continue

                exe_version = caps.executable_versions.get(scn.engine_id)
                adapter_cfg = self.migration_bridge.convert_scenario_to_adapter_config(scn)
                executable_scenarios.append((scn, "remote", adapter_cfg, exe_version, token))

            else:
                adapter = self.migration_bridge.get_adapter_for_scenario(scn)
                if adapter is None:
                    reason = f"Adapter '{scn.adapter_id}' is not registered"
                    excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                    self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                    continue

                is_valid, val_err, norm_cfg = self.migration_bridge.validate_scenario(scn)
                if not is_valid:
                    reason = val_err or "Configuration validation failed"
                    excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                    self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                    continue

                adapter_cfg = self.migration_bridge.convert_scenario_to_adapter_config(scn)

                if scn.engine_id == "xray" and adapter.metadata.security == SecurityType.TLS and adapter_cfg.get("verify_cert") is False:
                    reason = "Engine 'xray' (v26+) does not support disabling certificate verification ('verify_cert=False') because 'allowInsecure' was permanently removed upstream; certificate verification must remain enabled."
                    excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                    self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                    continue

                if scn.engine_id in ("sing_box", "singbox"):
                    if adapter_cfg.get("uot") is True:
                        reason = "Engine 'sing-box' does not support Shadowsocks UOT ('uot=True') in standard client outbound configuration."
                        excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                        self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                        continue
                    if adapter_cfg.get("multi_mode") is True:
                        reason = "Engine 'sing-box' does not support gRPC multi_mode ('multi_mode=True')."
                        excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                        self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                        continue
                    if adapter_cfg.get("packet_encoding") == "none":
                        reason = "Engine 'sing-box' does not support 'packet_encoding=none' (only 'packetaddr' or 'xudp' allowed)."
                        excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                        self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                        continue
                    sp = adapter_cfg.get("spiderX") or adapter_cfg.get("spider_x")
                    if sp not in (None, "", "/"):
                        reason = "REALITY 'spiderX' crawler path is not supported by sing-box outbound"
                        excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                        self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                        continue

                eng_def = self.catalog.get_engine(scn.engine_id)
                local_versions = detect_local_engine_versions()
                detected_v = local_versions.get(scn.engine_id)
                if detected_v and detected_v not in ("unavailable", "unknown"):
                    exe_version = detected_v
                else:
                    exe_version = eng_def.tested_versions[0] if eng_def and eng_def.tested_versions else None

                if execute:
                    exe_ok, exe_path = adapter.check_executable()
                    if not exe_ok:
                        reason = f"Required executable not found or not allowlisted: {exe_path}"
                        excluded_details.append({"scenario_id": scn.scenario_id, "reason": reason})
                        self._notify_progress("scenario_excluded", scenario_id=scn.scenario_id, reason=reason)
                        continue

                executable_scenarios.append((scn, adapter, adapter_cfg, exe_version, None))

        if not execute:
            summary = aggregate_execution_records(
                records=(),
                planned_count=len(plan.scenarios),
                excluded_details=excluded_details,
            )
            self._notify_progress("plan_complete", planned=len(plan.scenarios), executed=0, excluded=len(excluded_details))
            return MatrixExecutionResult(
                plan=plan,
                records=(),
                summary=summary,
                is_dry_run=True,
                metadata={"executable_scenarios_count": len(executable_scenarios)},
            )

        semaphore = asyncio.Semaphore(self.concurrency)
        all_records: list[MeasurementRecord] = []
        stop_requested = False

        async def run_scenario_reps(
            scn: Scenario,
            exec_target: Any,
            cfg: dict[str, Any],
            exe_ver: str | None,
            token: str | None,
        ) -> list[MeasurementRecord]:
            nonlocal stop_requested
            reps = repetitions_override if repetitions_override is not None else scn.workload.repetitions
            reps = max(1, int(reps))
            scn_records: list[MeasurementRecord] = []

            for rep_idx in range(reps):
                if stop_requested:
                    break

                self._notify_progress(
                    "repetition_start",
                    scenario_id=scn.scenario_id,
                    repetition_index=rep_idx,
                    total_repetitions=reps,
                )

                async with semaphore:
                    started_at = datetime.now(timezone.utc)
                    if exec_target == "remote":
                        client = self._get_client(
                            scn.node.endpoint_url,  # type: ignore[arg-type]
                            token,  # type: ignore[arg-type]
                            scn.node.execution_timeout_s,
                        )
                        try:
                            probe_res = await asyncio.to_thread(
                                client.execute_adapter,
                                scn.adapter_id,
                                scn.target,
                                cfg,
                                timeout_s=scn.workload.timeout_s,
                            )
                        except asyncio.CancelledError:
                            raise
                        except (RemoteConnectionError, RemoteUnavailableError) as exc:
                            probe_res = ProbeResult(
                                probe=scn.adapter_id or "remote",
                                target=scn.target,
                                status=ProbeStatus.FAILED,
                                started_at=started_at,
                                duration_ms=0.0,
                                error=f"Remote node unavailable: {exc}",
                                details={"failure_stage": "node_unavailable", "execution_mode": "remote_agent"},
                            )
                        except (RemotePolicyError, RemoteAuthenticationError) as exc:
                            probe_res = ProbeResult(
                                probe=scn.adapter_id or "remote",
                                target=scn.target,
                                status=ProbeStatus.FAILED,
                                started_at=started_at,
                                duration_ms=0.0,
                                error=f"Remote capability/policy error: {exc}",
                                details={"failure_stage": "capability_unavailable", "execution_mode": "remote_agent"},
                            )
                        except RemoteTimeoutError as exc:
                            probe_res = ProbeResult(
                                probe=scn.adapter_id or "remote",
                                target=scn.target,
                                status=ProbeStatus.TIMEOUT,
                                started_at=started_at,
                                duration_ms=0.0,
                                error=f"Remote timeout: {exc}",
                                details={"failure_stage": "timeout", "execution_mode": "remote_agent"},
                            )
                        except Exception as exc:
                            probe_res = ProbeResult(
                                probe=scn.adapter_id or "remote",
                                target=scn.target,
                                status=ProbeStatus.FAILED,
                                started_at=started_at,
                                duration_ms=0.0,
                                error=f"Remote adapter execution failed: {exc}",
                                details={"failure_stage": "process", "execution_mode": "remote_agent"},
                            )
                    else:
                        adapter = exec_target
                        try:
                            probe_res = await adapter.run(scn.target, config=cfg)
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            probe_res = ProbeResult(
                                probe=adapter.name,
                                target=scn.target,
                                status=ProbeStatus.FAILED,
                                started_at=started_at,
                                duration_ms=0.0,
                                error=f"Coordinator caught adapter exception: {exc}",
                                details={"failure_stage": "process"},
                            )
                    ended_at = datetime.now(timezone.utc)

                record = MeasurementRecord.from_probe_result(
                    scenario=scn,
                    result=probe_res,
                    repetition_index=rep_idx,
                    ended_at=ended_at,
                    executable_version=exe_ver,
                )
                scn_records.append(record)

                self._notify_progress(
                    "repetition_complete",
                    scenario_id=scn.scenario_id,
                    repetition_index=rep_idx,
                    status=record.status,
                    duration_ms=record.duration_ms,
                )

                if record.status != ProbeStatus.SUCCESS.value and self.failure_policy == FailurePolicy.STOP_ON_ERROR:
                    stop_requested = True
                    break

            return scn_records

        try:
            for scn, target_or_adp, cfg, exe_ver, token in executable_scenarios:
                if stop_requested:
                    excluded_details.append({
                        "scenario_id": scn.scenario_id,
                        "reason": "Execution aborted due to failure_policy=stop",
                    })
                    continue

                recs = await run_scenario_reps(scn, target_or_adp, cfg, exe_ver, token)
                all_records.extend(recs)
        except asyncio.CancelledError:
            pass

        all_records.sort(key=lambda r: (r.scenario_id, r.repetition_index))

        summary = aggregate_execution_records(
            records=all_records,
            planned_count=len(plan.scenarios),
            excluded_details=excluded_details,
        )

        self._notify_progress(
            "plan_complete",
            planned=len(plan.scenarios),
            executed=len({r.scenario_id for r in all_records}),
            excluded=len(excluded_details),
            records=len(all_records),
        )

        return MatrixExecutionResult(
            plan=plan,
            records=tuple(all_records),
            summary=summary,
            is_dry_run=False,
            metadata={"concurrency": self.concurrency, "failure_policy": self.failure_policy.value},
        )
