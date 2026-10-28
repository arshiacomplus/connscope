from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from connscope.core import Probe, ProbeResult, ProbeStatus, Target
from .models import AdapterMetadata, AdapterResultDetails, FailureStage
from .security import redact_sensitive_data

class EngineAdapter(Probe, ABC):

    metadata: AdapterMetadata

    @property
    def name(self) -> str:
        return self.metadata.adapter_id

    @abstractmethod
    def validate_config(self, config: dict[str, Any] | None) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def check_executable(self) -> tuple[bool, str | None]:
        raise NotImplementedError

    def create_result(
        self,
        target: Target,
        status: ProbeStatus,
        started_at: datetime,
        duration_ms: float,
        details: AdapterResultDetails | dict[str, Any] | None = None,
        metrics: dict[str, float] | None = None,
        error: str | None = None,
    ) -> ProbeResult:
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)

        raw_details = details.to_dict() if isinstance(details, AdapterResultDetails) else (details or {})
        clean_details = redact_sensitive_data(raw_details)

        return ProbeResult(
            probe=self.name,
            target=target,
            status=status,
            started_at=started_at,
            duration_ms=max(0.0, float(duration_ms)),
            metrics=dict(metrics or {}),
            details=clean_details,
            error=error,
        )

    def create_failure_result(
        self,
        target: Target,
        started_at: datetime,
        duration_ms: float,
        failure_stage: FailureStage,
        error: str,
        tunnel_established: bool = False,
        data_transfer_completed: bool = False,
        metrics: dict[str, float] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> ProbeResult:
        details = AdapterResultDetails(
            adapter_id=self.metadata.adapter_id,
            engine=self.metadata.engine.value,
            protocol=self.metadata.protocol.value,
            transport=self.metadata.transport.value,
            security=self.metadata.security.value,
            failure_stage=failure_stage,
            tunnel_established=tunnel_established,
            data_transfer_completed=data_transfer_completed,
            extra=extra or {},
        )
        return self.create_result(
            target=target,
            status=ProbeStatus.FAILED,
            started_at=started_at,
            duration_ms=duration_ms,
            details=details,
            metrics=metrics,
            error=error,
        )
