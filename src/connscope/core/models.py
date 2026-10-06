from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class ProbeStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True)
class Target:
    host: str
    port: int | None = None

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("host must not be empty")
        if self.port is not None and not (1 <= self.port <= 65535):
            raise ValueError("port must be between 1 and 65535")


@dataclass(frozen=True, slots=True)
class ProbeResult:
    probe: str
    target: Target
    status: ProbeStatus
    started_at: datetime
    duration_ms: float
    metrics: dict[str, float] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
