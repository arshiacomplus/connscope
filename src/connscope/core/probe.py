from abc import ABC, abstractmethod
from typing import Any

from .models import ProbeResult, Target


class Probe(ABC):
    name: str

    @abstractmethod
    async def run(
        self,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ProbeResult:
        raise NotImplementedError
