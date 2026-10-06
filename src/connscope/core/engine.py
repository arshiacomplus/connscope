from typing import Any

from .models import ProbeResult, Target
from .registry import ProbeRegistry


class ProbeEngine:
    def __init__(self, registry: ProbeRegistry | None = None) -> None:
        self.registry = registry or ProbeRegistry()

    async def run(
        self,
        probe: str,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ProbeResult:
        implementation = self.registry.get(probe)
        return await implementation.run(target, config)
