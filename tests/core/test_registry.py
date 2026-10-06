from datetime import datetime, timezone

import pytest

from connscope.core import (
    Probe,
    ProbeRegistry,
    ProbeResult,
    ProbeStatus,
    Target,
)


class DummyProbe(Probe):
    name = "dummy"

    async def run(self, target: Target, config=None) -> ProbeResult:
        return ProbeResult(
            probe=self.name,
            target=target,
            status=ProbeStatus.SUCCESS,
            started_at=datetime.now(timezone.utc),
            duration_ms=1.0,
        )


def test_registry_registers_and_resolves_probe():
    registry = ProbeRegistry()
    probe = DummyProbe()

    registry.register(probe)

    assert registry.get("dummy") is probe
    assert registry.names() == ("dummy",)


def test_registry_rejects_duplicates():
    registry = ProbeRegistry()
    registry.register(DummyProbe())

    with pytest.raises(ValueError, match="already registered"):
        registry.register(DummyProbe())


def test_registry_unknown_probe():
    registry = ProbeRegistry()

    with pytest.raises(KeyError, match="unknown probe"):
        registry.get("unknown")
