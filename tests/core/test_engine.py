from datetime import datetime, timezone

import pytest

from connscope.core import (
    Probe,
    ProbeEngine,
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
            duration_ms=2.5,
            metrics={"latency_ms": 2.5},
        )


@pytest.mark.asyncio
async def test_engine_runs_registered_probe():
    probe = DummyProbe()
    engine = ProbeEngine()
    engine.registry.register(probe)

    result = await engine.run(
        "dummy",
        Target(host="example.com", port=443),
    )

    assert result.probe == "dummy"
    assert result.status is ProbeStatus.SUCCESS
    assert result.target.host == "example.com"
    assert result.metrics["latency_ms"] == 2.5


@pytest.mark.asyncio
async def test_engine_passes_config():
    class ConfigProbe(Probe):
        name = "config_probe"
        async def run(self, target: Target, config=None) -> ProbeResult:
            return ProbeResult(
                probe=self.name,
                target=target,
                status=ProbeStatus.SUCCESS,
                started_at=datetime.now(timezone.utc),
                duration_ms=1.0,
                details={"received_config": config}
            )
            
    engine = ProbeEngine()
    engine.registry.register(ConfigProbe())
    
    config_dict = {"timeout": 10}
    result = await engine.run(
        "config_probe",
        Target(host="example.com"),
        config=config_dict
    )
    
    assert result.details["received_config"] == config_dict
