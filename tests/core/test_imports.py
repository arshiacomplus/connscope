from connscope.core import (
    Probe,
    ProbeEngine,
    ProbeRegistry,
    ProbeResult,
    ProbeStatus,
    Target,
)


def test_core_imports():
    assert Probe is not None
    assert ProbeEngine is not None
    assert ProbeRegistry is not None
    assert ProbeResult is not None
    assert ProbeStatus is not None
    assert Target is not None
