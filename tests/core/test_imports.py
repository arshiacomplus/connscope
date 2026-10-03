from connscope.core.engine import ProbeEngine
from connscope.core.registry import ProbeRegistry
from connscope.core.result import ProbeResult


def test_core_imports():
    assert ProbeEngine is not None
    assert ProbeRegistry is not None
    assert ProbeResult is not None
