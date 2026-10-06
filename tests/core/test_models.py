from datetime import datetime, timezone
import pytest
from connscope.core import Target, ProbeResult, ProbeStatus

def test_target_validation():
    # Valid targets
    Target(host="example.com")
    Target(host="example.com", port=443)

    # Empty host
    with pytest.raises(ValueError, match="host must not be empty"):
        Target(host="")

    # Invalid ports
    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        Target(host="example.com", port=0)
    
    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        Target(host="example.com", port=65536)

def test_proberesult_mutable_isolation():
    # Ensure default factories provide isolated dicts
    result1 = ProbeResult(
        probe="dummy",
        target=Target(host="example.com"),
        status=ProbeStatus.SUCCESS,
        started_at=datetime.now(timezone.utc),
        duration_ms=1.0,
    )
    result2 = ProbeResult(
        probe="dummy",
        target=Target(host="example.com"),
        status=ProbeStatus.SUCCESS,
        started_at=datetime.now(timezone.utc),
        duration_ms=1.0,
    )

    result1.metrics["a"] = 1.0
    result1.details["b"] = "value"

    assert "a" not in result2.metrics
    assert "b" not in result2.details
