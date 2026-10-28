from datetime import datetime, timedelta, timezone, tzinfo
import math
import sys
import pytest

from connscope.core import ProbeResult, ProbeStatus, Target
from connscope.serialization import result_from_dict, result_to_dict

def _make_valid_dict() -> dict:
    return {
        "probe": "tcp_connect",
        "target": {
            "host": "example.com",
            "port": 443,
        },
        "status": "success",
        "started_at": "2026-10-12T12:00:00+00:00",
        "duration_ms": 25.5,
        "metrics": {"connect_ms": 25.5},
        "details": {"connected": True},
        "error": None,
    }

def test_round_trip_success():
    res = ProbeResult(
        probe="tcp_connect",
        target=Target(host="example.com", port=443),
        status=ProbeStatus.SUCCESS,
        started_at=datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        duration_ms=45.2,
        metrics={"connect_ms": 45.2},
        details={"ip": "93.184.216.34"},
        error=None,
    )
    serialized = result_to_dict(res)
    deserialized = result_from_dict(serialized)
    assert deserialized == res
    assert result_to_dict(deserialized) == serialized

def test_round_trip_failed():
    res = ProbeResult(
        probe="tcp_connect",
        target=Target(host="example.com", port=81),
        status=ProbeStatus.FAILED,
        started_at=datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        duration_ms=105.0,
        metrics={"connect_ms": 105.0},
        details={},
        error="Connection refused",
    )
    serialized = result_to_dict(res)
    deserialized = result_from_dict(serialized)
    assert deserialized == res

def test_round_trip_timeout():
    res = ProbeResult(
        probe="tls_handshake",
        target=Target(host="2001:db8::1", port=443),
        status=ProbeStatus.TIMEOUT,
        started_at=datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        duration_ms=5000.0,
        metrics={},
        details={},
        error="Operation timed out after 5.0s",
    )
    serialized = result_to_dict(res)
    deserialized = result_from_dict(serialized)
    assert deserialized == res

def test_round_trip_target_port_none():
    res = ProbeResult(
        probe="dns_resolve",
        target=Target(host="example.com", port=None),
        status=ProbeStatus.SUCCESS,
        started_at=datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        duration_ms=10.0,
    )
    serialized = result_to_dict(res)
    assert serialized["target"]["port"] is None
    deserialized = result_from_dict(serialized)
    assert deserialized.target.port is None
    assert deserialized == res

def test_round_trip_nested_details():
    res = ProbeResult(
        probe="http_request",
        target=Target(host="example.com", port=443),
        status=ProbeStatus.SUCCESS,
        started_at=datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc),
        duration_ms=120.0,
        metrics={"dns_ms": 5.0, "connect_ms": 15.0},
        details={
            "status_code": 200,
            "headers": {"content-type": "text/html", "content-length": 1024},
            "redirects": [
                {"url": "http://example.com", "status": 301},
                {"url": "https://example.com", "status": 200},
            ],
            "flags": [True, False, None],
        },
    )
    serialized = result_to_dict(res)
    deserialized = result_from_dict(serialized)
    assert deserialized == res

def test_round_trip_non_utc_timezone():
    tz = timezone(timedelta(hours=3, minutes=30))
    res = ProbeResult(
        probe="tcp_connect",
        target=Target(host="example.com", port=443),
        status=ProbeStatus.SUCCESS,
        started_at=datetime(2026, 10, 12, 15, 30, 0, tzinfo=tz),
        duration_ms=20.0,
    )
    serialized = result_to_dict(res)
    deserialized = result_from_dict(serialized)
    assert deserialized.started_at == res.started_at
    assert deserialized.started_at.tzinfo is not None

def test_result_from_dict_rejects_non_dict():
    with pytest.raises(TypeError, match="data must be a dict"):
        result_from_dict("not-a-dict")  # type: ignore

    with pytest.raises(TypeError, match="data must be a dict"):
        result_from_dict([1, 2, 3])  # type: ignore

    with pytest.raises(TypeError, match="data must be a dict"):
        result_from_dict(None)  # type: ignore

@pytest.mark.parametrize(
    "field",
    [
        "probe",
        "target",
        "status",
        "started_at",
        "duration_ms",
        "metrics",
        "details",
        "error",
    ],
)
def test_result_from_dict_missing_required_field(field: str):
    data = _make_valid_dict()
    del data[field]
    with pytest.raises(ValueError, match=f"Missing required field: '{field}'"):
        result_from_dict(data)

def test_result_from_dict_invalid_probe_type():
    data = _make_valid_dict()
    data["probe"] = 123
    with pytest.raises(TypeError, match="probe must be a str"):
        result_from_dict(data)

def test_result_from_dict_empty_probe():
    data = _make_valid_dict()
    data["probe"] = "   "
    with pytest.raises(ValueError, match="probe must not be empty"):
        result_from_dict(data)

def test_result_from_dict_invalid_target_type():
    data = _make_valid_dict()
    data["target"] = "example.com:443"
    with pytest.raises(TypeError, match="target must be a dict"):
        result_from_dict(data)

def test_result_from_dict_missing_target_host():
    data = _make_valid_dict()
    data["target"] = {"port": 443}
    with pytest.raises(ValueError, match="target missing required field: 'host'"):
        result_from_dict(data)

def test_result_from_dict_invalid_target_host_type():
    data = _make_valid_dict()
    data["target"] = {"host": 12345}
    with pytest.raises(TypeError, match="target host must be a str"):
        result_from_dict(data)

def test_result_from_dict_empty_target_host():
    data = _make_valid_dict()
    data["target"] = {"host": ""}
    with pytest.raises(ValueError, match="host must not be empty"):
        result_from_dict(data)

@pytest.mark.parametrize("invalid_port", ["443", True, False, 3.14, []])
def test_result_from_dict_invalid_port_type(invalid_port):
    data = _make_valid_dict()
    data["target"] = {"host": "example.com", "port": invalid_port}
    with pytest.raises(TypeError, match="target port must be an int or None"):
        result_from_dict(data)

@pytest.mark.parametrize("out_of_bounds_port", [0, -1, 65536, 100000])
def test_result_from_dict_out_of_bounds_port(out_of_bounds_port: int):
    data = _make_valid_dict()
    data["target"] = {"host": "example.com", "port": out_of_bounds_port}
    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        result_from_dict(data)

def test_result_from_dict_invalid_status_type():
    data = _make_valid_dict()
    data["status"] = 1
    with pytest.raises(TypeError, match="status must be a str"):
        result_from_dict(data)

def test_result_from_dict_unknown_status_value():
    data = _make_valid_dict()
    data["status"] = "in_progress"
    with pytest.raises(ValueError, match="Invalid probe status: 'in_progress'"):
        result_from_dict(data)

def test_result_from_dict_invalid_started_at_type():
    data = _make_valid_dict()
    data["started_at"] = 1700000000
    with pytest.raises(TypeError, match="started_at must be an ISO 8601 str"):
        result_from_dict(data)

def test_result_from_dict_malformed_started_at():
    data = _make_valid_dict()
    data["started_at"] = "invalid-date-string"
    with pytest.raises(ValueError, match="Invalid started_at ISO 8601 timestamp"):
        result_from_dict(data)

def test_result_from_dict_timezone_naive_started_at():
    data = _make_valid_dict()
    data["started_at"] = "2026-10-12T12:00:00"
    with pytest.raises(ValueError, match="started_at timestamp must be timezone-aware"):
        result_from_dict(data)

@pytest.mark.parametrize("invalid_duration", ["25.5", True, False, None, [10]])
def test_result_from_dict_invalid_duration_type(invalid_duration):
    data = _make_valid_dict()
    data["duration_ms"] = invalid_duration
    with pytest.raises(TypeError, match="duration_ms must be a float or int"):
        result_from_dict(data)

@pytest.mark.parametrize("non_finite_duration", [float("nan"), float("inf"), float("-inf")])
def test_result_from_dict_non_finite_duration(non_finite_duration: float):
    data = _make_valid_dict()
    data["duration_ms"] = non_finite_duration
    with pytest.raises(ValueError, match="duration_ms must be a finite number"):
        result_from_dict(data)

def test_result_from_dict_negative_duration():
    data = _make_valid_dict()
    data["duration_ms"] = -0.5
    with pytest.raises(ValueError, match="duration_ms cannot be negative"):
        result_from_dict(data)

def test_result_from_dict_int_duration():
    data = _make_valid_dict()
    data["duration_ms"] = 50
    res = result_from_dict(data)
    assert res.duration_ms == 50.0
    assert isinstance(res.duration_ms, float)

def test_result_from_dict_invalid_metrics_type():
    data = _make_valid_dict()
    data["metrics"] = [1, 2, 3]
    with pytest.raises(TypeError, match="metrics must be a dict"):
        result_from_dict(data)

def test_result_from_dict_non_str_metrics_key():
    data = _make_valid_dict()
    data["metrics"] = {123: 15.0}  # type: ignore
    with pytest.raises(TypeError, match="metrics key must be a str"):
        result_from_dict(data)

@pytest.mark.parametrize("invalid_metric_val", ["string_val", True, [1], {"sub": 1}])
def test_result_from_dict_invalid_metric_value_type(invalid_metric_val):
    data = _make_valid_dict()
    data["metrics"] = {"latency": invalid_metric_val}
    with pytest.raises(TypeError, match="metrics value for 'latency' must be a number"):
        result_from_dict(data)

@pytest.mark.parametrize("non_finite_metric", [float("nan"), float("inf"), float("-inf")])
def test_result_from_dict_non_finite_metric_value(non_finite_metric: float):
    data = _make_valid_dict()
    data["metrics"] = {"latency": non_finite_metric}
    with pytest.raises(ValueError, match="metrics value for 'latency' must be finite"):
        result_from_dict(data)

def test_result_from_dict_int_metric_converted_to_float():
    data = _make_valid_dict()
    data["metrics"] = {"count": 42}
    res = result_from_dict(data)
    assert res.metrics == {"count": 42.0}
    assert isinstance(res.metrics["count"], float)

def test_result_from_dict_invalid_details_type():
    data = _make_valid_dict()
    data["details"] = "not-a-dict"
    with pytest.raises(TypeError, match="details must be a dict"):
        result_from_dict(data)

def test_result_from_dict_details_non_str_key():
    data = _make_valid_dict()
    data["details"] = {123: "val"}  # type: ignore
    with pytest.raises(TypeError, match="Dictionary key at 'details' must be str"):
        result_from_dict(data)

def test_result_from_dict_details_unsupported_object():
    data = _make_valid_dict()
    data["details"] = {"tags": {1, 2, 3}}
    with pytest.raises(TypeError, match="Unsupported value of type 'set'"):
        result_from_dict(data)

def test_result_from_dict_details_non_finite_float():
    data = _make_valid_dict()
    data["details"] = {"score": float("nan")}
    with pytest.raises(ValueError, match="Non-finite float value"):
        result_from_dict(data)

def test_result_from_dict_invalid_error_type():
    data = _make_valid_dict()
    data["error"] = 404
    with pytest.raises(TypeError, match="error must be a str or None"):
        result_from_dict(data)

def test_result_from_dict_valid_error_string():
    data = _make_valid_dict()
    data["error"] = "Connection reset by peer"
    data["status"] = "failed"
    res = result_from_dict(data)
    assert res.error == "Connection reset by peer"
    assert res.status == ProbeStatus.FAILED

def test_result_from_dict_isolation_from_input_mutations():
    data = _make_valid_dict()
    data["metrics"] = {"connect_ms": 10.0}
    data["details"] = {"notes": ["first"]}

    res = result_from_dict(data)

    data["metrics"]["connect_ms"] = 99.0
    data["details"]["notes"].append("second")

    assert res.metrics["connect_ms"] == 10.0
    assert res.details["notes"] == ["first"]

def test_serialization_does_not_import_cli():
    assert "connscope.serialization" in sys.modules
    import connscope.serialization as s_mod

    for val in s_mod.__dict__.values():
        if hasattr(val, "__module__"):
            assert not str(val.__module__).startswith("connscope.cli"), (
                f"Leaked CLI dependency: {val} from {val.__module__}"
            )

class NullOffsetTz(tzinfo):
    def utcoffset(self, dt):
        return None

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return "NULL"

def test_result_to_dict_rejects_custom_tzinfo_with_none_utcoffset():
    dt = datetime(2026, 10, 12, 12, 0, 0, tzinfo=NullOffsetTz())
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=dt,
        duration_ms=1.0,
    )
    with pytest.raises(ValueError, match="started_at timestamp must be timezone-aware"):
        result_to_dict(res)

def test_result_to_dict_rejects_timezone_naive():
    dt = datetime(2026, 10, 12, 12, 0, 0)
    res = ProbeResult(
        probe="test",
        target=Target(host="localhost"),
        status=ProbeStatus.SUCCESS,
        started_at=dt,
        duration_ms=1.0,
    )
    with pytest.raises(ValueError, match="started_at timestamp must be timezone-aware"):
        result_to_dict(res)
