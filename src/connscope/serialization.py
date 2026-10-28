from datetime import datetime
import math
from typing import Any

from connscope.core import ProbeResult, ProbeStatus, Target

def _validate_json_value(val: Any, path: str = "") -> Any:
    if val is None or isinstance(val, (str, bool, int)):
        return val
    if isinstance(val, float):
        if not math.isfinite(val):
            raise ValueError(f"Non-finite float value {val!r} at '{path}' is not allowed in JSON")
        return val
    if isinstance(val, (list, tuple)):
        return [_validate_json_value(item, f"{path}[{i}]") for i, item in enumerate(val)]
    if isinstance(val, dict):
        new_dict: dict[str, Any] = {}
        for k, v in val.items():
            if not isinstance(k, str):
                raise TypeError(f"Dictionary key at '{path}' must be str, got {type(k).__name__}: {k!r}")
            new_dict[k] = _validate_json_value(v, f"{path}.{k}" if path else k)
        return new_dict
    raise TypeError(f"Unsupported value of type '{type(val).__name__}' at '{path}' is not allowed in JSON")

def result_to_dict(result: ProbeResult) -> dict[str, Any]:
    if result.started_at.tzinfo is None or result.started_at.utcoffset() is None:
        raise ValueError("started_at timestamp must be timezone-aware")

    if not math.isfinite(result.duration_ms):
        raise ValueError(f"duration_ms must be a finite number, got {result.duration_ms!r}")

    validated_metrics = _validate_json_value(result.metrics, "metrics")
    validated_details = _validate_json_value(result.details, "details")

    return {
        "probe": result.probe,
        "target": {
            "host": result.target.host,
            "port": result.target.port,
        },
        "status": result.status.value,
        "started_at": result.started_at.isoformat(),
        "duration_ms": result.duration_ms,
        "metrics": validated_metrics,
        "details": validated_details,
        "error": result.error,
    }

_REQUIRED_FIELDS: tuple[str, ...] = (
    "probe",
    "target",
    "status",
    "started_at",
    "duration_ms",
    "metrics",
    "details",
    "error",
)

def result_from_dict(data: dict[str, Any]) -> ProbeResult:
    if not isinstance(data, dict):
        raise TypeError(f"data must be a dict, got {type(data).__name__}")

    for field_name in _REQUIRED_FIELDS:
        if field_name not in data:
            raise ValueError(f"Missing required field: '{field_name}'")

    probe = data["probe"]
    if not isinstance(probe, str):
        raise TypeError(f"probe must be a str, got {type(probe).__name__}")
    if not probe.strip():
        raise ValueError("probe must not be empty")

    target_data = data["target"]
    if not isinstance(target_data, dict):
        raise TypeError(f"target must be a dict, got {type(target_data).__name__}")
    if "host" not in target_data:
        raise ValueError("target missing required field: 'host'")
    host = target_data["host"]
    if not isinstance(host, str):
        raise TypeError(f"target host must be a str, got {type(host).__name__}")
    if not host:
        raise ValueError("host must not be empty")

    port = target_data.get("port")
    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int):
            raise TypeError(f"target port must be an int or None, got {type(port).__name__}")
        if not (1 <= port <= 65535):
            raise ValueError(f"port must be between 1 and 65535, got {port}")

    target = Target(host=host, port=port)

    status_val = data["status"]
    if not isinstance(status_val, str):
        raise TypeError(f"status must be a str, got {type(status_val).__name__}")
    try:
        status = ProbeStatus(status_val)
    except ValueError:
        raise ValueError(
            f"Invalid probe status: {status_val!r}. Must be one of {[s.value for s in ProbeStatus]}"
        )

    started_at_val = data["started_at"]
    if not isinstance(started_at_val, str):
        raise TypeError(f"started_at must be an ISO 8601 str, got {type(started_at_val).__name__}")
    try:
        started_at = datetime.fromisoformat(started_at_val)
    except ValueError as exc:
        raise ValueError(f"Invalid started_at ISO 8601 timestamp '{started_at_val}': {exc}") from exc
    if started_at.tzinfo is None or started_at.utcoffset() is None:
        raise ValueError("started_at timestamp must be timezone-aware")

    duration_val = data["duration_ms"]
    if isinstance(duration_val, bool) or not isinstance(duration_val, (int, float)):
        raise TypeError(f"duration_ms must be a float or int, got {type(duration_val).__name__}")
    duration_ms = float(duration_val)
    if not math.isfinite(duration_ms):
        raise ValueError(f"duration_ms must be a finite number, got {duration_val!r}")
    if duration_ms < 0:
        raise ValueError(f"duration_ms cannot be negative, got {duration_ms}")

    metrics_data = data["metrics"]
    if not isinstance(metrics_data, dict):
        raise TypeError(f"metrics must be a dict, got {type(metrics_data).__name__}")
    metrics: dict[str, float] = {}
    for k, v in metrics_data.items():
        if not isinstance(k, str):
            raise TypeError(f"metrics key must be a str, got {type(k).__name__}: {k!r}")
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise TypeError(f"metrics value for '{k}' must be a number, got {type(v).__name__}")
        float_v = float(v)
        if not math.isfinite(float_v):
            raise ValueError(f"metrics value for '{k}' must be finite, got {v!r}")
        metrics[k] = float_v

    details_data = data["details"]
    if not isinstance(details_data, dict):
        raise TypeError(f"details must be a dict, got {type(details_data).__name__}")
    details = _validate_json_value(details_data, "details")

    error_val = data["error"]
    if error_val is not None and not isinstance(error_val, str):
        raise TypeError(f"error must be a str or None, got {type(error_val).__name__}")

    return ProbeResult(
        probe=probe,
        target=target,
        status=status,
        started_at=started_at,
        duration_ms=duration_ms,
        metrics=metrics,
        details=details,
        error=error_val,
    )
