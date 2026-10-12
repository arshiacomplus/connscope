import json
import math
from typing import Any

from connscope.core import ProbeResult, Target


def _format_target(target: Target) -> str:
    if target.port is None:
        return target.host
    if ":" in target.host and not target.host.startswith("["):
        return f"[{target.host}]:{target.port}"
    return f"{target.host}:{target.port}"


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
    if result.started_at.tzinfo is None:
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


def render_result_json(result: ProbeResult, *, indent: int = 2) -> str:
    data = result_to_dict(result)
    return json.dumps(
        data,
        indent=indent,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
    )


def render_result(result: ProbeResult) -> str:
    lines = [
        f"Probe:    {result.probe}",
        f"Target:   {_format_target(result.target)}",
        f"Status:   {result.status.value}",
        f"Duration: {result.duration_ms:.2f} ms",
    ]

    if result.metrics:
        lines.append("")
        lines.append("Metrics:")
        for k in sorted(result.metrics):
            v = result.metrics[k]
            if isinstance(v, (int, float)):
                lines.append(f"  {k}: {v:.2f}")
            else:
                lines.append(f"  {k}: {v}")

    if result.details:
        lines.append("")
        lines.append("Details:")
        for k in sorted(result.details):
            v = result.details[k]
            if isinstance(v, (list, tuple, set)):
                val_str = ", ".join(str(item) for item in v)
            else:
                val_str = str(v)
            lines.append(f"  {k}: {val_str}")

    if result.error:
        lines.append("")
        lines.append(f"Error: {result.error}")

    return "\n".join(lines)


def render_probe_list(probe_names: tuple[str, ...], aliases: dict[str, str] | None = None) -> str:
    lines = ["Available probes:"]
    canonical_to_aliases: dict[str, list[str]] = {}
    if aliases:
        for alias, canonical in aliases.items():
            if alias != canonical:
                canonical_to_aliases.setdefault(canonical, []).append(alias)

    for name in sorted(probe_names):
        alias_list = sorted(canonical_to_aliases.get(name, []))
        if alias_list:
            aliases_str = ", ".join(alias_list)
            lines.append(f"  {name} (alias: {aliases_str})")
        else:
            lines.append(f"  {name}")
    return "\n".join(lines)


def render_error(message: str) -> str:
    return f"Error: {message}"
