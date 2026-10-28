import json

from connscope.core import ProbeResult, Target
from connscope.serialization import result_to_dict

def _format_target(target: Target) -> str:
    if target.port is None:
        return target.host
    if ":" in target.host and not target.host.startswith("["):
        return f"[{target.host}]:{target.port}"
    return f"{target.host}:{target.port}"

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
