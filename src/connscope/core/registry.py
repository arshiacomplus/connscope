from .probe import Probe


class ProbeRegistry:
    def __init__(self) -> None:
        self._probes: dict[str, Probe] = {}

    def register(self, probe: Probe) -> None:
        if probe.name in self._probes:
            raise ValueError(f"probe already registered: {probe.name}")
        self._probes[probe.name] = probe

    def get(self, name: str) -> Probe:
        try:
            return self._probes[name]
        except KeyError as exc:
            raise KeyError(f"unknown probe: {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._probes))
