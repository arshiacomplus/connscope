from typing import Any

from connscope.core import ProbeRegistry
from .base import EngineAdapter
from .models import (
    AdapterCapability,
    AdapterStatus,
    EngineType,
    OperatingMode,
    ProtocolType,
    SecurityType,
    TransportType,
)

class AdapterRegistry:

    def __init__(self) -> None:
        self._adapters: dict[str, EngineAdapter] = {}

    def register(self, adapter: EngineAdapter) -> None:
        if not isinstance(adapter, EngineAdapter):
            raise TypeError(f"Expected EngineAdapter, got {type(adapter).__name__}")

        aid = adapter.metadata.adapter_id
        if aid in self._adapters:
            raise ValueError(f"Adapter with ID '{aid}' is already registered")

        self._adapters[aid] = adapter

    def get(self, adapter_id: str) -> EngineAdapter:
        try:
            return self._adapters[adapter_id]
        except KeyError as exc:
            raise KeyError(f"Unknown adapter ID: '{adapter_id}'") from exc

    def list_all(self) -> list[EngineAdapter]:
        return [self._adapters[aid] for aid in sorted(self._adapters)]

    def adapter_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))

    def find(
        self,
        engine: EngineType | str | None = None,
        protocol: ProtocolType | str | None = None,
        transport: TransportType | str | None = None,
        security: SecurityType | str | None = None,
        status: AdapterStatus | str | None = None,
        capability: AdapterCapability | str | None = None,
        operating_mode: OperatingMode | str | None = None,
    ) -> list[EngineAdapter]:
        engine_val = str(engine.value if isinstance(engine, EngineType) else engine) if engine else None
        protocol_val = str(protocol.value if isinstance(protocol, ProtocolType) else protocol) if protocol else None
        transport_val = str(transport.value if isinstance(transport, TransportType) else transport) if transport else None
        security_val = str(security.value if isinstance(security, SecurityType) else security) if security else None
        status_val = str(status.value if isinstance(status, AdapterStatus) else status) if status else None
        cap_val = (
            capability.value if isinstance(capability, AdapterCapability) else (AdapterCapability(capability) if capability else None)
        )
        mode_val = str(operating_mode.value if isinstance(operating_mode, OperatingMode) else operating_mode) if operating_mode else None

        results: list[EngineAdapter] = []
        for aid in sorted(self._adapters):
            meta = self._adapters[aid].metadata
            if engine_val and meta.engine.value != engine_val:
                continue
            if protocol_val and meta.protocol.value != protocol_val:
                continue
            if transport_val and meta.transport.value != transport_val:
                continue
            if security_val and meta.security.value != security_val:
                continue
            if status_val and meta.status.value != status_val:
                continue
            if cap_val and cap_val not in meta.capabilities:
                continue
            if mode_val and meta.operating_mode.value != mode_val:
                continue
            results.append(self._adapters[aid])

        return results

    def get_catalog_metadata(self) -> list[dict[str, Any]]:
        return [adapter.metadata.to_dict() for adapter in self.list_all()]

    def populate_probe_registry(self, probe_registry: ProbeRegistry) -> None:
        for adapter in self.list_all():
            probe_registry.register(adapter)
