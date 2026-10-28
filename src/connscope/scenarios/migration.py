
from __future__ import annotations

from typing import Any

from connscope.adapters import (
    AdapterRegistry,
    EngineAdapter,
    EngineType,
    ProfileDrivenAdapter,
    ProtocolType,
    SecurityType,
    TransportType,
    AmneziaWGStandardAdapter,
    OpenVPNStandardAdapter,
    SingBoxVlessTcpRealityAdapter,
    SingBoxVmessWebSocketTlsAdapter,
    WireGuardStandardAdapter,
    XrayVlessTcpRealityAdapter,
    XrayVmessWebSocketTlsAdapter,
)
from .models import Scenario

class AdapterMigrationBridge:

    def __init__(self, registry: AdapterRegistry | None = None) -> None:
        if registry is not None:
            self.registry = registry
        else:
            self.registry = AdapterRegistry()
            self.registry.register(XrayVlessTcpRealityAdapter())
            self.registry.register(SingBoxVlessTcpRealityAdapter())
            self.registry.register(XrayVmessWebSocketTlsAdapter())
            self.registry.register(SingBoxVmessWebSocketTlsAdapter())
            self.registry.register(WireGuardStandardAdapter())
            self.registry.register(AmneziaWGStandardAdapter())
            self.registry.register(OpenVPNStandardAdapter())

            profile_configs = (
                ("vless_tcp_tls", ProtocolType.VLESS, TransportType.TCP, SecurityType.TLS),
                ("vless_tcp_none", ProtocolType.VLESS, TransportType.TCP, SecurityType.NONE),
                ("vless_ws_tls", ProtocolType.VLESS, TransportType.WEBSOCKET, SecurityType.TLS),
                ("vless_grpc_tls", ProtocolType.VLESS, TransportType.GRPC, SecurityType.TLS),
                ("trojan_tcp_tls", ProtocolType.TROJAN, TransportType.TCP, SecurityType.TLS),
                ("shadowsocks_tcp", ProtocolType.SHADOWSOCKS, TransportType.TCP, SecurityType.NONE),
            )
            for profile_suffix, proto, trans, sec in profile_configs:
                self.registry.register(
                    ProfileDrivenAdapter(
                        adapter_id=f"xray_{profile_suffix}",
                        engine=EngineType.XRAY,
                        protocol=proto,
                        transport=trans,
                        security=sec,
                    )
                )
                self.registry.register(
                    ProfileDrivenAdapter(
                        adapter_id=f"singbox_{profile_suffix}",
                        engine=EngineType.SING_BOX,
                        protocol=proto,
                        transport=trans,
                        security=sec,
                    )
                )

    def get_adapter_for_scenario(self, scenario: Scenario) -> EngineAdapter | None:
        if not scenario.adapter_id:
            return None
        try:
            return self.registry.get(scenario.adapter_id)
        except KeyError:
            return None

    def convert_scenario_to_adapter_config(self, scenario: Scenario) -> dict[str, Any]:
        cfg = dict(scenario.resolved_config)

        if "endpoint" not in cfg and scenario.target:
            cfg["endpoint"] = f"{scenario.target.host}:{scenario.target.port}"

        if scenario.workload:
            if "test_url" not in cfg and scenario.workload.test_url:
                cfg["test_url"] = scenario.workload.test_url
            if "timeout_s" not in cfg and scenario.workload.timeout_s:
                cfg["timeout_s"] = scenario.workload.timeout_s
            if "verify_cert" not in cfg:
                cfg["verify_cert"] = scenario.workload.verify_cert

        return cfg

    def validate_scenario(self, scenario: Scenario) -> tuple[bool, str | None, dict[str, Any] | None]:
        adapter = self.get_adapter_for_scenario(scenario)
        if adapter is None:
            return False, f"No implemented adapter for scenario adapter_id '{scenario.adapter_id}'", None

        adapter_cfg = self.convert_scenario_to_adapter_config(scenario)

        try:
            normalized = adapter.validate_config(adapter_cfg)
            return True, None, normalized
        except Exception as exc:
            return False, f"Adapter '{scenario.adapter_id}' validation failed: {exc}", None

    def dry_run_scenario(self, scenario: Scenario) -> dict[str, Any]:
        adapter = self.get_adapter_for_scenario(scenario)
        if adapter is None:
            return {
                "scenario_id": scenario.scenario_id,
                "supported": False,
                "reason": f"No concrete adapter mapped (status: {scenario.status.value})",
                "executable_available": False,
                "config_valid": False,
            }

        is_valid, val_err, norm_cfg = self.validate_scenario(scenario)
        exe_ok, exe_path = adapter.check_executable()

        redacted_cfg = scenario.get_redacted_config()
        if norm_cfg:
            for k in norm_cfg:
                if k in ("uuid", "password", "public_key", "private_key", "preshared_key", "client_key", "auth_password", "tls_auth_key", "tls_crypt_key"):
                    redacted_cfg[k] = "[REDACTED]"
                elif k not in redacted_cfg:
                    redacted_cfg[k] = norm_cfg[k]

        return {
            "scenario_id": scenario.scenario_id,
            "adapter_id": adapter.name,
            "supported": True,
            "config_valid": is_valid,
            "validation_error": val_err,
            "executable_available": exe_ok,
            "executable_path": exe_path,
            "target": f"{scenario.target.host}:{scenario.target.port}",
            "redacted_config": redacted_cfg,
        }
