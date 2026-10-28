
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from connscope.adapters.models import (
    ExecutableRequirement,
    ProtocolType,
    SecurityType,
    TransportType,
)
from .models import (
    CapabilityCategory,
    CapabilityDefinition,
    CoverageTier,
    EngineDefinition,
    EngineProfileCompatibility,
    MeasurementNode,
    MeasurementProfile,
    MeasurementWorkload,
    ParameterDefinition,
    ParameterType,
    ParameterVariant,
    ProtocolProfile,
    SourceReference,
    VerificationStatus,
)

class ProtocolCatalog:

    def __init__(self) -> None:
        self._engines: dict[str, EngineDefinition] = {}
        self._profiles: dict[str, ProtocolProfile] = {}
        self._compatibilities: dict[tuple[str, str], EngineProfileCompatibility] = {}
        self._nodes: dict[str, MeasurementNode] = {}
        self._measurement_profiles: dict[str, MeasurementProfile] = {}
        self._capabilities: dict[str, CapabilityDefinition] = {}

    def register_capability(self, capability: CapabilityDefinition) -> None:
        if capability.capability_id in self._capabilities:
            raise ValueError(f"Capability '{capability.capability_id}' is already registered in catalog")
        self._capabilities[capability.capability_id] = capability

    def get_capability(self, capability_id: str) -> CapabilityDefinition | None:
        return self._capabilities.get(capability_id)

    def list_capabilities(
        self,
        engine_id: str | None = None,
        category: str | None = None,
    ) -> list[CapabilityDefinition]:
        caps = [self._capabilities[k] for k in sorted(self._capabilities)]
        if engine_id is not None:
            caps = [c for c in caps if c.engine_id == engine_id]
        if category is not None:
            caps = [c for c in caps if c.category == category]
        return caps

    def register_engine(self, engine: EngineDefinition) -> None:
        if engine.engine_id in self._engines:
            raise ValueError(f"Engine '{engine.engine_id}' is already registered in catalog")
        self._engines[engine.engine_id] = engine

    def register_profile(self, profile: ProtocolProfile) -> None:
        if profile.profile_id in self._profiles:
            raise ValueError(f"Profile '{profile.profile_id}' is already registered in catalog")
        self._profiles[profile.profile_id] = profile

    def register_compatibility(self, compatibility: EngineProfileCompatibility) -> None:
        key = (compatibility.engine_id, compatibility.profile_id)
        if key in self._compatibilities:
            raise ValueError(f"Compatibility for engine '{compatibility.engine_id}' and profile '{compatibility.profile_id}' already registered")
        self._compatibilities[key] = compatibility

    def register_node(self, node: MeasurementNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError(f"MeasurementNode '{node.node_id}' is already registered")
        self._nodes[node.node_id] = node

    def register_measurement_profile(self, m_profile: MeasurementProfile) -> None:
        if m_profile.profile_id in self._measurement_profiles:
            raise ValueError(f"MeasurementProfile '{m_profile.profile_id}' is already registered")
        self._measurement_profiles[m_profile.profile_id] = m_profile

    def get_engine(self, engine_id: str) -> EngineDefinition | None:
        return self._engines.get(engine_id)

    def get_profile(self, profile_id: str) -> ProtocolProfile | None:
        return self._profiles.get(profile_id)

    def get_compatibility(self, engine_id: str, profile_id: str) -> EngineProfileCompatibility | None:
        return self._compatibilities.get((engine_id, profile_id))

    def get_node(self, node_id: str) -> MeasurementNode | None:
        return self._nodes.get(node_id)

    def get_measurement_profile(self, profile_id: str) -> MeasurementProfile | None:
        return self._measurement_profiles.get(profile_id)

    def list_engines(self) -> list[EngineDefinition]:
        return [self._engines[k] for k in sorted(self._engines)]

    def list_profiles(self) -> list[ProtocolProfile]:
        return [self._profiles[k] for k in sorted(self._profiles)]

    def list_compatibilities(self) -> list[EngineProfileCompatibility]:
        return [self._compatibilities[k] for k in sorted(self._compatibilities)]

    def list_nodes(self) -> list[MeasurementNode]:
        return [self._nodes[k] for k in sorted(self._nodes)]

    def validate_catalog(self) -> list[str]:
        errors: list[str] = []

        for (eng_id, prof_id), comp in self._compatibilities.items():
            if eng_id not in self._engines:
                errors.append(f"Compatibility references unknown engine '{eng_id}'")
            if prof_id not in self._profiles:
                errors.append(f"Compatibility references unknown profile '{prof_id}'")

            prof = self._profiles.get(prof_id)
            if prof:
                for param_name in comp.parameter_constraints:
                    pdef = prof.get_parameter(param_name)
                    if not pdef:
                        errors.append(
                            f"Compatibility ({eng_id}, {prof_id}) specifies constraint on unknown parameter '{param_name}'"
                        )

        for prof in self._profiles.values():
            param_ids = set()
            for p in prof.parameters:
                if p.param_id in param_ids:
                    errors.append(f"Profile '{prof.profile_id}' contains duplicate parameter '{p.param_id}'")
                param_ids.add(p.param_id)

                for c in p.conflicts_with:
                    if c == p.param_id:
                        errors.append(f"Parameter '{p.param_id}' in profile '{prof.profile_id}' conflicts with itself")

                if p.requires:
                    for req_param in p.requires:
                        if req_param not in [x.param_id for x in prof.parameters]:
                            errors.append(
                                f"Parameter '{p.param_id}' requires parameter '{req_param}' which is not in profile '{prof.profile_id}'"
                            )

            for variant in prof.default_variants:
                for o_param in variant.overrides:
                    if o_param not in param_ids:
                        errors.append(
                            f"Variant '{variant.variant_id}' in profile '{prof.profile_id}' overrides unknown parameter '{o_param}'"
                        )

        for cap in self._capabilities.values():
            if cap.engine_id not in self._engines:
                errors.append(f"Capability '{cap.capability_id}' references unknown engine '{cap.engine_id}'")
            for dep in cap.dependencies:
                if dep not in self._capabilities:
                    errors.append(f"Capability '{cap.capability_id}' references unknown dependency '{dep}'")

        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "engines": [e.to_dict() for e in self.list_engines()],
            "profiles": [p.to_dict() for p in self.list_profiles()],
            "compatibilities": [c.to_dict() for c in self.list_compatibilities()],
            "nodes": [n.to_dict() for n in self.list_nodes()],
            "measurement_profiles": [m.to_dict() for m in self._measurement_profiles.values()],
            "capabilities": [c.to_dict() for c in self.list_capabilities()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProtocolCatalog:
        catalog = cls()

        for ed in data.get("engines", []):
            exe_data = ed.get("executable")
            exe = None
            if exe_data:
                exe = ExecutableRequirement(
                    binary_name=exe_data["binary_name"],
                    min_version=exe_data.get("min_version"),
                    lookup_paths=tuple(exe_data.get("lookup_paths", ("/usr/local/bin", "/usr/bin", "/bin"))),
                )
            src_data = ed.get("source_reference")
            src_ref = None
            if src_data:
                src_ref = SourceReference(
                    repository_url=src_data.get("repository_url"),
                    pinned_commit=src_data.get("pinned_commit"),
                    pinned_version=src_data.get("pinned_version"),
                    requires_source_confirmation=bool(src_data.get("requires_source_confirmation", False)),
                    notes=src_data.get("notes", ""),
                    source_file=src_data.get("source_file"),
                    section=src_data.get("section"),
                    line_range=src_data.get("line_range"),
                    reference_type=src_data.get("reference_type"),
                    verification_status=src_data.get("verification_status"),
                    discrepancy=src_data.get("discrepancy"),
                )
            catalog.register_engine(
                EngineDefinition(
                    engine_id=ed["engine_id"],
                    display_name=ed["display_name"],
                    executable=exe,
                    supported_operations=tuple(ed.get("supported_operations", ("client",))),
                    version_constraints=ed.get("version_constraints"),
                    tested_versions=tuple(ed.get("tested_versions", ())),
                    evidence_status=VerificationStatus(ed.get("evidence_status", VerificationStatus.CATALOGUED.value)),
                    source_reference=src_ref,
                    description=ed.get("description", ""),
                )
            )

        for pd in data.get("profiles", []):
            params = []
            for p in pd.get("parameters", []):
                params.append(
                    ParameterDefinition(
                        param_id=p["param_id"],
                        display_name=p["display_name"],
                        param_type=ParameterType(p["param_type"]),
                        description=p.get("description", ""),
                        default=p.get("default"),
                        required=bool(p.get("required", False)),
                        allowed_values=tuple(p["allowed_values"]) if p.get("allowed_values") is not None else None,
                        min_value=p.get("min_value"),
                        max_value=p.get("max_value"),
                        applicable_engines=tuple(p["applicable_engines"]) if p.get("applicable_engines") is not None else None,
                        applicable_profiles=tuple(p["applicable_profiles"]) if p.get("applicable_profiles") is not None else None,
                        is_secret=bool(p.get("is_secret", False)),
                        documentation_ref=p.get("documentation_ref", ""),
                        requires=p.get("requires"),
                        conflicts_with=tuple(p.get("conflicts_with", ())),
                    )
                )

            variants = []
            for v in pd.get("default_variants", []):
                variants.append(
                    ParameterVariant(
                        variant_id=v["variant_id"],
                        display_name=v["display_name"],
                        description=v.get("description", ""),
                        overrides=dict(v.get("overrides", {})),
                    )
                )

            catalog.register_profile(
                ProtocolProfile(
                    profile_id=pd["profile_id"],
                    display_name=pd["display_name"],
                    protocol=pd["protocol"],
                    transport=pd["transport"],
                    security=pd["security"],
                    parameters=tuple(params),
                    default_variants=tuple(variants),
                    description=pd.get("description", ""),
                )
            )

        for cd in data.get("compatibilities", []):
            catalog.register_compatibility(
                EngineProfileCompatibility(
                    engine_id=cd["engine_id"],
                    profile_id=cd["profile_id"],
                    status=VerificationStatus(cd["status"]),
                    min_version=cd.get("min_version"),
                    max_version=cd.get("max_version"),
                    required_features=tuple(cd.get("required_features", ())),
                    conflicting_features=tuple(cd.get("conflicting_features", ())),
                    parameter_constraints=dict(cd.get("parameter_constraints", {})),
                    adapter_id=cd.get("adapter_id"),
                    known_limitations=tuple(cd.get("known_limitations", ())),
                )
            )

        def _load_node(nd: dict[str, Any]) -> MeasurementNode:
            return MeasurementNode(
                node_id=nd["node_id"],
                name=nd["name"],
                node_type=nd.get("node_type", "local"),
                endpoint_url=nd.get("endpoint_url"),
                auth_token_ref=nd.get("auth_token_ref"),
                supported_adapter_ids=tuple(nd.get("supported_adapter_ids", ())),
                allowed_execution_modes=tuple(nd.get("allowed_execution_modes", ("local_proxy",))),
                reported_software_versions=dict(nd.get("reported_software_versions", {})),
                route_context=dict(nd.get("route_context", {})),
                operator_labels=dict(nd.get("operator_labels", {})),
                evidence_status=VerificationStatus(nd.get("evidence_status", "catalogued")),
                connection_timeout_s=float(nd.get("connection_timeout_s", 10.0)),
                execution_timeout_s=float(nd.get("execution_timeout_s", 30.0)),
                description=nd.get("description", ""),
            )

        for nd in data.get("nodes", []):
            catalog.register_node(_load_node(nd))

        for md in data.get("measurement_profiles", []):
            node = _load_node(md["node"])
            wl_data = md.get("workload", {})
            workload = MeasurementWorkload(
                workload_type=wl_data.get("workload_type", "http_get_204"),
                test_url=wl_data.get("test_url", "http://cp.cloudflare.com/generate_204"),
                timeout_s=float(wl_data.get("timeout_s", 10.0)),
                repetitions=int(wl_data.get("repetitions", 1)),
                verify_cert=bool(wl_data.get("verify_cert", True)),
                extra_headers=dict(wl_data.get("extra_headers", {})),
            )
            catalog.register_measurement_profile(
                MeasurementProfile(
                    profile_id=md["profile_id"],
                    name=md["name"],
                    node=node,
                    workload=workload,
                    description=md.get("description", ""),
                )
            )

        for cap_data in data.get("capabilities", []):
            catalog.register_capability(CapabilityDefinition.from_dict(cap_data))

        return catalog

    @classmethod
    def from_json_file(cls, path: str | Path) -> ProtocolCatalog:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

def create_default_protocol_catalog() -> ProtocolCatalog:
    catalog = ProtocolCatalog()

    catalog.register_engine(
        EngineDefinition(
            engine_id="xray",
            display_name="Xray-core",
            executable=ExecutableRequirement(
                binary_name="xray",
                min_version="1.8.0",
                lookup_paths=("/usr/local/bin", "/usr/bin", "/bin"),
            ),
            supported_operations=("client", "config_test", "dry_run"),
            version_constraints=">=1.8.0",
            tested_versions=("26.3.27",),
            evidence_status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            source_reference=SourceReference(
                repository_url="https://github.com/XTLS/Xray-core",
                pinned_version="26.3.27",
            ),
            description="Multi-protocol user-space proxy core (XTLS Project)",
        )
    )

    catalog.register_engine(
        EngineDefinition(
            engine_id="sing_box",
            display_name="sing-box",
            executable=ExecutableRequirement(
                binary_name="sing-box",
                min_version="1.10.0",
                lookup_paths=("/usr/local/bin", "/usr/bin", "/bin"),
            ),
            supported_operations=("client", "config_test", "dry_run"),
            version_constraints=">=1.10.0",
            tested_versions=("1.12.12",),
            evidence_status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            source_reference=SourceReference(
                repository_url="https://github.com/SagerNet/sing-box",
                pinned_version="1.12.12",
            ),
            description="Universal proxy platform and network toolbox with strict schema validation",
        )
    )

    catalog.register_engine(
        EngineDefinition(
            engine_id="wireguard",
            display_name="WireGuard Tools",
            executable=ExecutableRequirement(
                binary_name="wg",
                lookup_paths=("/usr/local/bin", "/usr/bin", "/bin"),
            ),
            supported_operations=("client", "tunnel_config"),
            version_constraints=">=1.0.0",
            evidence_status=VerificationStatus.CATALOGUED,
            source_reference=SourceReference(
                repository_url="https://git.zx2c4.com/wireguard-tools",
            ),
            description="Fast, modern, and secure kernel/userspace VPN tunnel",
        )
    )

    catalog.register_engine(
        EngineDefinition(
            engine_id="amnezia_wg",
            display_name="AmneziaWG",
            executable=ExecutableRequirement(
                binary_name="awg",
                lookup_paths=("/usr/local/bin", "/usr/bin", "/bin"),
            ),
            supported_operations=("client", "tunnel_config"),
            version_constraints=">=1.0.0",
            evidence_status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            source_reference=SourceReference(
                repository_url="https://github.com/amnezia-vpn/amneziawg-linux-kernel-module",
            ),
            description="Obfuscated WireGuard fork with custom packet headers and junk data injection",
        )
    )

    catalog.register_engine(
        EngineDefinition(
            engine_id="openvpn",
            display_name="OpenVPN",
            executable=ExecutableRequirement(
                binary_name="openvpn",
                min_version="2.5.0",
                lookup_paths=(
                    "/usr/local/bin",
                    "/usr/bin",
                    "/bin",
                    "/usr/sbin",
                    "/sbin",
                ),
            ),
            supported_operations=("client", "config_test"),
            version_constraints=">=2.5.0",
            evidence_status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            source_reference=SourceReference(
                repository_url="https://github.com/OpenVPN/openvpn",
            ),
            description="Full-featured open-source SSL/TLS VPN solution",
        )
    )

    catalog.register_engine(
        EngineDefinition(
            engine_id="aether",
            display_name="Aether",
            supported_operations=("client",),
            evidence_status=VerificationStatus.CATALOGUED,
            source_reference=SourceReference(
                requires_source_confirmation=True,
                notes=(
                    "Source confirmation required: multiple ambiguous implementations exist in anti-censorship ecosystems; "
                    "exact upstream repository URL and commit must be confirmed before schema stabilization."
                ),
            ),
            description="Experimental censorship circumvention runtime requiring upstream source confirmation",
        )
    )

    catalog.register_engine(
        EngineDefinition(
            engine_id="exclave",
            display_name="Exclave",
            supported_operations=("client", "vpn_service", "proxy_only"),
            evidence_status=VerificationStatus.CATALOGUED,
            source_reference=SourceReference(
                repository_url="https://github.com/ExclaveNetwork/Exclave",
                pinned_version="0.17.66",
                pinned_commit="71ae3bca4217f78d704713dbb6328aad067404a1",
                source_file="README.md",
                section="Configuration",
                reference_type="upstream_source",
                notes="Verified against upstream repository tag 0.17.66 and immutable commit 71ae3bca4217f78d704713dbb6328aad067404a1; wiki documentation commit 6dba811e7a5b0bc45a6ee52978d975cb5d15b298",
                verification_status=VerificationStatus.CATALOGUED,
            ),
            description="Multi-protocol Android client and TUN proxy runtime supporting Shadowsocks, Trojan, Hysteria 2, AnyTLS, mieru, NaïveProxy, TUIC, Juicity, VLESS, VMess, WireGuard, MASQUE, TrustTunnel, Snell, and ShadowQUIC",
        )
    )

    vless_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            description="RFC 4122 client authentication UUID",
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="public_key",
            display_name="REALITY Public Key",
            param_type=ParameterType.STRING,
            description="Server Curve25519 public key (Base64 raw URL-safe)",
            required=True,
            is_secret=True,
            documentation_ref="https://xtls.github.io/en/config/transports/reality.html",
        ),
        ParameterDefinition(
            param_id="short_id",
            display_name="REALITY Short ID",
            param_type=ParameterType.HEX,
            description="Hex shortId (even length, 0 to 16 characters)",
            default="",
            max_value=16,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            description="TLS SNI target hostname",
            required=True,
        ),
        ParameterDefinition(
            param_id="fingerprint",
            display_name="uTLS Fingerprint",
            param_type=ParameterType.ENUM,
            description="ClientHello TLS fingerprint",
            default="chrome",
            allowed_values=("chrome", "safari", "firefox", "ios", "android", "edge"),
        ),
        ParameterDefinition(
            param_id="spider_x",
            display_name="REALITY SpiderX Path",
            param_type=ParameterType.STRING,
            description="Crawler crawl path for REALITY camouflage",
            default="/",
        ),
        ParameterDefinition(
            param_id="flow",
            display_name="VLESS Flow",
            param_type=ParameterType.ENUM,
            description="VLESS flow control",
            default="",
            allowed_values=("", "xtls-rprx-vision"),
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            description="Application-Layer Protocol Negotiation list",
            default=None,
        ),
        ParameterDefinition(
            param_id="min_version",
            display_name="Minimum TLS Version",
            param_type=ParameterType.ENUM,
            description="Minimum allowed TLS version",
            default=None,
            allowed_values=(None, "1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="max_version",
            display_name="Maximum TLS Version",
            param_type=ParameterType.ENUM,
            description="Maximum allowed TLS version",
            default=None,
            allowed_values=(None, "1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="verify_cert",
            display_name="Verify Server Certificate",
            param_type=ParameterType.BOOL,
            description="Enforces TLS peer certificate validation",
            default=True,
        ),
        ParameterDefinition(
            param_id="tcp_fast_open",
            display_name="TCP Fast Open",
            param_type=ParameterType.BOOL,
            description="Enables TCP Fast Open connection initiation",
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_enabled",
            display_name="Multiplexing Enabled",
            param_type=ParameterType.BOOL,
            description="Enables stream multiplexing",
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_concurrency",
            display_name="Multiplex Concurrency",
            param_type=ParameterType.INT,
            description="Maximum concurrent multiplexed streams",
            default=8,
            min_value=1,
            max_value=1024,
        ),
    )
    vless_variants = (
        ParameterVariant(
            variant_id="baseline",
            display_name="VLESS REALITY Baseline",
            description="Default configuration with chrome fingerprint",
            overrides={},
        ),
        ParameterVariant(
            variant_id="vision_flow",
            display_name="XTLS Vision Flow",
            description="Enables xtls-rprx-vision flow",
            overrides={"flow": "xtls-rprx-vision"},
        ),
        ParameterVariant(
            variant_id="firefox_fp",
            display_name="Firefox Fingerprint",
            description="Sets TLS ClientHello fingerprint to firefox",
            overrides={"fingerprint": "firefox"},
        ),
        ParameterVariant(
            variant_id="safari_fp",
            display_name="Safari Fingerprint",
            description="Sets TLS ClientHello fingerprint to safari",
            overrides={"fingerprint": "safari"},
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="vless_tcp_reality",
            display_name="VLESS over TCP with REALITY",
            protocol=ProtocolType.VLESS,
            transport=TransportType.TCP,
            security=SecurityType.REALITY,
            parameters=vless_params,
            default_variants=vless_variants,
            description="VLESS proxy protocol over TCP with REALITY ClientHello camouflage",
        )
    )

    vmess_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            description="RFC 4122 client authentication UUID",
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            description="TLS SNI target hostname",
            required=True,
        ),
        ParameterDefinition(
            param_id="path",
            display_name="WebSocket Path",
            param_type=ParameterType.STRING,
            description="WebSocket upgrade HTTP request path",
            default="/",
        ),
        ParameterDefinition(
            param_id="host_header",
            display_name="HTTP Host Header",
            param_type=ParameterType.STRING,
            description="Optional Host header for WebSocket upgrade request",
            default=None,
        ),
        ParameterDefinition(
            param_id="alter_id",
            display_name="VMess alterId",
            param_type=ParameterType.INT,
            description="VMess alterId (modern standard is 0)",
            default=0,
            min_value=0,
            max_value=65535,
        ),
        ParameterDefinition(
            param_id="security",
            display_name="VMess Encryption",
            param_type=ParameterType.ENUM,
            description="VMess payload encryption cipher",
            default="auto",
            allowed_values=("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"),
        ),
        ParameterDefinition(
            param_id="fingerprint",
            display_name="uTLS Fingerprint",
            param_type=ParameterType.ENUM,
            description="ClientHello TLS fingerprint",
            default="chrome",
            allowed_values=("chrome", "safari", "firefox", "ios", "android", "edge"),
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            description="Application-Layer Protocol Negotiation list",
            default=None,
        ),
        ParameterDefinition(
            param_id="min_version",
            display_name="Minimum TLS Version",
            param_type=ParameterType.ENUM,
            description="Minimum allowed TLS version",
            default=None,
            allowed_values=(None, "1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="max_version",
            display_name="Maximum TLS Version",
            param_type=ParameterType.ENUM,
            description="Maximum allowed TLS version",
            default=None,
            allowed_values=(None, "1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="verify_cert",
            display_name="Verify Server Certificate",
            param_type=ParameterType.BOOL,
            description="Enforces TLS peer certificate validation",
            default=True,
        ),
        ParameterDefinition(
            param_id="packet_encoding",
            display_name="Packet Encoding",
            param_type=ParameterType.ENUM,
            description="UDP packet encoding over VMess",
            default="",
            allowed_values=("", "packetaddr", "xudp", "none"),
        ),
        ParameterDefinition(
            param_id="max_early_data",
            display_name="Max Early Data",
            param_type=ParameterType.INT,
            description="Maximum 0-RTT early data length in bytes",
            default=None,
            min_value=0,
        ),
        ParameterDefinition(
            param_id="early_data_header_name",
            display_name="Early Data Header Name",
            param_type=ParameterType.STRING,
            description="HTTP header name used for early data transmission",
            default=None,
        ),
        ParameterDefinition(
            param_id="mux_enabled",
            display_name="Multiplexing Enabled",
            param_type=ParameterType.BOOL,
            description="Enables stream multiplexing",
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_concurrency",
            display_name="Multiplex Concurrency",
            param_type=ParameterType.INT,
            description="Maximum concurrent multiplexed streams",
            default=8,
            min_value=1,
            max_value=1024,
        ),
    )
    vmess_variants = (
        ParameterVariant(
            variant_id="baseline",
            display_name="VMess WS TLS Baseline",
            description="Standard VMess configuration with auto cipher",
            overrides={},
        ),
        ParameterVariant(
            variant_id="aes_cipher",
            display_name="AES-128-GCM Cipher",
            description="Forces aes-128-gcm encryption",
            overrides={"security": "aes-128-gcm"},
        ),
        ParameterVariant(
            variant_id="chacha_cipher",
            display_name="ChaCha20-Poly1305 Cipher",
            description="Forces chacha20-poly1305 encryption",
            overrides={"security": "chacha20-poly1305"},
        ),
        ParameterVariant(
            variant_id="custom_path",
            display_name="Custom WebSocket Path",
            description="Uses /custom-ws endpoint path",
            overrides={"path": "/custom-ws"},
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="vmess_ws_tls",
            display_name="VMess over WebSocket + TLS",
            protocol=ProtocolType.VMESS,
            transport=TransportType.WEBSOCKET,
            security=SecurityType.TLS,
            parameters=vmess_params,
            default_variants=vmess_variants,
            description="VMess proxy protocol over WebSocket upgrade stream encapsulated in TLS",
        )
    )

    wg_params = (
        ParameterDefinition(
            param_id="private_key",
            display_name="Interface Private Key",
            param_type=ParameterType.STRING,
            description="Base64 32-byte Curve25519 client private key",
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="public_key",
            display_name="Peer Public Key",
            param_type=ParameterType.STRING,
            description="Base64 32-byte Curve25519 peer public key",
            required=True,
        ),
        ParameterDefinition(
            param_id="preshared_key",
            display_name="Pre-Shared Key",
            param_type=ParameterType.STRING,
            description="Optional Base64 32-byte pre-shared symmetric key",
            default=None,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="endpoint",
            display_name="Peer Endpoint",
            param_type=ParameterType.STRING,
            description="Peer host:port socket address",
            default=None,
        ),
        ParameterDefinition(
            param_id="allowed_ips",
            display_name="Allowed IPs",
            param_type=ParameterType.STRING,
            description="Comma-separated CIDR ranges routed into tunnel",
            default="0.0.0.0/0, ::/0",
        ),
        ParameterDefinition(
            param_id="mtu",
            display_name="Interface MTU",
            param_type=ParameterType.INT,
            description="WireGuard interface maximum transmission unit",
            default=1420,
            min_value=1280,
            max_value=1500,
        ),
        ParameterDefinition(
            param_id="persistent_keepalive",
            display_name="Persistent Keepalive",
            param_type=ParameterType.INT,
            description="Seconds between keepalive packets (0 disables)",
            default=25,
            min_value=0,
            max_value=3600,
        ),
        ParameterDefinition(
            param_id="address",
            display_name="Interface Address",
            param_type=ParameterType.STRING,
            description="Interface client IP/CIDR address",
            default="10.0.0.2/32",
        ),
        ParameterDefinition(
            param_id="listen_port",
            display_name="Listen Port",
            param_type=ParameterType.INT,
            description="Optional local UDP listen port",
            default=None,
            min_value=1,
            max_value=65535,
        ),
    )
    wg_variants = (
        ParameterVariant(
            variant_id="baseline",
            display_name="WireGuard Baseline",
            description="Standard MTU 1420 with 25s keepalive",
            overrides={},
        ),
        ParameterVariant(
            variant_id="low_mtu",
            display_name="Conservative MTU (1280)",
            description="Sets MTU to IPv6 minimum 1280 bytes to avoid fragmentation",
            overrides={"mtu": 1280},
        ),
        ParameterVariant(
            variant_id="keepalive_disabled",
            display_name="Keepalive Disabled",
            description="Disables periodic keepalive packets (0s)",
            overrides={"persistent_keepalive": 0},
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="wireguard_standard",
            display_name="Standard WireGuard",
            protocol=ProtocolType.WIREGUARD,
            transport=TransportType.UDP,
            security=SecurityType.NONE,
            parameters=wg_params,
            default_variants=wg_variants,
            description="Native standard WireGuard L3 tunnel over UDP",
        )
    )

    awg_params = wg_params + (
        ParameterDefinition(
            param_id="jc",
            display_name="Junk Packet Count (Jc)",
            param_type=ParameterType.INT,
            description="Number of junk packets sent before initiation",
            default=4,
            min_value=1,
            max_value=128,
            documentation_ref="https://github.com/amnezia-vpn/amnezia-wg",
        ),
        ParameterDefinition(
            param_id="jmin",
            display_name="Junk Packet Min Size (Jmin)",
            param_type=ParameterType.INT,
            description="Minimum size in bytes of junk packets",
            default=40,
            min_value=0,
            max_value=1280,
        ),
        ParameterDefinition(
            param_id="jmax",
            display_name="Junk Packet Max Size (Jmax)",
            param_type=ParameterType.INT,
            description="Maximum size in bytes of junk packets",
            default=70,
            min_value=0,
            max_value=1280,
        ),
        ParameterDefinition(
            param_id="s1",
            display_name="Init Packet Junk Size (S1)",
            param_type=ParameterType.INT,
            description="Junk bytes appended to initiation packet",
            default=64,
            min_value=0,
            max_value=1280,
        ),
        ParameterDefinition(
            param_id="s2",
            display_name="Response Packet Junk Size (S2)",
            param_type=ParameterType.INT,
            description="Junk bytes appended to response packet",
            default=64,
            min_value=0,
            max_value=1280,
        ),
        ParameterDefinition(
            param_id="h1",
            display_name="Init Header Type (H1)",
            param_type=ParameterType.INT,
            description="Custom 4-byte header for initiation packet",
            default=1,
            min_value=1,
            max_value=4294967295,
        ),
        ParameterDefinition(
            param_id="h2",
            display_name="Response Header Type (H2)",
            param_type=ParameterType.INT,
            description="Custom 4-byte header for response packet",
            default=2,
            min_value=1,
            max_value=4294967295,
        ),
        ParameterDefinition(
            param_id="h3",
            display_name="Cookie Header Type (H3)",
            param_type=ParameterType.INT,
            description="Custom 4-byte header for cookie packet",
            default=3,
            min_value=1,
            max_value=4294967295,
        ),
        ParameterDefinition(
            param_id="h4",
            display_name="Data Header Type (H4)",
            param_type=ParameterType.INT,
            description="Custom 4-byte header for transport data packet",
            default=4,
            min_value=1,
            max_value=4294967295,
        ),
    )
    awg_variants = (
        ParameterVariant(
            variant_id="baseline",
            display_name="AmneziaWG Baseline",
            description="Default AmneziaWG obfuscation profile (Jc=4, Jmin=40, Jmax=70, S1=64, S2=64)",
            overrides={},
        ),
        ParameterVariant(
            variant_id="mild_junk",
            display_name="Mild Junk Packets",
            description="Lightweight junk packet overhead (Jc=3, Jmin=10, Jmax=50, S1=32, S2=32)",
            overrides={"jc": 3, "jmin": 10, "jmax": 50, "s1": 32, "s2": 32},
        ),
        ParameterVariant(
            variant_id="heavy_junk",
            display_name="Heavy Junk Packets",
            description="High-entropy obfuscation for aggressive DPI environments (Jc=10, Jmin=100, Jmax=500)",
            overrides={"jc": 10, "jmin": 100, "jmax": 500, "s1": 128, "s2": 128},
        ),
        ParameterVariant(
            variant_id="custom_headers",
            display_name="Custom Magic Headers",
            description="Non-standard packet type identifiers (H1..H4 in 100000000x range)",
            overrides={
                "h1": 1000000001,
                "h2": 1000000002,
                "h3": 1000000003,
                "h4": 1000000004,
            },
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="amnezia_wg_obfs",
            display_name="AmneziaWG Obfuscated WireGuard",
            protocol=ProtocolType.WIREGUARD,
            transport=TransportType.UDP,
            security=SecurityType.NOISE,
            parameters=awg_params,
            default_variants=awg_variants,
            description="Obfuscated WireGuard with custom packet headers, variable junk prefixes, and sizes",
        )
    )

    openvpn_params = (
        ParameterDefinition(
            param_id="proto",
            display_name="Client Protocol",
            param_type=ParameterType.ENUM,
            default="udp",
            allowed_values=("udp", "tcp"),
            description="OpenVPN transport protocol (UDP or TCP client)",
        ),
        ParameterDefinition(
            param_id="tun_mtu",
            display_name="TUN Interface MTU",
            param_type=ParameterType.INT,
            default=1500,
            min_value=1280,
            max_value=1500,
            description="Layer-3 maximum transmission unit for TUN device",
        ),
        ParameterDefinition(
            param_id="ca_cert",
            display_name="CA Certificate",
            param_type=ParameterType.STRING,
            default=None,
            description="Trusted CA certificate in PEM format or file path",
        ),
        ParameterDefinition(
            param_id="client_cert",
            display_name="Client Certificate",
            param_type=ParameterType.STRING,
            default=None,
            description="Optional client certificate for mutual TLS",
        ),
        ParameterDefinition(
            param_id="client_key",
            display_name="Client Private Key",
            param_type=ParameterType.STRING,
            default=None,
            is_secret=True,
            description="Optional client private key for mutual TLS",
        ),
        ParameterDefinition(
            param_id="tls_auth_key",
            display_name="TLS-Auth Key",
            param_type=ParameterType.STRING,
            default=None,
            is_secret=True,
            description="Optional pre-shared static HMAC key for tls-auth",
        ),
        ParameterDefinition(
            param_id="tls_crypt_key",
            display_name="TLS-Crypt Key",
            param_type=ParameterType.STRING,
            default=None,
            is_secret=True,
            description="Optional pre-shared static key for tls-crypt",
        ),
        ParameterDefinition(
            param_id="auth_user",
            display_name="Auth Username",
            param_type=ParameterType.STRING,
            default=None,
        ),
        ParameterDefinition(
            param_id="auth_password",
            display_name="Auth Password",
            param_type=ParameterType.STRING,
            default=None,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="cipher",
            display_name="Data Channel Cipher",
            param_type=ParameterType.ENUM,
            default="AES-256-GCM",
            allowed_values=("AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"),
        ),
        ParameterDefinition(
            param_id="remote_cert_tls",
            display_name="Verify Remote Server Certificate",
            param_type=ParameterType.BOOL,
            default=True,
            description="Enforces that remote server certificate has server designation",
        ),
        ParameterDefinition(
            param_id="route_nopull",
            display_name="Disable Server Route Takeover",
            param_type=ParameterType.BOOL,
            default=True,
            description="Enforces route-nopull so server routes do not modify host routing",
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="openvpn_udp",
            display_name="OpenVPN over UDP",
            protocol=ProtocolType.OPENVPN,
            transport=TransportType.UDP,
            security=SecurityType.TLS,
            parameters=openvpn_params,
            default_variants=(
                ParameterVariant(
                    variant_id="baseline",
                    display_name="OpenVPN UDP Baseline",
                    overrides={"proto": "udp", "tun_mtu": 1500},
                ),
                ParameterVariant(
                    variant_id="udp_baseline",
                    display_name="OpenVPN UDP Baseline Alias",
                    overrides={"proto": "udp", "tun_mtu": 1500},
                ),
                ParameterVariant(
                    variant_id="tcp_baseline",
                    display_name="OpenVPN TCP Baseline",
                    overrides={"proto": "tcp", "tun_mtu": 1500},
                ),
                ParameterVariant(
                    variant_id="low_mtu",
                    display_name="OpenVPN Low MTU (1280)",
                    overrides={"proto": "udp", "tun_mtu": 1280},
                ),
            ),
            description="Standard OpenVPN client over UDP with TLS authentication",
        )
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="openvpn_tcp",
            display_name="OpenVPN over TCP",
            protocol=ProtocolType.OPENVPN,
            transport=TransportType.TCP,
            security=SecurityType.TLS,
            parameters=openvpn_params,
            default_variants=(
                ParameterVariant(
                    variant_id="baseline",
                    display_name="OpenVPN TCP Baseline",
                    overrides={"proto": "tcp", "tun_mtu": 1500},
                ),
                ParameterVariant(
                    variant_id="tcp_baseline",
                    display_name="OpenVPN TCP Baseline Alias",
                    overrides={"proto": "tcp", "tun_mtu": 1500},
                ),
                ParameterVariant(
                    variant_id="low_mtu",
                    display_name="OpenVPN TCP Low MTU (1280)",
                    overrides={"proto": "tcp", "tun_mtu": 1280},
                ),
            ),
            description="Standard OpenVPN client over TCP with TLS authentication",
        )
    )

    vless_tcp_tls_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="fingerprint",
            display_name="Client Fingerprint",
            param_type=ParameterType.STRING,
            default="chrome",
        ),
        ParameterDefinition(
            param_id="flow",
            display_name="VLESS Flow",
            param_type=ParameterType.ENUM,
            default="",
            allowed_values=("", "xtls-rprx-vision"),
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default=None,
        ),
        ParameterDefinition(
            param_id="min_version",
            display_name="Minimum TLS Version",
            param_type=ParameterType.ENUM,
            default=None,
            allowed_values=("1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="max_version",
            display_name="Maximum TLS Version",
            param_type=ParameterType.ENUM,
            default=None,
            allowed_values=("1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="verify_cert",
            display_name="Verify Server Certificate",
            param_type=ParameterType.BOOL,
            description="Enforces TLS peer certificate validation",
            default=True,
        ),
        ParameterDefinition(
            param_id="tcp_fast_open",
            display_name="TCP Fast Open",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_enabled",
            display_name="Multiplexing Enabled",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_concurrency",
            display_name="Multiplex Concurrency",
            param_type=ParameterType.INT,
            default=8,
            min_value=1,
            max_value=1024,
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="vless_tcp_tls",
            display_name="VLESS over TCP with TLS",
            protocol=ProtocolType.VLESS,
            transport=TransportType.TCP,
            security=SecurityType.TLS,
            parameters=vless_tcp_tls_params,
            default_variants=(
                ParameterVariant(
                    variant_id="baseline",
                    display_name="VLESS TCP TLS Baseline",
                    overrides={},
                ),
                ParameterVariant(
                    variant_id="vision_flow",
                    display_name="XTLS Vision Flow",
                    overrides={"flow": "xtls-rprx-vision"},
                ),
                ParameterVariant(
                    variant_id="firefox_fp",
                    display_name="Firefox Fingerprint",
                    overrides={"fingerprint": "firefox"},
                ),
            ),
            description="VLESS proxy protocol over direct TCP with standard TLS",
        )
    )

    vless_tcp_none_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="tcp_fast_open",
            display_name="TCP Fast Open",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_enabled",
            display_name="Multiplexing Enabled",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_concurrency",
            display_name="Multiplex Concurrency",
            param_type=ParameterType.INT,
            default=8,
            min_value=1,
            max_value=1024,
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="vless_tcp_none",
            display_name="VLESS over TCP without TLS",
            protocol=ProtocolType.VLESS,
            transport=TransportType.TCP,
            security=SecurityType.NONE,
            parameters=vless_tcp_none_params,
            default_variants=(
                ParameterVariant(
                    variant_id="baseline",
                    display_name="VLESS TCP None Baseline",
                    overrides={},
                ),
            ),
            description="VLESS proxy protocol over plain TCP without transport encryption (diagnostic-scoped)",
        )
    )

    vless_ws_tls_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="path",
            display_name="WebSocket Path",
            param_type=ParameterType.STRING,
            default="/",
        ),
        ParameterDefinition(
            param_id="host_header",
            display_name="HTTP Host Header",
            param_type=ParameterType.STRING,
            default=None,
        ),
        ParameterDefinition(
            param_id="fingerprint",
            display_name="Client Fingerprint",
            param_type=ParameterType.STRING,
            default="chrome",
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default=None,
        ),
        ParameterDefinition(
            param_id="min_version",
            display_name="Minimum TLS Version",
            param_type=ParameterType.ENUM,
            default=None,
            allowed_values=(None, "1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="max_version",
            display_name="Maximum TLS Version",
            param_type=ParameterType.ENUM,
            default=None,
            allowed_values=(None, "1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="verify_cert",
            display_name="Verify Server Certificate",
            param_type=ParameterType.BOOL,
            description="Enforces TLS peer certificate validation",
            default=True,
        ),
        ParameterDefinition(
            param_id="max_early_data",
            display_name="Max Early Data",
            param_type=ParameterType.INT,
            default=None,
            min_value=0,
        ),
        ParameterDefinition(
            param_id="early_data_header_name",
            display_name="Early Data Header Name",
            param_type=ParameterType.STRING,
            default=None,
        ),
        ParameterDefinition(
            param_id="mux_enabled",
            display_name="Multiplexing Enabled",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_concurrency",
            display_name="Multiplex Concurrency",
            param_type=ParameterType.INT,
            default=8,
            min_value=1,
            max_value=1024,
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="vless_ws_tls",
            display_name="VLESS over WebSocket + TLS",
            protocol=ProtocolType.VLESS,
            transport=TransportType.WEBSOCKET,
            security=SecurityType.TLS,
            parameters=vless_ws_tls_params,
            default_variants=(
                ParameterVariant(
                    variant_id="baseline",
                    display_name="VLESS WS TLS Baseline",
                    overrides={},
                ),
                ParameterVariant(
                    variant_id="custom_path",
                    display_name="Custom WebSocket Path",
                    overrides={"path": "/custom-vless-ws"},
                ),
            ),
            description="VLESS proxy protocol over WebSocket upgrade stream encapsulated in TLS",
        )
    )

    vless_grpc_tls_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="service_name",
            display_name="gRPC Service Name",
            param_type=ParameterType.STRING,
            default="grpc",
        ),
        ParameterDefinition(
            param_id="fingerprint",
            display_name="Client Fingerprint",
            param_type=ParameterType.STRING,
            default="chrome",
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default=None,
        ),
        ParameterDefinition(
            param_id="min_version",
            display_name="Minimum TLS Version",
            param_type=ParameterType.ENUM,
            default=None,
            allowed_values=(None, "1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="max_version",
            display_name="Maximum TLS Version",
            param_type=ParameterType.ENUM,
            default=None,
            allowed_values=(None, "1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="verify_cert",
            display_name="Verify Server Certificate",
            param_type=ParameterType.BOOL,
            description="Enforces TLS peer certificate validation",
            default=True,
        ),
        ParameterDefinition(
            param_id="multi_mode",
            display_name="gRPC Multi-Mode",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="idle_timeout_s",
            display_name="Idle Timeout Seconds",
            param_type=ParameterType.INT,
            default=60,
            min_value=1,
        ),
        ParameterDefinition(
            param_id="ping_timeout_s",
            display_name="Health Check / Ping Timeout Seconds",
            param_type=ParameterType.INT,
            default=20,
            min_value=1,
        ),
        ParameterDefinition(
            param_id="mux_enabled",
            display_name="Multiplexing Enabled",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_concurrency",
            display_name="Multiplex Concurrency",
            param_type=ParameterType.INT,
            default=8,
            min_value=1,
            max_value=1024,
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="vless_grpc_tls",
            display_name="VLESS over gRPC + TLS",
            protocol=ProtocolType.VLESS,
            transport=TransportType.GRPC,
            security=SecurityType.TLS,
            parameters=vless_grpc_tls_params,
            default_variants=(
                ParameterVariant(
                    variant_id="baseline",
                    display_name="VLESS gRPC TLS Baseline",
                    overrides={},
                ),
                ParameterVariant(
                    variant_id="custom_service",
                    display_name="Custom Service Name",
                    overrides={"service_name": "custom-vless-grpc"},
                ),
            ),
            description="VLESS proxy protocol over gRPC transport encapsulated in TLS",
        )
    )

    trojan_tcp_tls_params = (
        ParameterDefinition(
            param_id="password",
            display_name="Trojan Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="fingerprint",
            display_name="Client Fingerprint",
            param_type=ParameterType.STRING,
            default="chrome",
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default=None,
        ),
        ParameterDefinition(
            param_id="min_version",
            display_name="Minimum TLS Version",
            param_type=ParameterType.ENUM,
            default=None,
            allowed_values=("1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="max_version",
            display_name="Maximum TLS Version",
            param_type=ParameterType.ENUM,
            default=None,
            allowed_values=("1.2", "1.3"),
        ),
        ParameterDefinition(
            param_id="verify_cert",
            display_name="Verify Server Certificate",
            param_type=ParameterType.BOOL,
            description="Enforces TLS peer certificate validation",
            default=True,
        ),
        ParameterDefinition(
            param_id="tcp_fast_open",
            display_name="TCP Fast Open",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_enabled",
            display_name="Multiplexing Enabled",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_concurrency",
            display_name="Multiplex Concurrency",
            param_type=ParameterType.INT,
            default=8,
            min_value=1,
            max_value=1024,
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="trojan_tcp_tls",
            display_name="Trojan over TCP + TLS",
            protocol=ProtocolType.TROJAN,
            transport=TransportType.TCP,
            security=SecurityType.TLS,
            parameters=trojan_tcp_tls_params,
            default_variants=(
                ParameterVariant(
                    variant_id="baseline",
                    display_name="Trojan Baseline",
                    overrides={},
                ),
                ParameterVariant(
                    variant_id="firefox_fp",
                    display_name="Firefox Fingerprint",
                    overrides={"fingerprint": "firefox"},
                ),
            ),
            description="Trojan protocol over direct TCP authenticated inside TLS",
        )
    )

    shadowsocks_tcp_params = (
        ParameterDefinition(
            param_id="method",
            display_name="Cipher Method",
            param_type=ParameterType.ENUM,
            required=True,
            default="2022-blake3-aes-128-gcm",
            allowed_values=(
                "2022-blake3-aes-128-gcm",
                "2022-blake3-aes-256-gcm",
                "2022-blake3-chacha20-poly1305",
                "aes-128-gcm",
                "aes-256-gcm",
                "chacha20-ietf-poly1305",
            ),
        ),
        ParameterDefinition(
            param_id="password",
            display_name="Shadowsocks Password / Pre-shared Key",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="uot",
            display_name="UDP Over TCP",
            param_type=ParameterType.BOOL,
            description="Enables UDP Over TCP tunneling for Shadowsocks",
            default=False,
        ),
        ParameterDefinition(
            param_id="tcp_fast_open",
            display_name="TCP Fast Open",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_enabled",
            display_name="Multiplexing Enabled",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="mux_concurrency",
            display_name="Multiplex Concurrency",
            param_type=ParameterType.INT,
            default=8,
            min_value=1,
            max_value=1024,
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="shadowsocks_tcp",
            display_name="Shadowsocks TCP",
            protocol=ProtocolType.SHADOWSOCKS,
            transport=TransportType.TCP,
            security=SecurityType.NONE,
            parameters=shadowsocks_tcp_params,
            default_variants=(
                ParameterVariant(
                    variant_id="baseline_2022_128",
                    display_name="Shadowsocks 2022 BLAKE3-AES-128-GCM",
                    overrides={"method": "2022-blake3-aes-128-gcm"},
                ),
                ParameterVariant(
                    variant_id="aead_aes_128",
                    display_name="Shadowsocks AEAD AES-128-GCM",
                    overrides={"method": "aes-128-gcm"},
                ),
                ParameterVariant(
                    variant_id="aead_chacha20",
                    display_name="Shadowsocks AEAD ChaCha20-Poly1305",
                    overrides={"method": "chacha20-ietf-poly1305"},
                ),
            ),
            description="Shadowsocks protocol over direct TCP with AEAD or 2022 ciphers",
        )
    )

    aether_params = (
        ParameterDefinition(
            param_id="mode",
            display_name="Operating Mode",
            param_type=ParameterType.ENUM,
            default="tunnel",
            allowed_values=("tunnel", "transport"),
        ),
        ParameterDefinition(
            param_id="protocol_version",
            display_name="Protocol Version",
            param_type=ParameterType.STRING,
            default="1.0",
        ),
        ParameterDefinition(
            param_id="auth_token",
            display_name="Authentication Token",
            param_type=ParameterType.STRING,
            default=None,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="obfuscation_seed",
            display_name="Obfuscation Seed",
            param_type=ParameterType.STRING,
            default=None,
            is_secret=True,
        ),
    )
    catalog.register_profile(
        ProtocolProfile(
            profile_id="aether_tun",
            display_name="Aether Tunnel",
            protocol=ProtocolType.TRUST_TUNNEL,
            transport=TransportType.TCP,
            security=SecurityType.NONE,
            parameters=aether_params,
            default_variants=(
                ParameterVariant(
                    variant_id="baseline",
                    display_name="Aether Baseline",
                    overrides={},
                ),
            ),
            description="Declarative placeholder for Aether tunnel runtime; requires upstream source confirmation",
        )
    )

    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="xray",
            profile_id="vless_tcp_reality",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            min_version="1.8.0",
            adapter_id="xray_vless_tcp_reality",
            parameter_constraints={},
            known_limitations=(
                "Requires Xray v1.8.0+ for REALITY support",
                "Live remote tunnel handshake unverified without explicitly configured test server",
            ),
        )
    )

    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="sing_box",
            profile_id="vless_tcp_reality",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            min_version="1.10.0",
            adapter_id="singbox_vless_tcp_reality",
            parameter_constraints={},
            known_limitations=(
                "Requires sing-box v1.10.0+ for uTLS client fingerprinting",
                "Strict DisallowUnknownFields parser rejects password or publicKey fields in reality block",
                "Live remote tunnel handshake unverified without explicitly configured test server",
            ),
        )
    )

    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="xray",
            profile_id="vmess_ws_tls",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            min_version="1.8.0",
            adapter_id="xray_vmess_ws_tls",
            parameter_constraints={
                "security": ("auto", "aes-128-gcm", "chacha20-poly1305"),
            },
            known_limitations=(
                "Client system clock must be synchronized within ±90s of UTC for VMess HMAC authentication",
                "Live remote tunnel handshake unverified without explicitly configured test server",
            ),
        )
    )

    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="sing_box",
            profile_id="vmess_ws_tls",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            min_version="1.10.0",
            adapter_id="singbox_vmess_ws_tls",
            parameter_constraints={
                "security": ("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"),
            },
            known_limitations=(
                "Requires sing-box v1.10.0+ for uTLS client fingerprinting",
                "Strict DisallowUnknownFields parser rejects allowInsecure in TLS block (must use insecure)",
                "Client system clock must be synchronized within ±90s of UTC for VMess HMAC authentication",
                "Live remote tunnel handshake unverified without explicitly configured test server",
            ),
        )
    )

    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="wireguard",
            profile_id="wireguard_standard",
            status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            adapter_id="wireguard_standard",
            known_limitations=(
                "Real interface creation requires root / CAP_NET_ADMIN privileges and explicit opt-in (CONNSCOPE_ENABLE_REAL_WIREGUARD=1); live tunnel verification requires controlled remote WireGuard peer endpoint",
            ),
        )
    )

    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="amnezia_wg",
            profile_id="amnezia_wg_obfs",
            status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            adapter_id="amnezia_wg_standard",
            known_limitations=(
                "Real interface creation requires root / CAP_NET_ADMIN privileges, awg binary, and amneziawg kernel module; requires explicit opt-in (CONNSCOPE_ENABLE_REAL_AMNEZIAWG=1); live tunnel verification requires controlled remote AmneziaWG peer endpoint",
            ),
        )
    )

    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="openvpn",
            profile_id="openvpn_udp",
            status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            adapter_id="openvpn_standard",
            known_limitations=(
                "Requires openvpn binary; userspace daemon cannot migrate socket across origin/netns without host NAT/forwarding (which violates ConnScope host safety invariants); live tunnel execution remains disabled and unclaimed",
            ),
        )
    )

    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="openvpn",
            profile_id="openvpn_tcp",
            status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            adapter_id="openvpn_standard",
            known_limitations=(
                "Requires openvpn binary; userspace daemon cannot migrate socket across origin/netns without host NAT/forwarding (which violates ConnScope host safety invariants); live tunnel execution remains disabled and unclaimed",
            ),
        )
    )

    catalog.register_compatibility(
        EngineProfileCompatibility(
            engine_id="aether",
            profile_id="aether_tun",
            status=VerificationStatus.CATALOGUED,
            adapter_id=None,
            known_limitations=(
                "Requires upstream source confirmation before adapter implementation; "
                "repository URL and commit hash must be confirmed.",
            ),
        )
    )

    for p_id in (
        "vless_tcp_tls",
        "vless_tcp_none",
        "vless_ws_tls",
        "vless_grpc_tls",
        "trojan_tcp_tls",
        "shadowsocks_tcp",
    ):
        catalog.register_compatibility(
            EngineProfileCompatibility(
                engine_id="xray",
                profile_id=p_id,
                status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
                min_version="1.8.0",
                adapter_id=f"xray_{p_id}",
            )
        )
        catalog.register_compatibility(
            EngineProfileCompatibility(
                engine_id="sing_box",
                profile_id=p_id,
                status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
                min_version="1.10.0",
                adapter_id=f"singbox_{p_id}",
            )
        )

    exclave_src = SourceReference(
        repository_url="https://github.com/ExclaveNetwork/Exclave",
        pinned_version="0.17.66",
        pinned_commit="71ae3bca4217f78d704713dbb6328aad067404a1",
        source_file="README.md",
        section="Configuration",
        reference_type="upstream_source",
        notes="Verified against upstream repository tag 0.17.66 and immutable commit 71ae3bca4217f78d704713dbb6328aad067404a1; wiki documentation commit 6dba811e7a5b0bc45a6ee52978d975cb5d15b298",
        verification_status=VerificationStatus.CATALOGUED,
    )

    exclave_ss_aead_params = (
        ParameterDefinition(
            param_id="method",
            display_name="AEAD Cipher Method",
            param_type=ParameterType.ENUM,
            required=True,
            default="chacha20-ietf-poly1305",
            allowed_values=("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"),
        ),
        ParameterDefinition(
            param_id="password",
            display_name="Pre-Shared Key / Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="udp_relay",
            display_name="UDP Relay Enabled",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_ss_2022_params = (
        ParameterDefinition(
            param_id="method",
            display_name="Shadowsocks 2022 Cipher",
            param_type=ParameterType.ENUM,
            required=True,
            default="2022-blake3-aes-128-gcm",
            allowed_values=("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"),
        ),
        ParameterDefinition(
            param_id="password",
            display_name="Base64 Pre-Shared Key",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="udp_relay",
            display_name="UDP Relay Enabled",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_ss_legacy_params = (
        ParameterDefinition(
            param_id="method",
            display_name="Legacy Stream Cipher",
            param_type=ParameterType.ENUM,
            required=True,
            default="aes-256-cfb",
            allowed_values=("aes-128-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf"),
        ),
        ParameterDefinition(
            param_id="password",
            display_name="Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
    )

    exclave_ss_plugin_params = (
        ParameterDefinition(
            param_id="plugin",
            display_name="SIP003 Plugin Name",
            param_type=ParameterType.ENUM,
            required=True,
            default="v2ray-plugin",
            allowed_values=("v2ray-plugin", "obfs-local"),
        ),
        ParameterDefinition(
            param_id="plugin_opts",
            display_name="SIP003 Plugin Options",
            param_type=ParameterType.STRING,
            default="",
        ),
    )

    exclave_trojan_params = (
        ParameterDefinition(
            param_id="password",
            display_name="Trojan Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default="h2,http/1.1",
        ),
        ParameterDefinition(
            param_id="fingerprint",
            display_name="uTLS Fingerprint",
            param_type=ParameterType.ENUM,
            default="chrome",
            allowed_values=("chrome", "firefox", "safari", "ios", "android", "edge"),
        ),
        ParameterDefinition(
            param_id="verify_cert",
            display_name="Verify Certificate",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_hy2_params = (
        ParameterDefinition(
            param_id="password",
            display_name="Authentication Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="ports",
            display_name="Port Hopping Range",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="up_mbps",
            display_name="Upload Bandwidth (Mbps)",
            param_type=ParameterType.INT,
            min_value=1,
            default=None,
        ),
        ParameterDefinition(
            param_id="down_mbps",
            display_name="Download Bandwidth (Mbps)",
            param_type=ParameterType.INT,
            min_value=1,
            default=None,
        ),
        ParameterDefinition(
            param_id="obfs_type",
            display_name="Obfuscation Type",
            param_type=ParameterType.ENUM,
            default="none",
            allowed_values=("none", "salamander"),
        ),
        ParameterDefinition(
            param_id="obfs_password",
            display_name="Obfuscation Password",
            param_type=ParameterType.STRING,
            is_secret=True,
            default="",
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default="h3",
        ),
        ParameterDefinition(
            param_id="chrome_parrot",
            display_name="Chrome ClientHello Parrot",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="insecure",
            display_name="Allow Insecure Certificate",
            param_type=ParameterType.BOOL,
            default=False,
        ),
    )

    exclave_anytls_params = (
        ParameterDefinition(
            param_id="password",
            display_name="AnyTLS Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default="h2,http/1.1",
        ),
        ParameterDefinition(
            param_id="idle_timeout",
            display_name="Idle Timeout Seconds",
            param_type=ParameterType.INT,
            min_value=1,
            default=30,
        ),
        ParameterDefinition(
            param_id="padding_mode",
            display_name="Padding Mode",
            param_type=ParameterType.ENUM,
            default="random",
            allowed_values=("none", "random", "stream"),
        ),
    )

    exclave_mieru_params = (
        ParameterDefinition(
            param_id="username",
            display_name="Username",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="password",
            display_name="Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="transport",
            display_name="Underlying Transport",
            param_type=ParameterType.ENUM,
            default="tcp",
            allowed_values=("tcp", "udp"),
        ),
        ParameterDefinition(
            param_id="port_range",
            display_name="Dynamic Port Range",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="multiplexing",
            display_name="Multiplexing Enabled",
            param_type=ParameterType.BOOL,
            default=True,
        ),
        ParameterDefinition(
            param_id="traffic_pattern",
            display_name="Base64 Protobuf Traffic Pattern",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="mtu",
            display_name="MTU",
            param_type=ParameterType.INT,
            min_value=576,
            max_value=9000,
            default=1400,
        ),
    )

    exclave_naive_params = (
        ParameterDefinition(
            param_id="username",
            display_name="Username",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="password",
            display_name="Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="protocol",
            display_name="Frontend Protocol",
            param_type=ParameterType.ENUM,
            default="https",
            allowed_values=("https", "quic"),
        ),
        ParameterDefinition(
            param_id="padding",
            display_name="Fast Open / Padding",
            param_type=ParameterType.BOOL,
            default=True,
        ),
        ParameterDefinition(
            param_id="plugin_path",
            display_name="Naïve Plugin Executable Path",
            param_type=ParameterType.STRING,
            default="",
        ),
    )

    exclave_tuic_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="password",
            display_name="Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="congestion_control",
            display_name="Congestion Control Algorithm",
            param_type=ParameterType.ENUM,
            default="bbr",
            allowed_values=("bbr", "cubic", "new_reno"),
        ),
        ParameterDefinition(
            param_id="udp_relay_mode",
            display_name="UDP Relay Mode",
            param_type=ParameterType.ENUM,
            default="native",
            allowed_values=("native", "quic"),
        ),
        ParameterDefinition(
            param_id="zero_rtt_handshake",
            display_name="Enable 0-RTT Handshake",
            param_type=ParameterType.BOOL,
            default=False,
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default="h3",
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="disable_sni",
            display_name="Disable SNI",
            param_type=ParameterType.BOOL,
            default=False,
        ),
    )

    exclave_juicity_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="password",
            display_name="Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="congestion_control",
            display_name="Congestion Control Algorithm",
            param_type=ParameterType.ENUM,
            default="bbr",
            allowed_values=("bbr", "cubic", "new_reno"),
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="pinned_certchain_sha256",
            display_name="Pinned Cert Chain SHA-256",
            param_type=ParameterType.STRING,
            default="",
        ),
    )

    exclave_vless_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="flow",
            display_name="VLESS Flow",
            param_type=ParameterType.ENUM,
            default="",
            allowed_values=("", "xtls-rprx-vision"),
        ),
        ParameterDefinition(
            param_id="encryption",
            display_name="Encryption",
            param_type=ParameterType.STRING,
            default="none",
        ),
        ParameterDefinition(
            param_id="packet_encoding",
            display_name="Packet Encoding",
            param_type=ParameterType.ENUM,
            default="packetaddr",
            allowed_values=("packetaddr", "xudp", "none"),
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="reality_public_key",
            display_name="REALITY Public Key",
            param_type=ParameterType.STRING,
            is_secret=True,
            default="",
        ),
        ParameterDefinition(
            param_id="reality_short_id",
            display_name="REALITY Short ID",
            param_type=ParameterType.STRING,
            default="",
        ),
    )

    exclave_vmess_params = (
        ParameterDefinition(
            param_id="uuid",
            display_name="Client UUID",
            param_type=ParameterType.UUID,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="alter_id",
            display_name="Alter ID",
            param_type=ParameterType.INT,
            default=0,
            min_value=0,
            max_value=65535,
        ),
        ParameterDefinition(
            param_id="security",
            display_name="Payload Security",
            param_type=ParameterType.ENUM,
            default="auto",
            allowed_values=("auto", "aes-128-gcm", "chacha20-poly1305", "none"),
        ),
        ParameterDefinition(
            param_id="packet_encoding",
            display_name="Packet Encoding",
            param_type=ParameterType.ENUM,
            default="packetaddr",
            allowed_values=("packetaddr", "xudp", "none"),
        ),
        ParameterDefinition(
            param_id="aead_enforced",
            display_name="Enforce AEAD Authentication",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_wireguard_params = (
        ParameterDefinition(
            param_id="private_key",
            display_name="Client Private Key",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="peer_public_key",
            display_name="Peer Public Key",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="preshared_key",
            display_name="Pre-Shared Key",
            param_type=ParameterType.STRING,
            is_secret=True,
            default="",
        ),
        ParameterDefinition(
            param_id="local_address",
            display_name="Local IP Address / CIDR",
            param_type=ParameterType.STRING,
            default="10.0.0.2/32",
        ),
        ParameterDefinition(
            param_id="reserved_bytes",
            display_name="Reserved Client Bytes",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="mtu",
            display_name="MTU",
            param_type=ParameterType.INT,
            min_value=576,
            max_value=1500,
            default=1420,
        ),
    )

    exclave_masque_params = (
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="uri_template",
            display_name="CONNECT-IP URI Template",
            param_type=ParameterType.STRING,
            default="/masque/ip{?target}",
        ),
        ParameterDefinition(
            param_id="auth_token",
            display_name="Authorization Bearer Token",
            param_type=ParameterType.STRING,
            is_secret=True,
            default="",
        ),
        ParameterDefinition(
            param_id="capsule_protocol",
            display_name="Capsule Protocol Enabled",
            param_type=ParameterType.BOOL,
            default=True,
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default="h3",
        ),
    )

    exclave_trusttunnel_params = (
        ParameterDefinition(
            param_id="username",
            display_name="Username",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="password",
            display_name="Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="transport",
            display_name="HTTP Transport Version",
            param_type=ParameterType.ENUM,
            default="h2",
            allowed_values=("h2", "h3"),
        ),
        ParameterDefinition(
            param_id="udp_over_tcp",
            display_name="Private UDP-over-TCP",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_snell_v4_params = (
        ParameterDefinition(
            param_id="psk",
            display_name="Pre-Shared Key",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="version",
            display_name="Snell Protocol Version",
            param_type=ParameterType.INT,
            default=4,
            min_value=4,
            max_value=4,
        ),
        ParameterDefinition(
            param_id="obfs",
            display_name="Obfuscation Mode",
            param_type=ParameterType.ENUM,
            default="none",
            allowed_values=("none", "http"),
        ),
        ParameterDefinition(
            param_id="obfs_host",
            display_name="Obfuscation HTTP Host",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="udp_relay",
            display_name="UDP Relay Enabled",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_snell_v6_params = (
        ParameterDefinition(
            param_id="psk",
            display_name="Pre-Shared Key",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="version",
            display_name="Snell Protocol Version",
            param_type=ParameterType.INT,
            default=6,
            min_value=6,
            max_value=6,
        ),
        ParameterDefinition(
            param_id="obfs",
            display_name="Obfuscation Mode",
            param_type=ParameterType.ENUM,
            default="none",
            allowed_values=("none", "http"),
        ),
        ParameterDefinition(
            param_id="obfs_host",
            display_name="Obfuscation HTTP Host",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="udp_relay",
            display_name="UDP Relay Enabled",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_shadowquic_params = (
        ParameterDefinition(
            param_id="password",
            display_name="Password",
            param_type=ParameterType.STRING,
            required=True,
            is_secret=True,
        ),
        ParameterDefinition(
            param_id="server_name",
            display_name="Server Name (SNI)",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="alpn",
            display_name="ALPN Protocols",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="zero_rtt",
            display_name="Enable 0-RTT",
            param_type=ParameterType.BOOL,
            default=False,
        ),
    )

    exclave_ssh_params = (
        ParameterDefinition(
            param_id="username",
            display_name="SSH Username",
            param_type=ParameterType.STRING,
            required=True,
        ),
        ParameterDefinition(
            param_id="password",
            display_name="SSH Password",
            param_type=ParameterType.STRING,
            is_secret=True,
            default="",
        ),
        ParameterDefinition(
            param_id="private_key",
            display_name="PEM / OpenSSH Private Key",
            param_type=ParameterType.STRING,
            is_secret=True,
            default="",
        ),
        ParameterDefinition(
            param_id="passphrase",
            display_name="Private Key Passphrase",
            param_type=ParameterType.STRING,
            is_secret=True,
            default="",
        ),
        ParameterDefinition(
            param_id="host_key_check",
            display_name="Strict Host Key Checking",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_http_connect_params = (
        ParameterDefinition(
            param_id="username",
            display_name="HTTP Proxy Username",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="password",
            display_name="HTTP Proxy Password",
            param_type=ParameterType.STRING,
            is_secret=True,
            default="",
        ),
        ParameterDefinition(
            param_id="tls",
            display_name="TLS Wrapped Connection",
            param_type=ParameterType.BOOL,
            default=True,
        ),
        ParameterDefinition(
            param_id="http_version",
            display_name="HTTP Version",
            param_type=ParameterType.ENUM,
            default="h2",
            allowed_values=("http/1.1", "h2", "h3"),
        ),
    )

    exclave_connect_udp_params = (
        ParameterDefinition(
            param_id="capsule_protocol",
            display_name="Capsule Protocol Framing",
            param_type=ParameterType.BOOL,
            default=True,
        ),
        ParameterDefinition(
            param_id="http_version",
            display_name="HTTP Framing Version",
            param_type=ParameterType.ENUM,
            default="h2",
            allowed_values=("h2", "h3"),
        ),
    )

    exclave_socks4_params = (
        ParameterDefinition(
            param_id="version",
            display_name="SOCKS Version",
            param_type=ParameterType.ENUM,
            default="4a",
            allowed_values=("4", "4a"),
        ),
        ParameterDefinition(
            param_id="user_id",
            display_name="Client User ID",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="remote_dns",
            display_name="Remote DNS Resolution",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_socks5_params = (
        ParameterDefinition(
            param_id="username",
            display_name="SOCKS5 Username",
            param_type=ParameterType.STRING,
            default="",
        ),
        ParameterDefinition(
            param_id="password",
            display_name="SOCKS5 Password",
            param_type=ParameterType.STRING,
            is_secret=True,
            default="",
        ),
        ParameterDefinition(
            param_id="udp_associate",
            display_name="UDP Associate Enabled",
            param_type=ParameterType.BOOL,
            default=True,
        ),
        ParameterDefinition(
            param_id="remote_dns",
            display_name="Remote DNS Resolution",
            param_type=ParameterType.BOOL,
            default=True,
        ),
    )

    exclave_tun_params = (
        ParameterDefinition(
            param_id="auto_route",
            display_name="Automatic Default Route Hijack",
            param_type=ParameterType.BOOL,
            default=True,
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="strict_route",
            display_name="Strict Routing Isolation",
            param_type=ParameterType.BOOL,
            default=True,
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="mtu",
            display_name="TUN MTU",
            param_type=ParameterType.INT,
            min_value=1280,
            max_value=9000,
            default=1500,
            impact_scope="network_behavior",
            is_source_confirmed=True,
        ),
    )

    exclave_netstack_gvisor_params = (
        ParameterDefinition(
            param_id="tun_stack",
            display_name="TUN Packet Stack",
            param_type=ParameterType.ENUM,
            default="gvisor",
            allowed_values=("gvisor",),
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="mtu",
            display_name="TUN MTU",
            param_type=ParameterType.INT,
            min_value=1280,
            max_value=9000,
            default=1500,
            impact_scope="network_behavior",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="pcap_enabled",
            display_name="Packet Capture PCAP Dump",
            param_type=ParameterType.BOOL,
            default=False,
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
    )

    exclave_tun_system_params = (
        ParameterDefinition(
            param_id="tun_stack",
            display_name="TUN Packet Stack",
            param_type=ParameterType.ENUM,
            default="system",
            allowed_values=("system",),
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="mtu",
            display_name="TUN MTU",
            param_type=ParameterType.INT,
            min_value=1280,
            max_value=9000,
            default=1500,
            impact_scope="network_behavior",
            is_source_confirmed=True,
        ),
    )

    exclave_traffic_sniffing_params = (
        ParameterDefinition(
            param_id="sniff_enabled",
            display_name="Protocol Sniffing Enabled",
            param_type=ParameterType.BOOL,
            default=True,
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="override_destination",
            display_name="Override Destination Address with Sniffed Domain",
            param_type=ParameterType.BOOL,
            default=False,
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="sniff_tls_sni",
            display_name="Sniff TLS ClientHello SNI",
            param_type=ParameterType.BOOL,
            default=True,
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="sniff_http_host",
            display_name="Sniff HTTP Host Header",
            param_type=ParameterType.BOOL,
            default=True,
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="sniff_quic_sni",
            display_name="Sniff QUIC Initial SNI",
            param_type=ParameterType.BOOL,
            default=True,
            impact_scope="runtime_operation",
            is_source_confirmed=True,
        ),
    )

    exclave_happy_eyeballs_params = (
        ParameterDefinition(
            param_id="tcp_concurrent",
            display_name="Happy Eyeballs Concurrent Dial",
            param_type=ParameterType.BOOL,
            default=True,
            impact_scope="network_behavior",
            is_source_confirmed=True,
        ),
        ParameterDefinition(
            param_id="dns_strategy",
            display_name="DNS Dual-Stack Strategy",
            param_type=ParameterType.ENUM,
            default="prefer_ipv4",
            allowed_values=("prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"),
            impact_scope="network_behavior",
            is_source_confirmed=True,
        ),
    )

    exclave_icmp_policy_params = (
        ParameterDefinition(
            param_id="discard_icmp",
            display_name="Discard ICMP Packets (Do Not Forge Echo)",
            param_type=ParameterType.BOOL,
            default=False,
            impact_scope="network_behavior",
            is_source_confirmed=True,
        ),
    )

    capabilities_data = (
        CapabilityDefinition(
            capability_id="xray_vless",
            display_name="Xray VLESS Protocol",
            engine_id="xray",
            category="protocol",
            protocol=ProtocolType.VLESS,
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].protocol='vless'",
            description="VLESS lightweight proxy protocol for Xray",
        ),
        CapabilityDefinition(
            capability_id="xray_vmess",
            display_name="Xray VMess Protocol",
            engine_id="xray",
            category="protocol",
            protocol=ProtocolType.VMESS,
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].protocol='vmess'",
            description="VMess encrypted proxy protocol for Xray",
        ),
        CapabilityDefinition(
            capability_id="xray_trojan",
            display_name="Xray Trojan Protocol",
            engine_id="xray",
            category="protocol",
            protocol=ProtocolType.TROJAN,
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].protocol='trojan'",
            description="Trojan TLS-camouflaged protocol for Xray",
        ),
        CapabilityDefinition(
            capability_id="xray_shadowsocks",
            display_name="Xray Shadowsocks Protocol",
            engine_id="xray",
            category="protocol",
            protocol=ProtocolType.SHADOWSOCKS,
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].protocol='shadowsocks'",
            description="Shadowsocks AEAD and 2022 protocol for Xray",
        ),
        CapabilityDefinition(
            capability_id="xray_tls",
            display_name="Xray Standard TLS",
            engine_id="xray",
            category="security",
            security=SecurityType.TLS,
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].streamSettings.security='tls'",
            description="Standard TLS encryption with uTLS fingerprinting",
        ),
        CapabilityDefinition(
            capability_id="xray_reality",
            display_name="Xray REALITY",
            engine_id="xray",
            category="security",
            security=SecurityType.REALITY,
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].streamSettings.security='reality'",
            description="REALITY TLS ClientHello camouflage without server cert",
        ),
        CapabilityDefinition(
            capability_id="xray_websocket",
            display_name="Xray WebSocket Transport",
            engine_id="xray",
            category="transport",
            transport=TransportType.WEBSOCKET,
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].streamSettings.network='ws'",
            description="WebSocket upgrade transport stream",
        ),
        CapabilityDefinition(
            capability_id="xray_grpc",
            display_name="Xray gRPC Transport",
            engine_id="xray",
            category="transport",
            transport=TransportType.GRPC,
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].streamSettings.network='grpc'",
            description="gRPC HTTP/2 transport stream",
        ),
        CapabilityDefinition(
            capability_id="xray_httpupgrade",
            display_name="Xray HTTPUpgrade Transport",
            engine_id="xray",
            category="transport",
            transport="httpupgrade",
            supported_versions=">=1.8.7",
            status=VerificationStatus.REAL_BINARY_CONFIG_VALIDATED,
            is_executable=False,
            config_mapping="outbounds[].streamSettings.network='httpupgrade'",
            description="HTTPUpgrade lightweight HTTP transport",
        ),
        CapabilityDefinition(
            capability_id="xray_splithttp",
            display_name="Xray SplitHTTP / XHTTP Transport",
            engine_id="xray",
            category="transport",
            transport="xhttp",
            supported_versions=">=1.8.11",
            status=VerificationStatus.REAL_BINARY_CONFIG_VALIDATED,
            is_executable=False,
            config_mapping="outbounds[].streamSettings.network='xhttp'",
            description="SplitHTTP / XHTTP chunked upload/download transport",
        ),
        CapabilityDefinition(
            capability_id="xray_mkcp",
            display_name="Xray mKCP Transport",
            engine_id="xray",
            category="transport",
            transport="mkcp",
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_BINARY_CONFIG_VALIDATED,
            is_executable=False,
            config_mapping="outbounds[].streamSettings.network='kcp'",
            description="mKCP reliable UDP transport with congestion control",
        ),
        CapabilityDefinition(
            capability_id="xray_quic",
            display_name="Xray QUIC Transport (Legacy)",
            engine_id="xray",
            category="transport",
            transport="quic",
            supported_versions="<26.0.0",
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            unsupported_reason="Removed upstream in Xray v26.3.27; superseded by XHTTP H3",
            description="Legacy standalone QUIC transport removed from Xray core",
        ),
        CapabilityDefinition(
            capability_id="xray_fragmentation",
            display_name="Xray Freedom Packet Fragmentation",
            engine_id="xray",
            category="packet_manipulation",
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_BINARY_CONFIG_VALIDATED,
            is_executable=False,
            config_mapping="outbounds[].settings.fragment",
            description="TCP packet fragmentation for SNI blocking circumvention",
        ),
        CapabilityDefinition(
            capability_id="xray_mux",
            display_name="Xray Stream Multiplexing",
            engine_id="xray",
            category="multiplexing",
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].mux",
            description="Stream multiplexing over single underlying TCP connection",
        ),
        CapabilityDefinition(
            capability_id="xray_tcp_fast_open",
            display_name="Xray TCP Fast Open",
            engine_id="xray",
            category="transport",
            supported_versions=">=1.8.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].streamSettings.sockopt.tcpFastOpen",
            description="TCP Fast Open socket option",
        ),
        CapabilityDefinition(
            capability_id="singbox_vless",
            display_name="sing-box VLESS Protocol",
            engine_id="sing_box",
            category="protocol",
            protocol=ProtocolType.VLESS,
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].type='vless'",
            description="VLESS lightweight proxy protocol for sing-box",
        ),
        CapabilityDefinition(
            capability_id="singbox_vmess",
            display_name="sing-box VMess Protocol",
            engine_id="sing_box",
            category="protocol",
            protocol=ProtocolType.VMESS,
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].type='vmess'",
            description="VMess encrypted proxy protocol for sing-box",
        ),
        CapabilityDefinition(
            capability_id="singbox_trojan",
            display_name="sing-box Trojan Protocol",
            engine_id="sing_box",
            category="protocol",
            protocol=ProtocolType.TROJAN,
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].type='trojan'",
            description="Trojan TLS-camouflaged protocol for sing-box",
        ),
        CapabilityDefinition(
            capability_id="singbox_shadowsocks",
            display_name="sing-box Shadowsocks Protocol",
            engine_id="sing_box",
            category="protocol",
            protocol=ProtocolType.SHADOWSOCKS,
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].type='shadowsocks'",
            description="Shadowsocks AEAD and 2022 protocol for sing-box",
        ),
        CapabilityDefinition(
            capability_id="singbox_tls",
            display_name="sing-box TLS",
            engine_id="sing_box",
            category="security",
            security=SecurityType.TLS,
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].tls",
            description="Strict-schema TLS outbound block with uTLS support",
        ),
        CapabilityDefinition(
            capability_id="singbox_reality",
            display_name="sing-box REALITY",
            engine_id="sing_box",
            category="security",
            security=SecurityType.REALITY,
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].tls.reality",
            description="REALITY client camouflage within sing-box TLS block",
        ),
        CapabilityDefinition(
            capability_id="singbox_websocket",
            display_name="sing-box WebSocket Transport",
            engine_id="sing_box",
            category="transport",
            transport=TransportType.WEBSOCKET,
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].transport.type='ws'",
            description="WebSocket upgrade transport block",
        ),
        CapabilityDefinition(
            capability_id="singbox_grpc",
            display_name="sing-box gRPC Transport",
            engine_id="sing_box",
            category="transport",
            transport=TransportType.GRPC,
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].transport.type='grpc'",
            description="gRPC transport block",
        ),
        CapabilityDefinition(
            capability_id="singbox_httpupgrade",
            display_name="sing-box HTTPUpgrade Transport",
            engine_id="sing_box",
            category="transport",
            transport="httpupgrade",
            supported_versions=">=1.9.0",
            status=VerificationStatus.REAL_BINARY_CONFIG_VALIDATED,
            is_executable=False,
            config_mapping="outbounds[].transport.type='httpupgrade'",
            description="HTTPUpgrade transport stream",
        ),
        CapabilityDefinition(
            capability_id="singbox_quic",
            display_name="sing-box QUIC Transport",
            engine_id="sing_box",
            category="transport",
            transport="quic",
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_BINARY_CONFIG_VALIDATED,
            is_executable=False,
            config_mapping="outbounds[].transport.type='quic'",
            description="Native QUIC transport stream",
        ),
        CapabilityDefinition(
            capability_id="singbox_splithttp",
            display_name="sing-box SplitHTTP / XHTTP Transport",
            engine_id="sing_box",
            category="transport",
            transport="splithttp",
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            unsupported_reason="Unsupported in sing-box v1.12.12; not in sing-box transport schema",
            description="SplitHTTP / XHTTP transport unsupported by sing-box core",
        ),
        CapabilityDefinition(
            capability_id="singbox_mkcp",
            display_name="sing-box mKCP Transport",
            engine_id="sing_box",
            category="transport",
            transport="mkcp",
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            unsupported_reason="Unsupported in sing-box",
            description="mKCP transport unsupported by sing-box core",
        ),
        CapabilityDefinition(
            capability_id="singbox_multiplex",
            display_name="sing-box Multiplexing",
            engine_id="sing_box",
            category="multiplexing",
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].multiplex",
            description="Native sing-box multiplex connection pool",
        ),
        CapabilityDefinition(
            capability_id="singbox_tcp_fast_open",
            display_name="sing-box TCP Fast Open",
            engine_id="sing_box",
            category="transport",
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].tcp_fast_open",
            description="TCP Fast Open outbound parameter",
        ),
        CapabilityDefinition(
            capability_id="singbox_packet_encoding",
            display_name="sing-box Packet Encoding",
            engine_id="sing_box",
            category="packet_manipulation",
            supported_versions=">=1.10.0",
            status=VerificationStatus.REAL_PROCESS_LIFECYCLE_TESTED,
            is_executable=True,
            config_mapping="outbounds[].packet_encoding",
            description="Packet encoding for UDP datagrams over proxy streams",
        ),
        CapabilityDefinition(
            capability_id="exclave_shadowsocks",
            display_name="Exclave Shadowsocks AEAD Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.SHADOWSOCKS,
            parameters=exclave_ss_aead_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave Shadowsocks AEAD outbound configuration",
            description="Exclave Shadowsocks AEAD implementation (chacha20-ietf-poly1305, aes-128/256-gcm)",
        ),
        CapabilityDefinition(
            capability_id="exclave_shadowsocks_2022",
            display_name="Exclave Shadowsocks 2022 Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL_VARIANT,
            protocol=ProtocolType.SHADOWSOCKS,
            parameters=exclave_ss_2022_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave Shadowsocks 2022 outbound configuration",
            description="Exclave Shadowsocks 2022 implementation (2022-blake3-aes-128/256-gcm, 2022-blake3-chacha20-poly1305)",
        ),
        CapabilityDefinition(
            capability_id="exclave_shadowsocks_legacy",
            display_name="Exclave Shadowsocks Legacy Stream Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL_VARIANT,
            protocol=ProtocolType.SHADOWSOCKS,
            parameters=exclave_ss_legacy_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave Shadowsocks legacy stream outbound configuration",
            description="Exclave Shadowsocks legacy stream ciphers (aes-128/256-cfb, rc4-md5, chacha20-ietf)",
        ),
        CapabilityDefinition(
            capability_id="exclave_shadowsocks_plugin",
            display_name="Exclave Shadowsocks SIP003 Plugin",
            engine_id="exclave",
            category=CapabilityCategory.PLUGIN,
            protocol=ProtocolType.SHADOWSOCKS,
            parameters=exclave_ss_plugin_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave Shadowsocks SIP003 plugin configuration",
            description="Exclave SIP003 plugin architecture (v2ray-plugin, obfs-local)",
        ),
        CapabilityDefinition(
            capability_id="exclave_trojan",
            display_name="Exclave Trojan Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.TROJAN,
            parameters=exclave_trojan_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave Trojan outbound configuration",
            description="Exclave Trojan client with uTLS fingerprinting and ALPN negotiation",
        ),
        CapabilityDefinition(
            capability_id="exclave_hysteria2",
            display_name="Exclave Hysteria 2 Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.HYSTERIA2,
            parameters=exclave_hy2_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave Hysteria 2 outbound configuration",
            description="Exclave Hysteria 2 protocol with Brutal congestion control and Salamander obfuscation",
        ),
        CapabilityDefinition(
            capability_id="exclave_anytls",
            display_name="Exclave AnyTLS Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.ANYTLS,
            parameters=exclave_anytls_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave AnyTLS outbound configuration",
            description="Exclave AnyTLS protocol with TLS camouflage and random/stream padding",
        ),
        CapabilityDefinition(
            capability_id="exclave_mieru",
            display_name="Exclave mieru v3 Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.MIERU,
            parameters=exclave_mieru_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave mieru outbound configuration",
            description="Exclave mieru v3 protocol with dynamic port hopping and protobuf traffic patterns",
        ),
        CapabilityDefinition(
            capability_id="exclave_naiveproxy",
            display_name="Exclave NaïveProxy Plugin",
            engine_id="exclave",
            category=CapabilityCategory.PLUGIN,
            protocol=ProtocolType.NAIVEPROXY,
            parameters=exclave_naive_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave NaïveProxy standalone plugin configuration",
            description="Exclave Chromium-network-stack NaïveProxy protocol via external plugin executable",
        ),
        CapabilityDefinition(
            capability_id="exclave_tuic_v5",
            display_name="Exclave TUIC v5 Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.TUIC,
            parameters=exclave_tuic_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            standards_reference="TUIC v5 / QUIC RFC 9000",
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave TUIC v5 outbound configuration",
            description="Exclave TUIC v5 QUIC protocol with 0-RTT handshake and native/quic UDP relay",
        ),
        CapabilityDefinition(
            capability_id="exclave_juicity",
            display_name="Exclave Juicity Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.JUICITY,
            parameters=exclave_juicity_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave Juicity outbound configuration",
            description="Exclave Juicity protocol over QUIC with pinned cert chain verification",
        ),
        CapabilityDefinition(
            capability_id="exclave_vless",
            display_name="Exclave VLESS Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.VLESS,
            parameters=exclave_vless_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave VLESS outbound configuration",
            description="Exclave VLESS proxy implementation with Vision flow, REALITY, and packetaddr UDP",
        ),
        CapabilityDefinition(
            capability_id="exclave_vmess",
            display_name="Exclave VMess Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.VMESS,
            parameters=exclave_vmess_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave VMess outbound configuration",
            description="Exclave VMess encrypted proxy implementation with AEAD enforcement and packetaddr UDP",
        ),
        CapabilityDefinition(
            capability_id="exclave_wireguard",
            display_name="Exclave WireGuard Userspace Netstack",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.WIREGUARD,
            parameters=exclave_wireguard_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            standards_reference="WireGuard Specification / RFC 8439",
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave WireGuard outbound configuration",
            description="Exclave userspace WireGuard netstack with reserved bytes obfuscation",
        ),
        CapabilityDefinition(
            capability_id="exclave_masque_connect_ip",
            display_name="Exclave MASQUE / CONNECT-IP (RFC 9484)",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.MASQUE,
            parameters=exclave_masque_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            standards_reference="RFC 9484",
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave MASQUE outbound configuration",
            description="Exclave RFC 9484 CONNECT-IP proxy via HTTP Datagrams over HTTP/3 or Capsule Protocol over HTTP/2",
        ),
        CapabilityDefinition(
            capability_id="exclave_trusttunnel",
            display_name="Exclave TrustTunnel (AdGuard Obfuscation)",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.TRUST_TUNNEL,
            parameters=exclave_trusttunnel_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave TrustTunnel outbound configuration",
            description="Exclave AdGuard TrustTunnel protocol with HTTP/2 / HTTP/3 CONNECT and private UDP-over-TCP",
        ),
        CapabilityDefinition(
            capability_id="exclave_snell_v4",
            display_name="Exclave Snell v4 Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL_VARIANT,
            protocol=ProtocolType.SNELL,
            parameters=exclave_snell_v4_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave Snell v4 outbound configuration",
            description="Exclave Snell v4 protocol with HTTP obfuscation and UDP relay",
        ),
        CapabilityDefinition(
            capability_id="exclave_snell_v6",
            display_name="Exclave Snell v6 Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL_VARIANT,
            protocol=ProtocolType.SNELL,
            parameters=exclave_snell_v6_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave Snell v6 outbound configuration",
            description="Exclave Snell v6 protocol with modern framing and HTTP obfuscation",
        ),
        CapabilityDefinition(
            capability_id="exclave_shadowquic",
            display_name="Exclave ShadowQUIC Protocol",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.SHADOWQUIC,
            parameters=exclave_shadowquic_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave ShadowQUIC outbound configuration",
            description="Exclave ShadowQUIC protocol with QUIC-based obfuscated transport and 0-RTT support",
        ),
        CapabilityDefinition(
            capability_id="exclave_ssh",
            display_name="Exclave SSH Dynamic Forwarding",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.SSH,
            parameters=exclave_ssh_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            standards_reference="RFC 4251 / RFC 4253",
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave SSH dynamic port forwarding configuration",
            description="Exclave SSH dynamic SOCKS forwarding with password or private key authentication",
        ),
        CapabilityDefinition(
            capability_id="exclave_http_connect",
            display_name="Exclave HTTP CONNECT Proxy",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.HTTP_CONNECT,
            parameters=exclave_http_connect_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            standards_reference="RFC 7231 / RFC 9110",
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave HTTP CONNECT proxy configuration",
            description="Exclave HTTP CONNECT proxy supporting HTTP/1.1, HTTP/2, and HTTP/3 transports with TLS",
        ),
        CapabilityDefinition(
            capability_id="exclave_connect_udp",
            display_name="Exclave CONNECT-UDP (RFC 9298)",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.HTTP_CONNECT,
            parameters=exclave_connect_udp_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            standards_reference="RFC 9298",
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave CONNECT-UDP proxy configuration",
            description="Exclave CONNECT-UDP RFC 9298 datagram proxying over HTTP/2 and HTTP/3",
        ),
        CapabilityDefinition(
            capability_id="exclave_socks4",
            display_name="Exclave SOCKS4/4a Client",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL_VARIANT,
            protocol=ProtocolType.SOCKS,
            parameters=exclave_socks4_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            standards_reference="SOCKS Protocol Version 4/4A",
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave SOCKS4/4a proxy configuration",
            description="Exclave legacy SOCKS4/4a client with remote DNS resolution",
        ),
        CapabilityDefinition(
            capability_id="exclave_socks5",
            display_name="Exclave SOCKS5 Client",
            engine_id="exclave",
            category=CapabilityCategory.PROTOCOL,
            protocol=ProtocolType.SOCKS,
            parameters=exclave_socks5_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            standards_reference="RFC 1928",
            unsupported_reason="Headless daemon execution on Linux host not yet implemented; Android runtime requires headless CLI extraction",
            config_mapping="Exclave SOCKS5 proxy configuration",
            description="Exclave SOCKS5 client supporting username/password auth and UDP Associate",
        ),
        CapabilityDefinition(
            capability_id="exclave_tun",
            display_name="Exclave Android VPN Service Mode",
            engine_id="exclave",
            category=CapabilityCategory.RUNTIME_MODE,
            parameters=exclave_tun_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Android OS specific routing; unsupported on Linux headless host",
            config_mapping="Exclave VpnService routing takeover service mode",
            description="Exclave Android VpnService TUN capture and routing takeover service mode",
        ),
        CapabilityDefinition(
            capability_id="exclave_netstack_gvisor",
            display_name="Exclave gVisor Userspace TCP/IP Stack",
            engine_id="exclave",
            category=CapabilityCategory.NETWORK_STACK,
            parameters=exclave_netstack_gvisor_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Android OS specific routing; unsupported on Linux headless host",
            config_mapping="Exclave gVisor userspace netstack configuration",
            description="Exclave userspace network stack based on Google gVisor netstack",
        ),
        CapabilityDefinition(
            capability_id="exclave_tun_system",
            display_name="Exclave System Kernel NAT TCP/IP Stack",
            engine_id="exclave",
            category=CapabilityCategory.NETWORK_STACK,
            parameters=exclave_tun_system_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Android OS specific routing; unsupported on Linux headless host",
            config_mapping="Exclave System kernel double-NAT network stack configuration",
            description="Exclave kernel-assisted double-NAT system network stack implementation",
        ),
        CapabilityDefinition(
            capability_id="exclave_traffic_sniffing",
            display_name="Exclave Inbound Traffic Sniffing",
            engine_id="exclave",
            category=CapabilityCategory.INBOUND_PROCESSING,
            parameters=exclave_traffic_sniffing_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Android OS specific routing; unsupported on Linux headless host",
            config_mapping="Exclave traffic sniffing configuration",
            description="Exclave inbound protocol sniffing for domain discovery across TLS SNI, HTTP Host, and QUIC SNI",
        ),
        CapabilityDefinition(
            capability_id="exclave_happy_eyeballs",
            display_name="Exclave Happy Eyeballs & DNS Strategy",
            engine_id="exclave",
            category=CapabilityCategory.GLOBAL_SETTING,
            parameters=exclave_happy_eyeballs_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Android OS specific routing; unsupported on Linux headless host",
            config_mapping="Exclave Happy Eyeballs dialer and domain strategy configuration",
            description="Exclave RFC 8305 Happy Eyeballs concurrent dual-stack dialer and domain strategy",
        ),
        CapabilityDefinition(
            capability_id="exclave_icmp_policy",
            display_name="Exclave ICMP Packet Handling Policy",
            engine_id="exclave",
            category=CapabilityCategory.GLOBAL_SETTING,
            parameters=exclave_icmp_policy_params,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            source_reference=exclave_src,
            unsupported_reason="Android OS specific routing; unsupported on Linux headless host",
            config_mapping="Exclave ICMP handling policy configuration",
            description="Exclave policy for discarding or forging ICMP/ICMPv6 echo replies under TUN mode",
        ),
        CapabilityDefinition(
            capability_id="wireguard_standard",
            display_name="WireGuard L3 Tunnel",
            engine_id="wireguard",
            category="protocol",
            protocol=ProtocolType.WIREGUARD,
            transport=TransportType.UDP,
            status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            is_executable=False,
            config_mapping="wg-quick / wg interface configuration",
            unsupported_reason="Real interface creation requires root / CAP_NET_ADMIN privileges and opt-in",
            description="Native kernel/userspace WireGuard L3 tunnel",
        ),
        CapabilityDefinition(
            capability_id="amneziawg_obfs",
            display_name="AmneziaWG Obfuscated Tunnel",
            engine_id="amnezia_wg",
            category="obfuscation",
            protocol=ProtocolType.WIREGUARD,
            transport=TransportType.UDP,
            status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            is_executable=False,
            config_mapping="awg interface configuration with Jc/Jmin/Jmax/S1/S2/H1-H4",
            unsupported_reason="Real interface creation requires root / CAP_NET_ADMIN privileges and awg kernel module",
            description="AmneziaWG obfuscated WireGuard tunnel with junk packet padding and randomized headers",
        ),
        CapabilityDefinition(
            capability_id="openvpn_udp",
            display_name="OpenVPN UDP Client",
            engine_id="openvpn",
            category="protocol",
            protocol=ProtocolType.OPENVPN,
            transport=TransportType.UDP,
            status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            is_executable=False,
            config_mapping="openvpn config proto udp",
            unsupported_reason="Userspace daemon execution disabled by ConnScope host safety policy",
            description="OpenVPN SSL/TLS client over UDP transport",
        ),
        CapabilityDefinition(
            capability_id="openvpn_tcp",
            display_name="OpenVPN TCP Client",
            engine_id="openvpn",
            category="protocol",
            protocol=ProtocolType.OPENVPN,
            transport=TransportType.TCP,
            status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
            is_executable=False,
            config_mapping="openvpn config proto tcp",
            unsupported_reason="Userspace daemon execution disabled by ConnScope host safety policy",
            description="OpenVPN SSL/TLS client over TCP transport",
        ),
        CapabilityDefinition(
            capability_id="aether_tun",
            display_name="Aether Experimental Tunnel",
            engine_id="aether",
            category="protocol",
            protocol=ProtocolType.TRUST_TUNNEL,
            status=VerificationStatus.CATALOGUED,
            is_executable=False,
            unsupported_reason="Upstream source confirmation required; exact repository and commit unconfirmed",
            description="Experimental censorship circumvention runtime awaiting upstream confirmation",
        ),
    )

    for cap in capabilities_data:
        catalog.register_capability(cap)

    local_node = MeasurementNode(
        node_id="local",
        name="Local Measurement Node",
        node_type="local",
        supported_adapter_ids=(
            "xray_vless_tcp_reality",
            "singbox_vless_tcp_reality",
            "xray_vmess_ws_tls",
            "singbox_vmess_ws_tls",
            "xray_vless_tcp_tls",
            "singbox_vless_tcp_tls",
            "xray_vless_tcp_none",
            "singbox_vless_tcp_none",
            "xray_vless_ws_tls",
            "singbox_vless_ws_tls",
            "xray_vless_grpc_tls",
            "singbox_vless_grpc_tls",
            "xray_trojan_tcp_tls",
            "singbox_trojan_tcp_tls",
            "xray_shadowsocks_tcp",
            "singbox_shadowsocks_tcp",
            "wireguard_standard",
            "amnezia_wg_standard",
            "openvpn_standard",
        ),
        allowed_execution_modes=("local_proxy", "network_interface"),
        route_context={"interface": "lo", "type": "loopback"},
        evidence_status=VerificationStatus.CONFIG_VALIDATION_IMPLEMENTED,
        description="Localhost testing and execution environment",
    )
    catalog.register_node(local_node)

    catalog.register_node(
        MeasurementNode(
            node_id="remote-agent-frankfurt",
            name="Frankfurt Edge Node",
            node_type="remote_agent",
            endpoint_url="https://agent-de-01.connscope.net:8443",
            auth_token_ref="CONNSCOPE_AGENT_TOKEN_FRANKFURT",
            supported_adapter_ids=(
                "xray_vless_tcp_reality",
                "singbox_vless_tcp_reality",
                "xray_vmess_ws_tls",
                "singbox_vmess_ws_tls",
            ),
            allowed_execution_modes=("local_proxy",),
            operator_labels={"country": "DE", "city": "Frankfurt", "isp": "Sample ISP"},
            route_context={"asn": 3320, "country": "DE", "city": "Frankfurt", "interface": "eth0"},
            evidence_status=VerificationStatus.CATALOGUED,
            description="Sample remote measurement agent vantage point",
        )
    )

    catalog.register_measurement_profile(
        MeasurementProfile(
            profile_id="default_local_profile",
            name="Default Local HTTP 204 Workload",
            node=local_node,
            workload=MeasurementWorkload(
                workload_type="http_get_204",
                test_url="http://cp.cloudflare.com/generate_204",
                timeout_s=10.0,
                repetitions=1,
                verify_cert=True,
            ),
            description="Standard local verification workload using HTTP 204 check",
        )
    )

    return catalog

def validate_exclave_config(
    capability_or_id: CapabilityDefinition | str,
    config: dict[str, Any],
    catalog: ProtocolCatalog | None = None,
) -> list[str]:
    errors: list[str] = []

    if isinstance(capability_or_id, str):
        cat = catalog if catalog is not None else create_default_protocol_catalog()
        cap = cat.get_capability(capability_or_id)
        if cap is None:
            return [f"Unknown Exclave capability '{capability_or_id}'"]
    else:
        cap = capability_or_id

    if cap.engine_id != "exclave":
        return [f"Capability '{cap.capability_id}' belongs to engine '{cap.engine_id}', not 'exclave'"]

    forbidden_execution_keys = (
        "command",
        "exec",
        "binary",
        "plugin_binary",
        "shell",
        "script",
        "eval",
        "so_path",
        "native_lib",
    )
    for k in config:
        if k in forbidden_execution_keys:
            errors.append(f"Forbidden/dangerous configuration key detected: '{k}'")

    param_map = {p.param_id: p for p in cap.parameters}
    for k in config:
        if k not in param_map and k not in forbidden_execution_keys:
            errors.append(f"Unknown field '{k}' for capability '{cap.capability_id}'")

    for p in cap.parameters:
        if p.required:
            if p.param_id not in config or config[p.param_id] is None or config[p.param_id] == "":
                errors.append(f"Missing required parameter '{p.param_id}' for '{cap.capability_id}'")

    for k, v in config.items():
        if k in param_map:
            pdef = param_map[k]
            try:
                pdef.validate_value(v, engine_id="exclave")
            except (ValueError, TypeError) as exc:
                errors.append(str(exc))

    if cap.capability_id == "exclave_shadowsocks_2022":
        pwd = config.get("password")
        method = config.get("method", "2022-blake3-aes-128-gcm")
        if pwd and isinstance(pwd, str):
            try:
                decoded = base64.b64decode(pwd, validate=True)
                if method == "2022-blake3-aes-128-gcm" and len(decoded) != 16:
                    errors.append(f"Shadowsocks 2022 method '{method}' requires 16-byte base64 key, got {len(decoded)} bytes")
                elif method in ("2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305") and len(decoded) != 32:
                    errors.append(f"Shadowsocks 2022 method '{method}' requires 32-byte base64 key, got {len(decoded)} bytes")
            except Exception:
                errors.append(f"Shadowsocks 2022 password must be valid base64 string, got '{pwd}'")

    elif cap.capability_id == "exclave_hysteria2":
        obfs_type = config.get("obfs_type", "none")
        obfs_pwd = config.get("obfs_password")
        if obfs_type == "salamander" and (not obfs_pwd or not str(obfs_pwd).strip()):
            errors.append("Hysteria 2 with salamander obfs requires non-empty 'obfs_password'")

    elif cap.capability_id == "exclave_ssh":
        has_pwd = bool(config.get("password"))
        has_key = bool(config.get("private_key"))
        if not has_pwd and not has_key:
            errors.append("SSH configuration requires at least one authentication method: 'password' or 'private_key'")

    elif cap.capability_id == "exclave_wireguard":
        for k in ("private_key", "peer_public_key"):
            val = config.get(k)
            if val and isinstance(val, str):
                try:
                    dec = base64.b64decode(val, validate=True)
                    if len(dec) != 32:
                        errors.append(f"WireGuard {k} must decode to 32 bytes, got {len(dec)}")
                except Exception:
                    errors.append(f"WireGuard {k} must be valid 32-byte base64 string")

    elif cap.capability_id == "exclave_naiveproxy":
        ppath = config.get("plugin_path")
        if ppath and isinstance(ppath, str):
            for char in (";", "&", "|", "`", "$", "\n", "\r"):
                if char in ppath:
                    errors.append(f"plugin_path contains dangerous character '{char}'")
                    break

    elif cap.capability_id == "exclave_socks4":
        uid = config.get("user_id")
        if uid and isinstance(uid, str) and len(uid) > 255:
            errors.append("SOCKS4 user_id cannot exceed 255 characters")

    return errors

