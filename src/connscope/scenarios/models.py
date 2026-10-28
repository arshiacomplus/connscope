
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any

from connscope.adapters.models import (
    EngineType,
    ExecutableRequirement,
    ProtocolType,
    SecurityType,
    TransportType,
)
from connscope.core import Target

class VerificationStatus(StrEnum):
    CATALOGUED = "catalogued"
    CONFIG_VALIDATION_IMPLEMENTED = "config_validation_implemented"
    MOCKED_LIFECYCLE_TESTED = "mocked_lifecycle_tested"
    REAL_BINARY_CONFIG_VALIDATED = "real_binary_config_validated"
    REAL_PROCESS_LIFECYCLE_TESTED = "real_process_lifecycle_tested"
    LOCAL_DIAGNOSTIC_VERIFIED = "local_diagnostic_verified"
    REAL_TUNNEL_VERIFIED = "real_tunnel_verified"
    REAL_DATA_TRANSFER_TESTED = "real_data_transfer_tested"

class CoverageTier(StrEnum):
    CATALOGUED = "catalogued"
    SCHEMA_VALIDATED = "schema_validated"
    CONFIG_GENERATED = "config_generated"
    BINARY_VALIDATED = "binary_validated"
    LIVE_CONNECTED = "live_connected"
    DATA_TRANSFERRED = "data_transferred"

class ParameterType(StrEnum):
    STRING = "string"
    INT = "int"
    FLOAT = "float"
    BOOL = "bool"
    ENUM = "enum"
    HEX = "hex"
    UUID = "uuid"

class CapabilityCategory(StrEnum):
    PROTOCOL = "protocol"
    TRANSPORT = "transport"
    SECURITY = "security"
    PROTOCOL_VARIANT = "protocol_variant"
    PLUGIN = "plugin"
    GLOBAL_SETTING = "global_setting"
    RUNTIME_MODE = "runtime_mode"
    NETWORK_STACK = "network_stack"
    INBOUND_PROCESSING = "inbound_processing"
    DIAGNOSTIC = "diagnostic"
    MULTIPLEXING = "multiplexing"
    PACKET_MANIPULATION = "packet_manipulation"
    OBFUSCATION = "obfuscation"
    SYSTEM = "system"

class GenerationMode(StrEnum):
    EXPLICIT = "explicit"
    OFAT = "ofat"
    PAIRWISE = "pairwise"
    EXHAUSTIVE = "exhaustive"

@dataclass(frozen=True, slots=True)
class SourceReference:
    repository_url: str | None = None
    pinned_commit: str | None = None
    pinned_version: str | None = None
    requires_source_confirmation: bool = False
    notes: str = ""
    source_file: str | None = None
    section: str | None = None
    line_range: str | None = None
    reference_type: str | None = None
    verification_status: VerificationStatus | str | None = None
    discrepancy: str | None = None

    def to_dict(self) -> dict[str, Any]:
        v_status = self.verification_status.value if isinstance(self.verification_status, VerificationStatus) else self.verification_status
        return {
            "repository_url": self.repository_url,
            "pinned_commit": self.pinned_commit,
            "pinned_version": self.pinned_version,
            "requires_source_confirmation": self.requires_source_confirmation,
            "notes": self.notes,
            "source_file": self.source_file,
            "section": self.section,
            "line_range": self.line_range,
            "reference_type": self.reference_type,
            "verification_status": v_status,
            "discrepancy": self.discrepancy,
        }

@dataclass(frozen=True, slots=True)
class EngineDefinition:
    engine_id: str
    display_name: str
    executable: ExecutableRequirement | None = None
    supported_operations: tuple[str, ...] = ("client",)
    version_constraints: str | None = None
    tested_versions: tuple[str, ...] = ()
    evidence_status: VerificationStatus = VerificationStatus.CATALOGUED
    source_reference: SourceReference | None = None
    description: str = ""

    def __post_init__(self) -> None:
        if not self.engine_id or not self.engine_id.strip():
            raise ValueError("engine_id must not be empty")
        if not self.display_name or not self.display_name.strip():
            raise ValueError("display_name must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_id": self.engine_id,
            "display_name": self.display_name,
            "executable": {
                "binary_name": self.executable.binary_name,
                "min_version": self.executable.min_version,
                "lookup_paths": list(self.executable.lookup_paths),
            }
            if self.executable
            else None,
            "supported_operations": list(self.supported_operations),
            "version_constraints": self.version_constraints,
            "tested_versions": list(self.tested_versions),
            "evidence_status": self.evidence_status.value,
            "source_reference": self.source_reference.to_dict() if self.source_reference else None,
            "description": self.description,
        }

UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
HEX_REGEX = re.compile(r"^[0-9a-f]*$", re.IGNORECASE)

@dataclass(frozen=True, slots=True)
class ParameterDefinition:
    param_id: str
    display_name: str
    param_type: ParameterType
    description: str = ""
    default: Any = None
    required: bool = False
    allowed_values: tuple[Any, ...] | None = None
    min_value: float | int | None = None
    max_value: float | int | None = None
    applicable_engines: tuple[str, ...] | None = None
    applicable_profiles: tuple[str, ...] | None = None
    is_secret: bool = False
    documentation_ref: str = ""
    requires: dict[str, Any] | None = None
    conflicts_with: tuple[str, ...] = ()
    source_reference: SourceReference | None = None
    evidence_status: VerificationStatus = VerificationStatus.CATALOGUED
    impact_scope: str = "network_behavior"
    is_source_confirmed: bool = False
    uncertainty_notes: str = ""

    def __post_init__(self) -> None:
        if not self.param_id or not self.param_id.strip():
            raise ValueError("param_id must not be empty")
        if not self.display_name or not self.display_name.strip():
            raise ValueError("display_name must not be empty")
        if self.min_value is not None and self.max_value is not None and self.min_value > self.max_value:
            raise ValueError(f"min_value ({self.min_value}) cannot exceed max_value ({self.max_value})")

    def validate_value(self, value: Any, engine_id: str | None = None) -> Any:
        if value is None:
            if self.required:
                raise ValueError(f"Parameter '{self.param_id}' is required and cannot be None")
            return self.default

        if self.applicable_engines is not None and engine_id is not None:
            if engine_id not in self.applicable_engines:
                raise ValueError(
                    f"Parameter '{self.param_id}' is not supported by engine '{engine_id}'. "
                    f"Applicable engines: {', '.join(self.applicable_engines)}"
                )

        match self.param_type:
            case ParameterType.STRING:
                if not isinstance(value, str):
                    raise TypeError(f"Parameter '{self.param_id}' must be a string, got {type(value).__name__}")
                val_str = value.strip()
                if self.allowed_values is not None and val_str not in self.allowed_values:
                    raise ValueError(
                        f"Parameter '{self.param_id}' value '{val_str}' not in allowed values: "
                        f"{', '.join(map(str, self.allowed_values))}"
                    )
                return val_str

            case ParameterType.INT:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise TypeError(f"Parameter '{self.param_id}' must be an integer, got {type(value).__name__}")
                int_val = int(value)
                if float(int_val) != float(value):
                    raise ValueError(f"Parameter '{self.param_id}' must be an exact integer, got {value}")
                if self.min_value is not None and int_val < self.min_value:
                    raise ValueError(f"Parameter '{self.param_id}' must be >= {self.min_value}, got {int_val}")
                if self.max_value is not None and int_val > self.max_value:
                    raise ValueError(f"Parameter '{self.param_id}' must be <= {self.max_value}, got {int_val}")
                if self.allowed_values is not None and int_val not in self.allowed_values:
                    raise ValueError(f"Parameter '{self.param_id}' value {int_val} not in allowed values: {self.allowed_values}")
                return int_val

            case ParameterType.FLOAT:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise TypeError(f"Parameter '{self.param_id}' must be a float, got {type(value).__name__}")
                flt_val = float(value)
                if self.min_value is not None and flt_val < self.min_value:
                    raise ValueError(f"Parameter '{self.param_id}' must be >= {self.min_value}, got {flt_val}")
                if self.max_value is not None and flt_val > self.max_value:
                    raise ValueError(f"Parameter '{self.param_id}' must be <= {self.max_value}, got {flt_val}")
                return flt_val

            case ParameterType.BOOL:
                if not isinstance(value, bool):
                    if isinstance(value, str) and value.lower() in ("true", "1", "yes"):
                        return True
                    if isinstance(value, str) and value.lower() in ("false", "0", "no"):
                        return False
                    raise TypeError(f"Parameter '{self.param_id}' must be a boolean, got {type(value).__name__}")
                return value

            case ParameterType.ENUM:
                val_str = str(value)
                if self.allowed_values is not None and val_str not in self.allowed_values:
                    raise ValueError(
                        f"Parameter '{self.param_id}' value '{val_str}' not in allowed enum options: "
                        f"{', '.join(map(str, self.allowed_values))}"
                    )
                return val_str

            case ParameterType.UUID:
                if not isinstance(value, str):
                    raise TypeError(f"Parameter '{self.param_id}' must be a UUID string, got {type(value).__name__}")
                u_str = value.strip().lower()
                if not UUID_REGEX.match(u_str):
                    raise ValueError(f"Parameter '{self.param_id}' must be a valid RFC 4122 UUID, got '{value}'")
                return u_str

            case ParameterType.HEX:
                if not isinstance(value, str):
                    raise TypeError(f"Parameter '{self.param_id}' must be a hex string, got {type(value).__name__}")
                h_str = value.strip().lower()
                if not HEX_REGEX.match(h_str):
                    raise ValueError(f"Parameter '{self.param_id}' must contain only hexadecimal digits, got '{value}'")
                if len(h_str) % 2 != 0:
                    raise ValueError(f"Parameter '{self.param_id}' must have an even length (full bytes), got len={len(h_str)}")
                if self.max_value is not None and len(h_str) > self.max_value:
                    raise ValueError(f"Parameter '{self.param_id}' length exceeds maximum {self.max_value} characters")
                return h_str

        return value

    def to_dict(self) -> dict[str, Any]:
        return {
            "param_id": self.param_id,
            "display_name": self.display_name,
            "param_type": self.param_type.value,
            "description": self.description,
            "default": self.default,
            "required": self.required,
            "allowed_values": list(self.allowed_values) if self.allowed_values is not None else None,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "applicable_engines": list(self.applicable_engines) if self.applicable_engines is not None else None,
            "applicable_profiles": list(self.applicable_profiles) if self.applicable_profiles is not None else None,
            "is_secret": self.is_secret,
            "documentation_ref": self.documentation_ref,
            "requires": self.requires,
            "conflicts_with": list(self.conflicts_with),
            "source_reference": self.source_reference.to_dict() if self.source_reference else None,
            "evidence_status": self.evidence_status.value if isinstance(self.evidence_status, VerificationStatus) else str(self.evidence_status),
            "impact_scope": self.impact_scope,
            "is_source_confirmed": self.is_source_confirmed,
            "uncertainty_notes": self.uncertainty_notes,
        }

@dataclass(frozen=True, slots=True)
class ParameterVariant:
    variant_id: str
    display_name: str
    description: str = ""
    overrides: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.variant_id or not self.variant_id.strip():
            raise ValueError("variant_id must not be empty")
        if not self.display_name or not self.display_name.strip():
            raise ValueError("display_name must not be empty")

    def to_dict(self, redact_secrets: bool = False, param_definitions: dict[str, ParameterDefinition] | None = None) -> dict[str, Any]:
        clean_overrides = dict(self.overrides)
        if redact_secrets and param_definitions:
            for k in clean_overrides:
                pdef = param_definitions.get(k)
                if pdef and pdef.is_secret:
                    clean_overrides[k] = "[REDACTED]"
        return {
            "variant_id": self.variant_id,
            "display_name": self.display_name,
            "description": self.description,
            "overrides": clean_overrides,
        }

@dataclass(frozen=True, slots=True)
class ProtocolProfile:
    profile_id: str
    display_name: str
    protocol: ProtocolType | str
    transport: TransportType | str
    security: SecurityType | str
    parameters: tuple[ParameterDefinition, ...] = ()
    default_variants: tuple[ParameterVariant, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not self.profile_id or not self.profile_id.strip():
            raise ValueError("profile_id must not be empty")
        if not self.display_name or not self.display_name.strip():
            raise ValueError("display_name must not be empty")

    def get_parameter(self, param_id: str) -> ParameterDefinition | None:
        for p in self.parameters:
            if p.param_id == param_id:
                return p
        return None

    def get_variant(self, variant_id: str) -> ParameterVariant | None:
        for v in self.default_variants:
            if v.variant_id == variant_id:
                return v
        return None

    def to_dict(self) -> dict[str, Any]:
        proto = self.protocol.value if isinstance(self.protocol, ProtocolType) else str(self.protocol)
        trans = self.transport.value if isinstance(self.transport, TransportType) else str(self.transport)
        sec = self.security.value if isinstance(self.security, SecurityType) else str(self.security)
        param_defs = {p.param_id: p for p in self.parameters}
        return {
            "profile_id": self.profile_id,
            "display_name": self.display_name,
            "protocol": proto,
            "transport": trans,
            "security": sec,
            "parameters": [p.to_dict() for p in self.parameters],
            "default_variants": [v.to_dict(param_definitions=param_defs) for v in self.default_variants],
            "description": self.description,
        }

@dataclass(frozen=True, slots=True)
class EngineProfileCompatibility:
    engine_id: str
    profile_id: str
    status: VerificationStatus
    min_version: str | None = None
    max_version: str | None = None
    required_features: tuple[str, ...] = ()
    conflicting_features: tuple[str, ...] = ()
    parameter_constraints: dict[str, Any] = field(default_factory=dict)
    adapter_id: str | None = None
    known_limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_id": self.engine_id,
            "profile_id": self.profile_id,
            "status": self.status.value,
            "min_version": self.min_version,
            "max_version": self.max_version,
            "required_features": list(self.required_features),
            "conflicting_features": list(self.conflicting_features),
            "parameter_constraints": self.parameter_constraints,
            "adapter_id": self.adapter_id,
            "known_limitations": list(self.known_limitations),
        }

@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    capability_id: str
    display_name: str
    engine_id: str
    category: CapabilityCategory | str
    protocol: ProtocolType | str | None = None
    transport: TransportType | str | None = None
    security: SecurityType | str | None = None
    supported_versions: str | None = None
    parameters: tuple[ParameterDefinition, ...] = ()
    status: VerificationStatus = VerificationStatus.CATALOGUED
    dependencies: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    config_mapping: str = ""
    source_reference: SourceReference | None = None
    is_executable: bool = False
    unsupported_reason: str | None = None
    description: str = ""
    standards_reference: str | None = None

    def __post_init__(self) -> None:
        if not self.capability_id or not self.capability_id.strip():
            raise ValueError("capability_id must not be empty")
        if not self.display_name or not self.display_name.strip():
            raise ValueError("display_name must not be empty")
        if not self.engine_id or not self.engine_id.strip():
            raise ValueError("engine_id must not be empty")
        if not self.category or not str(self.category).strip():
            raise ValueError("category must not be empty")
        valid_cats = {c.value for c in CapabilityCategory}
        if str(self.category) not in valid_cats:
            raise ValueError(f"Invalid capability category '{self.category}'. Allowed categories: {', '.join(sorted(valid_cats))}")

    def to_dict(self) -> dict[str, Any]:
        proto = self.protocol.value if isinstance(self.protocol, ProtocolType) else (str(self.protocol) if self.protocol else None)
        trans = self.transport.value if isinstance(self.transport, TransportType) else (str(self.transport) if self.transport else None)
        sec = self.security.value if isinstance(self.security, SecurityType) else (str(self.security) if self.security else None)
        cat_str = self.category.value if isinstance(self.category, CapabilityCategory) else str(self.category)
        return {
            "capability_id": self.capability_id,
            "display_name": self.display_name,
            "engine_id": self.engine_id,
            "category": cat_str,
            "protocol": proto,
            "transport": trans,
            "security": sec,
            "supported_versions": self.supported_versions,
            "parameters": [p.to_dict() for p in self.parameters],
            "status": self.status.value if isinstance(self.status, VerificationStatus) else str(self.status),
            "dependencies": list(self.dependencies),
            "exclusions": list(self.exclusions),
            "config_mapping": self.config_mapping,
            "source_reference": self.source_reference.to_dict() if self.source_reference else None,
            "is_executable": self.is_executable,
            "unsupported_reason": self.unsupported_reason,
            "description": self.description,
            "standards_reference": self.standards_reference,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityDefinition:
        params: list[ParameterDefinition] = []
        for p in data.get("parameters", []):
            p_src = None
            if p.get("source_reference"):
                ps = p["source_reference"]
                p_src = SourceReference(
                    repository_url=ps.get("repository_url"),
                    pinned_commit=ps.get("pinned_commit"),
                    pinned_version=ps.get("pinned_version"),
                    requires_source_confirmation=bool(ps.get("requires_source_confirmation", False)),
                    notes=ps.get("notes", ""),
                    source_file=ps.get("source_file"),
                    section=ps.get("section"),
                    line_range=ps.get("line_range"),
                    reference_type=ps.get("reference_type"),
                    verification_status=ps.get("verification_status"),
                    discrepancy=ps.get("discrepancy"),
                )
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
                    source_reference=p_src,
                    evidence_status=VerificationStatus(p.get("evidence_status", VerificationStatus.CATALOGUED.value)),
                    impact_scope=p.get("impact_scope", "network_behavior"),
                    is_source_confirmed=bool(p.get("is_source_confirmed", False)),
                    uncertainty_notes=p.get("uncertainty_notes", ""),
                )
            )
        src_ref = None
        if data.get("source_reference"):
            sdata = data["source_reference"]
            src_ref = SourceReference(
                repository_url=sdata.get("repository_url"),
                pinned_commit=sdata.get("pinned_commit"),
                pinned_version=sdata.get("pinned_version"),
                requires_source_confirmation=bool(sdata.get("requires_source_confirmation", False)),
                notes=sdata.get("notes", ""),
                source_file=sdata.get("source_file"),
                section=sdata.get("section"),
                line_range=sdata.get("line_range"),
                reference_type=sdata.get("reference_type"),
                verification_status=sdata.get("verification_status"),
                discrepancy=sdata.get("discrepancy"),
            )
        proto = data.get("protocol")
        if proto:
            try:
                proto = ProtocolType(proto)
            except ValueError:
                pass
        trans = data.get("transport")
        if trans:
            try:
                trans = TransportType(trans)
            except ValueError:
                pass
        sec = data.get("security")
        if sec:
            try:
                sec = SecurityType(sec)
            except ValueError:
                pass
        return cls(
            capability_id=data["capability_id"],
            display_name=data["display_name"],
            engine_id=data["engine_id"],
            category=data.get("category", "protocol"),
            protocol=proto,
            transport=trans,
            security=sec,
            supported_versions=data.get("supported_versions"),
            parameters=tuple(params),
            status=VerificationStatus(data.get("status", VerificationStatus.CATALOGUED.value)),
            dependencies=tuple(data.get("dependencies", ())),
            exclusions=tuple(data.get("exclusions", ())),
            config_mapping=data.get("config_mapping", ""),
            source_reference=src_ref,
            is_executable=bool(data.get("is_executable", False)),
            unsupported_reason=data.get("unsupported_reason"),
            description=data.get("description", ""),
            standards_reference=data.get("standards_reference"),
        )

class NodeType(StrEnum):
    LOCAL = "local"
    REMOTE_AGENT = "remote_agent"
    SANDBOX = "sandbox"

@dataclass(frozen=True, slots=True)
class MeasurementNode:
    node_id: str
    name: str = ""
    node_type: str | NodeType = NodeType.LOCAL
    endpoint_url: str | None = None
    agent_endpoint: str | None = None
    auth_token_ref: str | None = None
    supported_adapter_ids: tuple[str, ...] = ()
    allowed_execution_modes: tuple[str, ...] = ("local_proxy",)
    reported_software_versions: dict[str, str] = field(default_factory=dict)
    route_context: dict[str, Any] = field(default_factory=dict)
    operator_labels: dict[str, str] = field(default_factory=dict)
    evidence_status: VerificationStatus = VerificationStatus.CATALOGUED
    connection_timeout_s: float = 10.0
    execution_timeout_s: float = 30.0
    description: str = ""

    def __post_init__(self) -> None:
        if not self.node_id or not self.node_id.strip():
            raise ValueError("node_id must be a non-empty string")
        if any(c.isspace() for c in self.node_id):
            raise ValueError(f"node_id must not contain whitespace: {self.node_id!r}")
        if not re.match(r"^[a-zA-Z0-9_\-]+$", self.node_id):
            raise ValueError(f"node_id must contain only alphanumeric characters, underscores, or hyphens: {self.node_id!r}")

        if not self.name or not self.name.strip():
            object.__setattr__(self, "name", self.node_id)

        nt = self.node_type.value if isinstance(self.node_type, NodeType) else str(self.node_type)
        object.__setattr__(self, "node_type", nt)

        url = self.endpoint_url or self.agent_endpoint
        object.__setattr__(self, "endpoint_url", url)
        object.__setattr__(self, "agent_endpoint", url)

        if isinstance(self.supported_adapter_ids, list):
            object.__setattr__(self, "supported_adapter_ids", tuple(self.supported_adapter_ids))
        if isinstance(self.allowed_execution_modes, list):
            object.__setattr__(self, "allowed_execution_modes", tuple(self.allowed_execution_modes))

        if self.node_type not in ("local", "remote_agent", "sandbox"):
            raise ValueError(f"Invalid node_type '{self.node_type}'. Must be 'local', 'remote_agent', or 'sandbox'")
        if self.node_type == "remote_agent" and not self.endpoint_url:
            raise ValueError("Remote agent node requires endpoint_url")
        if self.endpoint_url:
            if "@" in self.endpoint_url:
                raise ValueError("endpoint_url must not contain embedded userinfo or credentials")
            if self.node_type == "remote_agent":
                if not (
                    self.endpoint_url.startswith("https://")
                    or self.endpoint_url.startswith("http://127.0.0.1")
                    or self.endpoint_url.startswith("http://[::1]")
                    or self.endpoint_url.startswith("http://localhost")
                ):
                    raise ValueError("Remote agent endpoint must use HTTPS (plain HTTP is restricted to loopback)")

        if self.auth_token_ref:
            if self.auth_token_ref.startswith("Bearer ") or len(self.auth_token_ref) > 128:
                raise ValueError("auth_token_ref must be an identifier reference (e.g. environment variable name), not a raw Bearer token")
        if (
            isinstance(self.connection_timeout_s, bool)
            or not isinstance(self.connection_timeout_s, (int, float))
            or not math.isfinite(self.connection_timeout_s)
            or self.connection_timeout_s <= 0
        ):
            raise ValueError("connection_timeout_s must be a positive finite number")
        if (
            isinstance(self.execution_timeout_s, bool)
            or not isinstance(self.execution_timeout_s, (int, float))
            or not math.isfinite(self.execution_timeout_s)
            or self.execution_timeout_s <= 0
        ):
            raise ValueError("execution_timeout_s must be a positive finite number")

    @property
    def is_local(self) -> bool:
        return self.node_type in ("local", NodeType.LOCAL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "node_type": self.node_type,
            "endpoint_url": self.endpoint_url,
            "agent_endpoint": self.endpoint_url,
            "auth_token_ref": self.auth_token_ref,
            "supported_adapter_ids": list(self.supported_adapter_ids),
            "allowed_execution_modes": list(self.allowed_execution_modes),
            "reported_software_versions": dict(self.reported_software_versions),
            "route_context": dict(self.route_context),
            "operator_labels": dict(self.operator_labels),
            "evidence_status": self.evidence_status.value if isinstance(self.evidence_status, VerificationStatus) else str(self.evidence_status),
            "connection_timeout_s": self.connection_timeout_s,
            "execution_timeout_s": self.execution_timeout_s,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MeasurementNode:
        if not isinstance(data, dict):
            raise ValueError("MeasurementNode data must be a dictionary")
        evidence = data.get("evidence_status", VerificationStatus.CATALOGUED.value)
        if isinstance(evidence, str):
            try:
                evidence_status = VerificationStatus(evidence)
            except ValueError:
                evidence_status = VerificationStatus.CATALOGUED
        else:
            evidence_status = VerificationStatus.CATALOGUED

        return cls(
            node_id=data["node_id"],
            name=data.get("name", data["node_id"]),
            node_type=data.get("node_type", "local"),
            endpoint_url=data.get("endpoint_url") or data.get("agent_endpoint"),
            auth_token_ref=data.get("auth_token_ref"),
            supported_adapter_ids=tuple(data.get("supported_adapter_ids", ())),
            allowed_execution_modes=tuple(data.get("allowed_execution_modes", ("local_proxy",))),
            reported_software_versions=dict(data.get("reported_software_versions", {})),
            route_context=dict(data.get("route_context", {})),
            operator_labels=dict(data.get("operator_labels", {})),
            evidence_status=evidence_status,
            connection_timeout_s=float(data.get("connection_timeout_s", 10.0)),
            execution_timeout_s=float(data.get("execution_timeout_s", 30.0)),
            description=data.get("description", ""),
        )

@dataclass(frozen=True, slots=True)
class MeasurementWorkload:
    workload_type: str = "http_get_204"
    test_url: str = "http://cp.cloudflare.com/generate_204"
    timeout_s: float = 10.0
    repetitions: int = 1
    verify_cert: bool = True
    extra_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workload_type": self.workload_type,
            "test_url": self.test_url,
            "timeout_s": self.timeout_s,
            "repetitions": self.repetitions,
            "verify_cert": self.verify_cert,
            "extra_headers": dict(self.extra_headers),
        }

@dataclass(frozen=True, slots=True)
class MeasurementProfile:
    profile_id: str
    name: str
    node: MeasurementNode
    workload: MeasurementWorkload = field(default_factory=MeasurementWorkload)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "node": self.node.to_dict(),
            "workload": self.workload.to_dict(),
            "description": self.description,
        }

@dataclass(frozen=True, slots=True)
class Scenario:
    scenario_id: str
    engine_id: str
    profile_id: str
    variant_id: str
    node: MeasurementNode
    target: Target
    workload: MeasurementWorkload
    resolved_config: dict[str, Any]
    status: VerificationStatus
    adapter_id: str | None = None
    is_valid: bool = True
    exclusion_reason: str | None = None
    generation_mode: GenerationMode = GenerationMode.EXPLICIT
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_redacted_config(self, secret_keys: set[str] | None = None) -> dict[str, Any]:
        clean = dict(self.resolved_config)
        s_keys = secret_keys or {
            "uuid", "password", "public_key", "private_key", "preshared_key",
            "token", "auth_token", "secret", "obfuscation_seed",
            "client_key", "auth_password", "tls_auth_key", "tls_crypt_key",
        }
        for k in clean:
            if k in s_keys:
                clean[k] = "[REDACTED]"
        return clean

    def to_dict(self, redact_secrets: bool = True, secret_keys: set[str] | None = None) -> dict[str, Any]:
        config_to_show = self.get_redacted_config(secret_keys) if redact_secrets else dict(self.resolved_config)
        return {
            "scenario_id": self.scenario_id,
            "engine_id": self.engine_id,
            "profile_id": self.profile_id,
            "variant_id": self.variant_id,
            "node": self.node.to_dict(),
            "target": {
                "host": self.target.host,
                "port": self.target.port,
            },
            "workload": self.workload.to_dict(),
            "resolved_config": config_to_show,
            "status": self.status.value,
            "adapter_id": self.adapter_id,
            "is_valid": self.is_valid,
            "exclusion_reason": self.exclusion_reason,
            "generation_mode": self.generation_mode.value,
            "metadata": dict(self.metadata),
        }

@dataclass(frozen=True, slots=True)
class MatrixPlan:
    plan_id: str
    generation_mode: GenerationMode
    scenarios: tuple[Scenario, ...]
    estimated_count: int
    actual_count: int
    deduplicated_count: int
    invalid_count: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, redact_secrets: bool = True) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "generation_mode": self.generation_mode.value,
            "estimated_count": self.estimated_count,
            "actual_count": self.actual_count,
            "deduplicated_count": self.deduplicated_count,
            "invalid_count": self.invalid_count,
            "metadata": dict(self.metadata),
            "scenarios": [s.to_dict(redact_secrets=redact_secrets) for s in self.scenarios],
        }
