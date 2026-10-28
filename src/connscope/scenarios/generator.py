
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any

from connscope.adapters.models import ExecutableRequirement
from connscope.agent.protocol import PROHIBITED_REMOTE_ADAPTERS
from connscope.core import Target
from .catalog import ProtocolCatalog, create_default_protocol_catalog
from .models import (
    EngineDefinition,
    EngineProfileCompatibility,
    GenerationMode,
    MatrixPlan,
    MeasurementNode,
    MeasurementWorkload,
    NodeType,
    ParameterDefinition,
    ParameterVariant,
    ProtocolProfile,
    Scenario,
    VerificationStatus,
)
from .parameter_coverage import (
    BASELINE_PROFILE_CONFIGS,
    categorize_parameter,
    get_parameter_invalid_test_values,
    get_parameter_test_variants,
)

class MatrixSizeExceededError(ValueError):
    pass

class ScenarioGenerator:

    def __init__(
        self,
        catalog: ProtocolCatalog | None = None,
        max_scenarios: int = 100,
        allow_exhaustive: bool = False,
    ) -> None:
        self.catalog = catalog if catalog is not None else create_default_protocol_catalog()
        self.max_scenarios = max(1, int(max_scenarios))
        self.allow_exhaustive = allow_exhaustive

    def create_scenario(
        self,
        engine_id: str,
        profile_id: str,
        variant_id: str,
        target: Target,
        node: MeasurementNode,
        workload: MeasurementWorkload,
        parameter_overrides: dict[str, Any] | None = None,
        generation_mode: GenerationMode = GenerationMode.EXPLICIT,
        extra_metadata: dict[str, Any] | None = None,
    ) -> Scenario:
        engine = self.catalog.get_engine(engine_id)
        profile = self.catalog.get_profile(profile_id)
        compat = self.catalog.get_compatibility(engine_id, profile_id)

        is_valid = True
        exclusion_reason: str | None = None
        adapter_id: str | None = None
        evidence_status = VerificationStatus.CATALOGUED

        if not engine:
            is_valid = False
            exclusion_reason = f"Unknown engine '{engine_id}'"
        elif not profile:
            is_valid = False
            exclusion_reason = f"Unknown profile '{profile_id}'"
        elif not compat:
            is_valid = False
            exclusion_reason = f"Engine '{engine_id}' does not support protocol profile '{profile_id}'"
        else:
            adapter_id = compat.adapter_id
            evidence_status = compat.status

        if is_valid and adapter_id:
            if node.node_type == NodeType.REMOTE_AGENT.value:
                if adapter_id in PROHIBITED_REMOTE_ADAPTERS:
                    is_valid = False
                    exclusion_reason = f"Layer-3 adapter '{adapter_id}' is not supported for remote execution on node '{node.node_id}'"
                elif node.supported_adapter_ids and adapter_id not in node.supported_adapter_ids:
                    is_valid = False
                    exclusion_reason = f"Node '{node.node_id}' does not support adapter '{adapter_id}'"
            elif node.node_type == NodeType.LOCAL.value:
                if node.supported_adapter_ids and adapter_id not in node.supported_adapter_ids:
                    is_valid = False
                    exclusion_reason = f"Node '{node.node_id}' does not support adapter '{adapter_id}'"

        resolved_config: dict[str, Any] = {}
        if profile:
            for p in profile.parameters:
                if p.default is not None:
                    resolved_config[p.param_id] = p.default

            variant = profile.get_variant(variant_id)
            if variant:
                resolved_config.update(variant.overrides)
            elif (
                variant_id != "baseline"
                and variant_id != "custom"
                and not variant_id.startswith("param_")
                and not variant_id.startswith("pairwise_")
                and not variant_id.startswith("invalid_")
            ):
                is_valid = False
                exclusion_reason = f"Unknown variant '{variant_id}' for profile '{profile_id}'"

            if parameter_overrides:
                resolved_config.update(parameter_overrides)

            if is_valid:
                param_defs = {p.param_id: p for p in profile.parameters}
                for param_id, val in list(resolved_config.items()):
                    pdef = param_defs.get(param_id)
                    if not pdef:
                        is_valid = False
                        exclusion_reason = f"Unknown parameter '{param_id}' in configuration"
                        break

                    try:
                        norm_val = pdef.validate_value(val, engine_id=engine_id)
                        resolved_config[param_id] = norm_val
                    except (TypeError, ValueError) as exc:
                        is_valid = False
                        exclusion_reason = f"Validation failed for parameter '{param_id}': {exc}"
                        break

                    if pdef.requires:
                        for req_key, req_val in pdef.requires.items():
                            if resolved_config.get(req_key) != req_val:
                                is_valid = False
                                exclusion_reason = f"Parameter '{param_id}' requires '{req_key}'={req_val}"
                                break

                    for conf_param in pdef.conflicts_with:
                        if conf_param in resolved_config and resolved_config[conf_param] is not None:
                            is_valid = False
                            exclusion_reason = f"Parameter '{param_id}' conflicts with '{conf_param}'"
                            break

                if is_valid:
                    for p in profile.parameters:
                        if p.required and (p.param_id not in resolved_config or resolved_config[p.param_id] is None):
                            is_valid = False
                            exclusion_reason = f"Missing required parameter '{p.param_id}'"
                            break

                if is_valid and compat and compat.parameter_constraints:
                    for c_param, allowed_in_engine in compat.parameter_constraints.items():
                        if c_param in resolved_config:
                            actual_val = resolved_config[c_param]
                            if actual_val not in allowed_in_engine:
                                is_valid = False
                                exclusion_reason = (
                                    f"Engine '{engine_id}' rejects '{c_param}'='{actual_val}'. "
                                    f"Allowed: {', '.join(map(str, allowed_in_engine))}"
                                )
                                break

        canonical_dict = {
            "engine_id": engine_id,
            "profile_id": profile_id,
            "variant_id": variant_id,
            "target": f"{target.host}:{target.port}",
            "node_id": node.node_id,
            "config": resolved_config,
            "workload": workload.to_dict(),
        }
        content_hash = hashlib.sha256(json.dumps(canonical_dict, sort_keys=True).encode("utf-8")).hexdigest()[:8]
        scenario_id = f"scn_{engine_id}_{profile_id}_{variant_id}_{content_hash}"

        meta = dict(extra_metadata or {})
        return Scenario(
            scenario_id=scenario_id,
            engine_id=engine_id,
            profile_id=profile_id,
            variant_id=variant_id,
            node=node,
            target=target,
            workload=workload,
            resolved_config=resolved_config,
            status=evidence_status,
            adapter_id=adapter_id,
            is_valid=is_valid,
            exclusion_reason=exclusion_reason,
            generation_mode=generation_mode,
            metadata=meta,
        )

    def generate_explicit(
        self,
        engine_ids: list[str],
        profile_ids: list[str],
        variant_ids: list[str] | None = None,
        target: Target | None = None,
        node: MeasurementNode | None = None,
        nodes: Sequence[MeasurementNode] | None = None,
        workload: MeasurementWorkload | None = None,
        parameter_overrides: dict[str, Any] | None = None,
    ) -> MatrixPlan:
        effective_target = target or Target(host="127.0.0.1", port=443)
        if nodes is not None:
            target_nodes = tuple(nodes)
        elif node is not None:
            target_nodes = (node,)
        else:
            default_node = self.catalog.get_node("local") or MeasurementNode(node_id="local", name="Localhost")
            target_nodes = (default_node,)
        effective_workload = workload or MeasurementWorkload()

        est = self.estimate_count(engine_ids, profile_ids, variant_ids, GenerationMode.EXPLICIT, node_count=len(target_nodes))
        if est > self.max_scenarios and not self.allow_exhaustive:
            raise MatrixSizeExceededError(
                f"Generated scenario count ({est}) exceeds maximum allowed ({self.max_scenarios}). "
                "Increase max_scenarios or pass allow_exhaustive=True."
            )

        scenarios: list[Scenario] = []
        seen_hashes: set[str] = set()
        dedup_count = 0
        invalid_count = 0

        for eff_node in target_nodes:
            for eng_id in sorted(engine_ids):
                for prof_id in sorted(profile_ids):
                    prof = self.catalog.get_profile(prof_id)
                    var_list = variant_ids
                    if not var_list:
                        var_list = [v.variant_id for v in prof.default_variants] if prof and prof.default_variants else ["baseline"]

                    for var_id in sorted(var_list):
                        scn = self.create_scenario(
                            engine_id=eng_id,
                            profile_id=prof_id,
                            variant_id=var_id,
                            target=effective_target,
                            node=eff_node,
                            workload=effective_workload,
                            parameter_overrides=parameter_overrides,
                            generation_mode=GenerationMode.EXPLICIT,
                        )
                        cfg_sig = f"{eff_node.node_id}:{scn.engine_id}:{scn.profile_id}:{scn.target.host}:{scn.target.port}:{json.dumps(scn.resolved_config, sort_keys=True)}"
                        if cfg_sig in seen_hashes:
                            dedup_count += 1
                            continue
                        seen_hashes.add(cfg_sig)

                        if not scn.is_valid:
                            invalid_count += 1
                        scenarios.append(scn)

        return MatrixPlan(
            plan_id=f"plan_explicit_{hashlib.sha256(json.dumps([s.scenario_id for s in scenarios]).encode()).hexdigest()[:8]}",
            generation_mode=GenerationMode.EXPLICIT,
            scenarios=tuple(scenarios),
            estimated_count=est,
            actual_count=len(scenarios),
            deduplicated_count=dedup_count,
            invalid_count=invalid_count,
            metadata={"strategy": "explicit_selection"},
        )

    def generate_ofat(
        self,
        engine_id: str,
        profile_id: str,
        baseline_variant_id: str = "baseline",
        target: Target | None = None,
        node: MeasurementNode | None = None,
        workload: MeasurementWorkload | None = None,
        factors_to_vary: list[str] | None = None,
        baseline_overrides: dict[str, Any] | None = None,
    ) -> MatrixPlan:
        effective_target = target or Target(host="127.0.0.1", port=443)
        effective_node = node or self.catalog.get_node("local") or MeasurementNode(node_id="local", name="Localhost")
        effective_workload = workload or MeasurementWorkload()

        profile = self.catalog.get_profile(profile_id)
        if not profile:
            raise ValueError(f"Unknown profile '{profile_id}' for OFAT generation")

        baseline_scn = self.create_scenario(
            engine_id=engine_id,
            profile_id=profile_id,
            variant_id=baseline_variant_id,
            target=effective_target,
            node=effective_node,
            workload=effective_workload,
            parameter_overrides=baseline_overrides,
            generation_mode=GenerationMode.OFAT,
            extra_metadata={"is_baseline": True, "varied_factor": "baseline"},
        )

        scenarios = [baseline_scn]
        seen_configs = {json.dumps(baseline_scn.resolved_config, sort_keys=True)}
        dedup_count = 0
        invalid_count = 1 if not baseline_scn.is_valid else 0

        if factors_to_vary is None:
            factors_to_vary = ["variant"]

        for factor in sorted(factors_to_vary):
            if factor == "variant":
                for v in profile.default_variants:
                    if v.variant_id == baseline_variant_id:
                        continue
                    scn = self.create_scenario(
                        engine_id=engine_id,
                        profile_id=profile_id,
                        variant_id=v.variant_id,
                        target=effective_target,
                        node=effective_node,
                        workload=effective_workload,
                        parameter_overrides=baseline_overrides,
                        generation_mode=GenerationMode.OFAT,
                        extra_metadata={"is_baseline": False, "varied_factor": f"variant:{v.variant_id}"},
                    )
                    cfg_str = json.dumps(scn.resolved_config, sort_keys=True)
                    if cfg_str in seen_configs:
                        dedup_count += 1
                        continue
                    seen_configs.add(cfg_str)
                    if not scn.is_valid:
                        invalid_count += 1
                    scenarios.append(scn)

            elif factor == "engine":
                for comp in self.catalog.list_compatibilities():
                    if comp.profile_id == profile_id and comp.engine_id != engine_id:
                        scn = self.create_scenario(
                            engine_id=comp.engine_id,
                            profile_id=profile_id,
                            variant_id=baseline_variant_id,
                            target=effective_target,
                            node=effective_node,
                            workload=effective_workload,
                            parameter_overrides=baseline_overrides,
                            generation_mode=GenerationMode.OFAT,
                            extra_metadata={"is_baseline": False, "varied_factor": f"engine:{comp.engine_id}"},
                        )
                        cfg_str = f"{comp.engine_id}:{json.dumps(scn.resolved_config, sort_keys=True)}"
                        if cfg_str in seen_configs:
                            dedup_count += 1
                            continue
                        seen_configs.add(cfg_str)
                        if not scn.is_valid:
                            invalid_count += 1
                        scenarios.append(scn)

            else:
                pdef = profile.get_parameter(factor)
                if pdef and pdef.allowed_values:
                    base_val = baseline_scn.resolved_config.get(factor)
                    for alt_val in pdef.allowed_values:
                        if alt_val == base_val:
                            continue
                        ov = dict(baseline_overrides or {})
                        ov[factor] = alt_val
                        scn = self.create_scenario(
                            engine_id=engine_id,
                            profile_id=profile_id,
                            variant_id="custom",
                            target=effective_target,
                            node=effective_node,
                            workload=effective_workload,
                            parameter_overrides=ov,
                            generation_mode=GenerationMode.OFAT,
                            extra_metadata={"is_baseline": False, "varied_factor": f"{factor}:{alt_val}"},
                        )
                        cfg_str = json.dumps(scn.resolved_config, sort_keys=True)
                        if cfg_str in seen_configs:
                            dedup_count += 1
                            continue
                        seen_configs.add(cfg_str)
                        if not scn.is_valid:
                            invalid_count += 1
                        scenarios.append(scn)

        return MatrixPlan(
            plan_id=f"plan_ofat_{baseline_scn.scenario_id[:16]}",
            generation_mode=GenerationMode.OFAT,
            scenarios=tuple(scenarios),
            estimated_count=len(scenarios) + dedup_count,
            actual_count=len(scenarios),
            deduplicated_count=dedup_count,
            invalid_count=invalid_count,
            metadata={"strategy": "one_factor_at_a_time", "baseline": baseline_scn.scenario_id},
        )

    def generate_pairwise(
        self,
        engine_ids: list[str],
        profile_ids: list[str],
        factors: dict[str, list[Any]] | None = None,
        target: Target | None = None,
        node: MeasurementNode | None = None,
        workload: MeasurementWorkload | None = None,
        base_overrides: dict[str, Any] | None = None,
    ) -> MatrixPlan:
        effective_target = target or Target(host="127.0.0.1", port=443)
        effective_node = node or self.catalog.get_node("local") or MeasurementNode(node_id="local", name="Localhost")
        effective_workload = workload or MeasurementWorkload()

        domain_dict: dict[str, list[Any]] = {}
        domain_dict["engine"] = sorted(engine_ids)
        domain_dict["profile"] = sorted(profile_ids)

        all_variants: set[str] = set()
        for pid in profile_ids:
            prof = self.catalog.get_profile(pid)
            if prof:
                for v in prof.default_variants:
                    all_variants.add(v.variant_id)
        if not all_variants:
            all_variants.add("baseline")
        domain_dict["variant"] = sorted(all_variants)

        if factors:
            for fk, fvals in factors.items():
                domain_dict[fk] = sorted(fvals)

        factor_names = sorted(domain_dict.keys())

        all_pairs: set[tuple[tuple[str, Any], tuple[str, Any]]] = set()
        for i in range(len(factor_names)):
            for j in range(i + 1, len(factor_names)):
                fa, fb = factor_names[i], factor_names[j]
                for va in domain_dict[fa]:
                    for vb in domain_dict[fb]:
                        all_pairs.add(((fa, va), (fb, vb)))

        uncovered = set(all_pairs)
        test_vectors: list[dict[str, Any]] = []

        while uncovered:
            best_vector: dict[str, Any] | None = None
            best_new_coverage = -1

            sorted_uncovered = sorted(
                uncovered,
                key=lambda p: (p[0][0], str(p[0][1]), p[1][0], str(p[1][1])),
            )
            seed_pair = sorted_uncovered[0]

            seed_vector: dict[str, Any] = {
                seed_pair[0][0]: seed_pair[0][1],
                seed_pair[1][0]: seed_pair[1][1],
            }

            for fn in factor_names:
                if fn in seed_vector:
                    continue
                best_val = None
                best_val_cov = -1
                for cand_val in domain_dict[fn]:
                    cnt = sum(
                        1 for assigned_f, assigned_v in seed_vector.items()
                        if tuple(sorted(((fn, cand_val), (assigned_f, assigned_v)))) in uncovered
                    )
                    if cnt > best_val_cov:
                        best_val_cov = cnt
                        best_val = cand_val
                seed_vector[fn] = best_val if best_val is not None else domain_dict[fn][0]

            best_vector = seed_vector

            covered_now = set()
            for i in range(len(factor_names)):
                for j in range(i + 1, len(factor_names)):
                    fa, fb = factor_names[i], factor_names[j]
                    p = tuple(sorted(((fa, best_vector[fa]), (fb, best_vector[fb]))))
                    if p in uncovered:
                        covered_now.add(p)

            uncovered -= covered_now
            test_vectors.append(best_vector)

            if not covered_now:
                break

        scenarios: list[Scenario] = []
        dedup_count = 0
        invalid_count = 0
        seen_hashes: set[str] = set()

        for vec in test_vectors:
            eng_id = str(vec["engine"])
            prof_id = str(vec["profile"])
            var_id = str(vec["variant"])

            overrides = dict(base_overrides or {})
            for fk, fval in vec.items():
                if fk not in ("engine", "profile", "variant"):
                    overrides[fk] = fval

            scn = self.create_scenario(
                engine_id=eng_id,
                profile_id=prof_id,
                variant_id=var_id,
                target=effective_target,
                node=effective_node,
                workload=effective_workload,
                parameter_overrides=overrides,
                generation_mode=GenerationMode.PAIRWISE,
                extra_metadata={"pairwise_vector": vec},
            )

            cfg_sig = f"{scn.engine_id}:{scn.profile_id}:{scn.target.host}:{scn.target.port}:{json.dumps(scn.resolved_config, sort_keys=True)}"
            if cfg_sig in seen_hashes:
                dedup_count += 1
                continue
            seen_hashes.add(cfg_sig)

            if not scn.is_valid:
                invalid_count += 1
            scenarios.append(scn)

        return MatrixPlan(
            plan_id=f"plan_pairwise_{hashlib.sha256(json.dumps([s.scenario_id for s in scenarios]).encode()).hexdigest()[:8]}",
            generation_mode=GenerationMode.PAIRWISE,
            scenarios=tuple(scenarios),
            estimated_count=len(test_vectors),
            actual_count=len(scenarios),
            deduplicated_count=dedup_count,
            invalid_count=invalid_count,
            metadata={
                "strategy": "pairwise_2way",
                "coverage": "2-way combinatorial coverage (NOT exhaustive)",
                "total_pairs_covered": len(all_pairs) - len(uncovered),
                "total_pairs_target": len(all_pairs),
            },
        )

    def generate_exhaustive(
        self,
        engine_ids: list[str],
        profile_ids: list[str],
        variant_ids: list[str] | None = None,
        target: Target | None = None,
        node: MeasurementNode | None = None,
        workload: MeasurementWorkload | None = None,
        parameter_overrides: dict[str, Any] | None = None,
    ) -> MatrixPlan:
        est = self.estimate_count(engine_ids, profile_ids, variant_ids, GenerationMode.EXHAUSTIVE)
        if est > self.max_scenarios and not self.allow_exhaustive:
            raise MatrixSizeExceededError(
                f"Exhaustive scenario matrix estimate ({est}) exceeds maximum allowed threshold ({self.max_scenarios}). "
                "Explicitly set allow_exhaustive=True to confirm large matrix generation."
            )

        plan = self.generate_explicit(
            engine_ids=engine_ids,
            profile_ids=profile_ids,
            variant_ids=variant_ids,
            target=target,
            node=node,
            workload=workload,
            parameter_overrides=parameter_overrides,
        )

        return MatrixPlan(
            plan_id=f"plan_exhaustive_{plan.plan_id.split('_')[-1]}",
            generation_mode=GenerationMode.EXHAUSTIVE,
            scenarios=plan.scenarios,
            estimated_count=plan.estimated_count,
            actual_count=plan.actual_count,
            deduplicated_count=plan.deduplicated_count,
            invalid_count=plan.invalid_count,
            metadata={"strategy": "exhaustive_cartesian_product"},
        )

    def estimate_count(
        self,
        engine_ids: list[str],
        profile_ids: list[str],
        variant_ids: list[str] | None,
        mode: GenerationMode,
        node_count: int = 1,
    ) -> int:
        n_eng = len(engine_ids)
        n_prof = len(profile_ids)
        mult = max(1, node_count)

        match mode:
            case GenerationMode.EXPLICIT | GenerationMode.EXHAUSTIVE:
                total_vars = 0
                for pid in profile_ids:
                    prof = self.catalog.get_profile(pid)
                    if variant_ids:
                        total_vars += len(variant_ids)
                    elif prof and prof.default_variants:
                        total_vars += len(prof.default_variants)
                    else:
                        total_vars += 1
                return n_eng * max(1, total_vars) * mult

            case GenerationMode.OFAT:
                prof = self.catalog.get_profile(profile_ids[0]) if profile_ids else None
                n_vars = len(prof.default_variants) if prof and prof.default_variants else 1
                return (1 + max(0, n_vars - 1) + max(0, n_eng - 1)) * mult

            case GenerationMode.PAIRWISE:
                max_domain = max(n_eng, n_prof, len(variant_ids) if variant_ids else 3)
                return max(4, max_domain * 2) * mult

        return mult

    def generate_parameter_matrix(
        self,
        engine_id: str,
        profile_id: str,
        strategy: str = "ofat",
        target: Target | None = None,
        node: MeasurementNode | None = None,
        workload: MeasurementWorkload | None = None,
        include_invalid: bool = False,
        parameters_to_test: list[str] | None = None,
    ) -> MatrixPlan:
        effective_target = target or Target(host="127.0.0.1", port=443)
        effective_node = node or self.catalog.get_node("local") or MeasurementNode(node_id="local", name="Localhost")
        effective_workload = workload or MeasurementWorkload()

        profile = self.catalog.get_profile(profile_id)
        if not profile:
            raise ValueError(f"Unknown profile '{profile_id}' for parameter matrix generation")

        compat = self.catalog.get_compatibility(engine_id, profile_id)
        if not compat:
            raise ValueError(f"Engine '{engine_id}' does not support protocol profile '{profile_id}'")

        base_config = dict(BASELINE_PROFILE_CONFIGS.get(profile_id, {}))
        for p in profile.parameters:
            if p.param_id not in base_config and p.default is not None:
                base_config[p.param_id] = p.default

        applicable_params: list[ParameterDefinition] = []
        for p in profile.parameters:
            if parameters_to_test and p.param_id not in parameters_to_test:
                continue
            if engine_id == "sing_box":
                if p.param_id == "uot":
                    continue
                if p.param_id == "multi_mode" and profile_id == "vless_grpc_tls":
                    continue
                if p.param_id == "spider_x" and profile_id == "vless_tcp_reality":
                    continue
            applicable_params.append(p)

        baseline_scn = self.create_scenario(
            engine_id=engine_id,
            profile_id=profile_id,
            variant_id="baseline",
            target=effective_target,
            node=effective_node,
            workload=effective_workload,
            parameter_overrides=base_config,
            generation_mode=GenerationMode.OFAT if strategy == "ofat" else GenerationMode.PAIRWISE,
            extra_metadata={
                "is_baseline": True,
                "varied_factor": "baseline",
                "parameter_name": "none",
                "parameter_value": None,
                "parameter_category": "baseline",
                "expected_validation_stage": "real_binary_validation",
                "applicable_constraints": list(compat.parameter_constraints.keys()) if compat.parameter_constraints else [],
            },
        )

        scenarios: list[Scenario] = [baseline_scn]
        seen_configs: set[str] = {json.dumps(baseline_scn.resolved_config, sort_keys=True)}
        dedup_count = 0
        invalid_count = 1 if not baseline_scn.is_valid else 0

        if strategy.lower() == "ofat":
            for pdef in applicable_params:
                pid = pdef.param_id
                cat = categorize_parameter(pid)
                base_val = base_config.get(pid)
                variants = get_parameter_test_variants(pdef, base_val, engine_id=engine_id)

                for vval in variants:
                    ov = dict(base_config)
                    ov[pid] = vval
                    if profile_id == "shadowsocks_tcp" and pid == "method":
                        if vval in ("2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"):
                            ov["password"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
                        elif vval in ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"):
                            ov["password"] = "secret_password_123"

                    scn = self.create_scenario(
                        engine_id=engine_id,
                        profile_id=profile_id,
                        variant_id=f"param_{pid}_{str(vval).replace('/', '_').replace('-', '_')}",
                        target=effective_target,
                        node=effective_node,
                        workload=effective_workload,
                        parameter_overrides=ov,
                        generation_mode=GenerationMode.OFAT,
                        extra_metadata={
                            "is_baseline": False,
                            "varied_factor": f"{pid}:{vval}",
                            "parameter_name": pid,
                            "parameter_value": vval,
                            "parameter_category": cat,
                            "expected_validation_stage": "real_binary_validation",
                            "applicable_constraints": list(compat.parameter_constraints.keys()) if compat.parameter_constraints else [],
                        },
                    )
                    cfg_sig = json.dumps(scn.resolved_config, sort_keys=True)
                    if cfg_sig in seen_configs:
                        dedup_count += 1
                        continue
                    seen_configs.add(cfg_sig)
                    if not scn.is_valid:
                        invalid_count += 1
                    scenarios.append(scn)

                if include_invalid:
                    invalids = get_parameter_invalid_test_values(pdef, engine_id=engine_id)
                    for ival in invalids:
                        ov = dict(base_config)
                        ov[pid] = ival
                        scn = self.create_scenario(
                            engine_id=engine_id,
                            profile_id=profile_id,
                            variant_id=f"invalid_{pid}",
                            target=effective_target,
                            node=effective_node,
                            workload=effective_workload,
                            parameter_overrides=ov,
                            generation_mode=GenerationMode.OFAT,
                            extra_metadata={
                                "is_baseline": False,
                                "varied_factor": f"{pid}:{ival} (invalid)",
                                "parameter_name": pid,
                                "parameter_value": ival,
                                "parameter_category": cat,
                                "is_invalid_test": True,
                                "expected_validation_stage": "pre_execution_validation",
                                "applicable_constraints": list(compat.parameter_constraints.keys()) if compat.parameter_constraints else [],
                            },
                        )
                        if not scn.is_valid:
                            invalid_count += 1
                        scenarios.append(scn)

        elif strategy.lower() == "pairwise":
            factor_domains: dict[str, list[Any]] = {}
            for pdef in applicable_params:
                pid = pdef.param_id
                base_val = base_config.get(pid)
                var_vals = get_parameter_test_variants(pdef, base_val, engine_id=engine_id)
                domain = [base_val]
                for vv in var_vals[:2]:
                    if vv not in domain:
                        domain.append(vv)
                factor_domains[pid] = domain

            factor_names = sorted(factor_domains.keys())
            all_pairs = set()
            for i in range(len(factor_names)):
                for j in range(i + 1, len(factor_names)):
                    fa, fb = factor_names[i], factor_names[j]
                    for va in factor_domains[fa]:
                        for vb in factor_domains[fb]:
                            all_pairs.add(((fa, va), (fb, vb)))

            uncovered = set(all_pairs)
            pairwise_vectors: list[dict[str, Any]] = []

            while uncovered:
                sorted_uncovered = sorted(
                    uncovered,
                    key=lambda p: (p[0][0], str(p[0][1]), p[1][0], str(p[1][1])),
                )
                seed_pair = sorted_uncovered[0]
                seed_vector = {
                    seed_pair[0][0]: seed_pair[0][1],
                    seed_pair[1][0]: seed_pair[1][1],
                }

                for fn in factor_names:
                    if fn in seed_vector:
                        continue
                    best_val = factor_domains[fn][0]
                    best_cov = -1
                    for cand in factor_domains[fn]:
                        cnt = sum(
                            1 for af, av in seed_vector.items()
                            if tuple(sorted(((fn, cand), (af, av)))) in uncovered
                        )
                        if cnt > best_cov:
                            best_cov = cnt
                            best_val = cand
                    seed_vector[fn] = best_val

                covered_now = set()
                for i in range(len(factor_names)):
                    for j in range(i + 1, len(factor_names)):
                        fa, fb = factor_names[i], factor_names[j]
                        p = tuple(sorted(((fa, seed_vector[fa]), (fb, seed_vector[fb]))))
                        if p in uncovered:
                            covered_now.add(p)

                uncovered -= covered_now
                pairwise_vectors.append(seed_vector)
                if not covered_now:
                    break

            for idx, vec in enumerate(pairwise_vectors):
                ov = dict(base_config)
                ov.update(vec)
                if profile_id == "shadowsocks_tcp" and "method" in vec:
                    m_val = vec["method"]
                    if m_val in ("2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"):
                        ov["password"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
                    elif m_val in ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"):
                        ov["password"] = "secret_password_123"

                scn = self.create_scenario(
                    engine_id=engine_id,
                    profile_id=profile_id,
                    variant_id=f"pairwise_{idx:02d}",
                    target=effective_target,
                    node=effective_node,
                    workload=effective_workload,
                    parameter_overrides=ov,
                    generation_mode=GenerationMode.PAIRWISE,
                    extra_metadata={
                        "is_baseline": False,
                        "varied_factor": "pairwise_combination",
                        "pairwise_vector": vec,
                        "expected_validation_stage": "real_binary_validation",
                        "applicable_constraints": list(compat.parameter_constraints.keys()) if compat.parameter_constraints else [],
                    },
                )
                cfg_sig = json.dumps(scn.resolved_config, sort_keys=True)
                if cfg_sig in seen_configs:
                    dedup_count += 1
                    continue
                seen_configs.add(cfg_sig)
                if not scn.is_valid:
                    invalid_count += 1
                scenarios.append(scn)

        return MatrixPlan(
            plan_id=f"plan_params_{engine_id}_{profile_id}_{strategy}_{hashlib.sha256(json.dumps([s.scenario_id for s in scenarios]).encode()).hexdigest()[:8]}",
            generation_mode=GenerationMode.OFAT if strategy == "ofat" else GenerationMode.PAIRWISE,
            scenarios=tuple(scenarios),
            estimated_count=len(scenarios) + dedup_count,
            actual_count=len(scenarios),
            deduplicated_count=dedup_count,
            invalid_count=invalid_count,
            metadata={
                "strategy": f"parameter_{strategy}",
                "engine_id": engine_id,
                "profile_id": profile_id,
                "applicable_parameters_count": len(applicable_params),
                "include_invalid": include_invalid,
            },
        )
